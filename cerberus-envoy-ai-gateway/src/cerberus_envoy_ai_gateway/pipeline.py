"""Span → event pipeline: classify, map, sanitize, cap, enqueue.

All privacy-affecting work happens here, before anything reaches the queue:
- source IPs are normalized and HMAC-SHA256 hashed via cerberus-core
  (same contract as cerberus-django / cerberus-mcp / the flex-gateway port);
- MCP arguments and optional LLM content pass through
  ``cerberus_core.sanitize_dict`` so SENSITIVE_KEYS values are redacted;
- long string values are truncated and oversized events dropped so a single
  giant prompt can't blow the ingest server's per-event byte cap.
"""

import json
import logging
import re
from typing import Any

from cerberus_core import REDACTED, SENSITIVE_KEYS, hash_pii, normalize_ip, sanitize_dict

from .classify import KIND_LLM, KIND_MCP, classify
from .config import Config
from .mapper_llm import map_llm_span
from .mapper_mcp import map_mcp_span
from .otlp import iter_spans, span_attributes, span_event_attributes
from .queue import BoundedQueue

logger = logging.getLogger(__name__)

# Per-string-value truncation applied to captured content/arguments. Keeps
# any single prompt/argument bounded well under CERBERUS_MAX_EVENT_BYTES.
MAX_VALUE_CHARS = 8192

# Caps for client-controlled scalar fields mapped from request headers.
# Without these, a single oversized header (Envoy allows ~60KiB of request
# headers by default) would push every event from that client over the
# event byte cap — a silent telemetry-evasion vector, since _enforce_size
# can only shed body/arguments before dropping the event entirely.
MAX_USER_AGENT_CHARS = 1024
MAX_USER_ID_CHARS = 256
MAX_ERROR_CHARS = 2048
# Extra attributes are correlation keys (tenant/session/request ids), not
# content — keep them tight, since they are unsheddable like user_id above.
MAX_EXTRA_VALUE_CHARS = 1024
# A valid IP (incl. IPv6 + zone) is <=45 chars; bound malformed raw values.
MAX_IP_CHARS = 64


def extra_attribute_key(name: str) -> str:
    """Derive a ``custom_data`` key from a span attribute name (``A.b-c`` -> ``a_b_c``).

    Lower-cased so a header copy-pasted with mixed case still lands on the
    snake_case key every other ``custom_data`` entry uses.
    """
    return name.strip().lower().replace(".", "_").replace("-", "_")


def is_sensitive_attribute(name: str) -> bool:
    """True when any segment of a span attribute name is a SENSITIVE_KEYS entry.

    ``sanitize_dict`` matches whole keys, so a namespaced OTel name like
    ``http.request.header.authorization`` flattens to
    ``http_request_header_authorization`` — which matches nothing, and would
    copy a bearer token through in cleartext. Splitting on ``.``/``-`` keeps
    compound entries like ``api_key`` intact; also splitting on ``_`` catches
    the dotted spelling (``access.token`` -> ``token``).
    """
    lowered = name.strip().lower()
    segments = set(re.split(r"[.\-]", lowered)) | set(re.split(r"[.\-_]", lowered))
    return any(segment in SENSITIVE_KEYS for segment in segments if segment)


def coerce_json_safe(value: Any) -> Any:
    """Convert OTLP values ``json.dumps`` can't encode (``bytes``) into text.

    An unserializable value would fail the ``json.dumps`` in ``_enforce_size``
    and take the whole event down with it, so a byte-valued attribute must not
    reach the queue unconverted.
    """
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        return {key: coerce_json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [coerce_json_safe(item) for item in value]
    return value


def coerce_extra_value(value: Any) -> Any:
    """Reduce an extra attribute to a scalar ``truncate_values`` can bound.

    Extras are correlation identifiers landing in ``custom_data`` keys that
    ``_enforce_size`` cannot shed, so their size has to be settled here.
    Truncation only bounds string *leaves*, so a structured attribute — an OTLP
    ``array_value``/``kvlist_value`` with thousands of small elements — would
    sail through it and push the event past the byte cap, dropping it whole.
    Serializing anything non-scalar gives every extra a hard bound.
    """
    safe = coerce_json_safe(value)
    if isinstance(safe, (str, int, float, bool)):
        return safe
    return json.dumps(safe, ensure_ascii=False)


def truncate_values(data: Any, limit: int = MAX_VALUE_CHARS) -> Any:
    """Recursively truncate string values longer than ``limit`` characters."""
    if isinstance(data, str):
        if len(data) > limit:
            return data[:limit] + "...[TRUNCATED]"
        return data
    if isinstance(data, dict):
        return {key: truncate_values(value, limit) for key, value in data.items()}
    if isinstance(data, list):
        return [truncate_values(item, limit) for item in data]
    return data


class Pipeline:
    """Stateful converter from OTLP export requests to queued Cerberus events."""

    def __init__(self, config: Config, queue: BoundedQueue, secret_key: str | None):
        self.config = config
        self.queue = queue
        self.secret_key = secret_key
        self.events_llm = 0
        self.events_mcp = 0
        # Collision warnings are once-per-key: the condition is a static config
        # mistake, so re-logging it per event would just flood.
        self._extra_key_collisions: set[str] = set()
        self.spans_ignored = 0
        self.spans_filtered = 0
        self.dropped_oversize = 0

    def process_export(self, request: Any) -> int:
        """Map every span in an ExportTraceServiceRequest; returns events queued."""
        queued = 0
        for _scope_name, span in iter_spans(request):
            attrs = span_attributes(span)
            # Envoy AI Gateway records MCP route info (mcp.backend.name,
            # mcp.session.id) as span-EVENT attributes via span.AddEvent, not
            # top-level attributes; merge them so MCP spans resolve their
            # backend/session instead of falling back to "unknown" (top-level
            # attrs win on collision).
            event_attrs = span_event_attributes(span)
            if event_attrs:
                attrs = {**event_attrs, **attrs}
            kind = classify(attrs)
            if kind is None:
                self.spans_ignored += 1
                continue
            event: dict[str, Any] | None
            if kind == KIND_LLM:
                event = map_llm_span(span, attrs, self.config)
            else:
                event = map_mcp_span(span, attrs, self.config)
            if event is None:
                # Classified but unroutable — MCP protocol overhead (initialize /
                # ping / notifications/*) or a tools/list with no recorded
                # response. Expected, so keep it out of spans_ignored, which is
                # reserved for truly unclassified spans operators should chase.
                self.spans_filtered += 1
                continue
            self._apply_extra_attributes(event, attrs)
            finalized = self._finalize(event, kind)
            if finalized is None:
                continue
            if self.queue.append(finalized):
                queued += 1
                if kind == KIND_LLM:
                    self.events_llm += 1
                else:
                    self.events_mcp += 1
        return queued

    def _apply_extra_attributes(self, event: dict[str, Any], attrs: dict[str, Any]) -> None:
        """Copy operator-selected span attributes into ``custom_data``.

        Correlating an agent's LLM events with its MCP events can't rely on
        ``trace_id`` (the gateway parents the two paths from different carriers
        and never joins them), so operators need a way to surface whatever
        header their application already sends on both. This copies those
        attributes through verbatim.

        Mapper-set keys always win: gateway telemetry outranks operator config,
        so a stray mapping can never replace ``trace_id`` and friends.
        """
        if not self.config.extra_attributes:
            return
        custom_data = event["custom_data"]
        extras: dict[str, Any] = {}
        # Keys whose *attribute name* is sensitive even though the flattened key
        # isn't — sanitize_dict can't see those, so redact them ourselves.
        redact: set[str] = set()
        for name in self.config.extra_attributes:
            value = attrs.get(name)
            if value is None:
                continue
            key = extra_attribute_key(name)
            # Guards against keys the *mappers* set, all of which are present by
            # now. Keys written later still win by overwriting — only
            # `content_dropped_oversize` from _enforce_size, which an operator
            # would have to name deliberately to collide with.
            if key in custom_data or key in extras:
                if key not in self._extra_key_collisions:
                    self._extra_key_collisions.add(key)
                    logger.warning(
                        "CERBERUS_EXTRA_ATTRIBUTES: %r maps to custom_data key %r, "
                        "which is already set — skipping (choose a different attribute)",
                        name,
                        key,
                    )
                continue
            extras[key] = coerce_extra_value(value)
            if is_sensitive_attribute(name):
                redact.add(key)
        if not extras:
            return
        extras = truncate_values(sanitize_dict(extras), MAX_EXTRA_VALUE_CHARS)
        for key in redact:
            extras[key] = REDACTED
        custom_data.update(extras)

    def _finalize(self, event: dict[str, Any], kind: str) -> dict[str, Any] | None:
        """Hash PII, sanitize captured content, and enforce the event byte cap."""
        event["remote_addr"] = self._pseudonymize_ip(event.get("remote_addr"))

        event["user_agent"] = truncate_values(event.get("user_agent"), MAX_USER_AGENT_CHARS)
        if event.get("user_id") is not None:
            event["user_id"] = truncate_values(event["user_id"], MAX_USER_ID_CHARS)
        if event["custom_data"].get("error") is not None:
            event["custom_data"]["error"] = truncate_values(
                event["custom_data"]["error"], MAX_ERROR_CHARS
            )

        if kind == KIND_MCP:
            if event["method"] == "mcp_schema_report":
                # Schema reports carry no arguments, but the tool/resource/prompt
                # declarations can embed credential-shaped keys in descriptions or
                # inputSchema examples — redact (and bound) all three lists, the
                # same set _enforce_size sheds.
                for catalogue_key in ("tools", "resources", "prompts"):
                    items = event["custom_data"].get(catalogue_key)
                    if items:
                        event["custom_data"][catalogue_key] = truncate_values(
                            [sanitize_dict(i) if isinstance(i, dict) else i for i in items]
                        )
            elif self.config.capture_mcp_arguments:
                arguments = sanitize_dict(event["custom_data"].get("arguments") or {})
                arguments = truncate_values(arguments)
                event["custom_data"]["arguments"] = arguments
                event["body"] = arguments or None
            else:
                event["custom_data"]["arguments"] = {}
                event["body"] = None

        if kind == KIND_LLM and event.get("body") is not None:
            event["body"] = truncate_values(sanitize_dict(event["body"]))

        return self._enforce_size(event)

    def _pseudonymize_ip(self, raw_ip: str | None) -> str:
        if not raw_ip:
            return "unknown"
        normalized = normalize_ip(raw_ip)
        if self.secret_key:
            return str(hash_pii(normalized, self.secret_key))
        # Raw-IP mode (no secret): normalize_ip passes malformed values through
        # verbatim, and remote_addr is unsheddable — cap it so a giant malformed
        # X-Forwarded-For hop can't push the event over the byte cap.
        return str(normalized)[:MAX_IP_CHARS]

    def _enforce_size(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Drop captured content, then the whole event, to stay under the cap."""
        try:
            size = len(json.dumps(event).encode("utf-8"))
        except (TypeError, ValueError):
            logger.warning("Dropping unserializable event for endpoint %s", event.get("endpoint"))
            self.dropped_oversize += 1
            return None
        if size <= self.config.max_event_bytes:
            return event

        event = {**event, "body": None}
        custom_data = dict(event.get("custom_data") or {})
        if "arguments" in custom_data:
            custom_data["arguments"] = {}
        # Schema reports carry their payload in tools/resources/prompts (body is
        # already None), so shed those too — otherwise an oversized tool
        # catalogue can't shrink and the event is dropped whole instead of
        # landing as a schema_only skeleton the backend can still record.
        for catalogue_key in ("tools", "resources", "prompts"):
            if custom_data.get(catalogue_key):
                custom_data[catalogue_key] = []
        custom_data["content_dropped_oversize"] = True
        event["custom_data"] = custom_data

        size = len(json.dumps(event).encode("utf-8"))
        if size <= self.config.max_event_bytes:
            return event
        logger.warning(
            "Dropping oversized event (%dB > %dB) for endpoint %s",
            size,
            self.config.max_event_bytes,
            event.get("endpoint"),
        )
        self.dropped_oversize += 1
        return None
