"""Span → event pipeline: classify, map, sanitize, cap, enqueue.

All privacy-affecting work happens here, before anything reaches the queue:
- source IPs are normalized and HMAC-SHA256 hashed via cerberus-core
  (same contract as cerberus-django / cerberus-mcp / the flex-gateway port);
- MCP arguments and optional LLM content pass through
  ``cerberus_core.sanitize_dict`` so SENSITIVE_KEYS values are redacted;
- long string values are truncated and oversized events dropped so a single
  giant prompt can't blow the ingest server's per-event byte cap.
"""

import base64
import json
import logging
import re
from typing import Any

from cerberus_core import REDACTED, SENSITIVE_KEYS, hash_pii, normalize_ip, sanitize_dict

from .classify import KIND_LLM, KIND_MCP, classify
from .config import Config, ConfigError
from .mapper_llm import CONSUMED_ATTRIBUTE_PREFIXES as LLM_CONSUMED_PREFIXES
from .mapper_llm import CONSUMED_ATTRIBUTES as LLM_CONSUMED
from .mapper_llm import map_llm_span
from .mapper_mcp import CONSUMED_ATTRIBUTE_PREFIXES as MCP_CONSUMED_PREFIXES
from .mapper_mcp import CONSUMED_ATTRIBUTES as MCP_CONSUMED
from .mapper_mcp import map_mcp_span
from .otlp import iter_spans, span_attributes, span_event_attributes
from .queue import BoundedQueue
from .spanfields import CONSUMED_ATTRIBUTES as SPANFIELDS_CONSUMED

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
# Measured in *encoded* bytes, not characters: json.dumps escapes non-ASCII, so
# a character cap lets an emoji-heavy value cost 12x its length.
MAX_EXTRA_VALUE_BYTES = 1024
# A valid IP (incl. IPv6 + zone) is <=45 chars; bound malformed raw values.
MAX_IP_CHARS = 64

# Longest SENSITIVE_KEYS entry in words, bounding the n-gram scan in
# is_sensitive_attribute. Derived so a longer entry added upstream widens the
# scan automatically instead of silently falling outside it.
_MAX_SENSITIVE_WORDS = max(len(key.split("_")) for key in SENSITIVE_KEYS)


def attribute_words(name: str) -> list[str]:
    """Split an attribute name into lower-case alphanumeric words.

    The standard three-rule identifier word-split, so every separator and case
    convention an operator might use decomposes the same way (names flow in
    arbitrary from ``OTEL_AIGW_SPAN_REQUEST_HEADER_ATTRIBUTES``):

    1. non-alphanumeric runs   — ``http/request/header/authorization``
    2. lower/digit → upper     — ``httpRequestHeaderAuthorization``
    3. upper → upper+lower     — ``HTTPAuthorization`` (acronym then word)

    Rule 3 is what an earlier two-rule version missed: without it
    ``HTTPAuthorization`` stayed one token and the credential shipped in
    cleartext. Case boundaries are marked before lower-casing, which would erase
    them. This covers every *structural* spelling; it cannot split a run with no
    boundary at all (``privatekey``) — see ``is_sensitive_attribute``.
    """
    marked = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", name.strip())  # acronym → word
    marked = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", marked)  # camelCase
    return [word for word in re.split(r"[^a-z0-9]+", marked.lower()) if word]


def extra_attribute_key(name: str) -> str:
    """Derive a ``custom_data`` key from a span attribute name (``A.b/c`` -> ``a_b_c``).

    Lower-cased and every separator collapsed to ``_``, so the key is clean
    snake_case whatever punctuation the source name used, and two names that
    differ only in separator land on the same key (caught by
    ``_reject_ambiguous_attribute_keys``).
    """
    return "_".join(attribute_words(name))


def is_sensitive_attribute(name: str) -> bool:
    """True when any run of words in a span attribute name is a SENSITIVE_KEYS entry.

    ``sanitize_dict`` matches whole keys, so a namespaced OTel name like
    ``http.request.header.authorization`` flattens to
    ``http_request_header_authorization``, matches nothing, and would copy a
    bearer token through in cleartext.

    Word runs rather than single segments, because several SENSITIVE_KEYS
    entries are multi-word (``api_key``, ``private_key``, ``credit_card``,
    ``session_id``) and none of their individual words is sensitive alone.

    **Best-effort, not a guarantee.** ``attribute_words`` decomposes every
    *structural* spelling — separators (``x-api-key``), camelCase, acronyms — so
    those are caught. It cannot split a name with no internal boundary
    (``privatekey``, ``sessiontoken``), because telling that apart from an
    ordinary word needs a dictionary, and it says nothing about a benign-named
    attribute carrying a secret *value*. The real contract, as with
    ``CERBERUS_CAPTURE_LLM_CONTENT``, is that operators must not select
    attributes that carry secrets; this check is a safety net for the common
    spellings of that mistake, not a content scanner.
    """
    words = attribute_words(name)
    for start in range(len(words)):
        for length in range(1, _MAX_SENSITIVE_WORDS + 1):
            if start + length > len(words):
                break
            if "_".join(words[start : start + length]) in SENSITIVE_KEYS:
                return True
    return False


def redact_sensitive_nested_keys(value: Any) -> Any:
    """Redact values under any dict key whose *name* is sensitive, recursively.

    ``sanitize_dict`` matches whole keys only, so a nested namespaced key like
    ``{"http.request.header.authorization": "Bearer ..."}`` inside a structured
    extra evades it — the outer attribute name is benign and the inner key never
    matches ``authorization`` exactly. Applying the same word-run test to every
    nested key closes that, mirroring what ``is_sensitive_attribute`` does for
    the top-level name.
    """
    if isinstance(value, dict):
        return {
            key: (
                REDACTED
                if isinstance(key, str) and is_sensitive_attribute(key)
                else redact_sensitive_nested_keys(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_nested_keys(item) for item in value]
    return value


def coerce_json_safe(value: Any) -> Any:
    """Convert OTLP values ``json.dumps`` can't encode (``bytes``) into text.

    An unserializable value would fail the ``json.dumps`` in ``_enforce_size``
    and take the whole event down with it, so a byte-valued attribute must not
    reach the queue unconverted.

    Conversion is **lossless**: valid UTF-8 decodes to readable text, and
    anything else becomes ``base64:<...>`` rather than replacement characters.
    These values are advertised as correlation keys, so a lossy decode that
    mapped ``b"\\xff"`` and ``b"\\xfe"`` both to U+FFFD would make distinct
    identifiers collide and correlate unrelated events.
    """
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return "base64:" + base64.b64encode(value).decode("ascii")
    if isinstance(value, dict):
        return {key: coerce_json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [coerce_json_safe(item) for item in value]
    return value


def stable_text(value: Any) -> str:
    """Deterministic text form of a value, so equal values hash alike.

    Sorted keys matter: an LLM span and an MCP span must produce the same digest
    for the same structured value, or the join this exists for silently fails.
    """
    safe = coerce_json_safe(value)
    if isinstance(safe, str):
        return safe
    return json.dumps(safe, sort_keys=True, ensure_ascii=False)


def fit_encoded(text: str, max_bytes: int) -> str:
    """Trim ``text`` until its JSON-encoded form fits ``max_bytes``.

    A character cap does **not** bound bytes: ``json.dumps`` escapes non-ASCII,
    so one astral character costs 12 bytes — 1024 emoji encode to ~12 KB. Extras
    land in ``custom_data`` keys ``_enforce_size`` can't shed, so an unbounded
    value pushes the event past the cap and drops it whole rather than degrading.
    """
    if len(json.dumps(text)) <= max_bytes:
        return text
    suffix = "...[TRUNCATED]"
    budget = max_bytes - len(json.dumps(suffix))
    if budget <= 0:
        # max_bytes is smaller than the marker itself. Drop the marker rather
        # than return something that still exceeds the cap it was handed —
        # unreachable at the current MAX_EXTRA_VALUE_BYTES, latent if lowered.
        suffix, budget = "", max_bytes
    low, high = 0, len(text)
    while low < high:
        mid = (low + high + 1) // 2
        if len(json.dumps(text[:mid])) <= budget:
            low = mid
        else:
            high = mid - 1
    return text[:low] + suffix


def bound_extra_value(value: Any) -> Any:
    """Reduce a sanitized extra to a scalar bounded by encoded size.

    Runs *after* ``sanitize_dict`` — serializing first would hide nested
    credential-shaped keys from it, shipping an inner secret in cleartext under
    a benign-looking outer key.
    """
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    return fit_encoded(stable_text(value), MAX_EXTRA_VALUE_BYTES)


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


def _reject_bridge_owned_attributes(config: Config) -> None:
    """Refuse to capture or hash an attribute the bridge already reads itself.

    Selecting one produces a *dual write*: the mapper copies the same source
    into ``custom_data``, a top-level field, or ``endpoint`` under its own name,
    so the raw value survives beside any digest — and for endpoint-embedded
    sources (``llm://{provider}/{model}``, ``mcp://{server}/{handler}``) it can't
    be pseudonymized at all without destroying the endpoint.

    Rejecting the configuration removes the whole class rather than chasing
    destinations one at a time. It fails loudly at startup instead of leaking
    quietly at runtime, and over-rejecting is safe — the operator maps their own
    header (``corr.session``, ``tenant.id``) and gets a conflict-free key.
    """
    owned = set(LLM_CONSUMED) | set(MCP_CONSUMED) | set(SPANFIELDS_CONSUMED)
    for attribute in (
        config.client_ip_attribute,
        config.user_id_attribute,
        config.user_agent_attribute,
    ):
        if attribute:
            owned.add(attribute.strip().lower())
    for label, names in (
        ("CERBERUS_EXTRA_ATTRIBUTES", config.extra_attributes),
        ("CERBERUS_HASH_ATTRIBUTES", config.hash_attributes),
    ):
        for name in names:
            lowered = name.strip().lower()
            prefixes = LLM_CONSUMED_PREFIXES + MCP_CONSUMED_PREFIXES
            if lowered in owned or lowered.startswith(prefixes):
                raise ConfigError(
                    f"{label}: {name!r} is already read by the bridge, which copies it into "
                    "the event under its own name — selecting it would leave the raw value "
                    "alongside the captured one. Map your application's own header to a "
                    "distinct attribute (e.g. 'corr.session') and select that instead."
                )


def _reject_ambiguous_attribute_keys(config: Config) -> None:
    """Refuse two different attributes that would claim the same ``custom_data`` key.

    ``extra_attribute_key`` maps both ``.`` and ``-`` to ``_``, so ``tenant-id``
    and ``tenant.id`` collapse together. With one in each list the outcome
    depended on processing order: extras ran first, the hash entry then hit the
    already-taken key and was skipped *before* its digest was computed, and the
    raw value shipped in cleartext — defeating the one guarantee
    ``CERBERUS_HASH_ATTRIBUTES`` exists to make.

    Naming the same attribute in both lists is fine and means "hash it"; only
    two *distinct* names claiming one key are ambiguous, so they are refused
    rather than silently resolved by iteration order.
    """
    claimed: dict[str, str] = {}
    for label, names in (
        ("CERBERUS_EXTRA_ATTRIBUTES", config.extra_attributes),
        ("CERBERUS_HASH_ATTRIBUTES", config.hash_attributes),
    ):
        for name in names:
            stripped = name.strip()
            key = extra_attribute_key(name)
            prior = claimed.get(key)
            if prior is not None and prior != stripped:
                raise ConfigError(
                    f"{label}: {name!r} and {prior!r} both map to custom_data key {key!r}. "
                    "Only one attribute may claim a key — otherwise which value is stored, "
                    "and whether it is hashed, depends on processing order. Rename one."
                )
            claimed[key] = stripped


class Pipeline:
    """Stateful converter from OTLP export requests to queued Cerberus events."""

    def __init__(self, config: Config, queue: BoundedQueue, secret_key: str | None):
        _reject_bridge_owned_attributes(config)
        _reject_ambiguous_attribute_keys(config)
        self.config = config
        self.queue = queue
        self.secret_key = secret_key
        self.events_llm = 0
        self.events_mcp = 0
        # Collision warnings are once-per-key: the condition is a static config
        # mistake, so re-logging it per event would just flood.
        self._extra_key_collisions: set[str] = set()
        # Configured names are static for the life of the pipeline, so settle
        # the sensitivity verdict once here rather than per span.
        self._sensitive_extras = frozenset(
            name for name in config.extra_attributes if is_sensitive_attribute(name)
        )
        # custom_data keys the extras path added to the *current* event. Only
        # these are sheddable in _enforce_size — the static configured set would
        # also include names that collided with a mapper key and were skipped,
        # so shedding those would delete the gateway's own trace_id/model/etc.
        # Reset per event in _apply_extra_attributes; safe because process_export
        # handles one span at a time (apply → finalize → enforce, no interleave).
        self._pending_extra_keys: set[str] = set()
        # Captured names (extras plus hash-only additions) and the hash set are
        # static, so settle them once rather than rebuilding per span. Hash-listed
        # attributes are captured too, so an operator correlating on one
        # identifier only has to name it once.
        self._hash_names = frozenset(config.hash_attributes)
        self._captured_names: tuple[str, ...] = config.extra_attributes + tuple(
            name for name in config.hash_attributes if name not in config.extra_attributes
        )
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

    def _pseudonymize_correlator(self, value: Any) -> str:
        """HMAC a correlation value so events join on it without storing it raw.

        Deterministic and key-scoped, so the same identifier on an LLM span and
        an MCP span yields the same digest and the two join — which is the point,
        given ``trace_id`` doesn't correlate the paths.

        Unlike :meth:`_pseudonymize_ip` this **never** falls back to the raw
        value. The operator asked for this attribute specifically not to be
        stored in the clear, so with no secret available the only safe answer is
        to drop it; failing open would do the exact opposite of what was asked.
        """
        if not self.secret_key:
            return str(REDACTED)
        return str(hash_pii(stable_text(value), self.secret_key))

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
        self._pending_extra_keys = set()
        hash_names = self._hash_names
        names = self._captured_names
        if not names:
            return
        hash_names = self._hash_names
        names = self._captured_names
        custom_data = event["custom_data"]
        extras: dict[str, Any] = {}
        # Keys whose *attribute name* is sensitive even though the flattened key
        # isn't — sanitize_dict can't see those, so redact them ourselves.
        redact: set[str] = set()
        # Applied after sanitize_dict, which would otherwise redact a digest
        # sitting under a sensitive-looking key (the session_id case).
        hashed: dict[str, str] = {}
        for name in names:
            value = attrs.get(name)
            if value is None:
                continue
            key = extra_attribute_key(name)
            is_hashed = name in hash_names
            # Guards keys the mappers set, so operator config can't spoof
            # trace_id and friends. Sources the mappers *read* are refused at
            # startup, so a hash-listed attribute can no longer alias one.
            # Deliberately does not check the in-progress `hashed` dict:
            # _reject_ambiguous_attribute_keys guarantees no two distinct names
            # in either list share a derived key, so nothing reaches here with a
            # pending hashed entry under `key`. If that invariant ever lapses,
            # this check has to grow to cover `hashed` too.
            if key in extras or key in custom_data:
                if key not in self._extra_key_collisions:
                    self._extra_key_collisions.add(key)
                    logger.warning(
                        "%s: %r maps to custom_data key %r, which the gateway already "
                        "set — skipping (choose a different attribute)",
                        "CERBERUS_HASH_ATTRIBUTES" if is_hashed else "CERBERUS_EXTRA_ATTRIBUTES",
                        name,
                        key,
                    )
                continue
            if is_hashed:
                # Never routed through `extras` — the raw value must not exist
                # in the event even transiently.
                hashed[key] = self._pseudonymize_correlator(value)
                continue
            # Structure is preserved here so sanitize_dict can recurse into it;
            # serializing before that would hide nested credential keys.
            extras[key] = coerce_json_safe(value)
            if name in self._sensitive_extras:
                redact.add(key)
        if extras:
            extras = {
                key: bound_extra_value(redact_sensitive_nested_keys(item))
                for key, item in sanitize_dict(extras).items()
            }
            for key in redact:
                extras[key] = REDACTED
        extras.update(hashed)
        if extras:
            custom_data.update(extras)
            self._pending_extra_keys = set(extras)

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

        # Last resort before dropping the event whole: shed operator-added
        # extras. They land in unsheddable-by-default custom_data keys, so a
        # small max_event_bytes could otherwise let a bounded extra sink an
        # otherwise-valid event. Losing enrichment beats losing the event. Only
        # the keys this event's extras path actually inserted — never a mapper
        # key a collided extra was skipped over.
        shed = [key for key in self._pending_extra_keys if key in custom_data]
        if shed:
            for key in shed:
                del custom_data[key]
            custom_data["extras_dropped_oversize"] = True
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
