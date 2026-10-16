"""Event finalization: sanitize, truncate, normalize the IP, enforce the cap.

All privacy-affecting work happens here, before anything reaches the queue:
- MCP arguments, LLM content, captured headers and schema catalogues pass
  through ``cerberus_core.sanitize_dict`` so SENSITIVE_KEYS values are redacted;
- credential-bearing headers are dropped outright;
- error and result text is scrubbed of credential-shaped substrings;
- long string values are truncated and oversized events shed content, then
  are dropped, so one giant prompt can't blow the ingest per-event cap.

Source IPs are normalized and shipped raw: they are not PII and are never
hashed. The numbers below are identical to cerberus-envoy-ai-gateway's; keep
them in step.
"""

import json
import logging
import math
from typing import Any

from cerberus_core import normalize_ip, sanitize_dict

from .config import SENSITIVE_HEADER_NAMES, Config
from .logthrottle import LogThrottle
from .redaction import redact_secrets

logger = logging.getLogger(__name__)

# Copied from cerberus_envoy_ai_gateway/pipeline.py (same numbers; keep them in step).
MAX_VALUE_CHARS = 8192
MAX_USER_AGENT_CHARS = 1024
MAX_USER_ID_CHARS = 256
MAX_ERROR_CHARS = 2048
MAX_IP_CHARS = 64
TRUNCATION_MARKER = "...[TRUNCATED]"
_CATALOGUE_KEYS = ("tools", "resources", "prompts")
# Identity-like custom_data strings that callers can influence (the request's
# ``user`` field, session and turn headers): bounded tighter than content.
_SHORT_CUSTOM_KEYS = (
    "litellm_end_user_id",
    "litellm_user_id",
    "litellm_key_alias",
    "litellm_team_id",
    "litellm_team_alias",
    "litellm_org_id",
    "litellm_session_id",
    "session_id",
    "turn_id",
)
# Wire-style credential header names (config.py normalises cerberus-core's
# Django-style spelling); matched case-insensitively below.
_SENSITIVE_HEADERS = SENSITIVE_HEADER_NAMES


def truncate_values(data: Any, limit: int = MAX_VALUE_CHARS) -> Any:
    """Recursively truncate string values longer than ``limit`` characters.

    Non-finite floats (NaN, Infinity) become None: they are not valid JSON and
    one of them would otherwise cost the event (or its whole batch).
    """
    if isinstance(data, str):
        return data[:limit] + TRUNCATION_MARKER if len(data) > limit else data
    if isinstance(data, float) and not math.isfinite(data):
        return None
    if isinstance(data, dict):
        return {key: truncate_values(value, limit) for key, value in data.items()}
    if isinstance(data, list):
        return [truncate_values(item, limit) for item in data]
    return data


def client_ip(raw: Any) -> str:
    """Normalized, raw (never hashed) client IP; malformed values are capped."""
    if not isinstance(raw, str) or not raw:
        return "unknown"
    return str(normalize_ip(raw))[:MAX_IP_CHARS]


def _encoded_size(event: dict[str, Any]) -> int:
    # allow_nan=False: the wire form must be valid JSON, so a stray NaN fails here
    # (and the event is dropped and counted) instead of failing the whole batch later.
    return len(json.dumps(event, allow_nan=False).encode("utf-8"))


class Pipeline:
    """Stateful finalizer with drop counters."""

    def __init__(self, config: Config):
        self.config = config
        self.dropped_oversize = 0
        self.dropped_unserializable = 0
        self._throttle = LogThrottle()

    def finalize(self, event: dict[str, Any], kind: str) -> tuple[dict[str, Any], int] | None:
        """Sanitize captured content, bound scalar fields, enforce the byte cap.

        Returns ``(event, encoded_size)``, or None when the event is dropped.
        """
        event["remote_addr"] = client_ip(event.get("remote_addr"))
        event["user_agent"] = truncate_values(event.get("user_agent"), MAX_USER_AGENT_CHARS)
        for field in ("user_id", "session_id"):
            if event.get(field) is not None:
                event[field] = truncate_values(event[field], MAX_USER_ID_CHARS)
        custom_data = event.get("custom_data")
        if not isinstance(custom_data, dict):
            custom_data = {}
            event["custom_data"] = custom_data
        if custom_data.get("error") is not None:
            error = custom_data["error"]
            if isinstance(error, str):
                error = redact_secrets(error)  # before truncation: no split tokens
            custom_data["error"] = truncate_values(error, MAX_ERROR_CHARS)
        if custom_data.get("result_summary") is not None:
            summary = custom_data["result_summary"]
            if isinstance(summary, str):
                summary = redact_secrets(summary)
            custom_data["result_summary"] = truncate_values(summary)
        # Everything else in custom_data can carry caller-supplied text (tags,
        # the request's ``user`` field, headers): bound every string, and the
        # identity-like ones tighter, so caller input cannot push an event
        # over the cap on its own.
        custom_data = truncate_values(custom_data)
        for key in _SHORT_CUSTOM_KEYS:
            if isinstance(custom_data.get(key), str):
                custom_data[key] = truncate_values(custom_data[key], MAX_USER_ID_CHARS)
        custom_data["integration"] = "litellm"
        event["custom_data"] = custom_data

        headers = event.get("headers")
        if isinstance(headers, dict):
            kept = {k: v for k, v in headers.items() if str(k).lower() not in _SENSITIVE_HEADERS}
            event["headers"] = truncate_values(sanitize_dict(kept)) or None
        else:
            event["headers"] = None

        if kind == "schema":
            for key in _CATALOGUE_KEYS:
                items = custom_data.get(key)
                if items:
                    custom_data[key] = truncate_values(
                        [sanitize_dict(i) if isinstance(i, dict) else i for i in items]
                    )
        elif kind == "mcp":
            if self.config.capture_mcp_arguments:
                arguments = truncate_values(sanitize_dict(custom_data.get("arguments") or {}))
                custom_data["arguments"] = arguments
                event["body"] = arguments or None
            else:
                custom_data["arguments"] = {}
                event["body"] = None
        elif event.get("body") is not None:
            event["body"] = truncate_values(sanitize_dict(event["body"]))

        return self._enforce_size(event)

    def _measure(self, event: dict[str, Any]) -> int | None:
        """Encoded size of ``event``, or None (counted and logged) if it cannot be encoded."""
        try:
            return _encoded_size(event)
        except (TypeError, ValueError):
            self._drop_unserializable(event)
            return None

    def _enforce_size(self, event: dict[str, Any]) -> tuple[dict[str, Any], int] | None:
        """Shed captured content, then drop the whole event, to stay under the cap.

        Returns the event with its encoded size (carried to the queue so the
        byte budget needs no second serialisation), or None when it is dropped.
        """
        size = self._measure(event)
        if size is None:
            return None
        if size <= self.config.max_event_bytes:
            return event, size

        event = {**event, "body": None}
        custom_data = dict(event.get("custom_data") or {})
        if "arguments" in custom_data:
            custom_data["arguments"] = {}
        if custom_data.get("result_summary"):
            custom_data["result_summary"] = None
        for key in _CATALOGUE_KEYS:
            if custom_data.get(key):
                custom_data[key] = []
        custom_data["content_dropped_oversize"] = True
        event["custom_data"] = custom_data

        size = self._measure(event)
        if size is None:
            return None
        if size <= self.config.max_event_bytes:
            return event, size

        # Second stage: shed the enrichment too (headers, tags, guardrails,
        # error text). Losing enrichment beats losing the event.
        event = {**event, "headers": None}
        custom_data = dict(event["custom_data"])
        for key in ("request_tags", "guardrails_applied"):
            if custom_data.get(key):
                custom_data[key] = []
        if custom_data.get("error"):
            custom_data["error"] = None
        custom_data["metadata_dropped_oversize"] = True
        event["custom_data"] = custom_data

        size = self._measure(event)
        if size is None:
            return None
        if size <= self.config.max_event_bytes:
            return event, size

        self._throttle.warn(
            logger,
            "Dropping oversized event (%dB > %dB) for endpoint %s",
            size,
            self.config.max_event_bytes,
            event.get("endpoint"),
        )
        self.dropped_oversize += 1
        return None

    def _drop_unserializable(self, event: dict[str, Any]) -> None:
        self._throttle.warn(
            logger, "Dropping unserializable event for endpoint %s", event.get("endpoint")
        )
        self.dropped_unserializable += 1
