"""Shared span-field extraction helpers used by both mappers."""

import json
from datetime import UTC, datetime
from typing import Any

from opentelemetry.proto.trace.v1.trace_pb2 import Span

# Span.status.code values (opentelemetry.proto.trace.v1.Status.StatusCode).
_STATUS_ERROR = 2

# Candidate attribute keys for the request model, shared by classify() (to
# detect an LLM span) and mapper_llm (to resolve it) so the two can't drift.
MODEL_KEYS = ("llm.model_name", "embedding.model_name", "llm.model", "gen_ai.request.model")

# Cap for scalar fields that feed the endpoint (LLM provider/model, MCP
# server/handler). _enforce_size can't shed these, so an overlong value would
# push the whole event over the byte cap and drop it — bound them at the source.
MAX_LABEL_CHARS = 256


def iso_timestamp(span: Span) -> str:
    """Span start time as an ISO 8601 string with a UTC offset.

    event_process parses timestamps with ``datetime.fromisoformat`` and
    requires an explicit offset (or trailing Z); ``+00:00`` satisfies it.
    """
    seconds = span.start_time_unix_nano / 1e9
    return datetime.fromtimestamp(seconds, tz=UTC).isoformat()


def duration_ms(span: Span) -> float:
    """Span duration in milliseconds (0 when timestamps are missing)."""
    if span.end_time_unix_nano <= span.start_time_unix_nano:
        return 0.0
    return (span.end_time_unix_nano - span.start_time_unix_nano) / 1e6


def error_message(span: Span, attrs: dict[str, Any]) -> str | None:
    """Error description when the span failed, else None."""
    if span.status.code != _STATUS_ERROR and not attrs.get("error.type"):
        return None
    return span.status.message or str(attrs.get("error.type") or "error")


def first_attr(attrs: dict[str, Any], keys: tuple[str, ...]) -> Any:
    """First non-empty attribute value among ``keys``."""
    for key in keys:
        value = attrs.get(key)
        if value not in (None, ""):
            return value
    return None


def raw_client_ip(attrs: dict[str, Any], attribute: str) -> str | None:
    """Client IP from the configured span attribute.

    The attribute is populated from a header like X-Forwarded-For via
    OTEL_AIGW_SPAN_REQUEST_HEADER_ATTRIBUTES, so it may hold a comma-folded
    hop list — the left-most NON-EMPTY entry is the original client (a
    malformed leading comma, e.g. ",10.0.0.1", must not drop the real IP).
    """
    value = attrs.get(attribute)
    if not isinstance(value, str) or not value.strip():
        return None
    return next((s for s in (p.strip() for p in value.split(",")) if s), None)


def parse_json_value(value: Any) -> Any:
    """JSON-parse strings when possible; pass other values through."""
    if isinstance(value, str):
        text = value.strip()
        if text.startswith(("{", "[")):
            try:
                return json.loads(text)
            except (ValueError, TypeError):
                return value
    return value


def span_user_agent(attrs: dict[str, Any], attribute: str, fallback: str) -> str:
    """User-agent from the configured span attribute, else the bridge default."""
    return str(attrs.get(attribute) or fallback)


def span_user_id(attrs: dict[str, Any], attribute: str | None) -> str | None:
    """End-user id from the configured span attribute, when set and non-empty."""
    if attribute and attrs.get(attribute) not in (None, ""):
        return str(attrs[attribute])
    return None
