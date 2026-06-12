"""Shared span-field extraction helpers used by both mappers."""

import json
from datetime import UTC, datetime
from typing import Any

from opentelemetry.proto.trace.v1.trace_pb2 import Span

# Span.status.code values (opentelemetry.proto.trace.v1.Status.StatusCode).
_STATUS_ERROR = 2


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
    hop list — the left-most entry is the original client.
    """
    value = attrs.get(attribute)
    if not isinstance(value, str) or not value.strip():
        return None
    return value.split(",")[0].strip()


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
