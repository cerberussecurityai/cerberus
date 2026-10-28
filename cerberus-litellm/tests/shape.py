"""The ingest API's per-event contract, re-stated for tests.

Mirrors what the Cerberus ingest endpoint validates on POST /v1/ingest/batch
(see cerberus-envoy-ai-gateway/ARCHITECTURE.md "Wire contract"): a string
endpoint, string-or-absent scalar fields, object-or-null containers, an
ISO-8601 timestamp, and — for llm:// events on a detection-enabled key — a
body whose input is a messages list (or text) and whose output is present.
"""

import json
from datetime import datetime
from typing import Any

_STRING_FIELDS = ("event_type", "user_id", "session_id", "user_agent", "remote_addr", "method")
_OBJECT_FIELDS = ("custom_data", "headers", "query_params", "body")


def shape_problem(event: Any, max_bytes: int = 57344) -> str | None:
    if not isinstance(event, dict):
        return "not_an_object"
    endpoint = event.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint:
        return "endpoint_missing"
    for field in _STRING_FIELDS:
        value = event.get(field)
        if value is not None and not isinstance(value, str):
            return f"{field}_not_string"
    for field in _OBJECT_FIELDS:
        value = event.get(field)
        if value is not None and not isinstance(value, dict):
            return f"{field}_not_object"
    timestamp = event.get("timestamp")
    if not isinstance(timestamp, str):
        return "timestamp_invalid"
    try:
        datetime.fromisoformat(timestamp)
    except ValueError:
        return "timestamp_invalid"
    try:
        size = len(json.dumps(event).encode("utf-8"))
    except (TypeError, ValueError):
        return "not_serializable"
    if size > max_bytes:
        return "oversize"
    return None


def detection_shape(event: dict[str, Any]) -> str:
    if not str(event.get("endpoint", "")).startswith("llm://"):
        return "not_llm"
    body = event.get("body")
    if not isinstance(body, dict):
        return "body_missing"
    body_in, body_out = body.get("input"), body.get("output")
    if body_in is None and body_out is None:
        return "input_output_missing"
    if isinstance(body_in, dict):
        messages = body_in.get("messages")
        usable = (isinstance(messages, list) and len(messages) > 0) or (
            isinstance(messages, str) and messages.strip() != ""
        )
    else:
        usable = isinstance(body_in, str) and body_in.strip() != ""
    if not usable:
        return "input_unusable"
    if not body_out:
        return "output_missing"
    return "ok"
