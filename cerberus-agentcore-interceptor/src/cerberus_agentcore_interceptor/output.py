"""Interceptor outputs that return the caller's payload unchanged.

The `mcp` shape has no empty pass-through: `{"mcp": {}}` is accepted, answers
HTTP 200 and replaces the payload. An `mcp` output has to echo the body back.
`{"http": {}}` is a true pass-through in both phases.
"""

from __future__ import annotations

import json
from typing import Any

from .envelope import HTTP, REQUEST, RESPONSE, Envelope

OUTPUT_VERSION = "1.0"


def http_passthrough() -> dict[str, Any]:
    """The documented pass-through, fresh each call so no caller shares it."""
    return {"interceptorOutputVersion": OUTPUT_VERSION, HTTP: {}}


def passthrough(envelope: Envelope) -> dict[str, Any]:
    """An output that returns the payload the gateway gave us, unchanged."""
    if envelope.kind == HTTP or not envelope.shape_key:
        # An unidentified shape has nothing to echo, and this is the one empty
        # form the gateway treats as "keep what you were given".
        return http_passthrough()

    key = envelope.shape_key
    if envelope.phase == RESPONSE:
        response = envelope.response or {}
        body = response.get("body")
        if body is None:
            return {"interceptorOutputVersion": OUTPUT_VERSION, key: {}}
        transformed: dict[str, Any] = {"body": body}
        status = response.get("statusCode")
        if status is not None:
            transformed["statusCode"] = status
        return {
            "interceptorOutputVersion": OUTPUT_VERSION,
            key: {"transformedGatewayResponse": transformed},
        }

    body = _request_body(envelope)
    if body is None:
        return {"interceptorOutputVersion": OUTPUT_VERSION, key: {}}
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        key: {"transformedGatewayRequest": {"body": body}},
    }


def is_valid_output(value: Any) -> bool:
    """True when a value is an interceptor output the gateway will accept."""
    return isinstance(value, dict) and value.get("interceptorOutputVersion") == OUTPUT_VERSION


def _request_body(envelope: Envelope) -> Any:
    body = (envelope.request or {}).get("body")
    if isinstance(body, str):
        # The gateway hands the target a parsed body; echoing the text would
        # send it a JSON string instead of the call.
        body = _parsed(body)
    if body is not None:
        return body
    if envelope.phase == REQUEST and envelope.raw_body:
        return _parsed(envelope.raw_body)
    return None


def _parsed(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None
