"""Interceptor outputs that leave the caller's request untouched.

The `mcp` shape has no empty pass-through: `{"mcp": {}}` is accepted, answers
HTTP 200 and replaces the payload — the target never runs at REQUEST, and the
caller receives a literal `{}` at RESPONSE. An `mcp` output must echo the body
back. `{"http": {}}` is a true pass-through in both phases.
"""

from __future__ import annotations

import json
from typing import Any

from .envelope import HTTP, MCP, REQUEST, RESPONSE, Envelope

OUTPUT_VERSION = "1.0"

HTTP_PASSTHROUGH: dict[str, Any] = {"interceptorOutputVersion": OUTPUT_VERSION, HTTP: {}}


def passthrough(envelope: Envelope) -> dict[str, Any]:
    """An output that returns the payload the gateway gave us, unchanged."""
    if envelope.kind == HTTP:
        return dict(HTTP_PASSTHROUGH)

    key = envelope.shape_key or MCP
    if envelope.phase == RESPONSE:
        body = (envelope.response or {}).get("body")
        field = "transformedGatewayResponse"
    else:
        body = _request_body(envelope)
        field = "transformedGatewayRequest"

    if body is None:
        # Nothing to echo. `body: null` is refused outright at REQUEST, so the
        # empty form is the only option left and the caller loses the payload
        # either way.
        return {"interceptorOutputVersion": OUTPUT_VERSION, key: {}}
    return {"interceptorOutputVersion": OUTPUT_VERSION, key: {field: {"body": body}}}


def is_valid_output(value: Any) -> bool:
    """True when a value is an interceptor output the gateway will accept."""
    return isinstance(value, dict) and value.get("interceptorOutputVersion") == OUTPUT_VERSION


def _request_body(envelope: Envelope) -> Any:
    body = (envelope.request or {}).get("body")
    if body is not None:
        return body
    if envelope.phase == REQUEST and envelope.raw_body:
        # The parsed body is what the gateway hands the target; echoing the raw
        # string would send the target a JSON string instead of the call.
        try:
            return json.loads(envelope.raw_body)
        except ValueError:
            return None
    return None
