"""Interceptor outputs that hand the gateway its payload back.

The `mcp` shape has no empty pass-through: `{"mcp": {}}` is accepted, answers
HTTP 200 and replaces the payload. An `mcp` output has to echo the body back.
`{"http": {}}` is a true pass-through everywhere except an `mcp` RESPONSE, where
the caller receives `{}`.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

from .envelope import HTTP, MCP, REQUEST, RESPONSE, Envelope

OUTPUT_VERSION = "1.0"

# A \uXXXX surrogate escape in JSON text that is not half of an escaped pair.
_LONE_SURROGATE_ESCAPE = re.compile(
    r"\\u[dD](?:[89abAB][0-9a-fA-F]{2}(?!\\u[dD][c-fC-F])"
    r"|[c-fC-F](?<!\\u[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F]))"
)

# A JSON number can only overflow a double with a three-digit exponent or a
# mantissa of 309 digits. Matching more than that only costs a full check.
_OVERFLOWING_NUMBER = re.compile(r"\d[eE]\+?\d{3}|\d{309}")


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
        return _response_echo(key, encodable(response.get("body")), response.get("statusCode"))

    body = _request_body(envelope)
    if body is None:
        return {"interceptorOutputVersion": OUTPUT_VERSION, key: {}}
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        key: {"transformedGatewayRequest": {"body": body}},
    }


def mcp_response(event: Any) -> dict[str, Any] | None:
    """The raw gatewayResponse of an `mcp` RESPONSE event, or None for any other event."""
    shape = event.get(MCP) if isinstance(event, dict) else None
    response = shape.get("gatewayResponse") if isinstance(shape, dict) else None
    return response if isinstance(response, dict) else None


def response_echo(response: dict[str, Any]) -> dict[str, Any]:
    """An `mcp` output echoing a raw gatewayResponse, for when parse() or passthrough() fails.

    The body comes back as given, without repair, and the status code only
    when it is an int.
    """
    status = response.get("statusCode")
    if isinstance(status, bool) or not isinstance(status, int):
        status = None
    return _response_echo(MCP, response.get("body"), status)


def is_valid_output(value: Any) -> bool:
    """True when a value is an interceptor output the gateway will accept."""
    return isinstance(value, dict) and value.get("interceptorOutputVersion") == OUTPUT_VERSION


def encodable(value: Any, source: str | None = None) -> Any:
    """value, or a copy the Lambda runtime encodes and the gateway accepts.

    A lone UTF-16 surrogate ends the runtime when it encodes the answer, so it
    becomes U+FFFD. A number outside the double range decodes as an infinity,
    which the runtime writes as a bare token the gateway refuses, so it becomes
    the string "Infinity" or "-Infinity", as the gateway hands it to a target
    on its own. Pass source, the JSON text value was decoded from, so a text
    that cannot hold either skips encoding value.
    """
    try:
        if source is not None and not _may_need_repair(source):
            return value
        if _encodes(value):
            return value
        return _repaired(value)
    except Exception:
        # Too deep to walk: the runtime may still encode it as it is.
        return value


def finite(value: Any) -> Any:
    """value with NaN and the infinities written as strings, as encodable writes them."""
    if isinstance(value, float) and not math.isfinite(value):
        return _non_finite_text(value)
    if isinstance(value, dict):
        return {key: finite(item) for key, item in value.items()}
    if isinstance(value, list):
        return [finite(item) for item in value]
    return value


def _response_echo(key: str, body: Any, status: Any) -> dict[str, Any]:
    if body is None:
        return _bodyless_response(key)
    transformed: dict[str, Any] = {"body": body}
    if status is not None:
        transformed["statusCode"] = status
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        key: {"transformedGatewayResponse": transformed},
    }


def _bodyless_response(key: str) -> dict[str, Any]:
    """The answer to a response with no body to echo."""
    return {"interceptorOutputVersion": OUTPUT_VERSION, key: {}}


def _request_body(envelope: Envelope) -> Any:
    body = (envelope.request or {}).get("body")
    source = envelope.raw_body
    if isinstance(body, str):
        # The gateway hands the target a parsed body; echoing the text would
        # send it a JSON string instead of the call.
        source = body
        body = _parsed(body)
    if body is not None:
        return encodable(body, source)
    if envelope.phase == REQUEST and envelope.raw_body:
        return encodable(_parsed(envelope.raw_body), envelope.raw_body)
    return None


def _parsed(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _may_need_repair(text: str) -> bool:
    return _may_hold_non_finite(text) or _may_hold_lone_surrogate(text)


def _may_hold_non_finite(text: str) -> bool:
    # Python's decoder also accepts the NaN and Infinity tokens.
    return "NaN" in text or "Infinity" in text or _OVERFLOWING_NUMBER.search(text) is not None


def _may_hold_lone_surrogate(text: str) -> bool:
    # The regex cannot tell an escaped backslash followed by u from an escape,
    # so text holding one is left to the encoding check.
    if "\\\\u" in text:
        return True
    # The substring checks cost far less than the regex on a large body.
    if ("\\ud" in text or "\\uD" in text) and _LONE_SURROGATE_ESCAPE.search(text):
        return True
    return not _utf8_encodable(text)


def _encodes(value: Any) -> bool:
    """True when the runtime's own encoding of value succeeds and is valid JSON."""
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (UnicodeEncodeError, ValueError):
        return False
    return True


def _repaired(value: Any) -> Any:
    if isinstance(value, str):
        return _repaired_text(value)
    if isinstance(value, float) and not math.isfinite(value):
        return _non_finite_text(value)
    if isinstance(value, dict):
        return {_repaired(key): _repaired(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_repaired(item) for item in value]
    return value


def _repaired_text(text: str) -> str:
    if _utf8_encodable(text):
        return text
    # Joins a pair held as two code points; a lone half becomes U+FFFD.
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")


def _non_finite_text(number: float) -> str:
    if math.isnan(number):
        return "NaN"
    return "Infinity" if number > 0 else "-Infinity"


def _utf8_encodable(text: str) -> bool:
    """False only when text holds a surrogate code point."""
    if text.isascii():
        return True
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True
