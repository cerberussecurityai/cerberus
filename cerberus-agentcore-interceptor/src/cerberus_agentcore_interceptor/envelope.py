"""Reading the AgentCore interceptor envelope: shape, phase, headers, body, context.

Nothing here raises. A malformed part degrades the capture, never the
customer's request.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

MCP = "mcp"
HTTP = "http"
SHAPE_KEYS = (MCP, HTTP)

REQUEST = "request"
RESPONSE = "response"

INPUT_VERSION = "1.0"

# Why a body is not attached to the event. The reason travels with the event,
# so a gap in what was captured is explained rather than silent.
BODY_EMPTY = "empty"
BODY_DECODE_ERROR = "decode_error"
BODY_NOT_JSON = "not_json"
BODY_NOT_OBJECT = "not_object"


@dataclass(frozen=True)
class GatewayContext:
    """Gateway and call identity, from the Lambda client context."""

    request_id: str = ""
    gateway_arn: str = ""
    gateway_id: str = ""
    region: str = ""
    account_id: str = ""
    source_ip: str = ""

    @property
    def host(self) -> str:
        """The gateway's public hostname, or '' when the ARN was unusable."""
        if not self.gateway_id or not self.region:
            return ""
        return f"{self.gateway_id}.gateway.bedrock-agentcore.{self.region}.amazonaws.com"


@dataclass(frozen=True)
class Envelope:
    """One interceptor input."""

    version: str = ""
    kind: str = ""
    shape_key: str = ""
    shape: dict[str, Any] | None = None
    phase: str = REQUEST
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    raw_body: str | None = None

    @property
    def supported_version(self) -> bool:
        return self.version == INPUT_VERSION

    @property
    def headers(self) -> dict[str, Any]:
        return _mapping((self.request or {}).get("headers"))

    @property
    def path(self) -> str:
        return _text((self.request or {}).get("path"))

    @property
    def method(self) -> str:
        return _text((self.request or {}).get("httpMethod"))


def parse(event: Any) -> Envelope:
    """Read an interceptor input into an Envelope."""
    if not isinstance(event, dict):
        return Envelope()

    version = _text(event.get("interceptorInputVersion"))
    shape_key = next((key for key in SHAPE_KEYS if isinstance(event.get(key), dict)), "")
    if not shape_key:
        # A shape we do not know still has to be echoed back, so keep whichever
        # key carries an envelope and let the output builder work from it.
        shape_key = next(
            (key for key, value in event.items() if _looks_like_shape(value)),
            "",
        )
    shape = event.get(shape_key) if shape_key else None
    if not isinstance(shape, dict):
        return Envelope(version=version)

    response = shape.get("gatewayResponse")
    response = response if isinstance(response, dict) else None
    request = shape.get("gatewayRequest")
    request = request if isinstance(request, dict) else None
    raw = shape.get("rawGatewayRequest")
    raw_body = _text(raw.get("body")) if isinstance(raw, dict) else ""

    return Envelope(
        version=version,
        kind=shape_key if shape_key in SHAPE_KEYS else "",
        shape_key=shape_key,
        shape=shape,
        # gatewayResponse is present and null at REQUEST, so the phase is read
        # from its value, never from key presence.
        phase=RESPONSE if response is not None else REQUEST,
        request=request,
        response=response,
        raw_body=raw_body or None,
    )


def gateway_context(context: Any) -> GatewayContext:
    """Read REQUEST_ID, GATEWAY_ARN, GATEWAY_ACCOUNT_ID and SOURCE_IP."""
    custom = _client_context_custom(context)
    arn = _text(custom.get("GATEWAY_ARN"))
    region, arn_account, gateway_id = _split_gateway_arn(arn)
    return GatewayContext(
        request_id=_text(custom.get("REQUEST_ID")),
        gateway_arn=arn,
        gateway_id=gateway_id,
        region=region,
        account_id=_text(custom.get("GATEWAY_ACCOUNT_ID")) or arn_account,
        source_ip=_text(custom.get("SOURCE_IP")),
    )


def header(headers: Any, name: str) -> str:
    """Case-insensitive header lookup. The gateway passes names through as sent."""
    wanted = name.lower()
    for key, value in _mapping(headers).items():
        if isinstance(key, str) and key.lower() == wanted:
            return _text(value)
    return ""


def request_body(envelope: Envelope) -> tuple[Any, str]:
    """The request body as a dict, or (None, reason)."""
    if envelope.phase != REQUEST:
        return None, BODY_EMPTY
    if envelope.kind == MCP:
        return _mcp_body(envelope)
    return _http_body(envelope)


def _mcp_body(envelope: Envelope) -> tuple[Any, str]:
    body = (envelope.request or {}).get("body")
    if isinstance(body, dict):
        return body, ""
    if body is None and envelope.raw_body:
        return _load_json(envelope.raw_body)
    if body is None:
        return None, BODY_EMPTY
    if isinstance(body, str):
        return _load_json(body)
    return None, BODY_NOT_OBJECT


def _http_body(envelope: Envelope) -> tuple[Any, str]:
    body = (envelope.request or {}).get("body")
    if isinstance(body, dict):
        return body, ""
    if not isinstance(body, str) or not body:
        return None, BODY_EMPTY
    try:
        decoded = base64.b64decode(body, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None, BODY_DECODE_ERROR
    return _load_json(decoded)


def _load_json(text: str) -> tuple[Any, str]:
    if not text.strip():
        return None, BODY_EMPTY
    try:
        value = json.loads(text)
    except ValueError:
        return None, BODY_NOT_JSON
    if not isinstance(value, dict):
        return None, BODY_NOT_OBJECT
    return value, ""


def _looks_like_shape(value: Any) -> bool:
    return isinstance(value, dict) and ("gatewayRequest" in value or "gatewayResponse" in value)


def _split_gateway_arn(arn: str) -> tuple[str, str, str]:
    """(region, account, gateway id) from arn:aws:bedrock-agentcore:…:gateway/<id>."""
    parts = arn.split(":")
    if len(parts) < 6 or not arn.startswith("arn:"):
        return "", "", ""
    resource = parts[5]
    gateway_id = resource.split("/", 1)[1] if "/" in resource else ""
    return parts[3], parts[4], gateway_id


def _client_context_custom(context: Any) -> dict[str, Any]:
    client_context = getattr(context, "client_context", None)
    if client_context is None and isinstance(context, dict):
        client_context = context.get("client_context")
    custom = getattr(client_context, "custom", None)
    if custom is None and isinstance(client_context, dict):
        custom = client_context.get("custom")
    return _mapping(custom)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""
