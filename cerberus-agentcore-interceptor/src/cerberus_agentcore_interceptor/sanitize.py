"""Header allowlisting and body redaction, on top of cerberus-core."""

from __future__ import annotations

from typing import Any

from cerberus_core import SENSITIVE_HEADERS, sanitize_dict

from .bounding import clip_text
from .envelope import header as _header

# Captured by default. Everything else is dropped, so a header that is useful
# for classification has to be named here or in CERBERUS_CAPTURE_HEADERS.
DEFAULT_CAPTURE_HEADERS: tuple[str, ...] = (
    "User-Agent",
    "Content-Type",
    "X-Amzn-Trace-Id",
    "anthropic-version",
    "anthropic-beta",
    "OpenAI-Organization",
    "OpenAI-Project",
)

# The session headers are carried in the event's own session_id field.
SESSION_HEADERS: tuple[str, ...] = (
    "Mcp-Session-Id",
    "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id",
)


def _from_wsgi(name: str) -> str:
    stripped = name[5:] if name.startswith("HTTP_") else name
    return stripped.replace("_", "-").lower()


# Dropped whatever the allowlist says. cerberus-core's set is the floor.
ALWAYS_DROP: frozenset[str] = frozenset(
    {_from_wsgi(name) for name in SENSITIVE_HEADERS}
    | {"x-amz-security-token", "www-authenticate"}
    # Session ids ride in the event's own field instead.
    | {name.lower() for name in SESSION_HEADERS}
)

# VPC-endpoint and TLS-negotiation headers the gateway adds to every request.
DROP_PREFIXES: tuple[str, ...] = ("x-amzn-vpce-", "x-amzn-tls-")

MAX_HEADER_VALUE_CHARS = 1024


def capture_headers(headers: Any, allowlist: tuple[str, ...]) -> dict[str, str]:
    """Allowlisted headers, keyed by the allowlist's own spelling."""
    canonical = {name.lower(): name for name in allowlist if name}
    captured: dict[str, str] = {}
    for name, value in (headers if isinstance(headers, dict) else {}).items():
        if not isinstance(name, str):
            continue
        lower = name.lower()
        if lower in ALWAYS_DROP or lower.startswith(DROP_PREFIXES):
            continue
        wanted = canonical.get(lower)
        if wanted is None:
            continue
        captured[wanted] = clip_text(_value(value), MAX_HEADER_VALUE_CHARS)
    return captured


def session_id(headers: Any) -> str:
    """The MCP or Runtime session id, whichever the caller sent."""
    for name in SESSION_HEADERS:
        value = _header(headers, name)
        if value:
            return value
    return ""


def sanitize_body(body: Any, extra_keys: tuple[str, ...] = ()) -> Any:
    """Redact sensitive keys in a captured body."""
    return sanitize_dict(body, extra_keys=extra_keys)


def _value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return ""
