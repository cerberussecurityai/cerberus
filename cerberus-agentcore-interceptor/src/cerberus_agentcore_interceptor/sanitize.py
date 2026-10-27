"""Header allowlisting and body redaction, on top of cerberus-core."""

from __future__ import annotations

import math
from typing import Any

from cerberus_core import REDACTED, SENSITIVE_HEADERS, SENSITIVE_KEYS, sanitize_dict

from .bounding import VALUES_PER_CHECK, check_deadline, clip_text, non_finite_text, storable_text
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

# A body that echoes the request can carry its credential headers, in wire or
# WSGI spelling. sanitize_dict matches a key's whole name, ignoring only case.
ECHOED_HEADER_KEYS: tuple[str, ...] = tuple(
    sorted(
        set(SENSITIVE_HEADERS)
        | {_from_wsgi(name) for name in SENSITIVE_HEADERS}
        | {"x-amz-security-token"}
    )
)

# VPC-endpoint and TLS-negotiation headers the gateway adds to every request.
DROP_PREFIXES: tuple[str, ...] = ("x-amzn-vpce-", "x-amzn-tls-")

MAX_HEADER_VALUE_CHARS = 1024

# As in sanitize_dict, a dict or list nested deeper than this is redacted whole.
MAX_SANITIZE_DEPTH = 20


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


def sanitize_storable(
    body: Any, extra_keys: tuple[str, ...] = (), deadline: float | None = None
) -> Any:
    """storable(sanitize_body(body, extra_keys)) in one walk, checking the deadline as it goes.

    Raises CaptureDeadlineExceeded once time.monotonic() reaches deadline.
    """
    keys = SENSITIVE_KEYS | {key.strip().lower() for key in extra_keys if key.strip()}
    left = 1

    def walk(node: Any, depth: int) -> Any:
        nonlocal left
        left -= 1
        if not left:
            left = VALUES_PER_CHECK
            check_deadline(deadline)
        if isinstance(node, dict):
            if depth > MAX_SANITIZE_DEPTH:
                return REDACTED
            sanitized = {}
            for key, item in node.items():
                redacted = isinstance(key, str) and key.lower() in keys
                sanitized[walk(key, depth)] = REDACTED if redacted else walk(item, depth + 1)
            return sanitized
        if isinstance(node, list):
            if depth > MAX_SANITIZE_DEPTH:
                return REDACTED
            return [walk(item, depth + 1) for item in node]
        if isinstance(node, str):
            return storable_text(node)
        if isinstance(node, float) and not math.isfinite(node):
            return non_finite_text(node)
        return node

    return walk(body, 0)


def _value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return ""
