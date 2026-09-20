"""The source event: one interception, in the HTTP shape the platform already ingests.

Provider semantics — model labels, target names, the MCP method ladder — are
left to the backend, so a provider change needs no redeploy here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cerberus_core import normalize_ip

from . import identity as identity_mod
from .bounding import (
    DEFAULT_MAX_EVENT_BYTES,
    STATE_CAPTURED,
    STATE_DISABLED,
    STATE_OMITTED,
    fit,
)
from .envelope import BODY_EMPTY, Envelope, GatewayContext, header, request_body
from .sanitize import DEFAULT_CAPTURE_HEADERS, capture_headers, sanitize_body, session_id

INTEGRATION = "agentcore-gateway"

MAX_EVENT_ID_CHARS = 255
MAX_ENDPOINT_CHARS = 500
MAX_USER_ID_CHARS = 255
MAX_SESSION_ID_CHARS = 255
MAX_USER_AGENT_CHARS = 1024


@dataclass(frozen=True)
class MapperOptions:
    """What the mapper needs from configuration."""

    identity_mode: str = identity_mod.JWT
    user_id_claim: str = identity_mod.DEFAULT_USER_ID_CLAIM
    capture_headers: tuple[str, ...] = DEFAULT_CAPTURE_HEADERS
    capture_bodies: bool = True
    sensitive_keys: tuple[str, ...] = ()
    max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES
    version: str = field(default="")


def source_event(
    envelope: Envelope,
    context: GatewayContext,
    options: MapperOptions,
    timestamp: datetime,
    chain: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Build the event for one interception. None when it could not be bounded."""
    headers = envelope.headers
    who = identity_mod.resolve(options.identity_mode, headers, options.user_id_claim)
    body, body_note = _body(envelope, options)

    event: dict[str, Any] = {
        "event_id": context.request_id[:MAX_EVENT_ID_CHARS],
        "timestamp": timestamp.isoformat(),
        "method": envelope.method,
        "endpoint": _endpoint(envelope.path),
        "host": context.host,
        "scheme": True,
        # The source IP the gateway resolved. X-Forwarded-For is caller-controlled
        # and never read.
        "remote_addr": normalize_ip(context.source_ip) or "",
        "custom_data": {
            "integration": INTEGRATION,
            "agentcore": {
                "gateway_id": context.gateway_id,
                "region": context.region,
                "account_id": context.account_id,
                "request_id": context.request_id,
                "kind": envelope.kind,
                "identity": who.detail,
                "body": body_note,
                "version": options.version,
            },
        },
    }
    # Absent rather than empty, following the other integrations' wire shape.
    optional = {
        "headers": capture_headers(headers, options.capture_headers),
        "user_agent": header(headers, "user-agent")[:MAX_USER_AGENT_CHARS],
        "user_id": who.user_id[:MAX_USER_ID_CHARS],
        "session_id": session_id(headers)[:MAX_SESSION_ID_CHARS],
        "body": body,
    }
    event.update({key: value for key, value in optional.items() if value})

    if chain is not None:
        event["custom_data"]["agentcore"]["chain"] = chain

    return fit(event, options.max_event_bytes)


def _body(envelope: Envelope, options: MapperOptions) -> tuple[Any, dict[str, Any]]:
    if not options.capture_bodies:
        return None, {"state": STATE_DISABLED}
    body, reason = request_body(envelope)
    if not body:
        return None, {"state": STATE_OMITTED, "reason": reason or BODY_EMPTY}
    return sanitize_body(body, options.sensitive_keys), {"state": STATE_CAPTURED}


def _endpoint(path: str) -> str:
    return path.split("?", 1)[0][:MAX_ENDPOINT_CHARS]
