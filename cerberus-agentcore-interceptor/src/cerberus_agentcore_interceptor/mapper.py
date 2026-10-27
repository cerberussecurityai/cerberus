"""The source event: one interception, in the shape the platform ingests.

Provider semantics — model labels, target names, the MCP method ladder — are
resolved server-side, so a provider change needs no redeploy here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cerberus_core import normalize_ip

from . import __version__, response_body
from . import identity as identity_mod
from .bounding import (
    DEFAULT_MAX_EVENT_BYTES,
    PRUNE_FACTOR,
    STATE_CAPTURED,
    STATE_DISABLED,
    STATE_OMITTED,
    STATE_SHED,
    check_deadline,
    clip_text,
    fit,
    prune,
    set_note,
    size,
)
from .envelope import (
    BODY_EMPTY,
    BODY_NOT_OBJECT,
    MCP,
    REQUEST,
    RESPONSE,
    Envelope,
    GatewayContext,
    header,
    http_body,
    request_body,
    request_body_size,
)
from .sanitize import DEFAULT_CAPTURE_HEADERS, capture_headers, sanitize_body, session_id

INTEGRATION = "agentcore-gateway"

# The body_override that captures the body as the caller sent it.
ORIGINAL_BODY: Any = object()

MAX_EVENT_ID_CHARS = 255
MAX_ENDPOINT_CHARS = 500
MAX_USER_ID_CHARS = 255
MAX_SESSION_ID_CHARS = 255
MAX_USER_AGENT_CHARS = 1024

RESPONSE_EVENT_SUFFIX = "#response"

# The least room an mcp response event keeps for a response that does not fit
# whole beside the request side. A cap under twice this splits evenly.
RESPONSE_FLOOR_BYTES = 8192


@dataclass(frozen=True)
class MapperOptions:
    """What the mapper needs from configuration."""

    identity_mode: str = identity_mod.JWT
    user_id_claim: str = identity_mod.DEFAULT_USER_ID_CLAIM
    capture_headers: tuple[str, ...] = DEFAULT_CAPTURE_HEADERS
    capture_bodies: bool = True
    sensitive_keys: tuple[str, ...] = ()
    max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES
    version: str = __version__


@dataclass(frozen=True)
class _Caller:
    """The request side of an event, its notes, and what prune() took out of its body."""

    fields: dict[str, Any]
    identity: dict[str, Any]
    body: dict[str, Any]
    pruned: dict[str, Any] | None


def source_event(
    envelope: Envelope,
    context: GatewayContext,
    options: MapperOptions,
    timestamp: datetime,
    chain: dict[str, Any] | None = None,
    body_override: Any = ORIGINAL_BODY,
    deadline: float | None = None,
    response_expected: bool = False,
) -> dict[str, Any] | None:
    """Build the event for one REQUEST interception. None when it could not be bounded.

    Raises CaptureDeadlineExceeded once time.monotonic() reaches deadline.
    """
    caller = _caller(envelope, options, body_override, deadline)
    event_id = clip_text(context.request_id, MAX_EVENT_ID_CHARS)
    event = _event(event_id, envelope, context, options, timestamp, REQUEST, caller, chain)
    event["custom_data"]["agentcore"]["response_expected"] = response_expected
    return fit(event, options.max_event_bytes, deadline, caller.pruned)


def response_event(
    envelope: Envelope,
    context: GatewayContext,
    options: MapperOptions,
    timestamp: datetime,
    chain: dict[str, Any] | None = None,
    deadline: float | None = None,
    request_side: bool = True,
) -> dict[str, Any] | None:
    """Build the event for one RESPONSE interception. None when it could not be bounded.

    An mcp response event also carries the request, which the shape still holds
    at RESPONSE, unless request_side is False; an http one has none to carry.
    Raises CaptureDeadlineExceeded once time.monotonic() reaches deadline.
    """
    if options.capture_bodies:
        value, note = response_body.read(envelope, options.sensitive_keys, deadline)
    else:
        value, note = None, response_body.note(envelope, STATE_DISABLED)
    is_mcp = envelope.kind == MCP
    caller = (
        _caller(envelope, options, ORIGINAL_BODY, deadline) if is_mcp and request_side else None
    )
    suffix = RESPONSE_EVENT_SUFFIX
    event_id = clip_text(context.request_id, MAX_EVENT_ID_CHARS - len(suffix)) + suffix
    # The request side is fitted beside the longest note the response can end with.
    widest = note if value is None else {**note, "state": STATE_SHED, "reason": "size"}

    def build() -> dict[str, Any]:
        event = _event(event_id, envelope, context, options, timestamp, RESPONSE, caller, chain)
        if envelope.status_code is not None:
            event["status_code"] = envelope.status_code
        set_note(event, "response", widest)
        return event

    cap = options.max_event_bytes
    event = fit(build(), cap, deadline, None if caller is None else caller.pruned)
    if event is None:
        return None
    floor = min(RESPONSE_FLOOR_BYTES, cap // 2)
    if caller is not None and value is not None and cap - size(event) < floor:
        if response_body.fits_whole(event, value, note, cap, deadline):
            return event
        event = fit(build(), cap - floor, deadline, caller.pruned) or event
    return response_body.attach(event, value, note, cap, is_mcp, deadline)


def _caller(
    envelope: Envelope, options: MapperOptions, body_override: Any, deadline: float | None
) -> _Caller:
    headers = envelope.headers
    who = identity_mod.resolve(options.identity_mode, headers, options.user_id_claim)
    body, body_note, pruned = _body(envelope, options, body_override, deadline)
    fields: dict[str, Any] = {"method": envelope.method, "endpoint": _endpoint(envelope.path)}
    # Absent rather than empty, following the other integrations' wire shape.
    optional = {
        "headers": capture_headers(headers, options.capture_headers),
        "user_agent": clip_text(header(headers, "user-agent"), MAX_USER_AGENT_CHARS),
        "user_id": clip_text(who.user_id, MAX_USER_ID_CHARS),
        "session_id": clip_text(session_id(headers), MAX_SESSION_ID_CHARS),
        "body": body,
    }
    fields.update({key: value for key, value in optional.items() if value})
    return _Caller(fields, who.detail, body_note, pruned)


def _event(
    event_id: str,
    envelope: Envelope,
    context: GatewayContext,
    options: MapperOptions,
    timestamp: datetime,
    phase: str,
    caller: _Caller | None,
    chain: dict[str, Any] | None,
) -> dict[str, Any]:
    agentcore: dict[str, Any] = {
        "gateway_id": context.gateway_id,
        "region": context.region,
        "account_id": context.account_id,
        "request_id": context.request_id,
        "kind": envelope.kind,
        "phase": phase,
    }
    event: dict[str, Any] = {
        "event_id": event_id,
        "timestamp": _timestamp(timestamp),
        "host": context.host,
        "scheme": True,
        # The source IP the gateway resolved. X-Forwarded-For is caller-controlled
        # and never read.
        "remote_addr": normalize_ip(context.source_ip) or "",
        "custom_data": {"integration": INTEGRATION, "agentcore": agentcore},
    }
    if caller is not None:
        event.update(caller.fields)
        agentcore["identity"] = caller.identity
        agentcore["body"] = caller.body
    agentcore["version"] = options.version
    if chain is not None:
        agentcore["chain"] = chain
    return event


def _body(
    envelope: Envelope, options: MapperOptions, override: Any, deadline: float | None
) -> tuple[Any, dict[str, Any], dict[str, Any] | None]:
    """The sanitised body, its note, and what prune() took out of it."""
    if not options.capture_bodies:
        return None, {"state": STATE_DISABLED}, None
    # With a chain, the transformed body is the one that reaches the target.
    overridden = override is not ORIGINAL_BODY
    if overridden:
        body, reason = _override_body(envelope, override)
    else:
        body, reason = request_body(envelope)
    if not body:
        return None, {"state": STATE_OMITTED, "reason": reason or BODY_EMPTY}, None

    pruned = None
    # The size as sent is the original body's, which says nothing of an override.
    sent = None if overridden else request_body_size(envelope)
    if sent is None or sent > PRUNE_FACTOR * options.max_event_bytes:
        body, pruned = prune(body, options.max_event_bytes)
        if body is None:
            return None, {"state": STATE_SHED, "reason": "size"}, None
    check_deadline(deadline)
    return sanitize_body(body, options.sensitive_keys), {"state": STATE_CAPTURED}, pruned


def _override_body(envelope: Envelope, override: Any) -> tuple[Any, str]:
    """A transformed body as a dict, or (None, reason), read like the original."""
    if isinstance(override, dict):
        return override, ""
    if envelope.kind != MCP and isinstance(override, str):
        return http_body(override)
    return None, BODY_NOT_OBJECT


def _endpoint(path: str) -> str:
    return clip_text(path.split("?", 1)[0], MAX_ENDPOINT_CHARS)


def _timestamp(value: datetime) -> str:
    """ISO-8601 UTC with microseconds, whatever the caller handed us."""
    moment = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return moment.isoformat(timespec="microseconds")
