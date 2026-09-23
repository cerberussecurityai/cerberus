"""Caller identity, read from whatever the gateway's authorizer put on the request.

The gateway refuses a bad, missing or malformed JWT with a 401 before the
interceptor runs, so `jwt` mode decodes the payload and never verifies it. A
token that somehow arrives unreadable yields no user id rather than a guess.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from typing import Any

from .bounding import clip_text
from .envelope import header

JWT = "jwt"
SIGV4 = "sigv4"
NONE = "none"
MODES = (JWT, SIGV4, NONE)

DEFAULT_USER_ID_CLAIM = "sub"

MAX_CLAIM_CHARS = 255

# Claims recorded beside the user id. The token itself is never recorded.
RECORDED_CLAIMS = ("username", "client_id")


@dataclass(frozen=True)
class Identity:
    """Per-caller identity and the note that travels with the event."""

    user_id: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


def resolve(mode: str, headers: Any, claim: str = DEFAULT_USER_ID_CLAIM) -> Identity:
    """Identity for a deployment mode, from the request headers."""
    if mode == JWT:
        return _jwt_identity(headers, claim)
    if mode == SIGV4:
        return _sigv4_identity(headers)
    return Identity(detail={"mode": NONE})


def _jwt_identity(headers: Any, claim: str) -> Identity:
    token = _bearer_token(header(headers, "authorization"))
    if not token:
        return Identity(detail={"mode": JWT, "status": "missing"})

    claims = _jwt_claims(token)
    if claims is None:
        return Identity(detail={"mode": JWT, "status": "malformed"})

    detail: dict[str, Any] = {"mode": JWT, "claim": claim}
    for name in RECORDED_CLAIMS:
        value = _claim_text(claims.get(name))
        if value:
            detail[name] = value
    return Identity(user_id=_claim_text(claims.get(claim)), detail=detail)


def _sigv4_identity(headers: Any) -> Identity:
    """Access key id only: the interceptor sees no principal, and keys rotate."""
    key_id = _access_key_id(header(headers, "authorization"))
    if not key_id:
        return Identity(detail={"mode": SIGV4, "status": "missing"})
    return Identity(detail={"mode": SIGV4, "access_key_id": key_id})


def _bearer_token(value: str) -> str:
    if not value:
        return ""
    scheme, _, rest = value.partition(" ")
    return rest.strip() if scheme.lower() == "bearer" else value


def _jwt_claims(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return claims if isinstance(claims, dict) else None


def _access_key_id(value: str) -> str:
    """The key id out of `AWS4-HMAC-SHA256 Credential=<id>/<date>/…`."""
    for part in value.replace(",", " ").split():
        if part.startswith("Credential="):
            return clip_text(part[len("Credential=") :].split("/", 1)[0], MAX_CLAIM_CHARS)
    return ""


def _claim_text(value: Any) -> str:
    if isinstance(value, str):
        return clip_text(value.strip(), MAX_CLAIM_CHARS)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)[:MAX_CLAIM_CHARS]
    return ""
