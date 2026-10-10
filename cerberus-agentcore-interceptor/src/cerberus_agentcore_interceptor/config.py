"""Environment configuration, read once per execution environment.

Lambda first runs init on a live request, and the gateway refuses every request
while init fails. So a capture setting never raises: an out-of-range number is
clamped, and any other value that cannot be used turns capture off and is logged.
A chain setting that cannot be used does fail init, because no request may be
served without the interceptor it names.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from . import identity
from .bounding import DEFAULT_MAX_EVENT_BYTES, MAX_EVENT_BYTES_CEILING
from .mapper import MapperOptions
from .sanitize import DEFAULT_CAPTURE_HEADERS

logger = logging.getLogger(__name__)

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
DEFAULT_LOG_LEVEL = "INFO"
LOG_LEVEL_ALIASES = {"WARN": "WARNING"}

# The gateway's authorizer types, accepted for the mode each one implies.
IDENTITY_ALIASES = {
    "custom_jwt": identity.JWT,
    "aws_iam": identity.SIGV4,
    "authenticate_only": identity.SIGV4,
}

DEFAULT_FIREHOSE_CONNECT_MS = 250
DEFAULT_FIREHOSE_READ_MS = 500
# Connect plus read: one put stays at half the recommended 3 s function timeout.
MAX_FIREHOSE_MS = 1500
# Connect gets at most half, so the read is never lowered below the other half.
MAX_FIREHOSE_CONNECT_MS = MAX_FIREHOSE_MS // 2

MAX_STREAMS = 16
STREAM_NAME = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")
STREAM_ARN = re.compile(r"^arn:aws[a-z-]*:firehose:[a-z0-9-]*:\d{12}:deliverystream/(?P<name>.+)$")

MAX_GATEWAY_IDS = 64
GATEWAY_ARN = re.compile(r"^arn:aws[a-z-]*:bedrock-agentcore:[a-z0-9-]*:\d{12}:gateway/(?P<id>.+)$")
LAMBDA_ARN = re.compile(r"^arn:aws[a-z-]*:lambda:[a-z0-9-]+:\d{12}:function:[^\s]+$")


class ConfigError(ValueError):
    """Raised when a CERBERUS_* value is missing or unusable."""


@dataclass(frozen=True)
class Config:
    """Interceptor configuration. Build with :meth:`from_env`."""

    streams: tuple[str, ...]
    identity_mode: str = identity.JWT
    user_id_claim: str = identity.DEFAULT_USER_ID_CLAIM
    capture_headers: tuple[str, ...] = DEFAULT_CAPTURE_HEADERS
    capture_bodies: bool = True
    sensitive_keys: tuple[str, ...] = ()
    max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES
    firehose_connect_ms: int = DEFAULT_FIREHOSE_CONNECT_MS
    firehose_read_ms: int = DEFAULT_FIREHOSE_READ_MS
    chain_arn: str = ""
    gateway_ids: tuple[str, ...] = ()
    chain_read_ms: int = 0
    log_level: str = DEFAULT_LOG_LEVEL
    # The capture settings that could not be used. Capture is off while any are.
    invalid: tuple[str, ...] = ()

    @property
    def capturing(self) -> bool:
        return not self.invalid

    def mapper_options(self, version: str) -> MapperOptions:
        return MapperOptions(
            identity_mode=self.identity_mode,
            user_id_claim=self.user_id_claim,
            capture_headers=self.capture_headers,
            capture_bodies=self.capture_bodies,
            sensitive_keys=self.sensitive_keys,
            max_event_bytes=self.max_event_bytes,
            version=version,
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        source: Mapping[str, str] = os.environ if env is None else env
        invalid: list[str] = []

        def capture[T](name: str, fallback: T, read: Callable[..., T], *args: Any) -> T:
            # A fallback is only used with capture off, and is the more private
            # choice in case that ever changes.
            try:
                return read(source, name, *args)
            except ConfigError as exc:
                logger.error("%s; capture is off", exc)
                invalid.append(name)
                return fallback

        chain_arn = _raw(source, "CERBERUS_CHAIN_REQUEST_ARN")
        gateway_ids = _list(source, "CERBERUS_GATEWAY_IDS")
        chain_read_ms = _int(source, "CERBERUS_CHAIN_READ_MS", 0, 0, 300000)
        if chain_arn:
            if not LAMBDA_ARN.match(chain_arn):
                raise ConfigError(
                    f"CERBERUS_CHAIN_REQUEST_ARN is not a Lambda function ARN ({chain_arn!r})"
                )
            gateway_ids = _gateway_ids(gateway_ids)
            if not gateway_ids:
                raise ConfigError("CERBERUS_GATEWAY_IDS is required when chaining")
            if len(gateway_ids) > MAX_GATEWAY_IDS:
                raise ConfigError(
                    f"CERBERUS_GATEWAY_IDS accepts at most {MAX_GATEWAY_IDS} ids "
                    f"(got {len(gateway_ids)})"
                )
            if not chain_read_ms:
                raise ConfigError("CERBERUS_CHAIN_READ_MS is required when chaining")

        streams: tuple[str, ...] = capture("CERBERUS_FIREHOSE_STREAM", (), _streams)
        mode = capture("CERBERUS_IDENTITY", identity.NONE, _identity_mode)
        capture_bodies = capture("CERBERUS_CAPTURE_BODIES", False, _bool, True)
        max_event_bytes = capture(
            "CERBERUS_MAX_EVENT_BYTES",
            DEFAULT_MAX_EVENT_BYTES,
            _int,
            DEFAULT_MAX_EVENT_BYTES,
            1024,
            MAX_EVENT_BYTES_CEILING,
        )
        connect_ms = capture(
            "CERBERUS_FIREHOSE_CONNECT_MS",
            DEFAULT_FIREHOSE_CONNECT_MS,
            _int,
            DEFAULT_FIREHOSE_CONNECT_MS,
            10,
            MAX_FIREHOSE_CONNECT_MS,
        )
        read_ms = capture(
            "CERBERUS_FIREHOSE_READ_MS",
            DEFAULT_FIREHOSE_READ_MS,
            _int,
            DEFAULT_FIREHOSE_READ_MS,
            10,
            MAX_FIREHOSE_MS - 10,
        )

        return cls(
            streams=streams,
            identity_mode=mode,
            user_id_claim=_text(source, "CERBERUS_USER_ID_CLAIM", identity.DEFAULT_USER_ID_CLAIM),
            capture_headers=_list(source, "CERBERUS_CAPTURE_HEADERS") or DEFAULT_CAPTURE_HEADERS,
            capture_bodies=capture_bodies,
            sensitive_keys=_list(source, "CERBERUS_SENSITIVE_KEYS"),
            max_event_bytes=max_event_bytes,
            firehose_connect_ms=connect_ms,
            firehose_read_ms=_read_budget(connect_ms, read_ms),
            chain_arn=chain_arn,
            gateway_ids=gateway_ids,
            chain_read_ms=chain_read_ms,
            log_level=_log_level(source),
            invalid=tuple(invalid),
        )


def _raw(source: Mapping[str, str], name: str) -> str:
    value: Any = source.get(name)
    return value.strip() if isinstance(value, str) else ""


def _text(source: Mapping[str, str], name: str, default: str) -> str:
    return _raw(source, name) or default


def _list(source: Mapping[str, str], name: str) -> tuple[str, ...]:
    """Comma-separated, order-preserving, de-duplicated, blanks dropped."""
    values: list[str] = []
    for part in _raw(source, name).split(","):
        item = part.strip()
        if item and item not in values:
            values.append(item)
    return tuple(values)


def _streams(source: Mapping[str, str], name: str) -> tuple[str, ...]:
    """Stream names, each given as a name or a delivery stream ARN."""
    streams: list[str] = []
    for item in _list(source, name):
        arn = STREAM_ARN.match(item)
        stream = arn.group("name") if arn else item
        if not STREAM_NAME.match(stream):
            raise ConfigError(f"{name}: {item!r} is not a stream name or ARN")
        if stream not in streams:
            streams.append(stream)
    if not streams:
        raise ConfigError(f"{name} is required")
    if len(streams) > MAX_STREAMS:
        raise ConfigError(f"{name} accepts at most {MAX_STREAMS} streams (got {len(streams)})")
    return tuple(streams)


def _gateway_ids(items: tuple[str, ...]) -> tuple[str, ...]:
    """Gateway ids, each given as an id or a gateway ARN."""
    ids: list[str] = []
    for item in items:
        arn = GATEWAY_ARN.match(item)
        gateway_id = arn.group("id") if arn else item
        # The handler compares the id after the gateway ARN's slash, so
        # anything else here could never match.
        if ":" in gateway_id or "/" in gateway_id:
            raise ConfigError(f"CERBERUS_GATEWAY_IDS: {item!r} is not a gateway id or ARN")
        if gateway_id not in ids:
            ids.append(gateway_id)
    return tuple(ids)


def _identity_mode(source: Mapping[str, str], name: str) -> str:
    raw = _text(source, name, identity.JWT).lower()
    mode = IDENTITY_ALIASES.get(raw, raw)
    if mode not in identity.MODES:
        raise ConfigError(f"{name} must be one of {identity.MODES} (got {raw!r})")
    return mode


def _read_budget(connect_ms: int, read_ms: int) -> int:
    """The read timeout, lowered so connect plus read stays within MAX_FIREHOSE_MS."""
    if connect_ms + read_ms <= MAX_FIREHOSE_MS:
        return read_ms
    lowered = MAX_FIREHOSE_MS - connect_ms
    logger.warning(
        "CERBERUS_FIREHOSE_CONNECT_MS + CERBERUS_FIREHOSE_READ_MS must be at most %d "
        "(got %d); using CERBERUS_FIREHOSE_READ_MS=%d",
        MAX_FIREHOSE_MS,
        connect_ms + read_ms,
        lowered,
    )
    return lowered


def _log_level(source: Mapping[str, str]) -> str:
    raw = _text(source, "CERBERUS_LOG_LEVEL", DEFAULT_LOG_LEVEL).upper()
    level = LOG_LEVEL_ALIASES.get(raw, raw)
    if level not in LOG_LEVELS:
        logger.warning(
            "CERBERUS_LOG_LEVEL must be one of %s (got %r); using %s",
            LOG_LEVELS,
            raw,
            DEFAULT_LOG_LEVEL,
        )
        return DEFAULT_LOG_LEVEL
    return level


def _bool(source: Mapping[str, str], name: str, default: bool) -> bool:
    raw = _raw(source, name)
    if not raw:
        return default
    value = raw.lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be a boolean (got {raw!r})")


def _int(source: Mapping[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    """An integer, clamped to minimum..maximum with a warning."""
    raw = _raw(source, name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer (got {raw!r})") from exc
    clamped = min(max(value, minimum), maximum)
    if clamped != value:
        logger.warning(
            "%s must be between %d and %d (got %d); using %d",
            name,
            minimum,
            maximum,
            value,
            clamped,
        )
    return clamped
