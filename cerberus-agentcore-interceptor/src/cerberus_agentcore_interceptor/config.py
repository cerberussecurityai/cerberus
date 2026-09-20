"""Environment configuration, read once per execution environment.

A malformed value fails at init rather than per request, so a broken deployment
is visible before the interceptor is attached to a gateway.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from . import identity
from .bounding import DEFAULT_MAX_EVENT_BYTES, MAX_EVENT_BYTES_CEILING
from .mapper import MapperOptions
from .sanitize import DEFAULT_CAPTURE_HEADERS

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

DEFAULT_FIREHOSE_CONNECT_MS = 250
DEFAULT_FIREHOSE_READ_MS = 500

MAX_STREAMS = 16
STREAM_NAME = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")


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
    log_level: str = "INFO"

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

        streams = _list(source, "CERBERUS_FIREHOSE_STREAM")
        if not streams:
            raise ConfigError("CERBERUS_FIREHOSE_STREAM is required")
        if len(streams) > MAX_STREAMS:
            raise ConfigError(
                f"CERBERUS_FIREHOSE_STREAM accepts at most {MAX_STREAMS} streams "
                f"(got {len(streams)})"
            )
        for name in streams:
            if not STREAM_NAME.match(name):
                raise ConfigError(f"CERBERUS_FIREHOSE_STREAM: {name!r} is not a stream name")

        mode = _text(source, "CERBERUS_IDENTITY", identity.JWT).lower()
        if mode not in identity.MODES:
            raise ConfigError(f"CERBERUS_IDENTITY must be one of {identity.MODES} (got {mode!r})")

        claim = _text(source, "CERBERUS_USER_ID_CLAIM", identity.DEFAULT_USER_ID_CLAIM)
        if not claim:
            raise ConfigError("CERBERUS_USER_ID_CLAIM must not be empty")

        log_level = _text(source, "CERBERUS_LOG_LEVEL", "INFO").upper()
        if log_level not in LOG_LEVELS:
            raise ConfigError(f"CERBERUS_LOG_LEVEL must be one of {LOG_LEVELS} (got {log_level!r})")

        return cls(
            streams=streams,
            identity_mode=mode,
            user_id_claim=claim,
            capture_headers=_list(source, "CERBERUS_CAPTURE_HEADERS") or DEFAULT_CAPTURE_HEADERS,
            capture_bodies=_bool(source, "CERBERUS_CAPTURE_BODIES", True),
            sensitive_keys=_list(source, "CERBERUS_SENSITIVE_KEYS"),
            max_event_bytes=_int(
                source,
                "CERBERUS_MAX_EVENT_BYTES",
                DEFAULT_MAX_EVENT_BYTES,
                1024,
                MAX_EVENT_BYTES_CEILING,
            ),
            firehose_connect_ms=_int(
                source, "CERBERUS_FIREHOSE_CONNECT_MS", DEFAULT_FIREHOSE_CONNECT_MS, 10, 10000
            ),
            firehose_read_ms=_int(
                source, "CERBERUS_FIREHOSE_READ_MS", DEFAULT_FIREHOSE_READ_MS, 10, 10000
            ),
            log_level=log_level,
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
    raw = _raw(source, name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer (got {raw!r})") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum} (got {value})")
    return value
