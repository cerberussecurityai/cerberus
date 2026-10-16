"""Environment-variable configuration for cerberus-litellm.

Names mirror cerberus-envoy-ai-gateway / the flex-gateway policy so operators
moving between Cerberus connectors meet a familiar surface. There is no
secret key: source IPs are shipped raw (they are not PII) and nothing is
hashed.
"""

import os
from dataclasses import dataclass, field

from cerberus_core import SENSITIVE_HEADERS

# The ingest API caps both batch size and per-event size. Stay under both
# client-side and leave headroom on the per-event cap: identifying fields are
# added server-side before the limit is applied. Same numbers as the bridge.
MAX_SERVER_BATCH_SIZE = 1000
DEFAULT_MAX_EVENT_BYTES = 57344  # 56KB
MAX_EVENT_BYTES_CEILING = 63488  # 62KB
MIN_FLUSH_INTERVAL_MS = 100

# Request headers an operator may forward. Bounded: each becomes an
# unsheddable `headers` entry on every event.
MAX_CAPTURE_HEADERS = 20

USER_ID_SOURCES = ("end_user", "user_id", "key_alias", "team_alias")
_LOG_LEVELS = ("debug", "info", "warning", "error")

# cerberus-core spells credential headers Django-style (HTTP_X_API_KEY). LiteLLM
# hands us wire-style names (x-api-key), so normalize once here and compare
# against this set everywhere (config validation and pipeline filtering).
#
# The proxy also accepts its virtual/master key in x-litellm-api-key, and
# Azure-style callers send api-key. cerberus-core does not know about those two,
# so they are plugin-specific additions: forwarding either would ship the proxy
# credential on every event.
_PLUGIN_SENSITIVE_HEADERS = frozenset({"x-litellm-api-key", "api-key"})
SENSITIVE_HEADER_NAMES = (
    frozenset(name.removeprefix("HTTP_").replace("_", "-").lower() for name in SENSITIVE_HEADERS)
    | _PLUGIN_SENSITIVE_HEADERS
)


class ConfigError(ValueError):
    """Raised when required configuration is missing or invalid."""


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be a boolean (got {raw!r})")


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer (got {raw!r})") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum} (got {value})")
    return value


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number (got {raw!r})") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum} (got {value})")
    return value


def _env_str(name: str, default: str) -> str:
    """Stripped string; unset or whitespace-only falls back to the default."""
    return (os.environ.get(name) or "").strip() or default


def _env_header_name(name: str, default: str) -> str:
    """A single header name, lower-cased; credential-bearing names are refused."""
    value = _env_str(name, default).lower()
    if value in SENSITIVE_HEADER_NAMES:
        raise ConfigError(f"{name}: {value!r} is a credential-bearing header and is never used")
    return value


def _env_list(name: str, maximum: int) -> tuple[str, ...]:
    """Comma-separated list, lower-cased, de-duplicated, order-preserving."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return ()
    items: list[str] = []
    for part in raw.split(","):
        item = part.strip().lower()
        if item and item not in items:
            items.append(item)
    if len(items) > maximum:
        raise ConfigError(f"{name} accepts at most {maximum} entries (got {len(items)})")
    return tuple(items)


@dataclass
class Config:
    """Plugin configuration. Build with :meth:`from_env`."""

    ingest_service: str
    token: str = field(repr=False)

    capture_llm_content: bool = True
    capture_mcp_arguments: bool = True
    capture_mcp_results: bool = True
    mcp_result_max_chars: int = 2048
    capture_headers: tuple[str, ...] = ()
    session_header: str = "x-litellm-session-id"
    turn_header: str = "x-cerberus-turn-id"
    user_id_source: tuple[str, ...] = ("end_user", "user_id", "key_alias")
    mcp_server_fallback: str = "litellm"

    batch_size: int = 50
    flush_interval_ms: int = 2000
    queue_capacity: int = 10000
    max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES
    sample_rate: float = 1.0
    schema_report_interval_s: int = 3600
    stats_log_interval_s: int = 300
    log_level: str = "info"

    @classmethod
    def from_env(cls) -> "Config":
        """Read configuration from CERBERUS_* environment variables.

        Raises:
            ConfigError: when a required variable is missing or a value is
                outside its allowed range.
        """
        ingest_service = (os.environ.get("CERBERUS_INGEST_SERVICE") or "").strip().rstrip("/")
        if not ingest_service:
            raise ConfigError("CERBERUS_INGEST_SERVICE is required (Cerberus ingest URL)")
        if not ingest_service.startswith(("http://", "https://")):
            raise ConfigError(
                "CERBERUS_INGEST_SERVICE must start with http:// or https:// "
                f"(got {ingest_service!r})"
            )

        token = (os.environ.get("CERBERUS_TOKEN") or "").strip()
        token_file = (os.environ.get("CERBERUS_TOKEN_FILE") or "").strip()
        if not token and token_file:
            try:
                with open(token_file, encoding="utf-8") as fh:
                    token = fh.read().strip()
            except OSError as exc:
                raise ConfigError(
                    f"could not read CERBERUS_TOKEN_FILE {token_file!r}: {exc}"
                ) from exc
        if not token:
            raise ConfigError(
                "CERBERUS_TOKEN (or CERBERUS_TOKEN_FILE) is required (Cerberus API key)"
            )

        log_level = (os.environ.get("CERBERUS_LOG_LEVEL") or "info").strip().lower()
        if log_level not in _LOG_LEVELS:
            raise ConfigError(
                f"CERBERUS_LOG_LEVEL must be one of {_LOG_LEVELS} (got {log_level!r})"
            )

        capture_headers = _env_list("CERBERUS_CAPTURE_HEADERS", MAX_CAPTURE_HEADERS)
        for header in capture_headers:
            if header in SENSITIVE_HEADER_NAMES:
                raise ConfigError(
                    f"CERBERUS_CAPTURE_HEADERS: {header!r} is a credential-bearing header "
                    "and is never forwarded"
                )

        user_id_source = _env_list("CERBERUS_USER_ID_SOURCE", len(USER_ID_SOURCES)) or (
            "end_user",
            "user_id",
            "key_alias",
        )
        for source in user_id_source:
            if source not in USER_ID_SOURCES:
                raise ConfigError(
                    f"CERBERUS_USER_ID_SOURCE entries must be one of {USER_ID_SOURCES} "
                    f"(got {source!r})"
                )

        session_header = _env_header_name("CERBERUS_SESSION_HEADER", "x-litellm-session-id")
        turn_header = _env_header_name("CERBERUS_TURN_HEADER", "x-cerberus-turn-id")

        return cls(
            ingest_service=ingest_service,
            token=token,
            capture_llm_content=_env_bool("CERBERUS_CAPTURE_LLM_CONTENT", True),
            capture_mcp_arguments=_env_bool("CERBERUS_CAPTURE_MCP_ARGUMENTS", True),
            capture_mcp_results=_env_bool("CERBERUS_CAPTURE_MCP_RESULTS", True),
            mcp_result_max_chars=_env_int("CERBERUS_MCP_RESULT_MAX_CHARS", 2048, 64, 8192),
            capture_headers=capture_headers,
            session_header=session_header,
            turn_header=turn_header,
            user_id_source=user_id_source,
            mcp_server_fallback=_env_str("CERBERUS_MCP_SERVER_FALLBACK", "litellm"),
            batch_size=_env_int("CERBERUS_BATCH_SIZE", 50, 1, MAX_SERVER_BATCH_SIZE),
            flush_interval_ms=_env_int(
                "CERBERUS_FLUSH_INTERVAL_MS", 2000, MIN_FLUSH_INTERVAL_MS, 60000
            ),
            queue_capacity=_env_int("CERBERUS_QUEUE_CAPACITY", 10000, 100, 1_000_000),
            max_event_bytes=_env_int(
                "CERBERUS_MAX_EVENT_BYTES", DEFAULT_MAX_EVENT_BYTES, 1024, MAX_EVENT_BYTES_CEILING
            ),
            sample_rate=_env_float("CERBERUS_SAMPLE_RATE", 1.0, 0.0, 1.0),
            schema_report_interval_s=_env_int("CERBERUS_SCHEMA_REPORT_INTERVAL_S", 3600, 0, 86400),
            stats_log_interval_s=_env_int("CERBERUS_STATS_LOG_INTERVAL_S", 300, 0, 86400),
            log_level=log_level,
        )
