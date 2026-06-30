"""Environment-variable configuration for the bridge.

Names and semantics mirror the cerberus-flex-gateway policy's gcl.yaml
properties (ingestService, token, secretKey, backendUrl, batchSize,
flushIntervalMs, queueCapacity, logLevel) so operators moving between
gateway integrations meet a familiar surface.
"""

import os
from dataclasses import dataclass, field

# Server-side caps in event_ingest (see cerberus-int services/event_ingest/main.py):
# batches over 1000 events get a 413; events over 64KB are skipped. We cap the
# batch client-side and leave headroom under the event cap because the server
# enlarges each event by fanning in api_key/client_id/token before the check.
MAX_SERVER_BATCH_SIZE = 1000
DEFAULT_MAX_EVENT_BYTES = 57344  # 56KB
# Ceiling for the CERBERUS_MAX_EVENT_BYTES override: stay under the server's
# 64KB skip threshold with headroom, because the server enlarges each event by
# fanning in api_key/client_id/token *before* the cap (see comment above).
# 62KB leaves ~2KB for that augmentation; 65536 would let capped events be
# silently skipped server-side.
MAX_EVENT_BYTES_CEILING = 63488  # 62KB

MIN_FLUSH_INTERVAL_MS = 100

_LOG_LEVELS = ("debug", "info", "warning", "error")


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


@dataclass
class Config:
    """Bridge configuration. Build with :meth:`from_env`."""

    ingest_service: str
    token: str = field(repr=False)

    secret_key: str | None = field(default=None, repr=False)
    backend_url: str | None = None

    client_ip_attribute: str = "http.client_ip"
    user_id_attribute: str | None = None
    user_agent_attribute: str = "http.user_agent"

    capture_llm_content: bool = False
    capture_mcp_arguments: bool = True

    batch_size: int = 50
    flush_interval_ms: int = 2000
    queue_capacity: int = 10000
    max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES

    mcp_server_fallback: str = "envoy-ai-gateway"

    listen_port: int = 4318
    log_level: str = "info"
    dump_spans: bool = field(default=False)

    @classmethod
    def from_env(cls) -> "Config":
        """Read configuration from CERBERUS_* environment variables.

        Raises:
            ConfigError: when a required variable is missing or a value is
                outside its allowed range.
        """
        ingest_service = (os.environ.get("CERBERUS_INGEST_SERVICE") or "").strip().rstrip("/")
        if not ingest_service:
            raise ConfigError("CERBERUS_INGEST_SERVICE is required (Cerberus backend URL)")

        token = (os.environ.get("CERBERUS_TOKEN") or "").strip()
        token_file = (os.environ.get("CERBERUS_TOKEN_FILE") or "").strip()
        if not token and token_file:
            try:
                with open(token_file, encoding="utf-8") as f:
                    token = f.read().strip()
            except OSError as exc:
                raise ConfigError(
                    f"could not read CERBERUS_TOKEN_FILE {token_file!r}: {exc}"
                ) from exc
        if not token:
            raise ConfigError(
                "CERBERUS_TOKEN (or CERBERUS_TOKEN_FILE) is required (Cerberus API key)"
            )

        secret_key = (os.environ.get("CERBERUS_SECRET_KEY") or "").strip() or None
        backend_url = (os.environ.get("CERBERUS_BACKEND_URL") or "").strip().rstrip("/") or None

        log_level = (os.environ.get("CERBERUS_LOG_LEVEL") or "info").strip().lower()
        if log_level not in _LOG_LEVELS:
            raise ConfigError(
                f"CERBERUS_LOG_LEVEL must be one of {_LOG_LEVELS} (got {log_level!r})"
            )

        return cls(
            ingest_service=ingest_service,
            token=token,
            secret_key=secret_key,
            backend_url=backend_url,
            client_ip_attribute=(
                os.environ.get("CERBERUS_CLIENT_IP_ATTRIBUTE") or "http.client_ip"
            ).strip(),
            user_id_attribute=(os.environ.get("CERBERUS_USER_ID_ATTRIBUTE") or "").strip() or None,
            user_agent_attribute=(
                os.environ.get("CERBERUS_USER_AGENT_ATTRIBUTE") or "http.user_agent"
            ).strip(),
            capture_llm_content=_env_bool("CERBERUS_CAPTURE_LLM_CONTENT", False),
            capture_mcp_arguments=_env_bool("CERBERUS_CAPTURE_MCP_ARGUMENTS", True),
            batch_size=_env_int("CERBERUS_BATCH_SIZE", 50, 1, MAX_SERVER_BATCH_SIZE),
            flush_interval_ms=_env_int(
                "CERBERUS_FLUSH_INTERVAL_MS", 2000, MIN_FLUSH_INTERVAL_MS, 60000
            ),
            queue_capacity=_env_int("CERBERUS_QUEUE_CAPACITY", 10000, 100, 1_000_000),
            max_event_bytes=_env_int(
                "CERBERUS_MAX_EVENT_BYTES", DEFAULT_MAX_EVENT_BYTES, 1024, MAX_EVENT_BYTES_CEILING
            ),
            mcp_server_fallback=(
                os.environ.get("CERBERUS_MCP_SERVER_FALLBACK") or "envoy-ai-gateway"
            ).strip(),
            listen_port=_env_int("CERBERUS_LISTEN_PORT", 4318, 1, 65535),
            log_level=log_level,
            dump_spans=_env_bool("CERBERUS_DUMP_SPANS", False),
        )
