import os

import pytest

from cerberus_litellm.config import (
    DEFAULT_MAX_EVENT_BYTES,
    MAX_EVENT_BYTES_CEILING,
    SENSITIVE_HEADER_NAMES,
    Config,
    ConfigError,
)


def test_sensitive_header_names_are_wire_style():
    # cerberus-core spells these Django-style (HTTP_X_API_KEY); the plugin
    # compares against wire-style lower-case names.
    assert {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
        "x-litellm-api-key",
        "api-key",
    } <= SENSITIVE_HEADER_NAMES
    assert all(name == name.lower() and "_" not in name for name in SENSITIVE_HEADER_NAMES)


BASE = {"CERBERUS_INGEST_SERVICE": "https://ingest.example.com/", "CERBERUS_TOKEN": "tok"}


def _env(monkeypatch, **extra):
    """Reset EVERY CERBERUS_* variable, then set the base pair plus ``extra``.

    Each call is a clean slate, so a test that calls it several times in a row
    (test_int_ranges) cannot have an earlier override leak into the next case
    and trip the wrong validation error.
    """
    for key in list(os.environ):
        if key.startswith("CERBERUS_"):
            monkeypatch.delenv(key, raising=False)
    for key, value in {**BASE, **extra}.items():
        monkeypatch.setenv(key, value)


def test_defaults(monkeypatch):
    _env(monkeypatch)
    cfg = Config.from_env()
    assert cfg.ingest_service == "https://ingest.example.com"  # trailing slash stripped
    assert cfg.token == "tok"
    assert cfg.capture_llm_content is True
    assert cfg.capture_mcp_arguments is True
    assert cfg.capture_mcp_results is True
    assert cfg.mcp_result_max_chars == 2048
    assert cfg.capture_headers == ()
    assert cfg.session_header == "x-litellm-session-id"
    assert cfg.turn_header == "x-cerberus-turn-id"
    assert cfg.user_id_source == ("end_user", "user_id", "key_alias")
    assert cfg.mcp_server_fallback == "litellm"
    assert cfg.batch_size == 50
    assert cfg.flush_interval_ms == 2000
    assert cfg.queue_capacity == 10000
    assert cfg.max_event_bytes == DEFAULT_MAX_EVENT_BYTES
    assert cfg.sample_rate == 1.0
    assert cfg.schema_report_interval_s == 3600
    assert cfg.stats_log_interval_s == 300
    assert cfg.log_level == "info"


def test_missing_ingest_service(monkeypatch):
    _env(monkeypatch)
    monkeypatch.delenv("CERBERUS_INGEST_SERVICE")
    with pytest.raises(ConfigError, match="CERBERUS_INGEST_SERVICE"):
        Config.from_env()


def test_ingest_service_must_be_http(monkeypatch):
    _env(monkeypatch, CERBERUS_INGEST_SERVICE="ingest.example.com")
    with pytest.raises(ConfigError, match="http"):
        Config.from_env()


def test_token_file(monkeypatch, tmp_path):
    path = tmp_path / "token"
    path.write_text("from-file\n")
    _env(monkeypatch)
    monkeypatch.delenv("CERBERUS_TOKEN")
    monkeypatch.setenv("CERBERUS_TOKEN_FILE", str(path))
    assert Config.from_env().token == "from-file"


def test_bool_parsing(monkeypatch):
    _env(monkeypatch, CERBERUS_CAPTURE_LLM_CONTENT="off", CERBERUS_CAPTURE_MCP_RESULTS="0")
    cfg = Config.from_env()
    assert cfg.capture_llm_content is False
    assert cfg.capture_mcp_results is False
    _env(monkeypatch, CERBERUS_CAPTURE_LLM_CONTENT="maybe")
    with pytest.raises(ConfigError):
        Config.from_env()


def test_capture_headers_lowercased_deduped_and_capped(monkeypatch):
    _env(monkeypatch, CERBERUS_CAPTURE_HEADERS="X-Tenant, x-tenant ,X-Request-Id")
    assert Config.from_env().capture_headers == ("x-tenant", "x-request-id")
    _env(monkeypatch, CERBERUS_CAPTURE_HEADERS=",".join(f"x-h{i}" for i in range(21)))
    with pytest.raises(ConfigError, match="at most 20"):
        Config.from_env()


def test_sensitive_header_names_refused(monkeypatch):
    _env(monkeypatch, CERBERUS_CAPTURE_HEADERS="x-tenant,authorization")
    with pytest.raises(ConfigError, match="authorization"):
        Config.from_env()


def test_user_id_source_validated(monkeypatch):
    _env(monkeypatch, CERBERUS_USER_ID_SOURCE="key_alias,end_user")
    assert Config.from_env().user_id_source == ("key_alias", "end_user")
    _env(monkeypatch, CERBERUS_USER_ID_SOURCE="email")
    with pytest.raises(ConfigError, match="CERBERUS_USER_ID_SOURCE"):
        Config.from_env()


def test_int_ranges(monkeypatch):
    _env(monkeypatch, CERBERUS_MAX_EVENT_BYTES=str(MAX_EVENT_BYTES_CEILING + 1))
    with pytest.raises(ConfigError, match="CERBERUS_MAX_EVENT_BYTES"):
        Config.from_env()
    _env(monkeypatch, CERBERUS_BATCH_SIZE="1001")
    with pytest.raises(ConfigError, match="CERBERUS_BATCH_SIZE"):
        Config.from_env()
    _env(monkeypatch, CERBERUS_FLUSH_INTERVAL_MS="50")
    with pytest.raises(ConfigError, match="CERBERUS_FLUSH_INTERVAL_MS"):
        Config.from_env()


def test_sample_rate_range(monkeypatch):
    _env(monkeypatch, CERBERUS_SAMPLE_RATE="0.25")
    assert Config.from_env().sample_rate == 0.25
    _env(monkeypatch, CERBERUS_SAMPLE_RATE="1.5")
    with pytest.raises(ConfigError, match="CERBERUS_SAMPLE_RATE"):
        Config.from_env()


def test_log_level_validated(monkeypatch):
    _env(monkeypatch, CERBERUS_LOG_LEVEL="verbose")
    with pytest.raises(ConfigError, match="CERBERUS_LOG_LEVEL"):
        Config.from_env()


@pytest.mark.parametrize(
    "name,value",
    [
        ("CERBERUS_BATCH_SIZE", "1"),
        ("CERBERUS_BATCH_SIZE", "1000"),
        ("CERBERUS_MAX_EVENT_BYTES", "1024"),
        ("CERBERUS_MAX_EVENT_BYTES", "63488"),
        ("CERBERUS_FLUSH_INTERVAL_MS", "100"),
        ("CERBERUS_FLUSH_INTERVAL_MS", "60000"),
        ("CERBERUS_MCP_RESULT_MAX_CHARS", "64"),
        ("CERBERUS_MCP_RESULT_MAX_CHARS", "8192"),
        ("CERBERUS_QUEUE_CAPACITY", "100"),
        ("CERBERUS_QUEUE_CAPACITY", "1000000"),
        ("CERBERUS_SCHEMA_REPORT_INTERVAL_S", "0"),
        ("CERBERUS_SCHEMA_REPORT_INTERVAL_S", "86400"),
        ("CERBERUS_STATS_LOG_INTERVAL_S", "0"),
        ("CERBERUS_STATS_LOG_INTERVAL_S", "86400"),
        ("CERBERUS_SAMPLE_RATE", "0"),
        ("CERBERUS_SAMPLE_RATE", "1"),
    ],
)
def test_inclusive_boundaries_accepted(monkeypatch, name, value):
    _env(monkeypatch, **{name: value})
    Config.from_env()


@pytest.mark.parametrize(
    "name,value",
    [
        ("CERBERUS_BATCH_SIZE", "0"),
        ("CERBERUS_BATCH_SIZE", "1001"),
        ("CERBERUS_MAX_EVENT_BYTES", "1023"),
        ("CERBERUS_FLUSH_INTERVAL_MS", "99"),
        ("CERBERUS_FLUSH_INTERVAL_MS", "60001"),
        ("CERBERUS_MCP_RESULT_MAX_CHARS", "63"),
        ("CERBERUS_MCP_RESULT_MAX_CHARS", "8193"),
        ("CERBERUS_QUEUE_CAPACITY", "99"),
        ("CERBERUS_QUEUE_CAPACITY", "1000001"),
        ("CERBERUS_SCHEMA_REPORT_INTERVAL_S", "-1"),
        ("CERBERUS_SCHEMA_REPORT_INTERVAL_S", "86401"),
        ("CERBERUS_STATS_LOG_INTERVAL_S", "-1"),
        ("CERBERUS_STATS_LOG_INTERVAL_S", "86401"),
        ("CERBERUS_SAMPLE_RATE", "-0.1"),
        ("CERBERUS_SAMPLE_RATE", "1.01"),
    ],
)
def test_out_of_range_rejected(monkeypatch, name, value):
    _env(monkeypatch, **{name: value})
    with pytest.raises(ConfigError, match=name):
        Config.from_env()


@pytest.mark.parametrize(
    "name,value",
    [
        ("CERBERUS_BATCH_SIZE", "abc"),
        ("CERBERUS_SAMPLE_RATE", "abc"),
        ("CERBERUS_SAMPLE_RATE", "nan"),
    ],
)
def test_non_numeric_rejected(monkeypatch, name, value):
    _env(monkeypatch, **{name: value})
    with pytest.raises(ConfigError, match=name):
        Config.from_env()


@pytest.mark.parametrize("header", sorted(SENSITIVE_HEADER_NAMES))
def test_every_sensitive_header_refused(monkeypatch, header):
    for spelling in (header, header.upper(), header.title()):
        _env(monkeypatch, CERBERUS_CAPTURE_HEADERS=f"x-tenant,{spelling}")
        with pytest.raises(ConfigError, match="CERBERUS_CAPTURE_HEADERS"):
            Config.from_env()


def test_token_env_wins_over_token_file(monkeypatch, tmp_path):
    path = tmp_path / "token"
    path.write_text("from-file\n")
    _env(monkeypatch, CERBERUS_TOKEN_FILE=str(path))
    assert Config.from_env().token == "tok"


def test_token_file_missing(monkeypatch, tmp_path):
    _env(monkeypatch, CERBERUS_TOKEN_FILE=str(tmp_path / "absent"))
    monkeypatch.delenv("CERBERUS_TOKEN")
    with pytest.raises(ConfigError, match="CERBERUS_TOKEN_FILE"):
        Config.from_env()


def test_token_file_empty(monkeypatch, tmp_path):
    path = tmp_path / "token"
    path.write_text("  \n")
    _env(monkeypatch, CERBERUS_TOKEN_FILE=str(path))
    monkeypatch.delenv("CERBERUS_TOKEN")
    with pytest.raises(ConfigError, match="is required"):
        Config.from_env()


def test_user_id_source_dedupes(monkeypatch):
    _env(monkeypatch, CERBERUS_USER_ID_SOURCE="end_user,end_user,user_id")
    assert Config.from_env().user_id_source == ("end_user", "user_id")


@pytest.mark.parametrize("value", ["", "   "])
def test_user_id_source_blank_uses_default(monkeypatch, value):
    _env(monkeypatch, CERBERUS_USER_ID_SOURCE=value)
    assert Config.from_env().user_id_source == ("end_user", "user_id", "key_alias")


@pytest.mark.parametrize(
    "name,value",
    [
        ("CERBERUS_SESSION_HEADER", "authorization"),
        ("CERBERUS_TURN_HEADER", "X-API-Key"),
    ],
)
def test_session_and_turn_header_refuse_credential_names(monkeypatch, name, value):
    _env(monkeypatch, **{name: value})
    with pytest.raises(ConfigError, match=name):
        Config.from_env()


def test_blank_strings_fall_back_to_defaults(monkeypatch):
    _env(
        monkeypatch,
        CERBERUS_SESSION_HEADER="  ",
        CERBERUS_TURN_HEADER=" ",
        CERBERUS_MCP_SERVER_FALLBACK="   ",
    )
    cfg = Config.from_env()
    assert cfg.session_header == "x-litellm-session-id"
    assert cfg.turn_header == "x-cerberus-turn-id"
    assert cfg.mcp_server_fallback == "litellm"
