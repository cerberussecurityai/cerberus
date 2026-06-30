import pytest

from cerberus_envoy_ai_gateway.config import Config, ConfigError


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in list(__import__("os").environ):
        if key.startswith("CERBERUS_"):
            monkeypatch.delenv(key)


def _set_required(monkeypatch):
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "https://ingest.example.com/")
    monkeypatch.setenv("CERBERUS_TOKEN", "  sk_live_abc  ")


def test_missing_ingest_service_raises(monkeypatch):
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_live_abc")
    with pytest.raises(ConfigError, match="CERBERUS_INGEST_SERVICE"):
        Config.from_env()


def test_missing_token_raises(monkeypatch):
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "https://ingest.example.com")
    with pytest.raises(ConfigError, match="CERBERUS_TOKEN"):
        Config.from_env()


def test_defaults(monkeypatch):
    _set_required(monkeypatch)
    config = Config.from_env()
    assert config.ingest_service == "https://ingest.example.com"  # trailing slash stripped
    assert config.token == "sk_live_abc"  # whitespace trimmed
    assert config.secret_key is None
    assert config.backend_url is None
    assert config.client_ip_attribute == "http.client_ip"
    assert config.user_id_attribute is None
    assert config.capture_llm_content is True
    assert config.capture_mcp_arguments is True
    assert config.batch_size == 50
    assert config.flush_interval_ms == 2000
    assert config.queue_capacity == 10000
    assert config.listen_port == 4318
    assert config.log_level == "info"
    assert config.dump_spans is False


def test_token_file(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("sk_live_from_file\n")
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "https://ingest.example.com")
    monkeypatch.setenv("CERBERUS_TOKEN_FILE", str(token_file))
    assert Config.from_env().token == "sk_live_from_file"


def test_unreadable_token_file_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "https://ingest.example.com")
    monkeypatch.setenv("CERBERUS_TOKEN_FILE", str(tmp_path / "missing"))
    with pytest.raises(ConfigError, match="CERBERUS_TOKEN_FILE"):
        Config.from_env()


def test_bool_and_int_overrides(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("CERBERUS_CAPTURE_LLM_CONTENT", "false")
    monkeypatch.setenv("CERBERUS_CAPTURE_MCP_ARGUMENTS", "off")
    monkeypatch.setenv("CERBERUS_BATCH_SIZE", "200")
    monkeypatch.setenv("CERBERUS_FLUSH_INTERVAL_MS", "500")
    config = Config.from_env()
    assert config.capture_llm_content is False
    assert config.capture_mcp_arguments is False
    assert config.batch_size == 200
    assert config.flush_interval_ms == 500


def test_invalid_bool_raises(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("CERBERUS_CAPTURE_LLM_CONTENT", "maybe")
    with pytest.raises(ConfigError, match="CERBERUS_CAPTURE_LLM_CONTENT"):
        Config.from_env()


def test_batch_size_over_server_cap_raises(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("CERBERUS_BATCH_SIZE", "1001")
    with pytest.raises(ConfigError, match="CERBERUS_BATCH_SIZE"):
        Config.from_env()


def test_flush_interval_floor(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("CERBERUS_FLUSH_INTERVAL_MS", "50")
    with pytest.raises(ConfigError, match="CERBERUS_FLUSH_INTERVAL_MS"):
        Config.from_env()


def test_invalid_log_level_raises(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("CERBERUS_LOG_LEVEL", "verbose")
    with pytest.raises(ConfigError, match="CERBERUS_LOG_LEVEL"):
        Config.from_env()


def test_repr_hides_token_and_secret_key():
    # Dataclass repr must not leak the API key or HMAC secret (tracebacks, logs).
    config = Config(ingest_service="http://x", token="sk_secret_123", secret_key="hmac_secret_456")
    text = repr(config)
    assert "sk_secret_123" not in text
    assert "hmac_secret_456" not in text


def test_backend_url_requires_scheme(monkeypatch):
    # Guard against sending the API key to a schemeless/SSRF-y target.
    _set_required(monkeypatch)
    monkeypatch.setenv("CERBERUS_BACKEND_URL", "169.254.169.254/api")
    with pytest.raises(ConfigError, match="CERBERUS_BACKEND_URL"):
        Config.from_env()


def test_backend_url_with_https_ok(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("CERBERUS_BACKEND_URL", "https://backend.example.com/")
    assert Config.from_env().backend_url == "https://backend.example.com"
