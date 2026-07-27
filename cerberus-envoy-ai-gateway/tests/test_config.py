import pytest

from cerberus_envoy_ai_gateway.config import (
    MAX_EXTRA_ATTRIBUTE_NAME_CHARS,
    MAX_EXTRA_ATTRIBUTES,
    Config,
    ConfigError,
)


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


def test_ingest_service_requires_scheme(monkeypatch):
    # A schemeless URL otherwise starts fine but drops every batch at POST.
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_live_abc")
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "ingest.example.com")
    with pytest.raises(ConfigError, match="CERBERUS_INGEST_SERVICE"):
        Config.from_env()


def test_extra_attributes_parsed_and_deduped(monkeypatch):
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_test")
    monkeypatch.setenv("CERBERUS_EXTRA_ATTRIBUTES", " a.b , c.d ,a.b, ,")
    config = Config.from_env()
    assert config.extra_attributes == ("a.b", "c.d")


def test_extra_attribute_name_length_is_capped(monkeypatch):
    # The name becomes an unsheddable custom_data key. Values are bounded in the
    # pipeline; an unbounded name would blow the event cap and silently drop
    # every event carrying that attribute.
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_test")
    monkeypatch.setenv("CERBERUS_EXTRA_ATTRIBUTES", "a." + "x" * MAX_EXTRA_ATTRIBUTE_NAME_CHARS)
    with pytest.raises(ConfigError, match="over the"):
        Config.from_env()


def test_normal_attribute_names_are_unaffected(monkeypatch):
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_test")
    monkeypatch.setenv("CERBERUS_EXTRA_ATTRIBUTES", "corr.session,tenant.id")
    assert Config.from_env().extra_attributes == ("corr.session", "tenant.id")


def test_extra_attributes_default_empty(monkeypatch):
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_test")
    monkeypatch.delenv("CERBERUS_EXTRA_ATTRIBUTES", raising=False)
    assert Config.from_env().extra_attributes == ()


def test_extra_attributes_rejects_oversized_list(monkeypatch):
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_test")
    monkeypatch.setenv(
        "CERBERUS_EXTRA_ATTRIBUTES", ",".join(f"a{i}" for i in range(MAX_EXTRA_ATTRIBUTES + 1))
    )
    with pytest.raises(ConfigError):
        Config.from_env()


def test_secret_fetch_knobs_parsed(monkeypatch):
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_test")
    monkeypatch.setenv("CERBERUS_SECRET_FETCH_ATTEMPTS", "6")
    monkeypatch.setenv("CERBERUS_SECRET_FETCH_TIMEOUT_MS", "3000")
    monkeypatch.setenv("CERBERUS_SECRET_FETCH_DEADLINE_MS", "15000")
    config = Config.from_env()
    assert config.secret_fetch_attempts == 6
    assert config.secret_fetch_timeout_ms == 3000
    assert config.secret_fetch_deadline_ms == 15000


def test_secret_fetch_knob_defaults(monkeypatch):
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_test")
    config = Config.from_env()
    assert config.secret_fetch_attempts == 4
    assert config.secret_fetch_timeout_ms == 5000
    assert config.secret_fetch_deadline_ms == 10000


@pytest.mark.parametrize(
    "name,value",
    [
        ("CERBERUS_SECRET_FETCH_ATTEMPTS", "0"),  # below the 1-attempt floor
        ("CERBERUS_SECRET_FETCH_ATTEMPTS", "11"),  # above the 10-attempt cap
        ("CERBERUS_SECRET_FETCH_TIMEOUT_MS", "99"),  # below the 100ms floor
        ("CERBERUS_SECRET_FETCH_TIMEOUT_MS", "60001"),  # above the 60s cap
        ("CERBERUS_SECRET_FETCH_DEADLINE_MS", "99"),  # below the 100ms floor
        ("CERBERUS_SECRET_FETCH_DEADLINE_MS", "120001"),  # above the 120s cap
    ],
)
def test_secret_fetch_knobs_out_of_range_rejected(monkeypatch, name, value):
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_test")
    monkeypatch.setenv(name, value)
    with pytest.raises(ConfigError):
        Config.from_env()


def test_hash_attributes_parsed(monkeypatch):
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_test")
    monkeypatch.setenv("CERBERUS_HASH_ATTRIBUTES", "corr.session, tenant.id")
    config = Config.from_env()
    assert config.hash_attributes == ("corr.session", "tenant.id")


def test_attribute_cap_binds_on_the_union_of_both_lists(monkeypatch):
    # Each captured attribute occupies an unsheddable custom_data key, so the
    # cap has to cover both lists together, not each independently.
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_test")
    half = MAX_EXTRA_ATTRIBUTES // 2 + 1
    monkeypatch.setenv("CERBERUS_EXTRA_ATTRIBUTES", ",".join(f"a{i}" for i in range(half)))
    monkeypatch.setenv("CERBERUS_HASH_ATTRIBUTES", ",".join(f"b{i}" for i in range(half)))
    with pytest.raises(ConfigError):
        Config.from_env()


def test_overlapping_lists_count_once_toward_the_cap(monkeypatch):
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_test")
    names = ",".join(f"a{i}" for i in range(MAX_EXTRA_ATTRIBUTES))
    monkeypatch.setenv("CERBERUS_EXTRA_ATTRIBUTES", names)
    monkeypatch.setenv("CERBERUS_HASH_ATTRIBUTES", names)
    assert len(Config.from_env().hash_attributes) == MAX_EXTRA_ATTRIBUTES
