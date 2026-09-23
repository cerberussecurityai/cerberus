import pytest

from cerberus_agentcore_interceptor.bounding import (
    DEFAULT_MAX_EVENT_BYTES,
    MAX_EVENT_BYTES_CEILING,
)
from cerberus_agentcore_interceptor.config import Config, ConfigError
from cerberus_agentcore_interceptor.sanitize import DEFAULT_CAPTURE_HEADERS

MINIMAL = {"CERBERUS_FIREHOSE_STREAM": "cerberus-capture"}


def build(**env):
    return Config.from_env({**MINIMAL, **env})


def test_defaults():
    config = build()
    assert config.streams == ("cerberus-capture",)
    assert config.identity_mode == "jwt"
    assert config.user_id_claim == "sub"
    assert config.capture_headers == DEFAULT_CAPTURE_HEADERS
    assert config.capture_bodies is True
    assert config.sensitive_keys == ()
    assert config.max_event_bytes == DEFAULT_MAX_EVENT_BYTES
    assert config.firehose_connect_ms == 250
    assert config.firehose_read_ms == 500
    assert config.log_level == "INFO"


def test_the_stream_is_required():
    with pytest.raises(ConfigError, match="CERBERUS_FIREHOSE_STREAM"):
        Config.from_env({})
    with pytest.raises(ConfigError):
        Config.from_env({"CERBERUS_FIREHOSE_STREAM": "   "})


def test_several_streams_are_ordered_and_deduplicated():
    config = build(CERBERUS_FIREHOSE_STREAM=" a , b ,a, ")
    assert config.streams == ("a", "b")


def test_a_stream_name_is_validated():
    with pytest.raises(ConfigError, match="not a stream name"):
        build(CERBERUS_FIREHOSE_STREAM="arn:aws:firehose:us-west-2:123456789012:stream/x")


def test_identity_mode_is_a_closed_set():
    assert build(CERBERUS_IDENTITY="SIGV4").identity_mode == "sigv4"
    with pytest.raises(ConfigError, match="CERBERUS_IDENTITY"):
        build(CERBERUS_IDENTITY="oauth")


def test_capture_headers_override():
    config = build(CERBERUS_CAPTURE_HEADERS="User-Agent, X-Tenant ,User-Agent")
    assert config.capture_headers == ("User-Agent", "X-Tenant")


def test_sensitive_keys_override():
    assert build(CERBERUS_SENSITIVE_KEYS="member_number,ssn").sensitive_keys == (
        "member_number",
        "ssn",
    )


@pytest.mark.parametrize(
    "raw,expected", [("false", False), ("0", False), ("off", False), ("TRUE", True)]
)
def test_capture_bodies_boolean(raw, expected):
    assert build(CERBERUS_CAPTURE_BODIES=raw).capture_bodies is expected


def test_a_bad_boolean_fails():
    with pytest.raises(ConfigError, match="boolean"):
        build(CERBERUS_CAPTURE_BODIES="maybe")


def test_max_event_bytes_range():
    assert build(CERBERUS_MAX_EVENT_BYTES="20000").max_event_bytes == 20000
    with pytest.raises(ConfigError, match="between"):
        build(CERBERUS_MAX_EVENT_BYTES=str(MAX_EVENT_BYTES_CEILING + 1))
    with pytest.raises(ConfigError, match="between"):
        build(CERBERUS_MAX_EVENT_BYTES="100")
    with pytest.raises(ConfigError, match="integer"):
        build(CERBERUS_MAX_EVENT_BYTES="57k")


def test_timeouts():
    config = build(CERBERUS_FIREHOSE_CONNECT_MS="100", CERBERUS_FIREHOSE_READ_MS="900")
    assert (config.firehose_connect_ms, config.firehose_read_ms) == (100, 900)


def test_log_level_is_a_closed_set():
    assert build(CERBERUS_LOG_LEVEL="debug").log_level == "DEBUG"
    with pytest.raises(ConfigError, match="CERBERUS_LOG_LEVEL"):
        build(CERBERUS_LOG_LEVEL="verbose")


def test_mapper_options_carry_the_configuration():
    options = build(
        CERBERUS_IDENTITY="none",
        CERBERUS_USER_ID_CLAIM="email",
        CERBERUS_SENSITIVE_KEYS="ssn",
        CERBERUS_MAX_EVENT_BYTES="8192",
    ).mapper_options("9.9.9")

    assert options.identity_mode == "none"
    assert options.user_id_claim == "email"
    assert options.sensitive_keys == ("ssn",)
    assert options.max_event_bytes == 8192
    assert options.version == "9.9.9"
