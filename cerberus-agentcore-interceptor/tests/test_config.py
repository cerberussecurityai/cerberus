import logging

import pytest

from cerberus_agentcore_interceptor.bounding import (
    DEFAULT_MAX_EVENT_BYTES,
    MAX_EVENT_BYTES_CEILING,
)
from cerberus_agentcore_interceptor.config import MAX_FIREHOSE_MS, MAX_STREAMS, Config
from cerberus_agentcore_interceptor.sanitize import DEFAULT_CAPTURE_HEADERS

MINIMAL = {"CERBERUS_FIREHOSE_STREAM": "cerberus-capture"}
STREAM_ARN = "arn:aws:firehose:us-east-1:123456789012:deliverystream/cerberus-capture"


def build(**env):
    return Config.from_env({**MINIMAL, **env})


def logged(caplog, level, name):
    return any(record.levelno == level and name in record.getMessage() for record in caplog.records)


def test_defaults():
    config = build()
    assert config.streams == ("cerberus-capture",)
    assert config.identity_mode == "jwt"
    assert config.user_id_claim == "sub"
    assert config.capture_headers == DEFAULT_CAPTURE_HEADERS
    assert config.capture_bodies is True
    assert config.response_capture is False
    assert config.sensitive_keys == ()
    assert config.max_event_bytes == DEFAULT_MAX_EVENT_BYTES
    assert config.firehose_connect_ms == 250
    assert config.firehose_read_ms == 500
    assert config.log_level == "INFO"
    assert config.capturing is True
    assert config.invalid == ()


def test_several_streams_are_ordered_and_deduplicated():
    config = build(CERBERUS_FIREHOSE_STREAM=" a , b ,a, ")
    assert config.streams == ("a", "b")


def test_a_stream_arn_is_read_as_its_name():
    assert build(CERBERUS_FIREHOSE_STREAM=STREAM_ARN).streams == ("cerberus-capture",)
    assert build(CERBERUS_FIREHOSE_STREAM=f"{STREAM_ARN}, cerberus-capture, other").streams == (
        "cerberus-capture",
        "other",
    )
    china = "arn:aws-cn:firehose:cn-north-1:123456789012:deliverystream/capture"
    assert build(CERBERUS_FIREHOSE_STREAM=china).streams == ("capture",)


@pytest.mark.parametrize(
    "raw,mode",
    [
        ("SIGV4", "sigv4"),
        ("CUSTOM_JWT", "jwt"),
        ("custom_jwt", "jwt"),
        ("AWS_IAM", "sigv4"),
        ("Authenticate_Only", "sigv4"),
        ("NONE", "none"),
    ],
)
def test_identity_accepts_the_gateway_authorizer_type(raw, mode):
    assert build(CERBERUS_IDENTITY=raw).identity_mode == mode


def test_a_missing_stream_turns_capture_off(caplog):
    config = Config.from_env({})
    assert config.capturing is False
    assert config.invalid == ("CERBERUS_FIREHOSE_STREAM",)
    assert logged(caplog, logging.ERROR, "CERBERUS_FIREHOSE_STREAM")


@pytest.mark.parametrize(
    "name,raw",
    [
        ("CERBERUS_FIREHOSE_STREAM", "   "),
        ("CERBERUS_FIREHOSE_STREAM", "arn:aws:firehose:us-west-2:123456789012:stream/x"),
        ("CERBERUS_FIREHOSE_STREAM", "has space"),
        ("CERBERUS_FIREHOSE_STREAM", ",".join(f"s{i}" for i in range(MAX_STREAMS + 1))),
        ("CERBERUS_IDENTITY", "oauth"),
        ("CERBERUS_CAPTURE_BODIES", "maybe"),
        ("CERBERUS_MAX_EVENT_BYTES", "57k"),
        ("CERBERUS_FIREHOSE_CONNECT_MS", "0.25"),
        ("CERBERUS_FIREHOSE_READ_MS", "fast"),
    ],
)
def test_an_unusable_capture_setting_turns_capture_off(caplog, name, raw):
    config = build(**{name: raw})
    assert config.capturing is False
    assert config.invalid == (name,)
    assert logged(caplog, logging.ERROR, name)


@pytest.mark.parametrize("raw", ["", "   "])
def test_an_empty_claim_is_unset(raw):
    config = build(CERBERUS_USER_ID_CLAIM=raw)
    assert config.user_id_claim == "sub"
    assert config.capturing is True


def test_a_fallback_is_never_less_private_than_the_setting():
    assert build(CERBERUS_CAPTURE_BODIES="maybe").capture_bodies is False
    assert build(CERBERUS_IDENTITY="oauth").identity_mode == "none"


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


@pytest.mark.parametrize(
    "raw,expected",
    [("true", True), ("1", True), ("YES", True), ("on", True), ("false", False), ("0", False)],
)
def test_response_capture_boolean(raw, expected):
    assert build(CERBERUS_RESPONSE_CAPTURE=raw).response_capture is expected


@pytest.mark.parametrize("raw", ["maybe", "enabled", "2"])
def test_an_unusable_response_capture_turns_off_response_capture_alone(caplog, raw):
    config = build(CERBERUS_RESPONSE_CAPTURE=raw)
    assert config.response_capture is False
    assert config.capturing is True
    assert config.invalid == ()
    assert logged(caplog, logging.ERROR, "CERBERUS_RESPONSE_CAPTURE")


def test_response_capture_beside_an_unusable_capture_setting_stays_on():
    config = build(CERBERUS_RESPONSE_CAPTURE="true", CERBERUS_CAPTURE_BODIES="maybe")
    assert config.response_capture is True
    assert config.invalid == ("CERBERUS_CAPTURE_BODIES",)


@pytest.mark.parametrize(
    "name,raw,field,expected",
    [
        ("CERBERUS_MAX_EVENT_BYTES", "65536", "max_event_bytes", MAX_EVENT_BYTES_CEILING),
        ("CERBERUS_MAX_EVENT_BYTES", "100", "max_event_bytes", 1024),
        ("CERBERUS_FIREHOSE_CONNECT_MS", "0", "firehose_connect_ms", 10),
        ("CERBERUS_FIREHOSE_CONNECT_MS", "1000", "firehose_connect_ms", 750),
    ],
)
def test_an_out_of_range_integer_is_clamped_with_a_warning(caplog, name, raw, field, expected):
    config = build(**{name: raw})
    assert getattr(config, field) == expected
    assert config.capturing is True
    assert logged(caplog, logging.WARNING, name)


@pytest.mark.parametrize(
    "connect,read,expected",
    [("500", "1400", (500, 1000)), ("250", "10000", (250, 1250)), ("10000", "10000", (750, 750))],
)
def test_connect_and_read_together_stay_within_the_budget(caplog, connect, read, expected):
    config = build(CERBERUS_FIREHOSE_CONNECT_MS=connect, CERBERUS_FIREHOSE_READ_MS=read)
    assert (config.firehose_connect_ms, config.firehose_read_ms) == expected
    assert sum(expected) <= MAX_FIREHOSE_MS
    assert config.capturing is True
    assert logged(caplog, logging.WARNING, "CERBERUS_FIREHOSE_READ_MS")


def test_integers_in_range_are_kept():
    config = build(
        CERBERUS_MAX_EVENT_BYTES="20000",
        CERBERUS_FIREHOSE_CONNECT_MS="100",
        CERBERUS_FIREHOSE_READ_MS="900",
    )
    assert config.max_event_bytes == 20000
    assert (config.firehose_connect_ms, config.firehose_read_ms) == (100, 900)


@pytest.mark.parametrize(
    "raw,level", [("debug", "DEBUG"), ("WARN", "WARNING"), ("warn", "WARNING"), ("Error", "ERROR")]
)
def test_log_level(raw, level):
    assert build(CERBERUS_LOG_LEVEL=raw).log_level == level


def test_an_unknown_log_level_falls_back_to_info(caplog):
    config = build(CERBERUS_LOG_LEVEL="verbose")
    assert config.log_level == "INFO"
    assert config.capturing is True
    assert logged(caplog, logging.WARNING, "CERBERUS_LOG_LEVEL")


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
