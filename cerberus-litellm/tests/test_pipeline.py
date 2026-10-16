import json
from dataclasses import replace

import pytest
from helpers import load_capture

from cerberus_litellm.mapper_llm import map_llm_event
from cerberus_litellm.mapper_mcp import map_mcp_event, map_schema_reports
from cerberus_litellm.pipeline import (
    MAX_VALUE_CHARS,
    Pipeline,
    client_ip,
    redact_secrets,
    truncate_values,
)


def _llm(name, config):
    return map_llm_event(load_capture(name)["standard_logging_object"], config)


def _mcp(name, config):
    return map_mcp_event(load_capture(name)["standard_logging_object"], config)


def test_client_ip_is_raw_normalized_and_capped():
    assert client_ip("203.0.113.7") == "203.0.113.7"
    # cerberus-core's normalize_ip keeps IPv4-mapped IPv6 in IPv6 form (it
    # canonicalises, it does not convert) — same as every other connector.
    # The hex spelling is pinned by cerberus-core's parity fixture; str() of
    # the address varies across CPython patch releases, so it is not used.
    assert client_ip("::ffff:203.0.113.7") == "::ffff:cb00:7107"
    assert client_ip("FE80::1%eth0") == "fe80::1"
    assert client_ip(None) == "unknown"
    assert client_ip("") == "unknown"
    assert len(client_ip("x" * 500)) <= 64


def test_llm_event_keeps_raw_ip(config):
    event = Pipeline(config).finalize(_llm("chat", config), "llm")
    assert event["remote_addr"] == "203.0.113.7"
    assert event["custom_data"]["integration"] == "litellm"


def test_mcp_arguments_are_sanitized_in_body_and_custom_data(config):
    event = Pipeline(config).finalize(_mcp("mcp_tool_call", config), "mcp")
    assert event["custom_data"]["arguments"]["api_key"] == "[REDACTED]"
    assert event["body"]["api_key"] == "[REDACTED]"
    assert event["custom_data"]["arguments"]["message"] == "hi mcp"
    assert event["remote_addr"] == "unknown"  # the MCP capture carries no requester IP


def test_mcp_arguments_flag_off_empties_arguments(config):
    cfg = replace(config, capture_mcp_arguments=False)
    event = Pipeline(cfg).finalize(_mcp("mcp_tool_call", cfg), "mcp")
    assert event["custom_data"]["arguments"] == {}
    assert event["body"] is None
    assert event["custom_data"]["result_summary"] == "echo: hi mcp"  # results are a separate flag


def test_llm_body_tool_arguments_are_sanitized(config):
    event = Pipeline(config).finalize(_llm("chat_stream_tools", config), "llm")
    message = event["body"]["output"]["choices"][0]["message"]
    arguments = message["tool_calls"][0]["function"]["arguments"]
    # The arguments string is JSON text, not a dict: key-based redaction cannot
    # see inside it. That is the documented limitation shared with the bridge.
    assert isinstance(arguments, str)
    assert event["body"]["input"]["messages"][0]["content"] == "weather in Reykjavik?"


def test_captured_headers_are_sanitized_and_credentials_dropped(config):
    cfg = replace(config, capture_headers=("x-cerberus-turn-id",))
    event = _llm("chat", cfg)
    event["headers"] = {
        "x-cerberus-turn-id": "turn-1",
        "authorization": "Bearer x",
        "x-api-key": "k",
    }
    out = Pipeline(cfg).finalize(event, "llm")
    assert out["headers"] == {"x-cerberus-turn-id": "turn-1"}


def test_long_strings_truncated(config):
    event = _llm("chat", config)
    event["user_agent"] = "u" * 5000
    event["user_id"] = "i" * 5000
    event["custom_data"]["error"] = "e" * 5000
    out = Pipeline(config).finalize(event, "llm")
    assert len(out["user_agent"]) <= 1024 + len("...[TRUNCATED]")
    assert len(out["user_id"]) <= 256 + len("...[TRUNCATED]")
    assert len(out["custom_data"]["error"]) <= 2048 + len("...[TRUNCATED]")


def test_content_values_truncated_at_max_value_chars(config):
    out = Pipeline(config).finalize(_llm("big_completion", config), "llm")
    content = out["body"]["output"]["choices"][0]["message"]["content"]
    assert len(content) == MAX_VALUE_CHARS + len("...[TRUNCATED]")
    assert len(json.dumps(out).encode()) <= config.max_event_bytes


def test_oversize_event_sheds_content_first(config):
    cfg = replace(config, max_event_bytes=4096)
    out = Pipeline(cfg).finalize(_llm("big_prompt", cfg), "llm")
    assert out is not None
    assert out["body"] is None
    assert out["custom_data"]["content_dropped_oversize"] is True
    assert out["custom_data"]["tokens_total"] is not None


def test_dropped_oversize_is_counted(config):
    cfg = replace(config, max_event_bytes=1024)
    pipeline = Pipeline(cfg)
    event = _llm("chat", cfg)
    event["custom_data"]["request_tags"] = ["t" * 2000]  # unsheddable
    assert pipeline.finalize(event, "llm") is None
    assert pipeline.dropped_oversize == 1


def test_oversize_schema_report_sheds_tools_but_keeps_skeleton(config):
    cfg = replace(config, max_event_bytes=2048)
    capture = load_capture("mcp_list_tools")
    event = map_schema_reports(capture["standard_logging_object"], capture["response_obj"], cfg)[0]
    event["custom_data"]["tools"] = [
        {"name": f"t{i}", "description": "d" * 300, "input_schema": {}} for i in range(40)
    ]
    out = Pipeline(cfg).finalize(event, "schema")
    assert out is not None
    assert out["custom_data"]["tools"] == []
    assert out["method"] == "mcp_schema_report"


def test_schema_report_catalogue_is_sanitized(config):
    capture = load_capture("mcp_list_tools")
    event = map_schema_reports(capture["standard_logging_object"], capture["response_obj"], config)[
        0
    ]
    event["custom_data"]["tools"][0]["input_schema"] = {"properties": {"api_key": "example-secret"}}
    out = Pipeline(config).finalize(event, "schema")
    assert out["custom_data"]["tools"][0]["input_schema"]["properties"]["api_key"] == "[REDACTED]"


def test_unserializable_event_is_dropped_and_counted(config):
    pipeline = Pipeline(config)
    event = _llm("chat", config)
    event["custom_data"]["junk"] = object()
    assert pipeline.finalize(event, "llm") is None
    assert pipeline.dropped_unserializable == 1


def test_truncate_values_recurses():
    assert truncate_values({"a": ["x" * 10]}, limit=4) == {"a": ["xxxx...[TRUNCATED]"]}


@pytest.mark.parametrize(
    "text,expected",
    [
        ("auth failed for sk-abcdef123456XYZ upstream", "auth failed for sk-[REDACTED] upstream"),
        ("sk-proj_ab-12345678 rejected", "sk-[REDACTED] rejected"),
        (
            "401 with Authorization: Bearer abc.def-123_456== end",
            "401 with Authorization: Bearer [REDACTED] end",
        ),
        ("bearer lowercase.token.value here", "Bearer [REDACTED] here"),
        (
            "GET https://api.example.com/v1?key=AIzaSyD&alt=json",
            "GET https://api.example.com/v1?key=[REDACTED]&alt=json",
        ),
        ("url ?api_key=abc123 failed", "url ?api_key=[REDACTED] failed"),
        ("apikey=abc api-key=def", "apikey=[REDACTED] api-key=[REDACTED]"),
        ("access_token=ya29.a0 and token=t1", "access_token=[REDACTED] and token=[REDACTED]"),
        ("body password=hunter2&user=bob", "body password=[REDACTED]&user=bob"),
        ("SECRET=s3cr3t more", "SECRET=[REDACTED] more"),
        (
            "connect https://user:pass@db.example.com:5432/x",
            "connect https://[REDACTED]@db.example.com:5432/x",
        ),
    ],
)
def test_redact_secrets_masks_patterns_and_keeps_surroundings(text, expected):
    assert redact_secrets(text) == expected


def test_redact_secrets_leaves_plain_messages_alone():
    for text in ("mock upstream exploded", "rate limit: retry in 20s", "a monkey=happy"):
        assert redact_secrets(text) == text


def test_finalize_redacts_error_and_result_summary(config):
    event = _llm("chat", config)
    event["custom_data"]["error"] = "failed at https://h.example/v1?key=SECRET1 sk-abcdef123456"
    out = Pipeline(config).finalize(event, "llm")
    assert "SECRET1" not in json.dumps(out)
    assert "sk-abcdef123456" not in json.dumps(out)
    assert out["custom_data"]["error"].startswith("failed at https://h.example/v1?key=[REDACTED]")

    mcp = _mcp("mcp_tool_call", config)
    mcp["custom_data"]["result_summary"] = "token=abc123 Bearer zzz.yyy"
    out = Pipeline(config).finalize(mcp, "mcp")
    assert out["custom_data"]["result_summary"] == "token=[REDACTED] Bearer [REDACTED]"
