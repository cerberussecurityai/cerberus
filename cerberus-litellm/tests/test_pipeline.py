import json
from dataclasses import replace

import pytest
from helpers import finalized, load_capture

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
    event = finalized(Pipeline(config), _llm("chat", config), "llm")
    assert event["remote_addr"] == "203.0.113.7"
    assert event["custom_data"]["integration"] == "litellm"


def test_mcp_arguments_are_sanitized_in_body_and_custom_data(config):
    event = finalized(Pipeline(config), _mcp("mcp_tool_call", config), "mcp")
    assert event["custom_data"]["arguments"]["api_key"] == "[REDACTED]"
    assert event["body"]["api_key"] == "[REDACTED]"
    assert event["custom_data"]["arguments"]["message"] == "hi mcp"
    assert event["remote_addr"] == "unknown"  # the MCP capture carries no requester IP


def test_mcp_arguments_flag_off_empties_arguments(config):
    cfg = replace(config, capture_mcp_arguments=False)
    event = finalized(Pipeline(cfg), _mcp("mcp_tool_call", cfg), "mcp")
    assert event["custom_data"]["arguments"] == {}
    assert event["body"] is None
    assert event["custom_data"]["result_summary"] == "echo: hi mcp"  # results are a separate flag


def test_llm_body_tool_arguments_are_sanitized(config):
    event = finalized(Pipeline(config), _llm("chat_stream_tools", config), "llm")
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
    out = finalized(Pipeline(cfg), event, "llm")
    assert out["headers"] == {"x-cerberus-turn-id": "turn-1"}


def test_long_strings_truncated(config):
    event = _llm("chat", config)
    event["user_agent"] = "u" * 5000
    event["user_id"] = "i" * 5000
    event["custom_data"]["error"] = "e" * 5000
    out = finalized(Pipeline(config), event, "llm")
    assert len(out["user_agent"]) <= 1024 + len("...[TRUNCATED]")
    assert len(out["user_id"]) <= 256 + len("...[TRUNCATED]")
    assert len(out["custom_data"]["error"]) <= 2048 + len("...[TRUNCATED]")


def test_content_values_truncated_at_max_value_chars(config):
    out = finalized(Pipeline(config), _llm("big_completion", config), "llm")
    content = out["body"]["output"]["choices"][0]["message"]["content"]
    assert len(content) == MAX_VALUE_CHARS + len("...[TRUNCATED]")
    assert len(json.dumps(out).encode()) <= config.max_event_bytes


def test_oversize_event_sheds_content_first(config):
    cfg = replace(config, max_event_bytes=4096)
    out = finalized(Pipeline(cfg), _llm("big_prompt", cfg), "llm")
    assert out is not None
    assert out["body"] is None
    assert out["custom_data"]["content_dropped_oversize"] is True
    assert out["custom_data"]["tokens_total"] is not None


def test_dropped_oversize_is_counted(config):
    cfg = replace(config, max_event_bytes=1024)
    pipeline = Pipeline(cfg)
    event = _llm("chat", cfg)
    event["custom_data"]["extra_field"] = ["t" * 2000]  # not content, tags or headers: unsheddable
    assert finalized(pipeline, event, "llm") is None
    assert pipeline.dropped_oversize == 1


def test_oversize_schema_report_sheds_tools_but_keeps_skeleton(config):
    cfg = replace(config, max_event_bytes=2048)
    capture = load_capture("mcp_list_tools")
    event = map_schema_reports(capture["standard_logging_object"], capture["response_obj"], cfg)[0]
    event["custom_data"]["tools"] = [
        {"name": f"t{i}", "description": "d" * 300, "input_schema": {}} for i in range(40)
    ]
    out = finalized(Pipeline(cfg), event, "schema")
    assert out is not None
    assert out["custom_data"]["tools"] == []
    assert out["method"] == "mcp_schema_report"


def test_schema_report_catalogue_is_sanitized(config):
    capture = load_capture("mcp_list_tools")
    event = map_schema_reports(capture["standard_logging_object"], capture["response_obj"], config)[
        0
    ]
    event["custom_data"]["tools"][0]["input_schema"] = {"properties": {"api_key": "example-secret"}}
    out = finalized(Pipeline(config), event, "schema")
    assert out["custom_data"]["tools"][0]["input_schema"]["properties"]["api_key"] == "[REDACTED]"


def test_unserializable_event_is_dropped_and_counted(config):
    pipeline = Pipeline(config)
    event = _llm("chat", config)
    event["custom_data"]["junk"] = object()
    assert finalized(pipeline, event, "llm") is None
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
        # Underscore/hyphen-prefixed secret names.
        ("client_secret=abc ok", "client_secret=[REDACTED] ok"),
        ("refresh_token=abc ok", "refresh_token=[REDACTED] ok"),
        ("AWS_SECRET_ACCESS_KEY=abc ok", "AWS_SECRET_ACCESS_KEY=[REDACTED] ok"),
        ("id_token=abc auth-token=def", "id_token=[REDACTED] auth-token=[REDACTED]"),
        # JSON-style and spaced separators, quoted keys and values.
        ('{"api_key": "abc def", "n": 1}', '{"api_key": "[REDACTED]", "n": 1}'),
        ("{'password':'p w','n':1}", "{'password':'[REDACTED]','n':1}"),
        ("api_key : abc rest", "api_key : [REDACTED] rest"),
        ('"client_secret" = "xyz"', '"client_secret" = "[REDACTED]"'),
        # Basic credentials.
        ("Authorization: Basic dXNlcjpwYXNzd29yZA== end", "Authorization: Basic [REDACTED] end"),
        # Provider key prefixes.
        ("key AIzaSyA1234567890abcdefghijKL end", "key [REDACTED] end"),
        ("slack xoxb-1234567890-abcdef end", "slack [REDACTED] end"),
        ("gh ghp_abcdefghijklmnopqrstuvwx end", "gh [REDACTED] end"),
        ("aws AKIAABCDEFGHIJKLMNOP end", "aws [REDACTED] end"),
        # Userinfo is masked up to the LAST @ before the host.
        ("see https://u:p@ss@host.example/x", "see https://[REDACTED]@host.example/x"),
        ("see https://TOKEN@github.com/o/r", "see https://[REDACTED]@github.com/o/r"),
        # An "sk-" inside a longer word is not a token.
        ("task-12345678 done", "task-12345678 done"),
    ],
)
def test_redact_secrets_masks_patterns_and_keeps_surroundings(text, expected):
    assert redact_secrets(text) == expected


def test_redact_secrets_leaves_plain_messages_alone():
    for text in (
        "mock upstream exploded",
        "rate limit: retry in 20s",
        "a monkey eats bananas",
        "keyboard layout: us",
        "see mail user@example.com for help",
    ):
        assert redact_secrets(text) == text


def test_redact_secrets_is_fast_on_adversarial_input():
    import time

    start = time.perf_counter()
    redact_secrets("a" * 200_000)
    redact_secrets("key=" * 50_000)
    redact_secrets("://" + "@" * 50_000)
    redact_secrets("Basic " + "A" * 200_000)
    assert time.perf_counter() - start < 5


@pytest.mark.parametrize("custom_data", [None, "junk", ["x"]])
def test_finalize_tolerates_junk_custom_data(config, custom_data):
    event = _llm("chat", config)
    event["custom_data"] = custom_data
    out = finalized(Pipeline(config), event, "llm")
    assert out is not None
    assert out["custom_data"] == {"integration": "litellm"}


def test_nan_in_content_and_metadata_is_scrubbed_not_fatal(config):
    event = _llm("chat", config)
    event["custom_data"]["duration_ms"] = float("nan")
    event["custom_data"]["temperature"] = float("inf")
    event["body"]["input"]["tools"] = [{"parameters": {"default": float("-inf")}}]
    pipeline = Pipeline(config)
    out = finalized(pipeline, event, "llm")
    assert out is not None
    assert out["custom_data"]["duration_ms"] is None
    assert out["custom_data"]["temperature"] is None
    assert out["body"]["input"]["tools"][0]["parameters"]["default"] is None
    json.dumps(out, allow_nan=False)  # strict JSON: this is what goes on the wire
    assert pipeline.dropped_unserializable == 0


def test_nan_outside_the_scrubbed_fields_is_dropped_and_counted(config):
    pipeline = Pipeline(config)
    event = _llm("chat", config)
    event["unscrubbed_top_level"] = float("nan")
    assert finalized(pipeline, event, "llm") is None
    assert pipeline.dropped_unserializable == 1


def test_caller_controlled_values_cannot_get_an_event_dropped(config):
    cfg = replace(config, max_event_bytes=16384)
    event = _llm("chat", cfg)
    event["custom_data"]["litellm_end_user_id"] = "u" * 60_000  # the request's ``user`` field
    event["user_id"] = "u" * 60_000
    event["session_id"] = "s" * 60_000
    event["custom_data"]["turn_id"] = "t" * 60_000
    pipeline = Pipeline(cfg)
    out = finalized(pipeline, event, "llm")
    assert out is not None
    assert pipeline.dropped_oversize == 0
    assert len(out["user_id"]) <= 256 + len("...[TRUNCATED]")
    assert len(out["session_id"]) <= 256 + len("...[TRUNCATED]")
    assert len(out["custom_data"]["litellm_end_user_id"]) <= 256 + len("...[TRUNCATED]")


def test_finalize_returns_the_event_with_its_encoded_size(config):
    result = Pipeline(config).finalize(_llm("chat", config), "llm")
    event, size = result
    assert size == len(json.dumps(event).encode())
    # Also for an event that had to be shed to fit.
    cfg = replace(config, max_event_bytes=2500)
    shed, shed_size = Pipeline(cfg).finalize(_llm("big_prompt", cfg), "llm")
    assert shed["body"] is None
    assert shed_size == len(json.dumps(shed).encode()) <= 2500


def test_a_late_serialisation_failure_counts_as_unserializable(config, monkeypatch):
    from cerberus_litellm import pipeline as pipeline_module

    real = pipeline_module._encoded_size
    calls = []

    def flaky(event):
        calls.append(1)
        if len(calls) >= 2:  # fine on the first measurement, fails on the next
            raise ValueError("late failure")
        return real(event)

    monkeypatch.setattr(pipeline_module, "_encoded_size", flaky)
    cfg = replace(config, max_event_bytes=2500)  # forces the shedding path
    pipeline = Pipeline(cfg)
    assert pipeline.finalize(_llm("big_prompt", cfg), "llm") is None
    assert pipeline.dropped_unserializable == 1
    assert pipeline.dropped_oversize == 0


def test_many_tags_are_shed_before_the_event_is_dropped(config):
    cfg = replace(config, max_event_bytes=6000)
    event = _llm("chat", cfg)
    event["custom_data"]["request_tags"] = [f"tag-{i}-" + "x" * 400 for i in range(1000)]
    event["headers"] = {"x-tenant": "h" * 8000}
    out = finalized(Pipeline(cfg), event, "llm")
    assert out is not None
    assert out["custom_data"]["request_tags"] == []
    assert out["headers"] is None
    assert out["custom_data"]["content_dropped_oversize"] is True
    assert out["custom_data"]["metadata_dropped_oversize"] is True


def test_oversize_warnings_are_throttled(config, caplog):
    import logging

    caplog.set_level(logging.WARNING, logger="cerberus_litellm.pipeline")
    cfg = replace(config, max_event_bytes=1024)
    pipeline = Pipeline(cfg)
    for _ in range(5):
        event = _llm("chat", cfg)
        event["custom_data"]["extra_field"] = ["t" * 2000]
        assert finalized(pipeline, event, "llm") is None
    assert pipeline.dropped_oversize == 5
    assert len([r for r in caplog.records if "oversized" in r.getMessage()]) == 1


@pytest.mark.parametrize(
    "secret,fragment",
    [
        ("sk-abcdef0123456789", "sk-abc"),
        ("Bearer abcdef0123456789", "Bearer a"),
        ("api_key=abcdef0123456789", "api_key=a"),
        ("AKIAABCDEFGHIJKLMNOP", "AKIAA"),
    ],
)
def test_credential_straddling_the_result_cut_leaves_no_prefix(config, secret, fragment):
    import copy

    limit = 256
    cfg = replace(config, mcp_result_max_chars=limit)
    # The cut lands inside the credential, leaving at least the fragment visible.
    for pad in (limit - len(fragment) - 1, limit - len(fragment) - 2):
        slo = copy.deepcopy(load_capture("mcp_tool_call")["standard_logging_object"])
        slo["response"]["content"] = [{"type": "text", "text": "x" * pad + " " + secret}]
        out = finalized(Pipeline(cfg), map_mcp_event(slo, cfg), "mcp")
        summary = out["custom_data"]["result_summary"]
        assert fragment not in summary, (pad, summary[-30:])
        assert secret not in json.dumps(out)


def test_credential_straddling_the_error_cut_leaves_no_prefix(config):
    import copy

    cfg = replace(config, mcp_result_max_chars=256)
    slo = copy.deepcopy(load_capture("mcp_tool_call_error")["standard_logging_object"])
    slo["error_information"]["error_message"] = "x" * 249 + " sk-abcdef0123456789"
    out = finalized(Pipeline(cfg), map_mcp_event(slo, cfg), "mcp")
    assert "sk-abc" not in out["custom_data"]["error"]
    assert "sk-abc" not in out["custom_data"]["result_summary"]


def test_finalize_redacts_error_and_result_summary(config):
    event = _llm("chat", config)
    event["custom_data"]["error"] = "failed at https://h.example/v1?key=SECRET1 sk-abcdef123456"
    out = finalized(Pipeline(config), event, "llm")
    assert "SECRET1" not in json.dumps(out)
    assert "sk-abcdef123456" not in json.dumps(out)
    assert out["custom_data"]["error"].startswith("failed at https://h.example/v1?key=[REDACTED]")

    mcp = _mcp("mcp_tool_call", config)
    mcp["custom_data"]["result_summary"] = "token=abc123 Bearer zzz.yyy"
    out = finalized(Pipeline(config), mcp, "mcp")
    assert out["custom_data"]["result_summary"] == "token=[REDACTED] Bearer [REDACTED]"
