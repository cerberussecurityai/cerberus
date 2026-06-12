import json
import re
from dataclasses import replace

from cerberus_core import REDACTED
from helpers import load_export

from cerberus_envoy_ai_gateway.pipeline import Pipeline, truncate_values
from cerberus_envoy_ai_gateway.queue import BoundedQueue

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _run(name: str, config, secret_key=None, capacity=100):
    queue = BoundedQueue(capacity)
    pipeline = Pipeline(config, queue, secret_key)
    queued = pipeline.process_export(load_export(name))
    return pipeline, queue, queued


def test_remote_addr_hashed_with_secret(config):
    _, queue, queued = _run("llm_openai_chat", config, secret_key="test-secret")
    assert queued == 1
    [event] = queue.drain(10)
    assert HEX64.match(event["remote_addr"])


def test_remote_addr_normalized_without_secret(config):
    _, queue, _ = _run("llm_anthropic_messages", config)
    [event] = queue.drain(10)
    # IPv6 zone id stripped by normalize_ip; no hashing without a secret.
    assert event["remote_addr"] == "2001:db8::1"


def test_missing_remote_addr_becomes_unknown(config):
    _, queue, _ = _run("llm_error", config)
    [event] = queue.drain(10)
    assert event["remote_addr"] == "unknown"


def test_same_ip_same_hash(config):
    _, queue_a, _ = _run("llm_openai_chat", config, secret_key="k")
    _, queue_b, _ = _run("llm_openai_chat", config, secret_key="k")
    assert queue_a.drain(1)[0]["remote_addr"] == queue_b.drain(1)[0]["remote_addr"]


def test_mcp_arguments_sanitized(config):
    _, queue, _ = _run("mcp_tool_call", config)
    [event] = queue.drain(10)
    arguments = event["custom_data"]["arguments"]
    assert arguments["location"] == "SF"
    assert arguments["api_key"] == REDACTED
    assert event["body"] == arguments


def test_mcp_arguments_flag_off(config):
    config = replace(config, capture_mcp_arguments=False)
    _, queue, _ = _run("mcp_tool_call", config)
    [event] = queue.drain(10)
    assert event["custom_data"]["arguments"] == {}
    assert event["body"] is None


def test_llm_content_sanitized_when_captured(config):
    config = replace(config, capture_llm_content=True)
    _, queue, _ = _run("llm_openai_chat", config)
    [event] = queue.drain(10)
    assert event["body"]["input"]["api_key"] == REDACTED
    assert event["body"]["input"]["messages"][0]["content"] == "hello"


def test_llm_content_flag_off_no_body(config):
    _, queue, _ = _run("llm_openai_chat", config)
    [event] = queue.drain(10)
    assert event["body"] is None


def test_ignored_spans_counted(config):
    pipeline, queue, queued = _run("mcp_initialize", config)
    assert queued == 0
    assert len(queue) == 0
    assert pipeline.spans_ignored == 1


def test_queue_full_drops_and_counts(config):
    queue = BoundedQueue(0)  # immediately full
    pipeline = Pipeline(config, queue, None)
    pipeline.process_export(load_export("llm_openai_chat"))
    assert queue.dropped_full == 1


def test_oversize_event_sheds_content_first(config):
    config = replace(config, capture_mcp_arguments=True, max_event_bytes=1024)
    queue = BoundedQueue(10)
    pipeline = Pipeline(config, queue, None)
    request = load_export("mcp_tool_call")
    span = request.resource_spans[0].scope_spans[0].spans[0]
    for kv in span.attributes:
        if kv.key == "mcp.tool.arguments":
            kv.value.string_value = json.dumps({"blob": "x" * 4000})
    pipeline.process_export(request)
    [event] = queue.drain(10)
    assert event["custom_data"]["arguments"] == {}
    assert event["body"] is None
    assert event["custom_data"]["content_dropped_oversize"] is True
    assert pipeline.dropped_oversize == 0


def test_event_serialized_size_within_cap(config):
    config = replace(config, capture_llm_content=True)
    _, queue, _ = _run("llm_openai_chat", config)
    [event] = queue.drain(10)
    assert len(json.dumps(event).encode()) <= config.max_event_bytes


def test_truncate_values():
    data = {"long": "a" * 10000, "nested": [{"also_long": "b" * 9000}], "n": 5}
    result = truncate_values(data, limit=8192)
    assert result["long"].endswith("...[TRUNCATED]")
    assert len(result["long"]) == 8192 + len("...[TRUNCATED]")
    assert result["nested"][0]["also_long"].endswith("...[TRUNCATED]")
    assert result["n"] == 5


def test_oversized_header_fields_truncated_not_dropped(config):
    # A client-controlled header (user-agent / x-user-id) larger than the
    # event cap must not let that client suppress its own events.
    queue = BoundedQueue(10)
    pipeline = Pipeline(config, queue, None)
    request = load_export("llm_openai_chat")
    span = request.resource_spans[0].scope_spans[0].spans[0]
    for kv in span.attributes:
        if kv.key == "http.user_agent":
            kv.value.string_value = "A" * 70000
        if kv.key == "user.id":
            kv.value.string_value = "u" * 5000
    pipeline.process_export(request)
    [event] = queue.drain(10)
    assert len(event["user_agent"]) <= 1024 + len("...[TRUNCATED]")
    assert len(event["user_id"]) <= 256 + len("...[TRUNCATED]")
    assert pipeline.dropped_oversize == 0
