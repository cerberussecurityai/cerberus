import json
from dataclasses import replace

from helpers import HEALTH_SEGMENTS, load_capture, load_expected

from cerberus_litellm.mapper_llm import llm_method, map_llm_event


def _map(name: str, config, headers=None):
    return map_llm_event(load_capture(name)["standard_logging_object"], config, headers)


def test_chat_golden(config):
    assert _map("chat", config) == load_expected("llm_chat")


def test_method_table():
    assert llm_method("acompletion") == "llm_chat_completion"
    assert llm_method("completion") == "llm_chat_completion"
    assert llm_method("anthropic_messages") == "llm_messages"
    assert llm_method("aembedding") == "llm_embeddings"
    assert llm_method("atext_completion") == "llm_completion"
    assert llm_method("aresponses") == "llm_responses"
    assert llm_method("something_new") == "llm_call"
    for call_type in ("acompletion", "anthropic_messages", "aresponses", "weird"):
        assert not llm_method(call_type).startswith("mcp_")


def test_streamed_tool_call_arguments_are_assembled(config):
    event = _map("chat_stream_tools", config)
    assert event["custom_data"]["streaming"] is True
    tool_calls = event["body"]["output"]["choices"][0]["message"]["tool_calls"]
    assert tool_calls[0]["function"]["name"] == "get_weather"
    args = json.loads(tool_calls[0]["function"]["arguments"])
    assert args["city"] == "Reykjavik"
    assert event["body"]["input"]["tools"][0]["function"]["name"] == "get_weather"
    assert event["custom_data"]["ttft_ms"] is not None


def test_anthropic_messages_route(config):
    event = _map("messages_stream_tools", config)
    assert event["method"] == "llm_messages"
    assert event["custom_data"]["event_type"] == "messages"
    assert event["custom_data"]["route_path"] == "/v1/messages"
    message = event["body"]["output"]["choices"][0]["message"]
    assert message["tool_calls"][0]["function"]["name"] == "get_weather"


def test_responses_route(config):
    event = _map("responses", config)
    assert event["method"] == "llm_responses"
    assert event["body"]["output"]["output"][0]["type"] == "message"
    assert event["body"]["input"]["messages"][0]["role"] == "user"


def test_embeddings_output_has_no_vectors(config):
    event = _map("embeddings", config)
    assert event["method"] == "llm_embeddings"
    assert event["endpoint"] == "llm://openai/mock-embed"
    assert event["body"]["output"] is None
    # No vector data anywhere in the body (the method name itself contains
    # "embedding", so check the body, not the whole event).
    assert '"data"' not in json.dumps(event["body"]) and "0.1" not in json.dumps(event["body"])
    assert event["custom_data"]["tokens_prompt"] == 8


def test_failure_keeps_input_and_identity(config):
    event = _map("failure_500", config)
    assert event["custom_data"]["status"] == "error"
    assert event["custom_data"]["error_class"] == "InternalServerError"
    assert event["custom_data"]["error_code"] == "mock_500"
    assert "mock upstream exploded" in event["custom_data"]["error"]
    assert event["custom_data"]["llm_api_status"] == "failure"
    assert event["body"]["input"]["messages"][0]["content"] == "boom"
    assert event["body"]["output"] is None
    assert event["custom_data"]["litellm_key_alias"] == "spike-key"
    assert event["endpoint"] == "llm://openai/mock-error"


def test_rate_limit_failure(config):
    event = _map("failure_429", config)
    assert event["custom_data"]["error_class"] == "RateLimitError"
    # LiteLLM normalises a 429's error_code to the status string, not the
    # provider's own code (the 500 keeps "mock_500"); the fixture says "429".
    assert event["custom_data"]["error_code"] == "429"


def test_content_flag_off_drops_body(config):
    event = _map("chat", replace(config, capture_llm_content=False))
    assert event["body"] is None
    assert event["custom_data"]["tokens_total"] == 23  # metadata unaffected


def test_trace_id_from_traceparent_header(config):
    headers = {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
    traced = _map("chat", config, headers)
    assert traced["custom_data"]["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert _map("chat", config, {"traceparent": "junk"})["custom_data"]["trace_id"] is None


def test_captured_headers_allowlist(config):
    cfg = replace(config, capture_headers=("x-cerberus-turn-id",))
    event = _map("chat", cfg)
    assert event["headers"] == {"x-cerberus-turn-id": "turn-1"}
    assert "x-custom-secret" not in json.dumps(event)  # not allowlisted → never forwarded


def test_user_id_source_is_configurable(config):
    assert _map("chat", replace(config, user_id_source=("key_alias",)))["user_id"] == "spike-key"


def test_endpoint_never_matches_health_filter(config):
    for name in ("chat", "embeddings", "responses", "failure_500"):
        endpoint = _map(name, config)["endpoint"]
        assert endpoint.rstrip("/").rsplit("/", 1)[-1].lower() not in HEALTH_SEGMENTS


def test_big_payload_is_not_truncated_by_mapper(config):
    # Truncation and caps are the pipeline's job; the mapper is lossless.
    event = _map("big_completion", config)
    assert len(event["body"]["output"]["choices"][0]["message"]["content"]) == 48000


def test_mapper_never_raises_on_junk(config):
    for junk in ({}, {"call_type": 7}, {"messages": None, "response": "text", "metadata": []}):
        event = map_llm_event(junk, config)
        assert event["scheme"] == "llm"
        assert event["endpoint"] == "llm://unknown/unknown"
        assert event["custom_data"]["integration"] == "litellm"
