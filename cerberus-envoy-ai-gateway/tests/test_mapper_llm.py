from dataclasses import replace

from helpers import load_expected, load_export, single_span

from cerberus_envoy_ai_gateway.mapper_llm import map_llm_span
from cerberus_envoy_ai_gateway.otlp import span_attributes


def _map(name: str, config):
    span = single_span(load_export(name))
    return map_llm_span(span, span_attributes(span), config)


def test_openai_chat_golden(config):
    config = replace(config, capture_llm_content=True)
    assert _map("llm_openai_chat", config) == load_expected("llm_openai_chat")


def test_anthropic_messages_golden(config):
    # capture_llm_content=False: recorded content must not appear in the body.
    config = replace(config, capture_llm_content=False)
    assert _map("llm_anthropic_messages", config) == load_expected("llm_anthropic_messages")


def test_error_span(config):
    event = _map("llm_error", config)
    assert event["custom_data"]["status"] == "error"
    assert event["custom_data"]["error"] == "upstream returned 429"
    assert event["custom_data"]["duration_ms"] == 100.0
    assert event["method"] == "llm_chat_completion"
    # No client-ip attribute on this span — pipeline maps None to "unknown".
    assert event["remote_addr"] is None


def test_content_flag_off_drops_body(config):
    config = replace(config, capture_llm_content=False)
    event = _map("llm_openai_chat", config)
    assert event["body"] is None
    # Metadata is unaffected by the content flag.
    assert event["custom_data"]["tokens_total"] == 170


def test_endpoint_never_matches_health_filter(config):
    # event_ingest drops events whose endpoint's last path segment looks like
    # a health check; llm:// endpoints end in the model name.
    event = _map("llm_openai_chat", config)
    assert event["endpoint"].rsplit("/", 1)[-1] == "gpt-4o-mini"


def test_embedding_span_classified_and_model_from_embedding_attrs(config):
    # OpenAI embeddings: span-kind EMBEDDING, model in embedding.model_name
    # (ai-gateway v0.7), not llm.model_name. classify() must route them to the
    # LLM path and the mapper must read the embedding model.
    from opentelemetry.proto.trace.v1.trace_pb2 import Span

    from cerberus_envoy_ai_gateway.classify import KIND_LLM, classify

    attrs = {
        "openinference.span.kind": "EMBEDDING",
        "embedding.model_name": "text-embedding-3-small",
    }
    assert classify(attrs) == KIND_LLM
    event = map_llm_span(Span(name="Embeddings"), attrs, config)
    assert event["method"] == "llm_embeddings"
    assert event["custom_data"]["model"] == "text-embedding-3-small"
    # provider inferred from the embedding model name (the gateway omits it)
    assert event["custom_data"]["provider"] == "openai"
    assert event["endpoint"] == "llm://openai/text-embedding-3-small"


def test_embedding_model_falls_back_to_invocation_parameters(config):
    from opentelemetry.proto.trace.v1.trace_pb2 import Span

    attrs = {
        "openinference.span.kind": "EMBEDDING",
        "embedding.invocation_parameters": '{"model": "text-embedding-3-large"}',
    }
    event = map_llm_span(Span(name="Embeddings"), attrs, config)
    assert event["custom_data"]["model"] == "text-embedding-3-large"


def test_embedding_provider_inferred_else_unknown(config):
    from opentelemetry.proto.trace.v1.trace_pb2 import Span

    def provider(model: str) -> str:
        attrs = {"openinference.span.kind": "EMBEDDING", "embedding.model_name": model}
        return map_llm_span(Span(name="Embeddings"), attrs, config)["custom_data"]["provider"]

    assert provider("text-embedding-3-large") == "openai"
    assert provider("embed-english-v3.0") == "cohere"
    assert provider("voyage-2") == "voyage"
    assert provider("some-unknown-model") == "unknown"


def test_chat_output_reconstructs_tool_calls(config):
    # v0.7 chat completions set no output.value; tool-call outputs live in
    # flattened llm.output_messages.*.tool_calls.* — capture them, not just text.
    from opentelemetry.proto.trace.v1.trace_pb2 import Span

    config = replace(config, capture_llm_content=True)
    attrs = {
        "llm.model_name": "gpt-4o",
        "input.value": '{"messages": []}',
        "llm.output_messages.0.message.role": "assistant",
        "llm.output_messages.0.message.tool_calls.0.tool_call.function.name": "get_weather",
        "llm.output_messages.0.message.tool_calls.0.tool_call.function.arguments": '{"q": 1}',
    }
    event = map_llm_span(Span(name="ChatCompletion"), attrs, config)
    [msg] = event["body"]["output"]
    assert msg["role"] == "assistant"
    assert msg["tool_calls"] == [{"name": "get_weather", "arguments": {"q": 1}}]


def test_v07_cache_and_reasoning_token_keys(config):
    # ai-gateway v0.7 uses prompt_details.cache_read / completion_details.reasoning.
    from opentelemetry.proto.trace.v1.trace_pb2 import Span

    attrs = {
        "llm.model_name": "gpt-4o",
        "llm.token_count.prompt_details.cache_read": 12,
        "llm.token_count.completion_details.reasoning": 34,
    }
    event = map_llm_span(Span(name="ChatCompletion"), attrs, config)
    assert event["custom_data"]["tokens_cache_hit"] == 12
    assert event["custom_data"]["tokens_reasoning"] == 34


def test_streaming_flag_coerces_non_bool_values(config):
    from opentelemetry.proto.trace.v1.trace_pb2 import Span

    def streaming(stream_json: str):
        attrs = {"llm.model_name": "gpt-4o", "llm.invocation_parameters": stream_json}
        return map_llm_span(Span(name="ChatCompletion"), attrs, config)["custom_data"]["streaming"]

    assert streaming('{"stream": true}') is True
    assert streaming('{"stream": 1}') is True
    assert streaming('{"stream": "false"}') is False
    assert streaming("{}") is None


def test_overlong_model_is_capped(config):
    # An overlong model name feeds the endpoint, which _enforce_size can't shed;
    # cap it at the mapper so it can't push the event over the byte cap.
    from opentelemetry.proto.trace.v1.trace_pb2 import Span

    from cerberus_envoy_ai_gateway.spanfields import MAX_LABEL_CHARS

    attrs = {"llm.model_name": "m" * 5000, "llm.system": "openai"}
    event = map_llm_span(Span(name="ChatCompletion"), attrs, config)
    assert len(event["custom_data"]["model"]) == MAX_LABEL_CHARS
    assert len(event["endpoint"]) < 400
