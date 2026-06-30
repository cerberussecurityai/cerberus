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
    # capture_llm_content defaults to False — recorded content must not
    # appear in the event body.
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
    event = _map("llm_openai_chat", config)
    assert event["body"] is None
    # Metadata is unaffected by the content flag.
    assert event["custom_data"]["tokens_total"] == 170


def test_endpoint_never_matches_health_filter(config):
    # event_ingest drops events whose endpoint's last path segment looks like
    # a health check; llm:// endpoints end in the model name.
    event = _map("llm_openai_chat", config)
    assert event["endpoint"].rsplit("/", 1)[-1] == "gpt-4o-mini"


def test_embedding_span_classified_and_model_from_invocation_params(config):
    # OpenAI embeddings spans use span-kind EMBEDDING and omit llm.model_name;
    # the model lives only in llm.invocation_parameters. classify() must route
    # them to the LLM path and the mapper must recover the model from params.
    from opentelemetry.proto.trace.v1.trace_pb2 import Span

    from cerberus_envoy_ai_gateway.classify import KIND_LLM, classify

    attrs = {
        "openinference.span.kind": "EMBEDDING",
        "llm.invocation_parameters": '{"model": "text-embedding-3-small"}',
    }
    assert classify(attrs) == KIND_LLM
    event = map_llm_span(Span(name="Embeddings"), attrs, config)
    assert event["method"] == "llm_embeddings"
    assert event["custom_data"]["model"] == "text-embedding-3-small"
    assert event["endpoint"] == "llm://unknown/text-embedding-3-small"
