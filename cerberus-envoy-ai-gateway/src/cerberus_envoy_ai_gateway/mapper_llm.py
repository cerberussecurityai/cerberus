"""Map an LLM span from the Envoy AI Gateway extproc to a Cerberus event.

Attribute names verified against the ai-gateway v0.7.0 source:
- OpenAI path (internal/tracing/openinference/openai/{request,response}_attrs.go):
  OpenInference keys — ``llm.model_name``, ``llm.system``, ``input.value`` /
  ``output.value``, ``llm.token_count.*``, ``llm.invocation_parameters``.
- Anthropic path (internal/tracing/openinference/anthropic/messages.go):
  ``llm.model``, ``llm.system``, ``gen_ai.input.value``.
OTel GenAI ``gen_ai.*`` names are probed as fallbacks for forward
compatibility (the project's metrics already use them).

The mapper extracts raw values only — PII hashing, content sanitization,
and size caps happen in pipeline.py.
"""

from typing import Any

from opentelemetry.proto.trace.v1.trace_pb2 import Span

from . import __version__
from .config import Config
from .spanfields import (
    duration_ms,
    error_message,
    first_attr,
    iso_timestamp,
    parse_json_value,
    raw_client_ip,
    span_user_agent,
    span_user_id,
)

_PROVIDER_KEYS = ("llm.system", "gen_ai.provider.name", "gen_ai.system")
_MODEL_KEYS = ("llm.model_name", "embedding.model_name", "llm.model", "gen_ai.request.model")
_RESPONSE_MODEL_KEYS = ("gen_ai.response.model",)
_INPUT_KEYS = ("input.value", "gen_ai.input.value", "gen_ai.request.input")
_OUTPUT_KEYS = ("output.value", "gen_ai.output.value")
_ROUTE_KEYS = ("http.route", "url.path", "http.target")

# gen_ai.operation.name (or span name) → Cerberus event method. The values
# must never start with "mcp_" — event_process routes on that prefix.
_OPERATION_METHODS = {
    "chat": "llm_chat_completion",
    "chat_completions": "llm_chat_completion",
    "completion": "llm_completion",
    "text_completion": "llm_completion",
    "embedding": "llm_embeddings",
    "embeddings": "llm_embeddings",
    "messages": "llm_messages",
}

_TOKEN_FIELDS = {
    # custom_data key → candidate attribute keys, first hit wins
    "tokens_prompt": ("llm.token_count.prompt", "gen_ai.usage.input_tokens"),
    "tokens_completion": ("llm.token_count.completion", "gen_ai.usage.output_tokens"),
    "tokens_total": ("llm.token_count.total", "gen_ai.usage.total_tokens"),
    "tokens_cache_hit": (
        "llm.token_count.prompt_details.cache_read",
        "llm.token_count.prompt_cache_hit",
    ),
    "tokens_reasoning": (
        "llm.token_count.completion_details.reasoning",
        "llm.token_count.completion.reasoning",
        "llm.token_count.completion_reasoning",
    ),
}


def _method(span: Span, attrs: dict[str, Any]) -> str:
    operation = str(attrs.get("gen_ai.operation.name") or span.name or "").strip().lower()
    if operation in _OPERATION_METHODS:
        return _OPERATION_METHODS[operation]
    compact = operation.replace(" ", "").replace("_", "").replace("-", "")
    if "chatcompletion" in compact or compact == "chat":
        return "llm_chat_completion"
    if "embedding" in compact:
        return "llm_embeddings"
    if "message" in compact:
        return "llm_messages"
    if "completion" in compact:
        return "llm_completion"
    return "llm_call"


def _token_counts(attrs: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for field, candidates in _TOKEN_FIELDS.items():
        value = first_attr(attrs, candidates)
        if isinstance(value, (int, float)):
            counts[field] = int(value)
    return counts


def _invocation_params(attrs: dict[str, Any]) -> dict[str, Any]:
    # Embeddings spans use embedding.invocation_parameters; chat/messages use
    # llm.invocation_parameters (ai-gateway v0.7 openinference).
    raw = attrs.get("llm.invocation_parameters") or attrs.get("embedding.invocation_parameters")
    params = parse_json_value(raw)
    return params if isinstance(params, dict) else {}


def map_llm_span(span: Span, attrs: dict[str, Any], config: Config) -> dict[str, Any]:
    """Build a raw (pre-sanitization) CoreData-shaped event dict."""
    params = _invocation_params(attrs)
    provider = str(first_attr(attrs, _PROVIDER_KEYS) or "unknown")
    # Embeddings spans omit llm.model_name/llm.system; the model is only in
    # llm.invocation_parameters, so fall back to it before "unknown".
    model = str(first_attr(attrs, _MODEL_KEYS) or params.get("model") or "unknown")
    error = error_message(span, attrs)
    method = _method(span, attrs)

    custom_data: dict[str, Any] = {
        "integration": "envoy-ai-gateway",
        # Short-form operation, mirroring mapper_mcp's custom_data event_type
        # (tool_call / resource_read): the namespaced form is the top-level
        # `method` (llm_chat_completion); strip the llm_ prefix here. Was
        # previously hardcoded "llm_call" regardless of the actual operation.
        "event_type": method.removeprefix("llm_"),
        "provider": provider,
        "model": model,
        "response_model": first_attr(attrs, _RESPONSE_MODEL_KEYS),
        "duration_ms": duration_ms(span),
        "status": "error" if error else "ok",
        "error": error,
        "streaming": params["stream"] if isinstance(params.get("stream"), bool) else None,
        "trace_id": span.trace_id.hex(),
        "span_id": span.span_id.hex(),
    }
    custom_data.update(_token_counts(attrs))
    for param in ("temperature", "top_p", "max_tokens"):
        value = attrs.get(f"gen_ai.request.{param}")
        if value is None:
            value = params.get(param)
        if isinstance(value, (int, float)):
            custom_data[param] = value
    route_path = first_attr(attrs, _ROUTE_KEYS)
    if route_path:
        custom_data["route_path"] = route_path

    body: dict[str, Any] | None = None
    if config.capture_llm_content:
        content = {
            "input": parse_json_value(first_attr(attrs, _INPUT_KEYS)),
            "output": parse_json_value(first_attr(attrs, _OUTPUT_KEYS)),
        }
        if content["input"] is not None or content["output"] is not None:
            body = content

    return {
        # Backend expects 'remote_addr' (same rename cerberus-django /
        # cerberus-mcp / flex-gateway apply at the wire boundary).
        "remote_addr": raw_client_ip(attrs, config.client_ip_attribute),
        "endpoint": f"llm://{provider}/{model}",
        "scheme": "llm",
        "method": method,
        "timestamp": iso_timestamp(span),
        "custom_data": custom_data,
        "headers": None,
        "query_params": None,
        "body": body,
        "user_agent": span_user_agent(
            attrs, config.user_agent_attribute, f"cerberus-envoy-ai-gateway/{__version__}"
        ),
        "user_id": span_user_id(attrs, config.user_id_attribute),
    }
