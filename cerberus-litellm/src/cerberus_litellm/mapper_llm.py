"""Map a LiteLLM LLM-call logging payload to a Cerberus event.

The mapper extracts raw values only — sanitization, truncation and size caps
happen in pipeline.py. Field names were verified against LiteLLM v1.105.1
captures; the accessors in payload.py tolerate their absence.
"""

import math
import re
from collections.abc import Mapping
from typing import Any

from . import __version__, payload
from .config import Config

MAX_LABEL_CHARS = 256

# LiteLLM call_type → Cerberus event method. Values must never start with
# "mcp_" — the backend routes on that prefix.
_CALL_TYPE_METHODS = {
    "completion": "llm_chat_completion",
    "acompletion": "llm_chat_completion",
    "anthropic_messages": "llm_messages",
    "embedding": "llm_embeddings",
    "aembedding": "llm_embeddings",
    "text_completion": "llm_completion",
    "atext_completion": "llm_completion",
    "responses": "llm_responses",
    "aresponses": "llm_responses",
}

# Last-path-segment names the ingest API treats as health probes and silently
# drops. Mirrors the ingest filter; keep in sync.
HEALTH_SEGMENTS = frozenset(
    {
        "health",
        "healthz",
        "healthcheck",
        "health_check",
        "health-check",
        "ready",
        "readyz",
        "readiness",
        "live",
        "livez",
        "liveness",
    }
)
_REQUEST_PARAMS = ("temperature", "top_p", "max_tokens", "max_output_tokens")


def llm_method(call_type: str) -> str:
    return _CALL_TYPE_METHODS.get(call_type.strip().lower(), "llm_call")


_WHITESPACE = re.compile(r"\s+")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def clean_label(value: str) -> str:
    """Trim, collapse internal whitespace to ``_`` and drop control characters.

    Labels come from client-influenced fields (wildcard model routing, tool
    names) and end up in endpoint strings and log lines.
    """
    return _CONTROL_CHARS.sub("", _WHITESPACE.sub("_", value.strip()))


def endpoint_segment(label: str, suffix: str = "_model") -> str:
    """Make an endpoint label safe from the ingest health filter.

    The label can be client-influenced (wildcard model routing), so a name
    like ``anything/health`` would make its events vanish. The ingest takes
    ``endpoint.rstrip("/").rsplit("/", 1)[-1].lower()``, so normalise the same
    way: strip whitespace and trailing slashes (``health/`` is dropped there),
    and guard every ``/``-separated piece, appending ``suffix`` to health names.
    An empty label becomes ``unknown`` so the provider can never be the last
    segment. The ingest filter does not parse ``?`` or ``#``, so ``health?x``
    is not a health name and passes unchanged.
    """
    core = clean_label(label).rstrip("/")
    if not core:
        return "unknown"
    return "/".join(
        piece + suffix if piece.lower() in HEALTH_SEGMENTS else piece for piece in core.split("/")
    )


def _label(value: Any, fallback: str = "unknown") -> str:
    if isinstance(value, str):
        cleaned = clean_label(value)[:MAX_LABEL_CHARS]
        if cleaned:
            return cleaned
    return fallback


def _model_label(slo: Mapping[str, Any], provider: str) -> str:
    """Public model name: the model_group alias when the proxy has one, else
    the deployment model with its ``provider/`` prefix stripped."""
    group = payload.get(slo, "model_group")
    if isinstance(group, str) and group.strip():
        return _label(group)
    model = payload.get(slo, "model")
    if isinstance(model, str) and model.startswith(provider + "/"):
        model = model[len(provider) + 1 :]
    return _label(model)


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _str_field(slo: Mapping[str, Any], *path: str) -> str | None:
    value = payload.get(slo, *path)
    return value if isinstance(value, str) else None


def _output_for_body(slo: Mapping[str, Any], method: str) -> Any:
    """The response as content. Embedding vectors are numbers, not content,
    and would blow the event cap, so embeddings ship no output."""
    if method == "llm_embeddings":
        return None
    response = payload.get(slo, "response")
    return response if isinstance(response, Mapping) and response else None


def _input_for_body(slo: Mapping[str, Any]) -> dict[str, Any] | None:
    messages = payload.get(slo, "messages")
    tools = payload.get(slo, "model_parameters", "tools")
    body_in: dict[str, Any] = {}
    if isinstance(messages, list):
        body_in["messages"] = messages
    elif isinstance(messages, str):
        body_in["messages"] = [{"role": "user", "content": messages}]
    if isinstance(tools, list):
        body_in["tools"] = tools
    return body_in or None


def _captured_headers(slo: Mapping[str, Any], config: Config) -> dict[str, str] | None:
    if not config.capture_headers:
        return None
    present = payload.custom_headers(slo)
    picked = {name: present[name] for name in config.capture_headers if name in present}
    return picked or None


def map_llm_event(
    slo: Mapping[str, Any],
    config: Config,
    request_headers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build a raw (pre-sanitization) CoreData-shaped event dict."""
    if not isinstance(slo, Mapping):
        slo = {}
    call_type = payload.call_type(slo)
    method = llm_method(call_type)
    provider = _label(payload.get(slo, "custom_llm_provider"))
    model = _model_label(slo, provider)
    status = payload.status(slo)
    errors = payload.error_info(slo)
    params = payload.get(slo, "model_parameters")
    params = params if isinstance(params, Mapping) else {}
    cost = payload.get(slo, "cost_breakdown")
    cost = cost if isinstance(cost, Mapping) else {}
    status_fields = payload.get(slo, "status_fields")
    status_fields = status_fields if isinstance(status_fields, Mapping) else {}
    response_model = payload.get(slo, "response", "model")
    guardrails = payload.get(slo, "metadata", "applied_guardrails")
    request_tags = payload.get(slo, "request_tags")
    traceparent = (request_headers or {}).get("traceparent") if request_headers else None

    custom_data: dict[str, Any] = {
        "integration": "litellm",
        "event_type": method.removeprefix("llm_"),
        "provider": provider,
        "model": model,
        "litellm_model": _str_field(slo, "model"),
        "model_group": _str_field(slo, "model_group"),
        "model_id": _str_field(slo, "model_id"),
        "response_model": response_model if isinstance(response_model, str) else None,
        "api_base_host": payload.host_only(payload.get(slo, "api_base")),
        "duration_ms": payload.duration_ms(slo),
        "ttft_ms": payload.ttft_ms(slo),
        "status": status,
        "error": errors["error_message"],
        "error_class": errors["error_class"],
        "error_code": errors["error_code"],
        "error_normalized": errors["error_normalized"],
        "llm_api_status": status_fields.get("llm_api_status"),
        "guardrail_status": status_fields.get("guardrail_status"),
        "guardrails_applied": guardrails if isinstance(guardrails, list) else [],
        "streaming": bool(payload.get(slo, "stream")),
        "cache_hit": payload.get(slo, "cache_hit"),
        "cost_usd": _number(payload.get(slo, "response_cost")),
        "cost_input_usd": _number(cost.get("input_cost")),
        "cost_output_usd": _number(cost.get("output_cost")),
        "tokens_prompt": _number(payload.get(slo, "prompt_tokens")),
        "tokens_completion": _number(payload.get(slo, "completion_tokens")),
        "tokens_total": _number(payload.get(slo, "total_tokens")),
        "route_path": payload.get(slo, "metadata", "user_api_key_request_route"),
        "trace_id": payload.w3c_trace_id(traceparent),
        "litellm_trace_id": _str_field(slo, "trace_id"),
        "litellm_call_id": _str_field(slo, "litellm_call_id"),
        "request_tags": request_tags if isinstance(request_tags, list) else [],
        "turn_id": payload.turn_id(slo, config.turn_header),
    }
    for param in _REQUEST_PARAMS:
        value = _number(params.get(param))
        if value is not None:
            custom_data[param] = value
    custom_data.update(payload.identity(slo))

    body: dict[str, Any] | None = None
    if config.capture_llm_content:
        body_in = _input_for_body(slo)
        body_out = _output_for_body(slo, method)
        if body_in is not None or body_out is not None:
            body = {"input": body_in, "output": body_out}

    user_agent = payload.get(slo, "user_agent")
    return {
        "remote_addr": payload.get(slo, "requester_ip_address"),
        "endpoint": f"llm://{provider}/{endpoint_segment(model)}",
        "scheme": "llm",
        "method": method,
        "timestamp": payload.iso_timestamp(payload.get(slo, "startTime")),
        "session_id": payload.session_id(slo, config.session_header),
        "custom_data": custom_data,
        "headers": _captured_headers(slo, config),
        "query_params": None,
        "body": body,
        "user_agent": (
            user_agent
            if isinstance(user_agent, str) and user_agent
            else f"cerberus-litellm/{__version__}"
        ),
        "user_id": payload.user_id(slo, config.user_id_source),
    }
