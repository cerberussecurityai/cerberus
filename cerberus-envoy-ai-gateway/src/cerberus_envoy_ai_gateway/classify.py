"""Span classification: decide whether a span is an LLM call, an MCP call,
or noise to ignore.

The extproc emits one span per gateway request plus assorted child/parent
spans (Envoy router spans, internal phases). We key off attributes that only
the terminal AI span carries, so each LLM/MCP call maps to exactly one event:

- MCP spans carry ``mcp.method.name`` (internal/tracing/mcp.go in
  envoyproxy/ai-gateway).
- LLM spans carry the request model (``gen_ai.request.model`` for the
  OpenAI-format path, ``llm.model`` for the Anthropic path) and/or an
  OpenInference span-kind marker.
"""

from typing import Any

KIND_LLM = "llm"
KIND_MCP = "mcp"

# OpenInference marks LLM spans with a span-kind attribute; the OpenAI path
# uses `openinference.span.kind: LLM`, the Anthropic path `span.kind: llm`.
_SPAN_KIND_KEYS = ("openinference.span.kind", "span.kind")
_MODEL_KEYS = ("llm.model_name", "llm.model", "gen_ai.request.model")


def classify(attrs: dict[str, Any]) -> str | None:
    """Return KIND_LLM, KIND_MCP, or None for spans to ignore."""
    if "mcp.method.name" in attrs:
        return KIND_MCP
    for key in _MODEL_KEYS:
        if attrs.get(key):
            return KIND_LLM
    for key in _SPAN_KIND_KEYS:
        kind = attrs.get(key)
        # OpenInference marks OpenAI embeddings with span-kind "EMBEDDING" and
        # omits llm.model_name/llm.system (the model lives in
        # llm.invocation_parameters), so accept it here too — otherwise
        # embedding requests fall through as ignored and never reach Cerberus.
        if isinstance(kind, str) and kind.lower() in ("llm", "embedding"):
            return KIND_LLM
    return None
