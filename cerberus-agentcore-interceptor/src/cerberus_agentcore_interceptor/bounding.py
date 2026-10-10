"""Bounding a source event to the ingest size cap.

The ladder trims a large body toward a shape that still describes the call
before it gives up on it: cap strings, reduce to a skeleton, shed the captured
headers, shed the body, drop the event.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

DEFAULT_MAX_EVENT_BYTES = 57344
MAX_EVENT_BYTES_CEILING = 63488

MAX_STRING_CHARS = 8192
MAX_SYSTEM_CHARS = 4096
ARGUMENT_CHAR_LIMITS = (4096, 1024, 256, 64)

# Escaped, one character can cost twelve bytes, so every character cap carries a
# byte cap at this multiple of it. Without one, a caller could pad a header or a
# prompt with astral-plane characters until the event no longer fits anywhere.
BYTES_PER_CAPPED_CHAR = 2

# Room for the notes, which grow as the ladder rewrites them.
NOTE_MARGIN_BYTES = 192

MAX_WALK_DEPTH = 24

STATE_CAPTURED = "captured"
STATE_CAPPED = "capped"
STATE_REDUCED = "reduced"
STATE_SHED = "shed"
STATE_OMITTED = "omitted"
STATE_DISABLED = "disabled"

LLM_KEEP_KEYS = ("model", "stream", "max_tokens")
LLM_ROUTE_KEYS = ("messages", "input", "prompt")
# Anthropic's top-level system prompt and its Responses API counterpart.
LLM_SYSTEM_KEYS = ("system", "instructions")
MCP_KEEP_KEYS = ("jsonrpc", "id", "method")
MCP_KEEP_PARAMS = ("name", "uri")


def serialize(event: dict[str, Any]) -> bytes:
    """The exact bytes the sink writes, and what the ladder measures."""
    return json.dumps(event, ensure_ascii=True, separators=(",", ":"), default=str).encode("utf-8")


def size(event: dict[str, Any]) -> int:
    return len(serialize(event))


def clip_text(value: str, max_chars: int, max_bytes: int | None = None) -> str:
    """Clip text to a character cap and to the byte cap that rides with it."""
    clipped = value[:max_chars]
    budget = max_chars * BYTES_PER_CAPPED_CHAR if max_bytes is None else max_bytes
    if _escaped_len(clipped) <= budget:
        return clipped
    low, high = 0, len(clipped)
    while low < high:
        middle = (low + high + 1) // 2
        if _escaped_len(clipped[:middle]) <= budget:
            low = middle
        else:
            high = middle - 1
    return clipped[:low]


def fit(event: dict[str, Any], max_bytes: int) -> dict[str, Any] | None:
    """Trim the event until it serializes under max_bytes. None means drop it.

    Updates the notes in the event's gateway block as it goes.
    """
    if size(event) <= max_bytes:
        return event

    body = event.get("body")
    if isinstance(body, dict):
        capped, capped_strings = cap_strings(body, MAX_STRING_CHARS)
        if capped_strings:
            event["body"] = capped
            set_note(event, "body", {"state": STATE_CAPPED, "strings": capped_strings})
            if size(event) <= max_bytes:
                return event
            body = capped

        budget = max_bytes - NOTE_MARGIN_BYTES
        reduced, detail = _reduce(body, lambda candidate: _fits(event, candidate, budget))
        if reduced is not None:
            if capped_strings:
                detail["strings"] = capped_strings
            event["body"] = reduced
            set_note(event, "body", {"state": STATE_REDUCED, **detail})
            if size(event) <= max_bytes:
                return event

    # Headers before the body: they are metadata, and the body is the call.
    shed_headers = event.pop("headers", None) is not None
    shed_user_agent = event.pop("user_agent", None) is not None
    if shed_headers or shed_user_agent:
        set_note(event, "headers", {"state": STATE_SHED, "reason": "size"})
        if size(event) <= max_bytes:
            return event

    if "body" in event:
        del event["body"]
        set_note(event, "body", {"state": STATE_SHED, "reason": "size"})
        if size(event) <= max_bytes:
            return event

    return None


def set_note(event: dict[str, Any], key: str, note: dict[str, Any]) -> None:
    """Record what happened to a captured field, beside the gateway context."""
    agentcore = event.setdefault("custom_data", {}).setdefault("agentcore", {})
    agentcore[key] = note


def cap_strings(value: Any, limit: int) -> tuple[Any, int]:
    """Clip every string in a tree; returns the tree and how many were cut."""
    capped = 0

    def walk(node: Any, depth: int) -> Any:
        nonlocal capped
        if depth > MAX_WALK_DEPTH:
            return node
        if isinstance(node, str):
            clipped = clip_text(node, limit)
            if clipped != node:
                capped += 1
            return clipped
        if isinstance(node, dict):
            return {key: walk(item, depth + 1) for key, item in node.items()}
        if isinstance(node, list):
            return [walk(item, depth + 1) for item in node]
        return node

    return walk(value, 0), capped


def _escaped_len(value: str) -> int:
    return len(json.dumps(value, ensure_ascii=True)) - 2


def _fits(event: dict[str, Any], candidate: Any, budget: int) -> bool:
    original = event.get("body")
    event["body"] = candidate
    try:
        return size(event) <= budget
    finally:
        event["body"] = original


def _reduce(body: dict[str, Any], fits: Callable[[Any], bool]) -> tuple[Any, dict[str, Any]]:
    if _looks_like_mcp(body):
        return _reduce_mcp(body, fits)
    if _looks_like_llm(body):
        return _reduce_llm(body, fits)
    return None, {}


def _looks_like_mcp(body: dict[str, Any]) -> bool:
    return "jsonrpc" in body or ("method" in body and "params" in body)


def _looks_like_llm(body: dict[str, Any]) -> bool:
    return "model" in body or any(key in body for key in LLM_ROUTE_KEYS)


def _reduce_llm(body: dict[str, Any], fits: Callable[[Any], bool]) -> tuple[Any, dict[str, Any]]:
    """Drop the parameters first, then the oldest messages, then the system prompt."""
    base: dict[str, Any] = {key: body[key] for key in LLM_KEEP_KEYS if key in body}
    route = next((key for key in LLM_ROUTE_KEYS if key in body), None)
    prompts = [key for key in LLM_SYSTEM_KEYS if body.get(key) is not None]
    dropped = [key for key in body if key not in base and key != route and key not in prompts]
    detail: dict[str, Any] = {"kind": "llm", "dropped_keys": len(dropped)}

    with_system = dict(base)
    for key in prompts:
        with_system[key] = cap_strings(body[key], MAX_SYSTEM_CHARS)[0]

    value = body.get(route) if route is not None else None
    # Every item counts, whatever its type: Responses API tool calls and their
    # outputs carry no role.
    messages = value if isinstance(value, list) else None

    for start, without_system in ((with_system, False), (base, True)):
        fitted = _llm_candidate(start, route, value, messages, fits)
        if fitted is None:
            continue
        candidate, kept = fitted
        if without_system:
            detail.update(dict.fromkeys(prompts, "dropped"))
        if messages is not None:
            detail["messages_kept"] = kept
            detail["messages_dropped"] = len(messages) - kept
        return candidate, detail
    return None, {}


def _llm_candidate(
    base: dict[str, Any],
    route: str | None,
    value: Any,
    messages: list[Any] | None,
    fits: Callable[[Any], bool],
) -> tuple[dict[str, Any], int] | None:
    """The largest body this base still fits, or None. Never an empty body."""
    if route is None:
        return (base, 0) if base and fits(base) else None

    if messages is None:
        candidate = {**base, route: cap_strings(value, MAX_SYSTEM_CHARS)[0]}
        return (candidate, 0) if fits(candidate) else None

    if not messages:
        return (base, 0) if base and fits(base) else None

    first_system = next(
        (item for item in messages if isinstance(item, dict) and item.get("role") == "system"),
        None,
    )
    lead = [first_system] if first_system is not None else []
    tail = [item for item in messages if item is not first_system]

    best: tuple[dict[str, Any], int] | None = None
    low, high = 1, len(tail)
    while low <= high:
        middle = (low + high) // 2
        candidate = {**base, route: lead + tail[-middle:]}
        if fits(candidate):
            best = (candidate, len(lead) + middle)
            low = middle + 1
        else:
            high = middle - 1
    if best is not None:
        return best
    if lead:
        candidate = {**base, route: lead}
        if fits(candidate):
            return candidate, len(lead)
    return None


def _reduce_mcp(body: dict[str, Any], fits: Callable[[Any], bool]) -> tuple[Any, dict[str, Any]]:
    """Keep the call's identity; truncate, then drop, the arguments."""
    base: dict[str, Any] = {key: body[key] for key in MCP_KEEP_KEYS if key in body}
    params = body.get("params")
    params = params if isinstance(params, dict) else {}
    kept_params = {key: params[key] for key in MCP_KEEP_PARAMS if key in params}
    arguments = params.get("arguments")
    detail: dict[str, Any] = {"kind": "mcp"}

    if arguments is not None:
        for limit in ARGUMENT_CHAR_LIMITS:
            candidate = {
                **base,
                "params": {**kept_params, "arguments": cap_strings(arguments, limit)[0]},
            }
            if fits(candidate):
                return candidate, {**detail, "arguments": "truncated", "chars": limit}
        detail["arguments"] = "dropped"

    candidate = {**base, "params": kept_params} if kept_params else dict(base)
    if candidate and fits(candidate):
        return candidate, detail
    return None, {}
