"""Bounding a source event to the ingest size cap.

The caller controls body size and an event without a dict body derives nothing,
so the ladder trims the body toward a still-classifiable skeleton before it
sheds it: cap strings, reduce to a skeleton, shed the body, drop the event.
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

# Room for the body note, which grows as the ladder rewrites it.
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
MCP_KEEP_KEYS = ("jsonrpc", "id", "method")
MCP_KEEP_PARAMS = ("name", "uri")


def serialize(event: dict[str, Any]) -> bytes:
    """The exact bytes the sink writes, and what the ladder measures."""
    return json.dumps(event, ensure_ascii=True, separators=(",", ":"), default=str).encode("utf-8")


def fit(event: dict[str, Any], max_bytes: int) -> dict[str, Any] | None:
    """Trim the event until it serializes under max_bytes. None means drop it.

    Updates the body note in place as it goes.
    """
    if size(event) <= max_bytes:
        return event

    body = event.get("body")
    if isinstance(body, dict):
        capped, capped_strings = cap_strings(body, MAX_STRING_CHARS)
        if capped_strings:
            event["body"] = capped
            set_note(event, {"state": STATE_CAPPED, "strings": capped_strings})
            if size(event) <= max_bytes:
                return event
            body = capped

        budget = max_bytes - NOTE_MARGIN_BYTES
        reduced, detail = _reduce(body, lambda candidate: _fits(event, candidate, budget))
        if reduced is not None:
            event["body"] = reduced
            set_note(event, {"state": STATE_REDUCED, **detail})
            if size(event) <= max_bytes:
                return event

        event.pop("body", None)
        set_note(event, {"state": STATE_SHED, "reason": "size"})
        if size(event) <= max_bytes:
            return event

    return None


def size(event: dict[str, Any]) -> int:
    return len(serialize(event))


def set_note(event: dict[str, Any], note: dict[str, Any]) -> None:
    """Record what happened to the body, beside the event's gateway context."""
    agentcore = event.setdefault("custom_data", {}).setdefault("agentcore", {})
    agentcore["body"] = note


def cap_strings(value: Any, limit: int) -> tuple[Any, int]:
    """Truncate every string in a tree; returns the tree and how many were cut."""
    capped = 0

    def walk(node: Any, depth: int) -> Any:
        nonlocal capped
        if depth > MAX_WALK_DEPTH:
            return node
        if isinstance(node, str):
            if len(node) > limit:
                capped += 1
                return node[:limit]
            return node
        if isinstance(node, dict):
            return {key: walk(item, depth + 1) for key, item in node.items()}
        if isinstance(node, list):
            return [walk(item, depth + 1) for item in node]
        return node

    return walk(value, 0), capped


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
    """Keep the model, the route key and the system prompt; shed the rest."""
    base: dict[str, Any] = {key: body[key] for key in LLM_KEEP_KEYS if key in body}
    route = next((key for key in LLM_ROUTE_KEYS if key in body), None)
    dropped = [key for key in body if key not in LLM_KEEP_KEYS and key != route and key != "system"]
    detail: dict[str, Any] = {"kind": "llm", "dropped_keys": len(dropped)}

    system = body.get("system")
    if system is not None:
        base["system"] = cap_strings(system, MAX_SYSTEM_CHARS)[0]

    if route is None:
        return (base, detail) if fits(base) else (None, {})

    value = body[route]
    if not isinstance(value, list):
        candidate = {**base, route: cap_strings(value, MAX_SYSTEM_CHARS)[0]}
        return (candidate, detail) if fits(candidate) else (None, {})

    messages = [item for item in value if isinstance(item, dict) and "role" in item]
    if not messages:
        return (base, detail) if fits(base) else (None, {})

    first_system = next((item for item in messages if item.get("role") == "system"), None)
    lead = [first_system] if first_system is not None else []
    tail = [item for item in messages if item is not first_system]

    kept = _largest_tail_that_fits(base, route, lead, tail, fits)
    if kept is None:
        return (None, {})
    candidate, tail_kept = kept
    detail["messages_kept"] = len(lead) + tail_kept
    detail["messages_dropped"] = len(messages) - detail["messages_kept"]
    return candidate, detail


def _largest_tail_that_fits(
    base: dict[str, Any],
    route: str,
    lead: list[Any],
    tail: list[Any],
    fits: Callable[[Any], bool],
) -> tuple[dict[str, Any], int] | None:
    """Binary search the newest messages that still fit, keeping the list non-empty."""
    best: tuple[dict[str, Any], int] | None = None
    low, high = 1, len(tail)
    while low <= high:
        middle = (low + high) // 2
        candidate = {**base, route: lead + tail[-middle:]}
        if fits(candidate):
            best = (candidate, middle)
            low = middle + 1
        else:
            high = middle - 1
    if best is not None:
        return best
    if lead:
        candidate = {**base, route: lead}
        if fits(candidate):
            return candidate, 0
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

    candidate = {**base, "params": kept_params}
    if fits(candidate):
        return candidate, {**detail, "arguments": "dropped"}
    return None, {}
