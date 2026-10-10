"""Bounding a source event to the ingest size cap.

The ladder trims a large body toward a shape that still describes the call
before it gives up on it: cap strings, reduce to a skeleton, shed the captured
headers, shed the body, drop the event.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator
from itertools import islice
from time import monotonic
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

# The ladder's cost follows how many values a body holds, not its bytes. Below
# this multiple of the cap it runs on the whole body; above it, prune() first
# takes out what could never fit.
PRUNE_FACTOR = 4

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
# Where a message keeps its content blocks: Chat and Messages content, Responses
# API tool output.
LLM_BLOCK_KEYS = ("content", "output")
MCP_KEEP_KEYS = ("jsonrpc", "id", "method")
MCP_KEEP_PARAMS = ("name", "uri")

# Counts that add up when a reduction runs on a body prune() already cut.
SUMMED_NOTE_KEYS = ("dropped_keys", "messages_dropped", "blocks_dropped")


class CaptureDeadlineExceeded(Exception):
    """Bounding ran past the deadline it was given."""


def check_deadline(deadline: float | None) -> None:
    """Raise CaptureDeadlineExceeded once time.monotonic() reaches deadline."""
    if deadline is not None and monotonic() >= deadline:
        raise CaptureDeadlineExceeded


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


def fit(
    event: dict[str, Any],
    max_bytes: int,
    deadline: float | None = None,
    pruned: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Trim the event until it serializes under max_bytes. None means drop it.

    Updates the notes in the event's gateway block as it goes, starting from
    pruned, the note prune() returned for the body. Raises
    CaptureDeadlineExceeded once time.monotonic() reaches deadline.
    """
    if pruned is not None:
        set_note(event, "body", {"state": STATE_REDUCED, **pruned})
    if _size(event, deadline) <= max_bytes:
        return event

    body = event.get("body")
    if isinstance(body, dict):
        check_deadline(deadline)
        capped, capped_strings = cap_strings(body, MAX_STRING_CHARS)
        if capped_strings:
            event["body"] = capped
            if pruned is None:
                set_note(event, "body", {"state": STATE_CAPPED, "strings": capped_strings})
            else:
                note = {"state": STATE_REDUCED, **pruned, "strings": capped_strings}
                set_note(event, "body", note)
            if _size(event, deadline) <= max_bytes:
                return event
            body = capped

        budget = max_bytes - NOTE_MARGIN_BYTES
        reduced, detail = _reduce(
            body, lambda candidate: _fits(event, candidate, budget, deadline), deadline
        )
        if reduced is not None:
            detail = _merge_notes(pruned or {}, detail)
            if capped_strings:
                detail["strings"] = capped_strings
            event["body"] = reduced
            set_note(event, "body", {"state": STATE_REDUCED, **detail})
            if _size(event, deadline) <= max_bytes:
                return event

    # Headers before the body: they are metadata, and the body is the call.
    shed_headers = event.pop("headers", None) is not None
    shed_user_agent = event.pop("user_agent", None) is not None
    if shed_headers or shed_user_agent:
        set_note(event, "headers", {"state": STATE_SHED, "reason": "size"})
        if _size(event, deadline) <= max_bytes:
            return event

    if "body" in event:
        del event["body"]
        set_note(event, "body", {"state": STATE_SHED, "reason": "size"})
        if _size(event, deadline) <= max_bytes:
            return event

    return None


def prune(
    body: dict[str, Any], max_bytes: int
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Take out of an unsanitised body what could never fit under max_bytes.

    Returns the body and a note of what was taken, None when nothing was. A
    None body means none of it can fit. Counts no further than what could fit,
    so its cost does not grow with the body.
    """
    limit = _value_limit(max_bytes)
    if _values(body, limit) <= limit:
        return body, None
    if _looks_like_mcp(body):
        return _prune_mcp(body, limit)
    if _looks_like_llm(body):
        return _prune_llm(body, limit)
    return None, None


def set_note(event: dict[str, Any], key: str, note: dict[str, Any]) -> None:
    """Record what happened to a captured field, beside the gateway context."""
    agentcore = event.setdefault("custom_data", {}).setdefault("agentcore", {})
    agentcore[key] = note


def cap_strings(value: Any, limit: int) -> tuple[Any, int]:
    """Clip every string in a tree; returns the tree and how many were cut."""
    capped, count, _ = _cap(value, limit)
    return capped, count


def _cap(value: Any, limit: int) -> tuple[Any, int, int]:
    """cap_strings, plus the lowest cap that would still leave every uncut string whole."""
    count = 0
    whole = 0

    def walk(node: Any, depth: int) -> Any:
        nonlocal count, whole
        if depth > MAX_WALK_DEPTH:
            return node
        if isinstance(node, str):
            need = _whole_at(node) if len(node) <= limit else limit + 1
            if need <= limit:
                whole = max(whole, need)
                return node
            count += 1
            return clip_text(node, limit)
        if isinstance(node, dict):
            return {key: walk(item, depth + 1) for key, item in node.items()}
        if isinstance(node, list):
            return [walk(item, depth + 1) for item in node]
        return node

    return walk(value, 0), count, whole


def _whole_at(value: str) -> int:
    """The lowest character cap clip_text leaves value whole under."""
    return max(len(value), -(-_escaped_len(value) // BYTES_PER_CAPPED_CHAR))


def _rungs(value: Any, deadline: float | None) -> Iterator[tuple[int, Any]]:
    """value capped at each of ARGUMENT_CHAR_LIMITS, skipping a cap that changes nothing."""
    whole: int | None = None
    for limit in ARGUMENT_CHAR_LIMITS:
        if whole is not None and whole <= limit:
            continue
        check_deadline(deadline)
        capped, count, whole = _cap(value, limit)
        if count:
            whole = None
        yield limit, capped


def _escaped_len(value: str) -> int:
    return len(json.dumps(value, ensure_ascii=True)) - 2


def _size(event: dict[str, Any], deadline: float | None) -> int:
    check_deadline(deadline)
    return size(event)


def _fits(event: dict[str, Any], candidate: Any, budget: int, deadline: float | None) -> bool:
    original = event.get("body")
    event["body"] = candidate
    try:
        return _size(event, deadline) <= budget
    finally:
        event["body"] = original


def _merge_notes(pruned: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    merged = {**pruned, **detail}
    for key in SUMMED_NOTE_KEYS:
        if key in pruned and key in detail:
            merged[key] = pruned[key] + detail[key]
    return merged


def _reduce(
    body: dict[str, Any], fits: Callable[[Any], bool], deadline: float | None
) -> tuple[Any, dict[str, Any]]:
    if _looks_like_mcp(body):
        return _reduce_mcp(body, fits, deadline)
    if _looks_like_llm(body):
        return _reduce_llm(body, fits, deadline)
    return None, {}


def _looks_like_mcp(body: dict[str, Any]) -> bool:
    return "jsonrpc" in body or ("method" in body and "params" in body)


def _looks_like_llm(body: dict[str, Any]) -> bool:
    return "model" in body or any(key in body for key in LLM_ROUTE_KEYS)


def _llm_parts(body: dict[str, Any]) -> tuple[dict[str, Any], str | None, list[str], int]:
    """The kept parameters, the route key, the system prompt keys, how many keys go."""
    base: dict[str, Any] = {key: body[key] for key in LLM_KEEP_KEYS if key in body}
    route = next((key for key in LLM_ROUTE_KEYS if key in body), None)
    prompts = [key for key in LLM_SYSTEM_KEYS if body.get(key) is not None]
    dropped = len(body) - len(base) - len(prompts) - (route is not None)
    return base, route, prompts, dropped


def _reduce_llm(
    body: dict[str, Any], fits: Callable[[Any], bool], deadline: float | None
) -> tuple[Any, dict[str, Any]]:
    """Drop the parameters first, then the oldest messages, then the system prompt.

    The newest message is never dropped: when it alone is over budget, its
    strings are cut shorter and then its oldest content blocks go.
    """
    base, route, prompts, dropped = _llm_parts(body)
    detail: dict[str, Any] = {"kind": "llm", "dropped_keys": dropped}

    with_system = dict(base)
    for key in prompts:
        with_system[key] = cap_strings(body[key], MAX_SYSTEM_CHARS)[0]
    starts = ((with_system, False), (base, True)) if prompts else ((base, False),)

    value = body.get(route) if route is not None else None
    # Every item counts, whatever its type: Responses API tool calls and their
    # outputs carry no role.
    messages = value if isinstance(value, list) else None

    for start, without_system in starts:
        fitted = _llm_candidate(start, route, value, messages, fits)
        if fitted is not None:
            candidate, kept = fitted
            return candidate, _llm_note(detail, prompts, without_system, messages, kept)

    if route is not None and messages:
        lead, _ = _split_lead(messages)
        frames = [(with_system, lead, False)]
        if prompts or lead:
            frames.append((base, [], bool(prompts)))
        shrunk = _shrink_newest(frames, route, messages[-1], fits, deadline)
        if shrunk is not None:
            candidate, kept, without_system, shrink = shrunk
            return candidate, {
                **_llm_note(detail, prompts, without_system, messages, kept),
                **shrink,
            }
    return None, {}


def _llm_note(
    detail: dict[str, Any],
    prompts: list[str],
    without_system: bool,
    messages: list[Any] | None,
    kept: int,
) -> dict[str, Any]:
    note = dict(detail)
    if without_system:
        note.update(dict.fromkeys(prompts, "dropped"))
    if messages is not None:
        note["messages_kept"] = kept
        note["messages_dropped"] = len(messages) - kept
    return note


def _llm_candidate(
    base: dict[str, Any],
    route: str | None,
    value: Any,
    messages: list[Any] | None,
    fits: Callable[[Any], bool],
) -> tuple[dict[str, Any], int] | None:
    """The largest body of whole messages this base still fits, or None. Never an empty body."""
    if route is None:
        return (base, 0) if base and fits(base) else None

    if messages is None:
        candidate = {**base, route: cap_strings(value, MAX_SYSTEM_CHARS)[0]}
        return (candidate, 0) if fits(candidate) else None

    if not messages:
        return (base, 0) if base and fits(base) else None

    lead, tail = _split_lead(messages)
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
    return best


def _split_lead(messages: list[Any]) -> tuple[list[Any], list[Any]]:
    """The first system message, unless it is the newest, and every other message."""
    first = next((item for item in messages[:-1] if _is_system(item)), None)
    if first is None:
        return [], messages
    return [first], [item for item in messages if item is not first]


def _is_system(message: Any) -> bool:
    return isinstance(message, dict) and message.get("role") == "system"


def _shrink_newest(
    frames: list[tuple[dict[str, Any], list[Any], bool]],
    route: str,
    newest: Any,
    fits: Callable[[Any], bool],
    deadline: float | None,
) -> tuple[dict[str, Any], int, bool, dict[str, Any]] | None:
    """The newest message cut down until it fits: shorter strings, then fewer blocks.

    Each frame is a base, the lead to keep before the message, and whether the
    frame dropped the system prompt. Frames are tried in order at every step.
    """
    shrunk = newest
    for limit, shrunk in _rungs(newest, deadline):
        for start, lead, without_system in frames:
            candidate = {**start, route: [*lead, shrunk]}
            if fits(candidate):
                return (
                    candidate,
                    len(lead) + 1,
                    without_system,
                    {"newest": "truncated", "chars": limit},
                )

    key = _block_key(shrunk)
    if key is None:
        return None
    blocks = shrunk[key]
    for start, lead, without_system in frames:
        best: tuple[dict[str, Any], int] | None = None
        low, high = 0, len(blocks) - 1
        while low <= high:
            middle = (low + high) // 2
            message = {**shrunk, key: blocks[len(blocks) - middle :]}
            candidate = {**start, route: [*lead, message]}
            if fits(candidate):
                best = (candidate, middle)
                low = middle + 1
            else:
                high = middle - 1
        if best is not None:
            candidate, kept_blocks = best
            shrink = {
                "newest": "truncated",
                "chars": ARGUMENT_CHAR_LIMITS[-1],
                "blocks_dropped": len(blocks) - kept_blocks,
            }
            return candidate, len(lead) + 1, without_system, shrink
    return None


def _block_key(message: Any) -> str | None:
    """The key holding a message's content blocks, if it has any."""
    if not isinstance(message, dict):
        return None
    return next((key for key in LLM_BLOCK_KEYS if isinstance(message.get(key), list)), None)


def _reduce_mcp(
    body: dict[str, Any], fits: Callable[[Any], bool], deadline: float | None
) -> tuple[Any, dict[str, Any]]:
    """Keep the call's identity; truncate, then drop, the arguments."""
    base: dict[str, Any] = {key: body[key] for key in MCP_KEEP_KEYS if key in body}
    params = body.get("params")
    params = params if isinstance(params, dict) else {}
    kept_params = {key: params[key] for key in MCP_KEEP_PARAMS if key in params}
    arguments = params.get("arguments")
    detail: dict[str, Any] = {"kind": "mcp"}

    if arguments is not None:
        for limit, capped in _rungs(arguments, deadline):
            candidate = {**base, "params": {**kept_params, "arguments": capped}}
            if fits(candidate):
                return candidate, {**detail, "arguments": "truncated", "chars": limit}
        detail["arguments"] = "dropped"

    candidate = {**base, "params": kept_params} if kept_params else dict(base)
    if candidate and fits(candidate):
        return candidate, detail
    return None, {}


def _value_limit(max_bytes: int) -> int:
    # A tree of n values serialises to at least 2n - 1 bytes, so one holding
    # more than this many can never fit under max_bytes.
    return max_bytes // 2 + 1


def _values(value: Any, limit: int) -> int:
    """How many values a tree holds, counting no further than limit + 1."""
    count = 1
    stack = [value]
    while stack:
        node = stack.pop()
        children: Iterable[Any]
        if isinstance(node, dict):
            children = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        for child in children:
            count += 1
            if count > limit:
                return count
            if isinstance(child, (dict, list)):
                stack.append(child)
    return count


def _prune_mcp(
    body: dict[str, Any], limit: int
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    shape: dict[str, Any] = {key: body[key] for key in MCP_KEEP_KEYS if key in body}
    params = body.get("params")
    params = params if isinstance(params, dict) else {}
    kept = {key: params[key] for key in MCP_KEEP_PARAMS if key in params}
    if _values(shape, limit) + _values(kept, limit) > limit:
        return None, None

    note: dict[str, Any] = {"kind": "mcp"}
    arguments = params.get("arguments")
    if arguments is not None:
        if _values(arguments, limit) <= limit:
            kept["arguments"] = arguments
        else:
            note["arguments"] = "dropped"
    return ({**shape, "params": kept} if kept else shape), note


def _prune_llm(
    body: dict[str, Any], limit: int
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    shape, route, prompts, dropped = _llm_parts(body)
    if _values(shape, limit) > limit:
        return None, None

    note: dict[str, Any] = {"kind": "llm", "dropped_keys": dropped}
    for key in prompts:
        if _values(body[key], limit) <= limit:
            shape[key] = body[key]
        else:
            note[key] = "dropped"
    if route is None:
        return shape, note

    value = body[route]
    if not isinstance(value, list):
        if _values(value, limit) > limit:
            return None, None
        shape[route] = value
        return shape, note

    messages = _prune_messages(value, limit, note)
    if messages is None:
        return None, None
    shape[route] = messages
    return shape, note


def _prune_messages(messages: list[Any], limit: int, note: dict[str, Any]) -> list[Any] | None:
    """The newest messages that could fit, after the system message that leads them."""
    kept: list[Any] = []
    used = 0
    for message in reversed(messages):
        count = _values(message, limit)
        if kept and used + count > limit:
            break
        kept.append(message)
        used += count
    kept.reverse()

    if used > limit:
        newest = _prune_blocks(kept[-1], limit, note)
        if newest is None:
            return None
        kept = [newest]

    older = len(messages) - len(kept)
    lead = next((item for item in islice(messages, min(older, limit)) if _is_system(item)), None)
    if lead is not None and _values(lead, limit) <= limit:
        kept.insert(0, lead)

    note["messages_kept"] = len(kept)
    note["messages_dropped"] = len(messages) - len(kept)
    return kept


def _prune_blocks(message: Any, limit: int, note: dict[str, Any]) -> dict[str, Any] | None:
    """The newest message with only the newest content blocks that could fit."""
    key = _block_key(message)
    if key is None:
        return None
    used = 1
    for name, item in message.items():
        if name != key:
            used += _values(item, limit)
            if used > limit:
                return None

    blocks = message[key]
    kept: list[Any] = []
    for block in reversed(blocks):
        used += _values(block, limit)
        if used > limit:
            break
        kept.append(block)
    kept.reverse()
    note["blocks_dropped"] = len(blocks) - len(kept)
    return {**message, key: kept}
