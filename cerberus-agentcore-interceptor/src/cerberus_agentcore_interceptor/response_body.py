"""Reading a response body into the shapes the platform reads, and fitting it to the cap."""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterator
from typing import Any

from .bounding import (
    ARGUMENT_CHAR_LIMITS,
    STATE_CAPTURED,
    STATE_OMITTED,
    STATE_REDUCED,
    STATE_SHED,
    check_deadline,
    clip_text,
    serialize,
    set_note,
    storable,
)
from .envelope import (
    BODY_DECODE_ERROR,
    BODY_EMPTY,
    BODY_NOT_JSON,
    BODY_NOT_OBJECT,
    HTTP,
    MCP,
    Envelope,
)
from .sanitize import ECHOED_HEADER_KEYS, sanitize_body

STATE_SKIPPED = "skipped"
STATE_TRUNCATED = "truncated"

BODY_ABSENT = "absent"
BODY_UNSUPPORTED_TYPE = "unsupported_type"

MAX_CONTENT_TYPE_CHARS = 255

GZIP_MAGIC = b"\x1f\x8b"
SSE_PREFIXES = ("data:", "event:", ":", "id:", "retry:")
SSE_LINE_BREAK = re.compile(r"(\r\n|\r|\n)")
# How many SSE lines are read between deadline checks.
SSE_LINES_PER_CHECK = 256

# The share of a truncated body's room that goes to its head.
HEAD_PERCENT = 60

MCP_ENVELOPE_KEYS = ("jsonrpc", "id")
MCP_LISTING_KEYS = ("tools", "prompts", "resources", "resourceTemplates")
MCP_LISTING_ITEM_KEYS = ("name", "title", "uri", "uriTemplate", "mimeType")


def read(
    envelope: Envelope, extra_keys: tuple[str, ...] = (), deadline: float | None = None
) -> tuple[Any, dict[str, Any]]:
    """The sanitized response body and its note. The body is None when there is none to send.

    Raises CaptureDeadlineExceeded once time.monotonic() reaches deadline.
    """
    check_deadline(deadline)
    keys = (*extra_keys, *ECHOED_HEADER_KEYS)
    if envelope.kind == MCP:
        value, state, reason = _mcp(envelope.response_body, keys, deadline)
    else:
        body, content_type = envelope.response_body, envelope.content_type
        value, state, reason = _http(body, content_type, keys, deadline)
    return value, note(envelope, state, reason)


def note(envelope: Envelope, state: str, reason: str = "") -> dict[str, Any]:
    """A response note: the state, why when omitted, and the content type an http response gave."""
    result: dict[str, Any] = {"state": state}
    if reason:
        result["reason"] = reason
    if envelope.kind == HTTP and envelope.content_type:
        result["content_type"] = storable(clip_text(envelope.content_type, MAX_CONTENT_TYPE_CHARS))
    return result


def sanitize_sse(text: str, keys: tuple[str, ...], deadline: float | None = None) -> str:
    """SSE text with each event's JSON data key-sanitized and compact. Other lines are kept as sent.

    An event's data lines are read joined, as an SSE client reads them. When
    they hold JSON together, they are written back as one data line.
    """
    parts = SSE_LINE_BREAK.split(text)
    # split() puts each line's ending in the slot after it; the last line has none.
    lines = zip(parts[::2], [*parts[1::2], ""], strict=True)
    out: list[str] = []
    event: list[tuple[str, str]] = []
    for index, (line, ending) in enumerate(lines):
        if index % SSE_LINES_PER_CHECK == 0:
            check_deadline(deadline)
        if line:
            event.append((line, ending))
            continue
        out.extend(_sse_event(event, keys, deadline))
        out.append(ending)
        event = []
    out.extend(_sse_event(event, keys, deadline))
    return "".join(out)


def attach(
    event: dict[str, Any],
    value: Any,
    response_note: dict[str, Any],
    max_bytes: int,
    reducible: bool,
    deadline: float | None = None,
) -> dict[str, Any] | None:
    """Put value in the event as its response_body, cut down until the event fits max_bytes.

    Tries the body whole, then reduced when reducible, then as the head and tail
    of its text, then sheds it. None means the event does not fit without it.
    Raises CaptureDeadlineExceeded once time.monotonic() reaches deadline.
    """
    set_note(event, "response", response_note)
    if value is not None:
        text = _text(value)
        if _whole(event, value, text, response_note, max_bytes, deadline):
            return event
        if response_note["state"] == STATE_CAPTURED:
            if reducible and isinstance(value, (dict, list)):
                reduced_note = {**response_note, "state": STATE_REDUCED}
                for reduced in _reductions(value, deadline):
                    if _fits_with(event, reduced, reduced_note, max_bytes, deadline):
                        return event
            if _truncate(event, text, response_note, max_bytes, deadline):
                return event
        set_note(event, "response", {**response_note, "state": STATE_SHED, "reason": "size"})
    return event if _size(event, deadline) <= max_bytes else None


def fits_whole(
    event: dict[str, Any],
    value: Any,
    response_note: dict[str, Any],
    max_bytes: int,
    deadline: float | None = None,
) -> bool:
    """Put value in the event whole and keep it there only if the event then fits max_bytes."""
    return _whole(event, value, _text(value), response_note, max_bytes, deadline)


def _mcp(body: Any, keys: tuple[str, ...], deadline: float | None) -> tuple[Any, str, str]:
    if body is None:
        return None, STATE_OMITTED, BODY_ABSENT
    if isinstance(body, (dict, list)):
        return _json(body, keys, deadline), STATE_CAPTURED, ""
    if isinstance(body, str):
        return _untyped(body, keys, BODY_NOT_JSON, deadline)
    return None, STATE_OMITTED, BODY_NOT_OBJECT


def _http(
    body: Any, content_type: str, keys: tuple[str, ...], deadline: float | None
) -> tuple[Any, str, str]:
    if body is None:
        return None, STATE_OMITTED, BODY_ABSENT
    if not isinstance(body, str):
        return None, STATE_OMITTED, BODY_DECODE_ERROR
    try:
        raw = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return None, STATE_OMITTED, BODY_DECODE_ERROR
    if not raw:
        return None, STATE_OMITTED, BODY_EMPTY
    # A compressed body cannot be read here, sliced or not.
    if raw.startswith(GZIP_MAGIC):
        return {"body_skipped_encoding": "gzip"}, STATE_SKIPPED, ""

    check_deadline(deadline)
    text = raw.decode("utf-8", "replace")
    kind = content_type.lower()
    if "json" in kind:
        return _json_text(text, keys, deadline)
    if "text/event-stream" in kind:
        return _sse(text, keys, deadline)
    if not content_type:
        return _untyped(text, keys, BODY_UNSUPPORTED_TYPE, deadline)
    return None, STATE_OMITTED, BODY_UNSUPPORTED_TYPE


def _untyped(
    text: str, keys: tuple[str, ...], otherwise: str, deadline: float | None
) -> tuple[Any, str, str]:
    """Text of no stated type: JSON when it parses, SSE when it is framed like SSE."""
    parsed = _json_text(text, keys, deadline)
    if parsed[2] != BODY_NOT_JSON:
        return parsed
    if text.lstrip().startswith(SSE_PREFIXES):
        return _sse(text, keys, deadline)
    return None, STATE_OMITTED, otherwise


def _json_text(text: str, keys: tuple[str, ...], deadline: float | None) -> tuple[Any, str, str]:
    if not text.strip():
        return None, STATE_OMITTED, BODY_EMPTY
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return None, STATE_OMITTED, BODY_NOT_JSON
    if not isinstance(value, (dict, list)):
        return None, STATE_OMITTED, BODY_NOT_OBJECT
    return _json(value, keys, deadline), STATE_CAPTURED, ""


def _sse(text: str, keys: tuple[str, ...], deadline: float | None) -> tuple[Any, str, str]:
    if not text.strip():
        return None, STATE_OMITTED, BODY_EMPTY
    return storable(sanitize_sse(text, keys, deadline)), STATE_CAPTURED, ""


def _sse_event(
    lines: list[tuple[str, str]], keys: tuple[str, ...], deadline: float | None
) -> list[str]:
    """One SSE event's lines with their endings, its JSON data sanitized."""
    data = [index for index, (line, _) in enumerate(lines) if line.startswith("data:")]
    if len(data) > 1:
        payload = "\n".join(_sse_payload(lines[index][0]) for index in data)
        joined = _sse_json(payload, keys, deadline)
        if joined is not None:
            # The last data line's ending is the one that closes the event.
            last, rest = data[-1], set(data[:-1])
            return [
                f"data: {joined}{ending}" if index == last else line + ending
                for index, (line, ending) in enumerate(lines)
                if index not in rest
            ]
    out: list[str] = []
    for index, (line, ending) in enumerate(lines):
        if index % SSE_LINES_PER_CHECK == 0:
            check_deadline(deadline)
        out.append(_sse_line(line, keys, deadline) + ending)
    return out


def _sse_line(line: str, keys: tuple[str, ...], deadline: float | None) -> str:
    if not line.startswith("data:"):
        return line
    value = _sse_json(_sse_payload(line), keys, deadline)
    return line if value is None else f"data: {value}"


def _sse_payload(line: str) -> str:
    return line[len("data:") :].lstrip(" ")


def _sse_json(payload: str, keys: tuple[str, ...], deadline: float | None) -> str | None:
    """A data payload sanitized and compact, or None when it is not a JSON object or array."""
    try:
        value = json.loads(payload)
    except (ValueError, RecursionError):
        return None
    if not isinstance(value, (dict, list)):
        return None
    return _dumps(_json(value, keys, deadline))


def _json(value: Any, keys: tuple[str, ...], deadline: float | None) -> Any:
    """A JSON body sanitized, MCP result text included, and made storable."""
    sanitized = sanitize_body(value, keys)
    for message in sanitized if isinstance(sanitized, list) else (sanitized,):
        check_deadline(deadline)
        _sanitize_result_text(message, keys, deadline)
    check_deadline(deadline)
    return storable(sanitized)


def _sanitize_result_text(message: Any, keys: tuple[str, ...], deadline: float | None) -> None:
    """Sanitize in place each MCP result text that holds a JSON object or array."""
    result = message.get("result") if isinstance(message, dict) else None
    content = result.get("content") if isinstance(result, dict) else None
    if not isinstance(content, list):
        return
    for item in content:
        check_deadline(deadline)
        text = item.get("text") if isinstance(item, dict) else None
        if not isinstance(text, str):
            continue
        try:
            parsed = json.loads(text)
        except (ValueError, RecursionError):
            continue
        if isinstance(parsed, (dict, list)):
            item["text"] = _dumps(storable(sanitize_body(parsed, keys)))


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _text(value: Any) -> str:
    return value if isinstance(value, str) else _dumps(value)


def _size(event: dict[str, Any], deadline: float | None) -> int:
    check_deadline(deadline)
    return len(serialize(event))


def _whole(
    event: dict[str, Any],
    value: Any,
    text: str,
    response_note: dict[str, Any],
    max_bytes: int,
    deadline: float | None,
) -> bool:
    # The text is never longer than the value serializes to, so this skips a
    # serialization that could not fit.
    if _size(event, deadline) + len(text) > max_bytes:
        return False
    return _fits_with(event, value, response_note, max_bytes, deadline)


def _fits_with(
    event: dict[str, Any],
    value: Any,
    response_note: dict[str, Any],
    max_bytes: int,
    deadline: float | None,
) -> bool:
    """Set value and its note on the event; leave the value there only if the event fits."""
    event["response_body"] = value
    set_note(event, "response", response_note)
    if _size(event, deadline) <= max_bytes:
        return True
    del event["response_body"]
    return False


def _truncate(
    event: dict[str, Any],
    text: str,
    response_note: dict[str, Any],
    max_bytes: int,
    deadline: float | None,
) -> bool:
    """Attach the head and tail of text that fit, with the marker that says so."""
    total = len(text.encode("utf-8"))
    marker: dict[str, Any] = {
        "body_truncated": True,
        "body_bytes_total": total,
        "body_bytes_dropped": total,
        "head": "",
        "tail": "",
    }
    truncated_note = {**response_note, "state": STATE_TRUNCATED}
    if not _fits_with(event, marker, truncated_note, max_bytes, deadline):
        return False

    # The slices cost their escaped length, and the count of dropped bytes only shrinks.
    room = max_bytes - _size(event, deadline)
    head_room = room * HEAD_PERCENT // 100
    head = clip_text(text, head_room, head_room)
    tail = _clip_tail(text[len(head) :], room - head_room)
    marker["head"] = head
    marker["tail"] = tail
    marker["body_bytes_dropped"] = total - len(head.encode("utf-8")) - len(tail.encode("utf-8"))
    if _size(event, deadline) <= max_bytes:
        return True
    del event["response_body"]
    return False


def _clip_tail(text: str, max_bytes: int) -> str:
    """The longest end of text whose escaped form fits max_bytes."""
    end = text[max(len(text) - max_bytes, 0) :]
    # Each character escapes on its own, so the reversed text clips the same way.
    return clip_text(end[::-1], max_bytes, max_bytes)[::-1]


def _reductions(value: Any, deadline: float | None) -> Iterator[Any]:
    for limit in ARGUMENT_CHAR_LIMITS:
        check_deadline(deadline)
        if isinstance(value, list):
            yield [_reduce_mcp(item, limit) for item in value if isinstance(item, dict)]
        else:
            yield _reduce_mcp(value, limit)


def _reduce_mcp(message: dict[str, Any], limit: int) -> dict[str, Any]:
    """A JSON-RPC response cut to its id, its error, and the result's names, flags and text."""
    reduced = {key: message[key] for key in MCP_ENVELOPE_KEYS if key in message}
    error = message.get("error")
    if isinstance(error, dict):
        kept = {"code": error["code"]} if "code" in error else {}
        if isinstance(error.get("message"), str):
            kept["message"] = clip_text(error["message"], limit)
        reduced["error"] = kept
    result = message.get("result")
    if isinstance(result, dict):
        reduced["result"] = _reduce_result(result, limit)
    return reduced


def _reduce_result(result: dict[str, Any], limit: int) -> dict[str, Any]:
    kept: dict[str, Any] = {"isError": result["isError"]} if "isError" in result else {}
    for key in MCP_LISTING_KEYS:
        items = result.get(key)
        if isinstance(items, list):
            kept[key] = [_listing_item(item, limit) for item in items if isinstance(item, dict)]
    if isinstance(result.get("nextCursor"), str):
        kept["nextCursor"] = clip_text(result["nextCursor"], limit)
    content = result.get("content")
    if isinstance(content, list):
        kept["content"] = [_content_item(item, limit) for item in content if isinstance(item, dict)]
    return kept


def _listing_item(item: dict[str, Any], limit: int) -> dict[str, Any]:
    kept = {key: item[key] for key in MCP_LISTING_ITEM_KEYS if key in item}
    if isinstance(item.get("description"), str):
        kept["description"] = clip_text(item["description"], limit)
    return kept


def _content_item(item: dict[str, Any], limit: int) -> dict[str, Any]:
    kept: dict[str, Any] = {"type": item["type"]} if "type" in item else {}
    if isinstance(item.get("text"), str):
        kept["text"] = clip_text(item["text"], limit)
    return kept
