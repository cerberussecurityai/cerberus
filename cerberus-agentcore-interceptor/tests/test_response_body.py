import base64
import gzip
import json
import zlib
from time import monotonic

import pytest
from cerberus_core import SENSITIVE_HEADERS
from helpers import TIMESTAMP, LambdaContext, load_case, options

from cerberus_agentcore_interceptor import CaptureDeadlineExceeded, bounding, response_body
from cerberus_agentcore_interceptor import envelope as envelope_mod
from cerberus_agentcore_interceptor.mapper import RESPONSE_FLOOR_BYTES, response_event
from cerberus_agentcore_interceptor.sanitize import ECHOED_HEADER_KEYS

MAX = bounding.DEFAULT_MAX_EVENT_BYTES


def http_input(body, content_type="application/json"):
    """An http RESPONSE input. A bytes body is base64-encoded, as the gateway sends it."""
    if isinstance(body, bytes):
        body = base64.b64encode(body).decode()
    response = {"statusCode": 200, "headers": None, "body": body}
    if content_type is not None:
        response["contentType"] = content_type
    return {
        "interceptorInputVersion": "1.0",
        "http": {"gatewayRequest": None, "gatewayResponse": response},
    }


def mcp_input(body):
    case = load_case("mcp-tools-call-lambda-response")
    case["input"]["mcp"]["gatewayResponse"]["body"] = body
    return case["input"]


def read(given, keys=()):
    return response_body.read(envelope_mod.parse(given), keys)


def event_for(given, case_name="mcp-tools-call-lambda-response", deadline=None, **overrides):
    case = load_case(case_name)
    return response_event(
        envelope_mod.parse(given),
        envelope_mod.gateway_context(LambdaContext(case["client_context"])),
        options(case, **overrides),
        TIMESTAMP,
        deadline=deadline,
    )


def note(event):
    return event["custom_data"]["agentcore"]["response"]


def chunk(i):
    return {"i": i, "echo": {"canary": "c-" + "x" * 40, "stream": True}}


def tool_result(*texts, **result):
    content = [{"type": "text", "text": text} for text in texts]
    return {"jsonrpc": "2.0", "id": 1, "result": {"content": content, **result}}


def test_a_json_body_is_captured_whole_and_sanitized():
    value, given = read(http_input(b'{"ok": true, "api_key": "sk-live"}'))
    assert value == {"ok": True, "api_key": "[REDACTED]"}
    assert given == {"state": "captured", "content_type": "application/json"}


def test_a_json_list_is_captured():
    value, given = read(http_input(b'[1, {"token": "t"}]'))
    assert value == [1, {"token": "[REDACTED]"}]
    assert given["state"] == "captured"


def test_any_content_type_naming_json_is_parsed():
    value, given = read(http_input(b'{"a": 1}', "Application/Problem+JSON; charset=utf-8"))
    assert value == {"a": 1}
    assert given["content_type"] == "Application/Problem+JSON; charset=utf-8"


@pytest.mark.parametrize(
    ("body", "content_type", "reason"),
    [
        (None, "application/json", "absent"),
        ("", "application/json", "empty"),
        (b"  \n", "application/json", "empty"),
        ("!!!not base64!!!", "application/json", "decode_error"),
        (7, "application/json", "decode_error"),
        (b"nope", "application/json", "not_json"),
        (b"42", "application/json", "not_object"),
        (b"<html></html>", "text/html", "unsupported_type"),
        (b"plain words", None, "unsupported_type"),
        (b'"OK"', None, "not_object"),
    ],
)
def test_http_bodies_that_are_omitted_say_why(body, content_type, reason):
    value, given = read(http_input(body, content_type))
    assert value is None
    assert given["state"] == "omitted"
    assert given["reason"] == reason


def test_a_missing_body_key_is_absent():
    given = http_input(b"{}")
    del given["http"]["gatewayResponse"]["body"]
    assert read(given) == (
        None,
        {"state": "omitted", "reason": "absent", "content_type": "application/json"},
    )


def test_a_gzip_body_is_skipped():
    value, given = read(http_input(gzip.compress(b'{"secret": "s"}')))
    assert value == {"body_skipped_encoding": "gzip"}
    assert given == {"state": "skipped", "content_type": "application/json"}


def test_an_event_stream_is_captured_as_sanitized_text():
    stream = b'data: {"token": "t", "i": 0}\n\ndata: [DONE]\n\n'
    value, given = read(http_input(stream, "text/event-stream; charset=utf-8"))
    assert value == 'data: {"token":"[REDACTED]","i":0}\n\ndata: [DONE]\n\n'
    assert given["state"] == "captured"


def test_an_event_stream_that_is_not_utf8_is_decoded_with_replacement():
    value, _ = read(http_input(b"data: caf\xe9\n\n", "text/event-stream"))
    assert value == "data: caf\ufffd\n\n"


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(zlib.compress(b'data: {"token": "t"}\n\n'), id="deflate"),
        pytest.param(b'!T\x00\x04data: {"token": "t"}\n\n\x03', id="brotli"),
        pytest.param(b'(\xb5/\xfd$\x16\xb1\x00\x00data: {"token": "t"}\n\nA\xe4\\g', id="zstd"),
    ],
)
def test_an_event_stream_compressed_other_than_with_gzip_is_not_kept(body):
    value, given = read(http_input(body, "text/event-stream"))
    assert value is None
    assert given["state"] == "omitted"
    assert given["reason"] == "decode_error"


def test_an_untyped_body_is_read_as_json_then_as_sse():
    assert read(http_input(b'{"a": 1}', None))[0] == {"a": 1}
    for framing in (
        b"data: x\n\n",
        b"event: e\ndata: x\n\n",
        b": ping\n\n",
        b"id: 1\n",
        b"retry: 9\n",
    ):
        value, given = read(http_input(b"\n" + framing, None))
        assert value == "\n" + framing.decode(), framing
        assert given == {"state": "captured"}


def test_the_content_type_is_clipped():
    _, given = read(http_input(b"{}", "application/json; " + "x" * 500))
    assert len(given["content_type"]) == response_body.MAX_CONTENT_TYPE_CHARS


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            {"jsonrpc": "2.0", "id": 1, "result": {}},
            ({"jsonrpc": "2.0", "id": 1, "result": {}}, {}),
        ),
        (
            [{"jsonrpc": "2.0", "id": 1, "result": {}}],
            ([{"jsonrpc": "2.0", "id": 1, "result": {}}], {}),
        ),
        (
            '{"jsonrpc": "2.0", "id": 1, "result": {}}',
            ({"jsonrpc": "2.0", "id": 1, "result": {}}, {}),
        ),
        ('event: message\ndata: {"id": 1}\n\n', ('event: message\ndata: {"id":1}\n\n', {})),
        (None, (None, {"reason": "absent"})),
        ("", (None, {"reason": "empty"})),
        ("not json", (None, {"reason": "not_json"})),
        ("5", (None, {"reason": "not_object"})),
        (5, (None, {"reason": "not_object"})),
    ],
)
def test_mcp_bodies(body, expected):
    value, given = read(mcp_input(body))
    want_value, want_note = expected
    assert value == want_value
    assert given == {"state": "omitted" if want_value is None else "captured", **want_note}


def test_an_mcp_response_without_a_body_is_absent():
    given = mcp_input(None)
    del given["mcp"]["gatewayResponse"]["body"]
    event = event_for(given)
    assert "response_body" not in event
    assert note(event) == {"state": "omitted", "reason": "absent"}
    assert event["status_code"] == 200
    assert event["body"]["method"] == "tools/call"


def test_sse_frames_are_key_sanitized_and_framing_is_kept():
    text = 'event: message\r\ndata: {"result":{"api_key":"sk-1","name":"x"}}\r\n\r\n'
    assert response_body.sanitize_sse(text, ()) == (
        'event: message\r\ndata: {"result":{"api_key":"[REDACTED]","name":"x"}}\r\n\r\n'
    )


def test_sse_lines_that_are_not_json_frames_are_left_alone():
    text = ': keep-alive\nid: 7\nretry: 3000\ndata: [DONE]\ndata: 42\ndata: {"token": cut\n\n'
    assert response_body.sanitize_sse(text, ()) == text


def test_an_sse_data_line_without_a_space_is_written_back_with_one():
    assert (
        response_body.sanitize_sse('data:{"token":"t"}\n', ()) == 'data: {"token":"[REDACTED]"}\n'
    )


def test_an_sse_event_split_over_data_lines_is_sanitized_whole():
    payload = json.dumps({"headers": {"authorization": "Bearer sk-1"}, "password": "p"}, indent=2)
    lines = "".join(f"data: {line}\r\n" for line in payload.split("\n"))
    value, _ = read(http_input(f"event: echo\r\nid: 1\r\n{lines}\r\n".encode(), None))
    assert value == (
        "event: echo\r\nid: 1\r\n"
        'data: {"headers":{"authorization":"[REDACTED]"},"password":"[REDACTED]"}\r\n\r\n'
    )


@pytest.mark.parametrize(
    "text,expected",
    [
        ('data: {"a":\rdata: 1}\n\ndata: {"ok":2}\n\n', 'data: {"a":1}\n\ndata: {"ok":2}\n\n'),
        ("data: {\n: c\rdata: }\n\n", ": c\rdata: {}\n\n"),
    ],
)
def test_a_joined_event_keeps_its_blank_line_when_line_endings_are_mixed(text, expected):
    assert response_body.sanitize_sse(text, ()) == expected


def test_data_lines_that_are_not_json_together_are_sanitized_one_by_one():
    text = 'data: {"token":"t"}\ndata: {"n":1}\n\n'
    assert response_body.sanitize_sse(text, ()) == 'data: {"token":"[REDACTED]"}\ndata: {"n":1}\n\n'


def test_sse_lines_ended_by_a_bare_cr_are_sanitized():
    text = 'data: {"password":"hunter2","n":1}\r\rdata: {"token":"tok-abc"}\r\r'
    assert response_body.sanitize_sse(text, ()) == (
        'data: {"password":"[REDACTED]","n":1}\r\rdata: {"token":"[REDACTED]"}\r\r'
    )


def test_sse_text_and_the_content_type_are_made_storable():
    body = b'event: a\x00b\ndata: {"t": "\\ud800"}\n\n'
    value, given = read(http_input(body, "text/event-stream\x00"))
    assert value == 'event: a\ufffdb\ndata: {"t":"\ufffd"}\n\n'
    assert given["content_type"] == "text/event-stream\ufffd"


def flip_clock_at_call(monkeypatch, name, call=1):
    """Count calls to a response_body function; the clock passes 1.0 from call number `call`."""
    calls = [0]
    real = getattr(response_body, name)

    def counted(*args):
        calls[0] += 1
        return real(*args)

    monkeypatch.setattr(response_body, name, counted)
    monkeypatch.setattr(bounding, "monotonic", lambda: 2.0 if calls[0] >= call else 0.0)
    return calls


@pytest.mark.parametrize(
    "given",
    [
        http_input(b'data: {"a": 1}\n\n' * 1000, "text/event-stream"),
        mcp_input(tool_result(*['{"a": 1}'] * 1000)),
    ],
    ids=["sse", "mcp"],
)
def test_short_payloads_add_up_to_a_deadline_check(monkeypatch, given):
    calls = flip_clock_at_call(monkeypatch, "sanitize_storable", 2)
    with pytest.raises(CaptureDeadlineExceeded):
        response_body.read(envelope_mod.parse(given), (), 1.0)
    assert 2 <= calls[0] < 1000


def test_short_sse_events_share_their_deadline_checks(monkeypatch):
    reads = [0]

    def monotonic():
        reads[0] += 1
        return 0.0

    events = 4 * bounding.VALUES_PER_CHECK
    given = http_input(b"data: {}\n\n" * events, "text/event-stream")
    monkeypatch.setattr(bounding, "monotonic", monotonic)
    response_body.read(envelope_mod.parse(given), (), 1.0)
    assert reads[0] < events / 100


def test_an_sse_event_stops_partway_through_its_data_lines(monkeypatch):
    data = ["data: [", *["data: 0,"] * 20 * bounding.VALUES_PER_CHECK, "data: 0]"]
    calls = flip_clock_at_call(monkeypatch, "_sse_payload")
    with pytest.raises(CaptureDeadlineExceeded):
        response_body.sanitize_sse("\n".join(data) + "\n\n", (), bounding.Ticker(1.0))
    assert 0 < calls[0] < len(data)


def test_the_reduce_ladder_stops_partway_through_a_dense_listing(monkeypatch):
    tools = [{"name": "t", "description": "d"}] * 20 * bounding.VALUES_PER_CHECK
    value = {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}
    calls = flip_clock_at_call(monkeypatch, "_listing_item")
    with pytest.raises(CaptureDeadlineExceeded):
        response_body.attach({}, value, {"state": "captured"}, MAX, True, 1.0)
    assert 0 < calls[0] < len(tools)


@pytest.mark.parametrize(
    "given",
    [
        mcp_input(tool_result(*['{"a": [1, {"token": "t"}]}'] * 2000)),
        http_input(json.dumps([{"a": [1, {"token": "t"}]}] * 5000).encode()),
        http_input(b'data: {"a": [1, {"token": "t"}]}\n\n' * 2000, "text/event-stream"),
    ],
    ids=["mcp", "json", "sse"],
)
def test_a_future_deadline_changes_no_response_event(given):
    assert event_for(given, deadline=monotonic() + 60) == event_for(given)


def test_mcp_result_text_holding_json_is_sanitized_in_place():
    body = tool_result('{"password": "hunter2", "n": 1}', '[{"token": "t"}]', "password: x", "42")
    value, _ = read(mcp_input(body))
    texts = [item["text"] for item in value["result"]["content"]]
    assert texts == [
        '{"password":"[REDACTED]","n":1}',
        '[{"token":"[REDACTED]"}]',
        "password: x",
        "42",
    ]


def test_mcp_result_text_holding_a_raw_nul_is_sanitized():
    value, _ = read(mcp_input(tool_result('{"password": "x\x00y", "n": "a\x00b"}')))
    assert value["result"]["content"][0]["text"] == '{"password":"[REDACTED]","n":"a\ufffdb"}'


def test_mcp_result_text_inside_an_sse_frame_is_sanitized():
    message = tool_result('{"secret": "s"}')
    value, _ = read(http_input(f"data: {json.dumps(message)}\n\n".encode(), "text/event-stream"))
    frame = json.loads(value[len("data: ") :])
    assert frame["result"]["content"][0]["text"] == '{"secret":"[REDACTED]"}'


def test_echoed_credential_headers_are_redacted():
    echoed = {
        "headers": {
            "Authorization": "AWS4-HMAC-SHA256 Credential=EXAMPLE",
            "X-Api-Key": "k",
            "x-auth-token": "a",
            "Proxy-Authorization": "p",
            "Cookie": "c",
            "Set-Cookie": "c",
            "HTTP_AUTHORIZATION": "w",
            "X-Amz-Security-Token": "t",
            "accept": "*/*",
        }
    }
    value, _ = read(http_input(json.dumps(echoed).encode()))
    redacted = {name for name, item in value["headers"].items() if item == "[REDACTED]"}
    assert redacted == set(echoed["headers"]) - {"accept"}


def test_echoed_header_keys_cover_every_core_sensitive_header():
    keys = {key.lower() for key in ECHOED_HEADER_KEYS}
    for name in SENSITIVE_HEADERS:
        assert name.lower() in keys
        assert name[len("HTTP_") :].replace("_", "-").lower() in keys


def test_extra_sensitive_keys_apply_to_responses():
    value, _ = read(http_input(b'{"member_number": "M-1", "plan": "gold"}'), ("member_number",))
    assert value == {"member_number": "[REDACTED]", "plan": "gold"}


def test_non_finite_numbers_become_strings():
    value, _ = read(http_input(b'{"a": 1e999, "b": -1e999, "c": NaN}'))
    assert value == {"a": "Infinity", "b": "-Infinity", "c": "NaN"}

    value, _ = read(http_input(b'data: {"n": 1e999}\n\n', "text/event-stream"))
    assert value == 'data: {"n":"Infinity"}\n\n'

    value, _ = read(mcp_input(tool_result('{"n": 1e999}')))
    assert value["result"]["content"][0]["text"] == '{"n":"Infinity"}'


def test_response_events_serialize_as_strict_json():
    body = {"jsonrpc": "2.0", "id": 1, "result": {"n": float("inf"), "text": "a\x00b\ud800c"}}
    event = event_for(mcp_input(body))
    strict = json.dumps(event, ensure_ascii=False, allow_nan=False).encode("utf-8")
    result = json.loads(strict)["response_body"]["result"]
    assert result == {"n": "Infinity", "text": "a\ufffdb\ufffdc"}


def test_http_response_events_serialize_as_strict_json():
    context = load_case("inference-chat-response")["client_context"]
    context["REQUEST_ID"] = "r\x00\ud800"
    event = response_event(
        envelope_mod.parse(http_input(b"{}")),
        envelope_mod.gateway_context(LambdaContext(context)),
        options({}),
        TIMESTAMP,
    )
    strict = json.loads(json.dumps(event, ensure_ascii=False, allow_nan=False).encode("utf-8"))
    assert strict["event_id"] == "r\ufffd\ufffd#response"
    assert strict["custom_data"]["agentcore"]["request_id"] == "r\ufffd\ufffd"


def test_a_small_response_is_attached_whole():
    event = event_for(mcp_input({"jsonrpc": "2.0", "id": 1, "result": {"isError": False}}))
    assert note(event) == {"state": "captured"}
    assert event["response_body"]["result"] == {"isError": False}


def test_an_mcp_listing_is_reduced_to_what_names_each_item():
    tools = [
        {
            "name": f"t___tool{index}",
            "title": f"Tool {index}",
            "description": "d" * 2000,
            "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
        }
        for index in range(100)
    ]
    body = {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools, "nextCursor": "page-2"}}
    event = event_for(mcp_input(body))

    assert note(event) == {"state": "reduced"}
    result = event["response_body"]["result"]
    assert [tool["name"] for tool in result["tools"]] == [tool["name"] for tool in tools]
    assert all(set(tool) == {"name", "title", "description"} for tool in result["tools"])
    assert {len(tool["description"]) for tool in result["tools"]} == {256}
    assert result["nextCursor"] == "page-2"
    assert bounding.size(event) <= MAX


@pytest.mark.parametrize(
    ("key", "item", "kept"),
    [
        ("prompts", {"name": "p", "title": "P", "arguments": [{"name": "a"}]}, ("name", "title")),
        (
            "resources",
            {"uri": "file:///r", "name": "r", "mimeType": "text/plain", "size": 10},
            ("uri", "name", "mimeType"),
        ),
        (
            "resourceTemplates",
            {"uriTemplate": "file:///{id}", "name": "r", "mimeType": "text/plain", "icons": []},
            ("uriTemplate", "name", "mimeType"),
        ),
    ],
)
def test_each_mcp_listing_keeps_what_names_its_items(key, item, kept):
    items = [{**item, "description": "d" * 2000} for _ in range(100)]
    event = event_for(mcp_input({"jsonrpc": "2.0", "id": 1, "result": {key: items}}))

    assert note(event) == {"state": "reduced"}
    expected = {**{name: item[name] for name in kept}, "description": "d" * 256}
    assert event["response_body"]["result"][key] == [expected] * 100


def test_a_json_rpc_batch_is_reduced_message_by_message():
    batch = [
        tool_result("x" * 40000),
        {"jsonrpc": "2.0", "id": 2, "error": {"code": -32603, "message": "m" * 40000}},
    ]
    event = event_for(mcp_input(batch))
    assert note(event) == {"state": "reduced"}
    assert event["response_body"] == [
        {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "x" * 4096}]}},
        {"jsonrpc": "2.0", "id": 2, "error": {"code": -32603, "message": "m" * 4096}},
    ]


def test_an_mcp_error_is_reduced_to_its_code_and_message():
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32602, "message": "m" * 70000, "data": {"trace": "t" * 70000}},
    }
    event = event_for(mcp_input(body))
    assert note(event) == {"state": "reduced"}
    assert event["response_body"] == {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32602, "message": "m" * 4096},
    }


def test_an_mcp_tool_result_keeps_its_flag_and_content_types():
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "isError": True,
            "content": [
                {"type": "text", "text": "x" * 70000},
                {"type": "image", "data": "i" * 70000},
            ],
            "structuredContent": {"rows": ["r" * 100] * 500},
        },
    }
    event = event_for(mcp_input(body))
    assert note(event) == {"state": "reduced"}
    assert event["response_body"]["result"] == {
        "isError": True,
        "content": [{"type": "text", "text": "x" * 4096}, {"type": "image"}],
    }


def test_an_mcp_response_reduction_cannot_fit_is_truncated():
    event = event_for(mcp_input(tool_result(*["y" * 64] * 5000)))
    assert note(event) == {"state": "truncated"}
    assert event["response_body"]["head"].startswith('{"jsonrpc":"2.0","id":1,"result"')
    assert event["response_body"]["tail"].endswith('"}]}}')
    assert bounding.size(event) <= MAX


def test_a_large_json_body_is_truncated_to_a_head_and_a_tail():
    rows = [{"id": index, "item": "widget", "token": "t"} for index in range(5000)]
    event = event_for(http_input(json.dumps({"rows": rows}).encode()), "inference-chat-response")

    marker = event["response_body"]
    text = json.dumps(
        {"rows": [{**row, "token": "[REDACTED]"} for row in rows]},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    assert note(event) == {"state": "truncated", "content_type": "application/json"}
    assert marker["body_truncated"] is True
    assert text.startswith(marker["head"])
    assert text.endswith(marker["tail"])
    assert marker["body_bytes_total"] == len(text.encode("utf-8"))
    assert marker["body_bytes_dropped"] == len(text) - len(marker["head"]) - len(marker["tail"])
    assert 1.4 < len(marker["head"]) / len(marker["tail"]) < 1.6
    assert MAX - 64 < bounding.size(event) <= MAX


def test_truncation_measures_escaped_text_and_counts_utf8_bytes():
    text = "é🙂" * 40000
    event = event_for(
        http_input(json.dumps({"t": text}, ensure_ascii=False).encode()), "inference-chat-response"
    )

    marker = event["response_body"]
    whole = json.dumps({"t": text}, ensure_ascii=False, separators=(",", ":"))
    assert note(event)["state"] == "truncated"
    assert marker["body_bytes_total"] == len(whole.encode("utf-8"))
    kept = len(marker["head"].encode("utf-8")) + len(marker["tail"].encode("utf-8"))
    assert marker["body_bytes_dropped"] == marker["body_bytes_total"] - kept
    assert whole.endswith(marker["tail"])
    assert bounding.size(event) <= MAX


def test_an_event_stream_is_truncated_never_reduced():
    stream = "".join(f"data: {json.dumps(chunk(index))}\n\n" for index in range(2000))
    event = event_for(http_input(stream.encode(), "text/event-stream"), "inference-chat-response")
    marker = event["response_body"]
    assert note(event)["state"] == "truncated"
    assert marker["head"].startswith('data: {"i":0,')
    assert marker["tail"].endswith('"stream":true}}\n\n')
    assert bounding.size(event) <= MAX


@pytest.mark.parametrize("body", [b'{"a": "' + b"z" * 2000 + b'"}', gzip.compress(b"{}")])
def test_a_response_with_no_room_is_shed(body):
    event = event_for(http_input(body), "inference-chat-response", max_event_bytes=560)
    assert "response_body" not in event
    assert note(event) == {"state": "shed", "reason": "size", "content_type": "application/json"}
    assert event["status_code"] == 200
    assert bounding.size(event) <= 560


@pytest.mark.parametrize("cap", [1024, 2048, 4096, 8192, 16384, MAX])
@pytest.mark.parametrize("kind", ["mcp", "json", "sse"])
def test_every_response_event_fits_the_cap(cap, kind):
    if kind == "mcp":
        given = mcp_input(tool_result("é" * 90000))
    elif kind == "json":
        given = http_input(json.dumps({"rows": [chunk(index) for index in range(3000)]}).encode())
    else:
        stream = "".join(f"data: {json.dumps(chunk(index))}\n\n" for index in range(3000))
        given = http_input(stream.encode(), "text/event-stream")
    event = event_for(given, max_event_bytes=cap)
    assert event is not None
    assert bounding.size(event) <= cap


def large_request_input(response, arguments=None):
    given = mcp_input(response)
    request = given["mcp"]["gatewayRequest"]
    if arguments is None:
        arguments = {f"blob{index}": "a" * 7000 for index in range(7)}
    request["body"]["params"]["arguments"] = arguments
    given["mcp"]["rawGatewayRequest"] = {"body": json.dumps(request["body"])}
    return given


def test_a_large_request_leaves_the_response_its_floor():
    response = tool_result("r" * 20000)
    event = event_for(large_request_input(response))

    agentcore = event["custom_data"]["agentcore"]
    assert agentcore["body"]["state"] == "reduced"
    assert agentcore["response"] == {"state": "captured"}
    assert event["response_body"] == response
    assert bounding.size(event) <= MAX


def test_the_request_side_keeps_its_room_when_the_response_is_omitted():
    event = event_for(large_request_input(None))
    assert event["custom_data"]["agentcore"]["body"] == {"state": "captured"}
    assert note(event)["reason"] == "absent"


def test_the_response_room_is_at_least_the_floor_after_a_refit():
    event = event_for(large_request_input(tool_result("r" * 90000)))
    del event["response_body"]
    assert MAX - bounding.size(event) >= RESPONSE_FLOOR_BYTES


def test_a_response_that_fits_beside_a_large_request_leaves_it_whole():
    response = tool_result("ok")
    event = event_for(large_request_input(response))

    agentcore = event["custom_data"]["agentcore"]
    assert agentcore["body"] == {"state": "captured"}
    assert agentcore["response"] == {"state": "captured"}
    assert event["response_body"] == response
    del event["response_body"]
    assert MAX - bounding.size(event) < RESPONSE_FLOOR_BYTES


def test_a_cap_under_twice_the_floor_splits_it_evenly():
    cap = 12288
    given = large_request_input(tool_result("r" * 20000), {"a": "a" * 6000})
    event = event_for(given, max_event_bytes=cap)
    del event["response_body"]
    assert cap - RESPONSE_FLOOR_BYTES < bounding.size(event) <= cap // 2


@pytest.mark.parametrize("length", range(0, 200, 3))
def test_an_mcp_event_at_the_smallest_cap_survives_its_response(length):
    given = mcp_input(tool_result("r" * 5000))
    given["mcp"]["gatewayRequest"]["body"]["params"]["arguments"] = {"a": "x" * length}
    event = event_for(given, max_event_bytes=1024)
    assert event is not None
    assert bounding.size(event) <= 1024


def test_capture_bodies_off_sends_status_and_notes_only():
    event = event_for(mcp_input({"jsonrpc": "2.0", "id": 1, "result": {}}), capture_bodies=False)
    assert "response_body" not in event
    assert "body" not in event
    assert note(event) == {"state": "disabled"}
    assert event["custom_data"]["agentcore"]["body"] == {"state": "disabled"}
    assert event["status_code"] == 200

    event = event_for(http_input(b"{}"), "inference-chat-response", capture_bodies=False)
    assert note(event) == {"state": "disabled", "content_type": "application/json"}
    assert event["status_code"] == 200


def test_a_passed_deadline_stops_the_response_ladder():
    with pytest.raises(CaptureDeadlineExceeded):
        response_body.attach({}, "x" * 1000, {"state": "captured"}, 100, False, monotonic() - 1)
