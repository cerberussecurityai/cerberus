import base64
import gzip
import json
from time import monotonic

import pytest
from cerberus_core import SENSITIVE_HEADERS
from helpers import load_case

from cerberus_agentcore_interceptor import CaptureDeadlineExceeded, response_body
from cerberus_agentcore_interceptor import envelope as envelope_mod
from cerberus_agentcore_interceptor.sanitize import ECHOED_HEADER_KEYS


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


@pytest.mark.parametrize(
    "given",
    [
        http_input(b'data: {"a": 1}\n\n' * 1000, "text/event-stream"),
        mcp_input(tool_result(*['{"a": 1}'] * 1000)),
    ],
    ids=["sse", "mcp"],
)
def test_reading_stops_at_the_deadline_after_one_sanitizing_pass(monkeypatch, given):
    clock = [0.0]
    real = response_body.sanitize_body

    def sanitize_body(body, keys):
        clock[0] += 1
        return real(body, keys)

    monkeypatch.setattr("cerberus_agentcore_interceptor.bounding.monotonic", lambda: clock[0])
    monkeypatch.setattr(response_body, "sanitize_body", sanitize_body)
    with pytest.raises(CaptureDeadlineExceeded):
        response_body.read(envelope_mod.parse(given), (), 0.5)
    assert clock[0] == 1


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


def test_a_passed_deadline_stops_the_response_ladder():
    with pytest.raises(CaptureDeadlineExceeded):
        response_body.attach({}, "x" * 1000, {"state": "captured"}, 100, False, monotonic() - 1)
