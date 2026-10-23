import json
import random
from typing import Any

import pytest
from helpers import load_case, runtime_encode

from cerberus_agentcore_interceptor import envelope as env
from cerberus_agentcore_interceptor.output import (
    OUTPUT_VERSION,
    encodable,
    is_valid_output,
    passthrough,
)

LONE_SURROGATE_CALL = (
    '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t", '
    '"arguments": {"message": "Party \\ud83c", "emoji": "\\ud83c\\udf89"}}}'
)


def out(name: str) -> dict:
    return passthrough(env.parse(load_case(name)["input"]))


def mcp_request(raw: str) -> dict:
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {"path": "/mcp", "httpMethod": "POST", "body": json.loads(raw)},
            "gatewayResponse": None,
            "rawGatewayRequest": {"body": raw},
        },
    }


def echoed(result: dict) -> Any:
    return result["mcp"]["transformedGatewayRequest"]["body"]


def test_http_passes_through_empty():
    assert out("inference-chat") == {"interceptorOutputVersion": OUTPUT_VERSION, "http": {}}
    assert out("passthrough-echo")["http"] == {}


def test_http_response_phase_passes_through_empty():
    assert out("inference-chat-response-phase") == {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "http": {},
    }


def test_mcp_echoes_the_request_body():
    case = load_case("mcp-tools-call-lambda")
    body = case["input"]["mcp"]["gatewayRequest"]["body"]
    assert out("mcp-tools-call-lambda") == {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "mcp": {"transformedGatewayRequest": {"body": body}},
    }


def test_mcp_echoes_the_response_body_at_response_phase():
    response = load_case("mcp-tools-call-response-phase")["input"]["mcp"]["gatewayResponse"]
    assert out("mcp-tools-call-response-phase") == {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "mcp": {
            "transformedGatewayResponse": {
                "body": response["body"],
                "statusCode": response["statusCode"],
            }
        },
    }


def test_mcp_never_returns_the_empty_form_when_it_has_a_body():
    # An empty mcp output is accepted and empties the payload behind a 200.
    for name in ("mcp-tools-call-lambda", "mcp-tools-list", "mcp-initialize", "mcp-prompts-get"):
        assert out(name)["mcp"] != {}


def test_mcp_echo_falls_back_to_the_raw_body_parsed():
    envelope = {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {"path": "/mcp", "httpMethod": "POST", "body": None},
            "rawGatewayRequest": {"body": '{"jsonrpc":"2.0","method":"ping","id":3}'},
        },
    }
    assert passthrough(env.parse(envelope))["mcp"] == {
        "transformedGatewayRequest": {"body": {"jsonrpc": "2.0", "method": "ping", "id": 3}}
    }


def test_a_json_rpc_batch_is_echoed_as_the_list_it_is():
    batch = [{"jsonrpc": "2.0", "method": "ping", "id": 1}, {"jsonrpc": "2.0", "method": "ping"}]
    envelope = {
        "interceptorInputVersion": "1.0",
        "mcp": {"gatewayRequest": {"path": "/mcp", "httpMethod": "POST", "body": batch}},
    }
    assert passthrough(env.parse(envelope))["mcp"]["transformedGatewayRequest"]["body"] == batch


def test_an_unknown_shape_is_echoed_under_its_own_key():
    envelope = {
        "interceptorInputVersion": "1.0",
        "grpc": {"gatewayRequest": {"body": {"x": 1}}, "gatewayResponse": None},
    }
    assert passthrough(env.parse(envelope)) == {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "grpc": {"transformedGatewayRequest": {"body": {"x": 1}}},
    }


def test_an_unrecognisable_envelope_uses_the_documented_pass_through():
    # Nothing to echo: the empty http form is the only one that means "keep it".
    for payload in (None, {}, {"interceptorInputVersion": "1.0"}, {"meta": {"id": 1}}):
        assert passthrough(env.parse(payload)) == {
            "interceptorOutputVersion": OUTPUT_VERSION,
            "http": {},
        }


def test_the_http_pass_through_is_not_shared_between_calls():
    first = passthrough(env.parse(load_case("inference-chat")["input"]))
    first["http"]["mutated"] = True
    assert passthrough(env.parse(load_case("inference-chat")["input"]))["http"] == {}


def test_the_response_echo_carries_the_status_code():
    envelope = {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": None,
            "gatewayResponse": {"body": {"result": {}}, "statusCode": 503},
        },
    }
    assert passthrough(env.parse(envelope))["mcp"]["transformedGatewayResponse"] == {
        "body": {"result": {}},
        "statusCode": 503,
    }


def test_a_string_mcp_body_is_echoed_as_the_call_it_encodes():
    envelope = {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {"body": '{"jsonrpc":"2.0","method":"ping","id":9}'},
            "gatewayResponse": None,
        },
    }
    assert passthrough(env.parse(envelope))["mcp"]["transformedGatewayRequest"]["body"] == {
        "jsonrpc": "2.0",
        "method": "ping",
        "id": 9,
    }


def test_nothing_to_echo_still_produces_a_valid_output():
    result = passthrough(env.parse({"interceptorInputVersion": "1.0", "mcp": {}}))
    assert result == {"interceptorOutputVersion": OUTPUT_VERSION, "mcp": {}}
    assert is_valid_output(result)


def test_every_fixture_produces_a_valid_output():
    for name in ("mcp-tools-call-lambda", "inference-chat", "unknown-input-version"):
        assert is_valid_output(out(name))


def test_is_valid_output_rejects_the_wrong_version_and_shape():
    assert not is_valid_output({"interceptorOutputVersion": "2.0", "http": {}})
    assert not is_valid_output({"http": {}})
    assert not is_valid_output("ok")
    assert not is_valid_output(None)


def test_a_string_body_too_deep_to_parse_echoes_like_any_unparseable_one():
    def echo(text):
        envelope = {
            "interceptorInputVersion": "1.0",
            "mcp": {"gatewayRequest": {"body": text}, "gatewayResponse": None},
        }
        return passthrough(env.parse(envelope))

    assert echo("[" * 100_000 + "]" * 100_000) == echo("not json")


def test_a_lone_surrogate_is_echoed_as_a_replacement_character():
    result = passthrough(env.parse(mcp_request(LONE_SURROGATE_CALL)))

    assert echoed(result)["params"]["arguments"] == {
        "message": "Party \ufffd",
        "emoji": "\U0001f389",
    }
    runtime_encode(result)


def test_a_lone_surrogate_in_a_key_is_replaced_too():
    result = passthrough(env.parse(mcp_request('{"id": 1, "params": {"\\udc00": 1}}')))
    assert echoed(result)["params"] == {"\ufffd": 1}


@pytest.mark.parametrize("carried", ["string body", "raw body only", "parsed body only"])
def test_a_lone_surrogate_is_replaced_however_the_body_arrives(carried):
    envelope = mcp_request(LONE_SURROGATE_CALL)
    mcp = envelope["mcp"]
    if carried == "string body":
        mcp["gatewayRequest"]["body"] = LONE_SURROGATE_CALL
        del mcp["rawGatewayRequest"]
    elif carried == "raw body only":
        mcp["gatewayRequest"]["body"] = None
    else:
        del mcp["rawGatewayRequest"]

    result = passthrough(env.parse(envelope))
    assert echoed(result)["params"]["arguments"]["message"] == "Party \ufffd"
    runtime_encode(result)


def test_a_surrogate_code_point_in_a_string_body_is_replaced():
    envelope = {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {"body": '{"id": 1, "note": "cut \ud83c"}'},
            "gatewayResponse": None,
        },
    }
    assert echoed(passthrough(env.parse(envelope)))["note"] == "cut \ufffd"


def test_the_response_echo_replaces_a_lone_surrogate():
    envelope = {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": None,
            "gatewayResponse": {"body": {"result": {"text": "cut \ud83c"}}, "statusCode": 200},
        },
    }
    result = passthrough(env.parse(envelope))

    assert result["mcp"]["transformedGatewayResponse"]["body"] == {"result": {"text": "cut \ufffd"}}
    runtime_encode(result)


def strict_json(data: bytes) -> Any:
    def refuse(token: str) -> Any:
        raise AssertionError(f"{token} is not JSON")

    return json.loads(data, parse_constant=refuse)


OVERFLOWING_CALL = (
    '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t", '
    '"arguments": {"big": 1e999, "small": -1E+400, "long": 1' + "0" * 400 + ".5}}}"
)


@pytest.mark.parametrize("carried", ["string body", "raw body only", "parsed body only"])
def test_an_overflowing_number_is_echoed_as_the_gateway_writes_it(carried):
    envelope = mcp_request(OVERFLOWING_CALL)
    mcp = envelope["mcp"]
    if carried == "string body":
        mcp["gatewayRequest"]["body"] = OVERFLOWING_CALL
        del mcp["rawGatewayRequest"]
    elif carried == "raw body only":
        mcp["gatewayRequest"]["body"] = None
    else:
        del mcp["rawGatewayRequest"]

    result = passthrough(env.parse(envelope))

    assert echoed(result)["params"]["arguments"] == {
        "big": "Infinity",
        "small": "-Infinity",
        "long": "Infinity",
    }
    strict_json(runtime_encode(result))


def test_a_nan_token_is_echoed_as_a_string():
    result = passthrough(env.parse(mcp_request('{"id": 1, "params": {"n": NaN}}')))
    assert echoed(result)["params"] == {"n": "NaN"}
    strict_json(runtime_encode(result))


def test_the_response_echo_writes_an_infinity_as_a_string():
    envelope = {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": None,
            "gatewayResponse": {"body": {"result": {"n": float("-inf")}}, "statusCode": 200},
        },
    }
    result = passthrough(env.parse(envelope))

    assert result["mcp"]["transformedGatewayResponse"]["body"] == {"result": {"n": "-Infinity"}}
    strict_json(runtime_encode(result))


@pytest.mark.parametrize(
    "raw",
    [
        '{"id": 1, "params": {"n": 1e308, "m": 1e-999, "k": 12345678901234567890}}',
        '{"id": 1, "params": {"note": "e100 and 9e123"}}',
    ],
)
def test_a_finite_number_is_echoed_as_it_is(raw):
    envelope = mcp_request(raw)
    result = passthrough(env.parse(envelope))

    assert echoed(result) is envelope["mcp"]["gatewayRequest"]["body"]
    strict_json(runtime_encode(result))


@pytest.mark.parametrize(
    "raw",
    [
        '{"jsonrpc": "2.0", "id": 1, "method": "ping"}',
        '{"id": 1, "params": {"emoji": "\\ud83c\\udf89", "upper": "\\uD83C\\uDF89"}}',
        '{"id": 1, "params": {"text": "h\u00e9llo \U0001f389"}}',
    ],
)
def test_a_body_its_raw_text_clears_is_echoed_without_a_copy(raw):
    envelope = mcp_request(raw)
    assert echoed(passthrough(env.parse(envelope))) is envelope["mcp"]["gatewayRequest"]["body"]


@pytest.mark.parametrize(
    "raw,expected",
    [
        ('{"id": 1, "params": {"m": "\\\\ud83c\\udf89"}}', "\\ud83c\ufffd"),
        ('{"id": 1, "params": {"m": "\\\\\\\\ud83c\\udf89"}}', "\\\\ud83c\ufffd"),
        ('{"id": 1, "params": {"m": "x\\\\uD800\\uDC00"}}', "x\\uD800\ufffd"),
    ],
)
def test_an_escaped_backslash_does_not_hide_a_lone_surrogate(raw, expected):
    result = passthrough(env.parse(mcp_request(raw)))

    assert echoed(result)["params"]["m"] == expected
    runtime_encode(result)


# JSON text pieces that make and unmake surrogate escapes when run together.
SURROGATE_PIECES = [
    "\\ud83c",
    "\\udf89",
    "\\uD800",
    "\\uDC00",
    "\\\\",
    "u",
    "ud83c",
    "d83c",
    "x",
    "\u00e9",
    '\\"',
    "\ud83c",
]


def test_text_the_pre_filter_clears_always_encodes():
    pick = random.Random(0)
    checked = 0
    while checked < 20_000:
        key = "".join(pick.choices(SURROGATE_PIECES, k=pick.randint(0, 3)))
        text = "".join(pick.choices(SURROGATE_PIECES, k=pick.randint(1, 8)))
        raw = f'{{"{key}": "{text}"}}'
        try:
            value = json.loads(raw)
        except ValueError:
            continue
        checked += 1
        runtime_encode(encodable(value, raw))


def test_text_that_only_looks_like_a_surrogate_escape_is_left_as_it_is():
    raw = '{"path": "C:\\\\ud83c"}'
    value = json.loads(raw)
    assert encodable(value, raw) is value


def test_a_value_too_deep_to_check_is_returned_as_it_is():
    deep: Any = "cut \ud83c"
    for _ in range(100_000):
        deep = [deep]
    assert encodable(deep) is deep
