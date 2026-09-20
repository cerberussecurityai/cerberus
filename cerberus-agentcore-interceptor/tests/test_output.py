from helpers import load_case

from cerberus_agentcore_interceptor import envelope as env
from cerberus_agentcore_interceptor.output import (
    OUTPUT_VERSION,
    is_valid_output,
    passthrough,
)


def out(name: str) -> dict:
    return passthrough(env.parse(load_case(name)["input"]))


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
    case = load_case("mcp-tools-call-response-phase")
    body = case["input"]["mcp"]["gatewayResponse"]["body"]
    assert out("mcp-tools-call-response-phase") == {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "mcp": {"transformedGatewayResponse": {"body": body}},
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
