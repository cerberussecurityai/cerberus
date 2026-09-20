import base64
import json

from helpers import load_case

from cerberus_agentcore_interceptor import envelope as env


def test_mcp_request_is_parsed_with_its_raw_body():
    parsed = env.parse(load_case("mcp-tools-call-lambda")["input"])
    assert parsed.kind == env.MCP
    assert parsed.phase == env.REQUEST
    assert parsed.supported_version
    assert parsed.path == "/mcp"
    assert parsed.method == "POST"
    assert json.loads(parsed.raw_body)["method"] == "tools/call"


def test_http_request_is_parsed():
    parsed = env.parse(load_case("inference-chat")["input"])
    assert parsed.kind == env.HTTP
    assert parsed.phase == env.REQUEST
    assert parsed.path == "/v1/chat/completions"


def test_phase_is_read_from_the_response_value_not_the_key():
    request = env.parse(load_case("mcp-tools-call-lambda")["input"])
    assert "gatewayResponse" in request.shape
    assert request.shape["gatewayResponse"] is None
    assert request.phase == env.REQUEST

    response = env.parse(load_case("mcp-tools-call-response-phase")["input"])
    assert response.phase == env.RESPONSE


def test_http_response_phase_has_no_request():
    parsed = env.parse(load_case("inference-chat-response-phase")["input"])
    assert parsed.phase == env.RESPONSE
    assert parsed.request is None
    assert parsed.headers == {}


def test_unsupported_version_is_reported_not_raised():
    parsed = env.parse(load_case("unknown-input-version")["input"])
    assert parsed.version == "2.0"
    assert not parsed.supported_version
    assert parsed.kind == env.MCP


def test_unknown_shape_key_keeps_the_key_for_the_echo():
    parsed = env.parse({"interceptorInputVersion": "1.0", "grpc": {"gatewayRequest": {}}})
    assert parsed.kind == ""
    assert parsed.shape_key == "grpc"


def test_junk_input_parses_to_an_empty_envelope():
    for value in (None, [], "text", 7, {}, {"interceptorInputVersion": "1.0"}):
        parsed = env.parse(value)
        assert parsed.kind == ""
        assert parsed.request is None


def test_headers_are_matched_case_insensitively():
    headers = {"user-agent": "OpenAI/Python", "X-Amzn-Trace-Id": "Root=1-x"}
    assert env.header(headers, "User-Agent") == "OpenAI/Python"
    assert env.header(headers, "x-amzn-trace-id") == "Root=1-x"
    assert env.header(headers, "absent") == ""
    assert env.header(None, "User-Agent") == ""


def test_gateway_arn_yields_host_region_and_account():
    context = env.gateway_context(
        {
            "client_context": {
                "custom": {
                    "GATEWAY_ARN": (
                        "arn:aws:bedrock-agentcore:eu-west-1:123456789012:gateway/gw-abc"
                    ),
                    "REQUEST_ID": "req-1",
                    "SOURCE_IP": "192.0.2.5",
                }
            }
        }
    )
    assert context.region == "eu-west-1"
    assert context.account_id == "123456789012"
    assert context.gateway_id == "gw-abc"
    assert context.host == "gw-abc.gateway.bedrock-agentcore.eu-west-1.amazonaws.com"


def test_unparseable_gateway_arn_yields_no_host():
    context = env.gateway_context({"client_context": {"custom": {"GATEWAY_ARN": "not-an-arn"}}})
    assert context.gateway_id == ""
    assert context.host == ""


def test_http_body_is_base64_json():
    parsed = env.parse(load_case("passthrough-echo")["input"])
    body, reason = env.request_body(parsed)
    assert reason == ""
    assert isinstance(body, dict)


def test_body_reasons():
    def http_body(raw):
        envelope = {
            "interceptorInputVersion": "1.0",
            "http": {"gatewayRequest": {"path": "/x", "httpMethod": "POST", "body": raw}},
        }
        return env.request_body(env.parse(envelope))

    assert http_body(base64.b64encode(b"nope").decode()) == (None, env.BODY_NOT_JSON)
    assert http_body(base64.b64encode(b"[1,2]").decode()) == (None, env.BODY_NOT_OBJECT)
    assert http_body("!!!not base64!!!") == (None, env.BODY_DECODE_ERROR)
    assert http_body("") == (None, env.BODY_EMPTY)
    assert http_body(None) == (None, env.BODY_EMPTY)


def test_mcp_body_falls_back_to_the_raw_body():
    envelope = {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {"path": "/mcp", "httpMethod": "POST", "body": None},
            "rawGatewayRequest": {"body": '{"jsonrpc":"2.0","method":"ping"}'},
        },
    }
    body, reason = env.request_body(env.parse(envelope))
    assert reason == ""
    assert body["method"] == "ping"


def test_response_phase_has_no_request_body():
    parsed = env.parse(load_case("mcp-tools-call-response-phase")["input"])
    assert env.request_body(parsed) == (None, env.BODY_EMPTY)
