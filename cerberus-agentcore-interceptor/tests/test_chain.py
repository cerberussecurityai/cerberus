"""Chaining: the customer's interceptor decides, and our failures never skip it."""

import base64
import importlib
import json

import pytest
from helpers import LambdaContext, load_case
from test_handler import RecordingSink, _boom

from cerberus_agentcore_interceptor import chain as chain_mod
from cerberus_agentcore_interceptor import envelope as env
from cerberus_agentcore_interceptor import handler as handler_mod
from cerberus_agentcore_interceptor import metrics
from cerberus_agentcore_interceptor.chain import ChainClient
from cerberus_agentcore_interceptor.config import Config, ConfigError

CHAIN_ARN = "arn:aws:lambda:us-west-2:123456789012:function:customer-auth:live"
GATEWAY_ID = "example-gateway-abcdefghij"


class FakeLambda:
    def __init__(self, payload=None, function_error=None, raises=None):
        self.calls = []
        self._payload = payload
        self._function_error = function_error
        self._raises = raises

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        if self._raises is not None:
            raise self._raises
        response = {"StatusCode": 200, "Payload": json.dumps(self._payload).encode()}
        if self._function_error:
            response["FunctionError"] = self._function_error
        return response


class Throttled(Exception):
    def __init__(self):
        super().__init__("slow down")
        self.response = {"Error": {"Code": "TooManyRequestsException"}}


def mcp_output(body=None, status=None):
    shape = {}
    if status is not None:
        shape["transformedGatewayResponse"] = {"body": {"error": "denied"}, "statusCode": status}
    elif body is not None:
        shape["transformedGatewayRequest"] = {"body": body}
    return {"interceptorOutputVersion": "1.0", "mcp": shape}


def client(payload=None, **kwargs):
    fake = FakeLambda(payload=payload, **kwargs)
    return ChainClient(CHAIN_ARN, 5000, client=fake, sleep=lambda _: None), fake


def parsed(name="mcp-tools-call-lambda"):
    return env.parse(load_case(name)["input"])


def context(name="mcp-tools-call-lambda"):
    return LambdaContext(load_case(name)["client_context"])


# ============================================================================
# Classifying what the chained function answered
# ============================================================================


def test_an_unchanged_body_passes():
    body = load_case("mcp-tools-call-lambda")["input"]["mcp"]["gatewayRequest"]["body"]
    chain, _ = client(mcp_output(body))
    result = chain.invoke({}, context(), parsed())

    assert result.outcome == chain_mod.OUTCOME_PASSED
    assert result.body is None
    assert result.note == {"outcome": "passed"}


def test_a_changed_body_is_the_one_captured():
    chain, _ = client(mcp_output({"jsonrpc": "2.0", "method": "tools/call", "id": 1}))
    result = chain.invoke({}, context(), parsed())

    assert result.outcome == chain_mod.OUTCOME_TRANSFORMED
    assert result.body == {"jsonrpc": "2.0", "method": "tools/call", "id": 1}


def test_a_short_circuit_records_its_status():
    chain, _ = client(mcp_output(status=403))
    result = chain.invoke({}, context(), parsed())

    assert result.outcome == chain_mod.OUTCOME_SHORT_CIRCUIT
    assert result.note == {"outcome": "short_circuit", "status_code": 403}


def test_an_output_the_gateway_would_refuse_is_returned_unchanged():
    chain, _ = client({"not": "an output"})
    result = chain.invoke({}, context(), parsed())

    assert result.outcome == chain_mod.OUTCOME_INVALID_OUTPUT
    assert result.output == {"not": "an output"}
    assert not result.failed


def test_a_function_error_is_an_error_even_behind_a_200():
    chain, _ = client(mcp_output({}), function_error="Unhandled")
    result = chain.invoke({}, context(), parsed())

    assert result.outcome == chain_mod.OUTCOME_ERROR
    assert result.failed


def test_an_unreadable_payload_is_an_invalid_output():
    chain, fake = client(None)
    fake._payload = None
    result = chain.invoke({}, context(), parsed())
    assert result.outcome == chain_mod.OUTCOME_INVALID_OUTPUT


def test_an_invoke_failure_is_an_error():
    chain, _ = client(raises=RuntimeError("no such function"))
    assert chain.invoke({}, context(), parsed()).failed


# ============================================================================
# One invoke per interception
# ============================================================================


def test_the_chained_function_runs_once():
    chain, fake = client(mcp_output({}))
    chain.invoke({"interceptorInputVersion": "1.0"}, context(), parsed())
    assert len(fake.calls) == 1


def test_a_throttle_is_retried_twice_at_most():
    chain, fake = client(raises=Throttled())
    assert chain.invoke({}, context(), parsed()).failed
    assert len(fake.calls) == chain_mod.THROTTLE_ATTEMPTS


def test_anything_but_a_throttle_is_not_retried():
    chain, fake = client(raises=RuntimeError("read timeout"))
    chain.invoke({}, context(), parsed())
    assert len(fake.calls) == 1


def test_the_gateway_client_context_is_forwarded_unchanged():
    chain, fake = client(mcp_output({}))
    chain.invoke({}, context(), parsed())

    forwarded = json.loads(base64.b64decode(fake.calls[0]["ClientContext"]))
    assert forwarded["custom"] == load_case("mcp-tools-call-lambda")["client_context"]


def test_an_oversized_client_context_is_left_off_rather_than_failing():
    chain, fake = client(mcp_output({}))
    chain.invoke({}, LambdaContext({"PADDING": "x" * 5000}), parsed())
    assert "ClientContext" not in fake.calls[0]


def test_the_raw_event_is_what_the_chained_function_receives():
    chain, fake = client(mcp_output({}))
    event = load_case("mcp-tools-call-lambda")["input"]
    chain.invoke(event, context(), parsed())
    assert json.loads(fake.calls[0]["Payload"]) == event


# ============================================================================
# Configuration
# ============================================================================

MINIMAL = {"CERBERUS_FIREHOSE_STREAM": "s"}


def test_chaining_needs_gateway_ids_and_a_read_timeout():
    with pytest.raises(ConfigError, match="CERBERUS_GATEWAY_IDS"):
        Config.from_env({**MINIMAL, "CERBERUS_CHAIN_REQUEST_ARN": CHAIN_ARN})
    with pytest.raises(ConfigError, match="CERBERUS_CHAIN_READ_MS"):
        Config.from_env(
            {
                **MINIMAL,
                "CERBERUS_CHAIN_REQUEST_ARN": CHAIN_ARN,
                "CERBERUS_GATEWAY_IDS": GATEWAY_ID,
            }
        )


def test_a_chain_target_must_be_a_function_arn():
    with pytest.raises(ConfigError, match="Lambda function ARN"):
        Config.from_env(
            {
                **MINIMAL,
                "CERBERUS_CHAIN_REQUEST_ARN": "customer-auth",
                "CERBERUS_GATEWAY_IDS": GATEWAY_ID,
                "CERBERUS_CHAIN_READ_MS": "5000",
            }
        )


def test_a_full_chain_configuration():
    config = Config.from_env(
        {
            **MINIMAL,
            "CERBERUS_CHAIN_REQUEST_ARN": CHAIN_ARN,
            "CERBERUS_GATEWAY_IDS": f"{GATEWAY_ID}, other-gateway",
            "CERBERUS_CHAIN_READ_MS": "5000",
        }
    )
    assert config.chain_arn == CHAIN_ARN
    assert config.gateway_ids == (GATEWAY_ID, "other-gateway")
    assert config.chain_read_ms == 5000


# ============================================================================
# The handler with a chain
# ============================================================================


@pytest.fixture
def chained(monkeypatch):
    config = Config(
        streams=("s",),
        chain_arn=CHAIN_ARN,
        gateway_ids=(GATEWAY_ID,),
        chain_read_ms=5000,
    )
    monkeypatch.setattr(handler_mod, "CONFIG", config)
    monkeypatch.setattr(handler_mod, "OPTIONS", config.mapper_options("0.1.0"))
    sink = RecordingSink()
    monkeypatch.setattr(handler_mod, "SINK", sink)

    def install(payload=None, **kwargs):
        fake = FakeLambda(payload=payload, **kwargs)
        monkeypatch.setattr(
            handler_mod,
            "CHAIN",
            ChainClient(CHAIN_ARN, 5000, client=fake, sleep=lambda _: None),
        )
        return fake

    install.sink = sink
    return install


def invoke(name="mcp-tools-call-lambda"):
    case = load_case(name)
    return handler_mod.handler(case["input"], LambdaContext(case["client_context"]))


def test_the_chained_output_is_returned_unchanged(chained):
    answer = mcp_output({"jsonrpc": "2.0", "method": "tools/call", "id": 99})
    chained(answer)
    assert invoke() == answer


def test_the_transformed_body_is_what_gets_captured(chained):
    transformed = {"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {"name": "safe"}}
    chained(mcp_output(transformed))
    invoke()

    event = chained.sink.events[0]
    assert event["body"] == transformed
    assert event["custom_data"]["agentcore"]["chain"] == {"outcome": "transformed"}


def test_a_refused_request_is_still_captured_as_an_attempt(chained):
    chained(mcp_output(status=403))
    invoke()

    event = chained.sink.events[0]
    assert event["body"]["params"]["name"] == "echo___echo"
    assert event["custom_data"]["agentcore"]["chain"] == {
        "outcome": "short_circuit",
        "status_code": 403,
    }


def test_a_chain_error_is_captured_and_then_raised(chained):
    chained(raises=RuntimeError("chain is gone"))
    with pytest.raises(handler_mod.InterceptorError):
        invoke()
    assert chained.sink.events[0]["custom_data"]["agentcore"]["chain"] == {"outcome": "error"}


def test_an_unlisted_gateway_is_refused_before_the_chain_runs(chained):
    fake = chained(mcp_output({}))
    case = load_case("mcp-tools-call-lambda")
    context = dict(case["client_context"])
    context["GATEWAY_ARN"] = context["GATEWAY_ARN"].replace(GATEWAY_ID, "unlisted-gateway")

    with pytest.raises(handler_mod.InterceptorError):
        handler_mod.handler(case["input"], LambdaContext(context))
    assert fake.calls == []
    assert chained.sink.events == []


def test_the_error_text_names_nothing_a_customer_should_not_see(chained):
    chained(raises=RuntimeError("arn:aws:lambda:us-west-2:123456789012:function:secret"))
    with pytest.raises(handler_mod.InterceptorError) as raised:
        invoke()
    assert "arn:" not in str(raised.value)
    assert "123456789012" not in str(raised.value)


def test_a_raising_parser_still_invokes_the_chain_once(chained, monkeypatch):
    fake = chained(mcp_output({}))
    monkeypatch.setattr(handler_mod, "parse", _boom)
    handler_mod.handler(load_case("mcp-tools-call-lambda")["input"], context())
    assert len(fake.calls) == 1


def test_an_unknown_input_version_still_invokes_the_chain_once(chained):
    fake = chained(mcp_output({}))
    invoke("unknown-input-version")
    assert len(fake.calls) == 1
    assert chained.sink.events == []


def test_a_raising_mapper_leaves_the_chained_answer_alone(chained, monkeypatch):
    answer = mcp_output({"jsonrpc": "2.0", "id": 5, "method": "tools/call"})
    chained(answer)
    monkeypatch.setattr(handler_mod, "source_event", _boom)
    assert invoke() == answer


def test_the_response_phase_never_chains(chained):
    fake = chained(mcp_output({}))
    result = invoke("mcp-tools-call-response-phase")
    assert fake.calls == []
    assert "transformedGatewayResponse" in result["mcp"]


def test_an_invalid_chained_output_is_handed_back_as_it_came(chained):
    chained({"interceptorOutputVersion": "9.9"})
    assert invoke() == {"interceptorOutputVersion": "9.9"}
    assert chained.sink.events[0]["custom_data"]["agentcore"]["chain"] == {
        "outcome": "invalid_output"
    }


def test_without_a_chain_the_handler_answers_for_itself(monkeypatch):
    monkeypatch.setattr(handler_mod, "CHAIN", None)
    monkeypatch.setattr(handler_mod, "SINK", RecordingSink())
    assert "transformedGatewayRequest" in invoke()["mcp"]


def test_the_module_builds_a_chain_client_from_the_environment(monkeypatch):
    monkeypatch.setenv("CERBERUS_FIREHOSE_STREAM", "s")
    monkeypatch.setenv("CERBERUS_CHAIN_REQUEST_ARN", CHAIN_ARN)
    monkeypatch.setenv("CERBERUS_GATEWAY_IDS", GATEWAY_ID)
    monkeypatch.setenv("CERBERUS_CHAIN_READ_MS", "4000")
    reloaded = importlib.reload(handler_mod)
    try:
        assert reloaded.CHAIN is not None
        assert reloaded.CONFIG.gateway_ids == (GATEWAY_ID,)
    finally:
        monkeypatch.undo()
        importlib.reload(handler_mod)


def test_metrics_still_count_the_capture(chained):
    counts = []
    chained(mcp_output({}))
    original = metrics.count
    try:
        metrics.count = lambda name, reason="", **fields: counts.append(name)
        handler_mod.metrics.count = metrics.count
        invoke()
    finally:
        metrics.count = original
        handler_mod.metrics.count = original
    assert metrics.CAPTURED in counts
