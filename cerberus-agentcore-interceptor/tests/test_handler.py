"""The handler's contract: whatever fails, the caller's payload comes back intact."""

import importlib
import json

import pytest
from helpers import LambdaContext, case_names, load_case

from cerberus_agentcore_interceptor import handler as handler_mod
from cerberus_agentcore_interceptor import metrics, output
from cerberus_agentcore_interceptor.config import Config
from cerberus_agentcore_interceptor.sink import FirehoseSink


class RecordingSink(FirehoseSink):
    """A sink that records instead of writing, and can fail on demand."""

    def __init__(self, reason: str = "", raises: Exception | None = None):
        super().__init__(("stream",), 250, 500, client=object())
        self.events: list[dict] = []
        self.keys: list[str] = []
        self._reason = reason
        self._raises = raises

    def put(self, event, key):
        if self._raises is not None:
            raise self._raises
        self.events.append(event)
        self.keys.append(key)
        return self._reason


def _boom(*args, **kwargs):
    raise RuntimeError("boom")


@pytest.fixture
def sink(monkeypatch):
    recording = RecordingSink()
    monkeypatch.setattr(handler_mod, "SINK", recording)
    monkeypatch.setattr(handler_mod, "OPTIONS", Config(streams=("s",)).mapper_options("0.1.0"))
    return recording


@pytest.fixture
def counted(monkeypatch):
    counts: list[tuple[str, str]] = []
    monkeypatch.setattr(
        handler_mod.metrics,
        "count",
        lambda name, reason="", **fields: counts.append((name, reason)),
    )
    return counts


def invoke(name: str):
    case = load_case(name)
    return handler_mod.handler(case["input"], LambdaContext(case["client_context"]))


def test_mcp_request_is_captured_and_echoed(sink):
    case = load_case("mcp-tools-call-lambda")
    result = invoke("mcp-tools-call-lambda")

    assert result == {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayRequest": {"body": case["input"]["mcp"]["gatewayRequest"]["body"]}
        },
    }
    assert sink.events[0]["event_id"] == "request-id-01"
    assert sink.keys[0] == case["client_context"]["GATEWAY_ARN"]


def test_http_request_is_captured_and_passed_through(sink):
    assert invoke("inference-chat") == {"interceptorOutputVersion": "1.0", "http": {}}
    assert sink.events[0]["endpoint"] == "/v1/chat/completions"


@pytest.mark.parametrize("name", case_names())
def test_every_fixture_returns_a_valid_output(sink, name):
    assert output.is_valid_output(invoke(name))


@pytest.mark.parametrize("name", case_names())
def test_every_output_is_serializable(sink, name):
    json.dumps(invoke(name))


def test_response_phase_captures_nothing_and_echoes_the_response(sink, counted):
    response = load_case("mcp-tools-call-response-phase")["input"]["mcp"]["gatewayResponse"]
    result = invoke("mcp-tools-call-response-phase")

    assert result["mcp"]["transformedGatewayResponse"] == {
        "body": response["body"],
        "statusCode": response["statusCode"],
    }
    assert sink.events == []
    assert (metrics.UNEXPECTED_PHASE, "") in counted


def test_unknown_input_version_captures_nothing_and_echoes(sink, counted):
    result = invoke("unknown-input-version")
    assert result["mcp"]["transformedGatewayRequest"]["body"]["method"] == "tools/call"
    assert sink.events == []
    assert (metrics.UNKNOWN_INPUT_VERSION, "") in counted


def test_a_raising_parser_leaves_the_request_alone(sink, counted, monkeypatch):
    monkeypatch.setattr(handler_mod, "parse", _boom)
    result = handler_mod.handler(load_case("inference-chat")["input"], None)

    assert output.is_valid_output(result)
    assert sink.events == []
    assert (metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER) in counted


def test_a_raising_mapper_leaves_the_request_alone(sink, counted, monkeypatch):
    monkeypatch.setattr(handler_mod, "source_event", _boom)
    case = load_case("mcp-tools-call-lambda")
    result = handler_mod.handler(case["input"], LambdaContext(case["client_context"]))

    assert result["mcp"]["transformedGatewayRequest"] == {
        "body": case["input"]["mcp"]["gatewayRequest"]["body"]
    }
    assert (metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER) in counted


def test_a_raising_sink_leaves_the_request_alone(counted, monkeypatch):
    monkeypatch.setattr(handler_mod, "SINK", RecordingSink(raises=RuntimeError("firehose")))
    assert invoke("inference-chat") == {"interceptorOutputVersion": "1.0", "http": {}}
    assert (metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER) in counted


def test_a_dropped_record_is_counted_by_reason(counted, monkeypatch):
    monkeypatch.setattr(handler_mod, "SINK", RecordingSink(reason=metrics.REASON_THROTTLE))
    invoke("inference-chat")
    assert (metrics.CAPTURE_DROPPED, metrics.REASON_THROTTLE) in counted


def test_an_unboundable_event_is_dropped_not_raised(sink, counted, monkeypatch):
    monkeypatch.setattr(handler_mod, "source_event", lambda *args, **kwargs: None)
    assert output.is_valid_output(invoke("mcp-tools-call-lambda"))
    assert (metrics.CAPTURE_DROPPED, metrics.REASON_OVERSIZE) in counted


def test_a_missing_client_context_still_captures(sink):
    case = load_case("mcp-tools-call-lambda")
    handler_mod.handler(case["input"], None)
    assert sink.events[0]["event_id"] == ""


@pytest.mark.parametrize(
    "payload",
    [None, [], "text", 7, {}, {"interceptorInputVersion": "1.0"}, {"mcp": None}, {"http": {}}],
)
def test_junk_input_returns_a_valid_output(sink, payload):
    assert output.is_valid_output(handler_mod.handler(payload, None))


def test_capture_bodies_off_still_returns_the_body_to_the_gateway(sink, monkeypatch):
    monkeypatch.setattr(
        handler_mod, "OPTIONS", Config(streams=("s",), capture_bodies=False).mapper_options("0.1.0")
    )
    case = load_case("mcp-tools-call-lambda")
    result = handler_mod.handler(case["input"], LambdaContext(case["client_context"]))

    assert "body" not in sink.events[0]
    assert result["mcp"]["transformedGatewayRequest"] == {
        "body": case["input"]["mcp"]["gatewayRequest"]["body"]
    }


def test_the_module_reads_its_configuration_at_import(monkeypatch):
    monkeypatch.setenv("CERBERUS_FIREHOSE_STREAM", "one,two")
    monkeypatch.setenv("CERBERUS_IDENTITY", "sigv4")
    monkeypatch.setenv("CERBERUS_MAX_EVENT_BYTES", "4096")
    reloaded = importlib.reload(handler_mod)

    assert reloaded.CONFIG.streams == ("one", "two")
    assert reloaded.OPTIONS.identity_mode == "sigv4"
    assert reloaded.OPTIONS.max_event_bytes == 4096

    monkeypatch.undo()
    importlib.reload(handler_mod)
