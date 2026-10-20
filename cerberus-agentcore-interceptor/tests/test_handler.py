"""The handler's contract: whatever fails, the caller's payload comes back intact."""

import importlib
import json
import logging
from io import BytesIO
from time import monotonic

import boto3
import pytest
from botocore.awsrequest import AWSResponse
from helpers import LambdaContext, case_names, load_case, runtime_encode

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
        self.deadlines: list[float | None] = []
        self._reason = reason
        self._raises = raises

    def put(self, event, key, deadline=None):
        if self._raises is not None:
            raise self._raises
        self.events.append(event)
        self.keys.append(key)
        self.deadlines.append(deadline)
        return self._reason


class TimedContext(LambdaContext):
    """A Lambda context that reports a fixed remaining time."""

    def __init__(self, custom, remaining_ms):
        super().__init__(custom)
        self.remaining_ms = remaining_ms

    def get_remaining_time_in_millis(self):
        return self.remaining_ms


class CountingFirehose:
    def __init__(self):
        self.calls = 0

    def put_record(self, **kwargs):
        self.calls += 1
        return {"RecordId": "r-1"}


def _boom(*args, **kwargs):
    raise RuntimeError("boom")


def invoke_with(name: str, remaining_ms: int):
    case = load_case(name)
    context = TimedContext(case["client_context"], remaining_ms)
    return case, handler_mod.handler(case["input"], context)


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
    runtime_encode(invoke(name))


def test_an_echoed_lone_surrogate_survives_the_runtime_encode(sink):
    case = load_case("mcp-tools-call-lambda")
    mcp = case["input"]["mcp"]
    mcp["gatewayRequest"]["body"]["params"]["arguments"]["message"] = "Party \ud83c"
    raw = mcp["rawGatewayRequest"]["body"]
    mcp["rawGatewayRequest"]["body"] = raw.replace('"envelope"', '"Party \\ud83c"')
    result = handler_mod.handler(case["input"], LambdaContext(case["client_context"]))

    wire = json.loads(runtime_encode(result))
    body = wire["mcp"]["transformedGatewayRequest"]["body"]
    assert body["params"]["arguments"]["message"] == "Party �"
    assert len(sink.events) == 1


def test_response_phase_captures_nothing_and_echoes_the_response(sink, counted):
    response = load_case("mcp-tools-call-lambda-response")["input"]["mcp"]["gatewayResponse"]
    result = invoke("mcp-tools-call-lambda-response")

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
    assert counted == [(metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER)]


def test_a_failure_is_logged_without_its_message(sink, counted, monkeypatch, caplog):
    quoted = "Bearer " + "caller-token"

    def quoting(*args, **kwargs):
        raise ValueError(quoted)

    monkeypatch.setattr(handler_mod, "source_event", quoting)
    with caplog.at_level(logging.ERROR, logger="cerberus_agentcore_interceptor"):
        invoke("mcp-tools-call-lambda")

    assert "capture failed: ValueError" in caplog.text
    assert "in quoting" in caplog.text
    assert quoted not in caplog.text


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


def test_capture_is_bounded_by_the_time_the_function_has_left(sink):
    before = monotonic()
    invoke_with("mcp-tools-call-lambda", 3000)
    after = monotonic()

    budget = 3 - handler_mod.ANSWER_MARGIN_MS / 1000
    assert before + budget - 0.001 <= sink.deadlines[0] <= after + budget + 0.001


def test_capture_past_its_deadline_passes_the_request_through(sink, counted):
    case, result = invoke_with("mcp-tools-call-lambda", handler_mod.ANSWER_MARGIN_MS)

    assert result["mcp"]["transformedGatewayRequest"] == {
        "body": case["input"]["mcp"]["gatewayRequest"]["body"]
    }
    assert sink.events == []
    assert counted == [(metrics.CAPTURE_DROPPED, metrics.REASON_DEADLINE)]


@pytest.mark.parametrize("extra_ms", [0, 700])
def test_a_deadline_drop_names_the_request(monkeypatch, extra_ms):
    monkeypatch.setattr(
        handler_mod, "SINK", FirehoseSink(("s",), 250, 500, client=CountingFirehose())
    )
    monkeypatch.setattr(handler_mod, "OPTIONS", Config(streams=("s",)).mapper_options("0.1.0"))
    fields: list[dict] = []
    monkeypatch.setattr(
        handler_mod.metrics, "count", lambda name, reason="", **kw: fields.append(kw)
    )
    case, _ = invoke_with("mcp-tools-call-lambda", handler_mod.ANSWER_MARGIN_MS + extra_ms)

    assert fields == [{"request_id": case["client_context"]["REQUEST_ID"]}]


def test_a_put_that_could_outlast_the_deadline_is_skipped(counted, monkeypatch):
    client = CountingFirehose()
    monkeypatch.setattr(handler_mod, "SINK", FirehoseSink(("s",), 250, 500, client=client))
    monkeypatch.setattr(handler_mod, "OPTIONS", Config(streams=("s",)).mapper_options("0.1.0"))
    case, result = invoke_with("mcp-tools-call-lambda", handler_mod.ANSWER_MARGIN_MS + 700)

    assert output.is_valid_output(result)
    assert client.calls == 0
    assert counted == [(metrics.CAPTURE_DROPPED, metrics.REASON_DEADLINE)]

    invoke_with("mcp-tools-call-lambda", handler_mod.ANSWER_MARGIN_MS + 1000)
    assert client.calls == 1
    assert counted[-1] == (metrics.CAPTURED, "")


@pytest.mark.parametrize("name", case_names())
def test_capture_off_passes_every_request_through(sink, counted, monkeypatch, name):
    off = Config.from_env({"CERBERUS_FIREHOSE_STREAM": "s", "CERBERUS_CAPTURE_BODIES": "maybe"})
    expected = invoke(name)
    sink.events.clear()
    counted.clear()
    monkeypatch.setattr(handler_mod, "CONFIG", off)

    assert invoke(name) == expected
    assert sink.events == []
    assert (metrics.CAPTURED, "") not in counted


def test_capture_off_is_counted(sink, counted, monkeypatch):
    monkeypatch.setattr(handler_mod, "CONFIG", Config.from_env({}))
    invoke("mcp-tools-call-lambda")
    assert counted == [(metrics.CAPTURE_DROPPED, metrics.REASON_CONFIG)]


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


def test_an_unusable_setting_does_not_fail_the_import(monkeypatch):
    monkeypatch.setenv("CERBERUS_CAPTURE_BODIES", "maybe")
    monkeypatch.setenv("CERBERUS_LOG_LEVEL", "verbose")
    reloaded = importlib.reload(handler_mod)

    assert reloaded.CONFIG.invalid == ("CERBERUS_CAPTURE_BODIES",)
    assert reloaded.logger.level == logging.INFO

    monkeypatch.undo()
    importlib.reload(handler_mod)


def test_the_aws_client_stack_logs_no_payload_when_the_runtime_logs_at_debug(monkeypatch, caplog):
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    for name in ("botocore", "urllib3"):
        logging.getLogger(name).setLevel(logging.NOTSET)
    importlib.reload(handler_mod)
    caplog.set_level(logging.DEBUG)

    client = boto3.client(
        "lambda",
        region_name="us-east-1",
        aws_access_key_id="AKIDEXAMPLE",
        aws_secret_access_key="example",
    )
    client.meta.events.register("before-send", lambda **_: AWSResponse("", 200, {}, BytesIO()))
    client.invoke(FunctionName="chained", Payload=b'{"body": "caller-secret"}')

    assert "caller-secret" not in caplog.text
    assert not logging.getLogger("urllib3.connectionpool").isEnabledFor(logging.DEBUG)
