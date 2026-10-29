"""The handler's contract: whatever fails, the caller's payload comes back intact."""

import base64
import copy
import importlib
import itertools
import json
import logging
from io import BytesIO
from time import monotonic

import boto3
import pytest
from botocore.awsrequest import AWSResponse
from helpers import LambdaContext, case_names, load_case, runtime_encode

from cerberus_agentcore_interceptor import bounding, metrics, output, sanitize
from cerberus_agentcore_interceptor import envelope as env
from cerberus_agentcore_interceptor import handler as handler_mod
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


@pytest.fixture
def phased(monkeypatch):
    counts: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        handler_mod.metrics,
        "count",
        lambda name, reason="", phase="", **fields: counts.append((name, reason, phase)),
    )
    return counts


@pytest.fixture
def responses(monkeypatch, sink):
    monkeypatch.setattr(handler_mod, "CONFIG", Config(streams=("s",), response_capture=True))
    return sink


def invoke(name: str):
    case = load_case(name)
    return handler_mod.handler(case["input"], LambdaContext(case["client_context"]))


def invoke_case(case: dict):
    return handler_mod.handler(case["input"], LambdaContext(case["client_context"]))


RESPONSE_CASES = [
    name for name in case_names() if env.parse(load_case(name)["input"]).phase == env.RESPONSE
]
RESPONSE_SHAPES = ["mcp-tools-call-lambda-response", "inference-chat-response"]
REQUEST_SHAPES = ["mcp-tools-call-lambda", "inference-chat"]
HTTP_PASSTHROUGH = {"interceptorOutputVersion": "1.0", "http": {}}


def echo(name: str) -> dict:
    """The answer that hands a RESPONSE case's response back as the gateway gave it."""
    shape = load_case(name)["input"].get("mcp")
    if shape is None:
        return {"interceptorOutputVersion": "1.0", "http": {}}
    response = shape["gatewayResponse"]
    transformed = {"body": response["body"], "statusCode": response["statusCode"]}
    return {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayResponse": transformed}}


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


@pytest.mark.parametrize("name", RESPONSE_SHAPES)
def test_response_capture_off_captures_nothing_and_echoes_the_response(sink, counted, name):
    assert invoke(name) == echo(name)
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

    assert fields == [{"phase": "request", "request_id": case["client_context"]["REQUEST_ID"]}]


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


def test_request_capture_is_counted_by_phase(sink, phased):
    invoke("mcp-tools-call-lambda")
    assert phased == [(metrics.CAPTURED, "", "request")]


def test_request_events_expect_a_response_only_with_response_capture_on(sink, monkeypatch):
    invoke("mcp-tools-call-lambda")
    monkeypatch.setattr(handler_mod, "CONFIG", Config(streams=("s",), response_capture=True))
    invoke("inference-chat")

    assert [event["custom_data"]["agentcore"]["response_expected"] for event in sink.events] == [
        False,
        True,
    ]


@pytest.mark.parametrize("name", RESPONSE_SHAPES)
def test_a_response_is_captured_and_echoed(responses, phased, name):
    case = load_case(name)
    result = invoke(name)

    assert result == echo(name)
    event = responses.events[0]
    assert event["event_id"] == case["client_context"]["REQUEST_ID"] + "#response"
    assert event["custom_data"]["agentcore"]["phase"] == "response"
    assert responses.keys[0] == case["client_context"]["GATEWAY_ARN"]
    assert phased == [(metrics.CAPTURED, "", "response")]


@pytest.mark.parametrize("name", RESPONSE_CASES)
def test_response_capture_answers_every_response_as_capture_off_does(responses, monkeypatch, name):
    captured = invoke(name)
    monkeypatch.setattr(handler_mod, "CONFIG", Config(streams=("s",)))

    assert captured == invoke(name) == echo(name)
    assert len(responses.events) == 1


@pytest.mark.parametrize("name", case_names())
def test_every_fixture_returns_a_valid_output_with_response_capture_on(responses, name):
    result = invoke(name)
    assert output.is_valid_output(result)
    runtime_encode(result)


@pytest.mark.parametrize("name", RESPONSE_SHAPES)
def test_a_raising_parser_at_response_echoes_the_raw_response(responses, phased, monkeypatch, name):
    monkeypatch.setattr(handler_mod, "parse", _boom)
    assert invoke(name) == echo(name)
    assert responses.events == []
    assert phased == [(metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER, "")]


@pytest.mark.parametrize("name", RESPONSE_SHAPES)
def test_a_raising_response_mapper_leaves_the_response_alone(responses, phased, monkeypatch, name):
    monkeypatch.setattr(handler_mod, "response_event", _boom)
    assert invoke(name) == echo(name)
    assert phased == [(metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER, "response")]


@pytest.mark.parametrize("name", RESPONSE_SHAPES)
def test_an_unboundable_response_event_is_dropped(responses, phased, monkeypatch, name):
    monkeypatch.setattr(handler_mod, "response_event", lambda *args, **kwargs: None)
    assert invoke(name) == echo(name)
    assert phased == [(metrics.CAPTURE_DROPPED, metrics.REASON_OVERSIZE, "response")]


@pytest.mark.parametrize("name", RESPONSE_SHAPES)
def test_response_capture_past_its_deadline_echoes_the_response(responses, phased, name):
    _, result = invoke_with(name, handler_mod.ANSWER_MARGIN_MS)
    assert result == echo(name)
    assert responses.events == []
    assert phased == [(metrics.CAPTURE_DROPPED, metrics.REASON_DEADLINE, "response")]


def dense(name: str) -> dict:
    """A RESPONSE case whose body holds tens of thousands of strings."""
    case = load_case(name)
    values = ["v"] * 50 * bounding.VALUES_PER_CHECK
    shape = case["input"].get("mcp")
    if shape is not None:
        shape["gatewayResponse"]["body"]["result"]["structuredContent"] = values
    else:
        body = base64.b64encode(json.dumps(values).encode()).decode()
        case["input"]["http"]["gatewayResponse"]["body"] = body
    return case


@pytest.mark.parametrize("name", RESPONSE_SHAPES)
def test_a_dense_response_past_its_deadline_mid_sanitize_is_dropped_and_echoed(
    responses, phased, monkeypatch, name
):
    case = dense(name)
    walked = [0]
    real = sanitize.storable_text

    def storable_text(value):
        walked[0] += 1
        return real(value)

    reads = itertools.count()
    monkeypatch.setattr(sanitize, "storable_text", storable_text)
    monkeypatch.setattr(handler_mod, "monotonic", lambda: 0.0)
    monkeypatch.setattr(bounding, "monotonic", lambda: next(reads) / 1000)
    context = TimedContext(case["client_context"], handler_mod.ANSWER_MARGIN_MS + 20)
    result = handler_mod.handler(case["input"], context)

    assert 0 < walked[0] < 50 * bounding.VALUES_PER_CHECK
    assert responses.events == []
    assert phased == [(metrics.CAPTURE_DROPPED, metrics.REASON_DEADLINE, "response")]
    monkeypatch.setattr(handler_mod, "CONFIG", Config(streams=("s",)))
    assert result == handler_mod.handler(case["input"], context)


@pytest.mark.parametrize("name", RESPONSE_SHAPES)
@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        ({"reason": metrics.REASON_THROTTLE}, metrics.REASON_THROTTLE),
        ({"raises": RuntimeError("firehose")}, metrics.REASON_HANDLER),
    ],
    ids=["throttled", "raising"],
)
def test_a_response_the_sink_drops_is_counted_by_reason(
    responses, phased, monkeypatch, name, failure, reason
):
    monkeypatch.setattr(handler_mod, "SINK", RecordingSink(**failure))
    assert invoke(name) == echo(name)
    assert phased == [(metrics.CAPTURE_DROPPED, reason, "response")]


@pytest.mark.parametrize("name", RESPONSE_SHAPES)
def test_response_capture_with_capture_off_is_counted(sink, phased, monkeypatch, name):
    off = Config.from_env({"CERBERUS_RESPONSE_CAPTURE": "true"})
    monkeypatch.setattr(handler_mod, "CONFIG", off)

    assert off.response_capture and not off.capturing
    assert invoke(name) == echo(name)
    assert sink.events == []
    assert phased == [(metrics.CAPTURE_DROPPED, metrics.REASON_CONFIG, "response")]


@pytest.mark.parametrize("name", RESPONSE_SHAPES)
def test_an_unknown_input_version_at_response_is_echoed_and_never_mapped(
    responses, phased, monkeypatch, name
):
    monkeypatch.setattr(handler_mod, "response_event", lambda *a, **k: pytest.fail("mapped"))
    case = load_case(name)
    case["input"]["interceptorInputVersion"] = "2.0"

    assert invoke_case(case) == echo(name)
    assert responses.events == []
    assert phased == [(metrics.UNKNOWN_INPUT_VERSION, "", "")]


def test_an_unknown_shape_at_response_is_counted_captured_and_echoed(responses, phased):
    response = {"body": {"x": 1}, "statusCode": 200}
    payload = {
        "interceptorInputVersion": "1.0",
        "grpc": {"gatewayRequest": None, "gatewayResponse": response},
    }
    result = handler_mod.handler(payload, None)

    assert result == {
        "interceptorOutputVersion": "1.0",
        "grpc": {"transformedGatewayResponse": response},
    }
    assert phased == [(metrics.UNKNOWN_SHAPE, "", ""), (metrics.CAPTURED, "", "response")]


@pytest.mark.parametrize("on", [False, True])
@pytest.mark.parametrize("name", RESPONSE_SHAPES)
def test_an_output_that_cannot_be_built_echoes_the_raw_response(sink, monkeypatch, on, name):
    monkeypatch.setattr(handler_mod, "CONFIG", Config(streams=("s",), response_capture=on))
    monkeypatch.setattr(output, "passthrough", _boom)
    assert invoke(name) == echo(name)


@pytest.mark.parametrize(
    ("module", "attribute"),
    [(handler_mod, "parse"), (output, "passthrough")],
    ids=["parse", "passthrough"],
)
def test_the_raw_echo_survives_the_runtime_encode(responses, monkeypatch, module, attribute):
    monkeypatch.setattr(module, attribute, _boom)
    case = load_case("mcp-tools-call-lambda-response")
    body = {"jsonrpc": "2.0", "id": 1, "result": {"text": "cut \ud83c", "n": float("inf")}}
    case["input"]["mcp"]["gatewayResponse"]["body"] = body

    wire = json.loads(runtime_encode(invoke_case(case)))
    assert wire["mcp"]["transformedGatewayResponse"]["body"]["result"] == {
        "text": "cut �",
        "n": "Infinity",
    }


@pytest.mark.parametrize("status", ["200", True, 200.0, None])
def test_the_raw_echo_carries_only_an_int_status_code(responses, monkeypatch, status):
    monkeypatch.setattr(output, "passthrough", _boom)
    case = load_case("mcp-tools-call-lambda-response")
    case["input"]["mcp"]["gatewayResponse"]["statusCode"] = status

    assert "statusCode" not in invoke_case(case)["mcp"]["transformedGatewayResponse"]


@pytest.mark.parametrize("raw_echo", [False, True])
@pytest.mark.parametrize("on", [False, True])
def test_a_bodyless_mcp_response_is_answered_with_the_empty_form(sink, monkeypatch, on, raw_echo):
    monkeypatch.setattr(handler_mod, "CONFIG", Config(streams=("s",), response_capture=on))
    if raw_echo:
        monkeypatch.setattr(output, "passthrough", _boom)
    case = load_case("mcp-tools-call-lambda-response")
    del case["input"]["mcp"]["gatewayResponse"]["body"]

    assert invoke_case(case) == {"interceptorOutputVersion": "1.0", "mcp": {}}


QUOTED_ARN = "arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/example"


class Unreadable(dict):
    """A dict whose every read raises, quoting what it holds."""

    def get(self, key, default=None):
        raise RuntimeError(f"{self['body']} {QUOTED_ARN}")


def test_a_response_that_cannot_be_echoed_is_refused_with_text_safe_to_show(responses, caplog):
    case = load_case("mcp-tools-call-lambda-response")
    mcp = case["input"]["mcp"]
    mcp["gatewayResponse"] = Unreadable(body="SECRET-response-body", statusCode=200)
    with caplog.at_level(logging.ERROR, logger="cerberus_agentcore_interceptor"):
        with pytest.raises(handler_mod.InterceptorError) as raised:
            invoke_case(case)

    text = str(raised.value)
    for internal in ("SECRET", "arn:", "123456789012", "RuntimeError"):
        assert internal not in text
    assert raised.value.__suppress_context__
    assert "pass-through could not be built: RuntimeError" in caplog.text
    assert "SECRET" not in caplog.text


@pytest.mark.parametrize("on", [False, True])
@pytest.mark.parametrize("name", ["mcp-tools-call-lambda", "mcp-tools-call-lambda-response"])
def test_an_mcp_input_that_cannot_be_read_passes_through(sink, monkeypatch, on, name):
    monkeypatch.setattr(handler_mod, "CONFIG", Config(streams=("s",), response_capture=on))
    case = load_case(name)
    case["input"]["mcp"] = Unreadable(case["input"]["mcp"], body="SECRET")
    assert invoke_case(case) == HTTP_PASSTHROUGH


@pytest.mark.parametrize(
    ("module", "attribute"),
    [(handler_mod, "parse"), (output, "passthrough")],
    ids=["parse", "passthrough"],
)
@pytest.mark.parametrize("on", [False, True])
@pytest.mark.parametrize("name", REQUEST_SHAPES)
def test_a_request_whose_answer_cannot_be_built_passes_through(
    sink, monkeypatch, module, attribute, on, name
):
    monkeypatch.setattr(handler_mod, "CONFIG", Config(streams=("s",), response_capture=on))
    monkeypatch.setattr(module, attribute, _boom)
    assert invoke(name) == HTTP_PASSTHROUGH


def test_an_unparsed_mcp_value_that_is_not_an_object_passes_through(sink, monkeypatch):
    monkeypatch.setattr(handler_mod, "parse", _boom)
    payload = {"interceptorInputVersion": "1.0", "mcp": [1]}
    assert handler_mod.handler(payload, None) == HTTP_PASSTHROUGH


def test_an_http_response_that_cannot_be_read_still_passes_through(responses):
    case = load_case("inference-chat-response")
    case["input"]["http"]["gatewayResponse"] = Unreadable(body="SECRET", statusCode=200)
    assert invoke_case(case) == {"interceptorOutputVersion": "1.0", "http": {}}


@pytest.mark.parametrize(
    "payload",
    [
        {"mcp": {"gatewayResponse": {}}},
        {"interceptorInputVersion": "1.0", "mcp": {"gatewayResponse": {"body": None}}},
        {"interceptorInputVersion": "1.0", "http": {"gatewayResponse": {"body": 7}}},
        {"interceptorInputVersion": "1.0", "mcp": {"gatewayResponse": {"body": "text"}}},
    ],
)
def test_junk_responses_return_a_valid_output(responses, payload):
    assert output.is_valid_output(handler_mod.handler(payload, None))


def test_a_credential_a_passthrough_response_echoes_is_not_captured(responses):
    case = load_case("passthrough-echo-response")
    response = case["input"]["http"]["gatewayResponse"]
    echoed = json.loads(base64.b64decode(response["body"]))
    echoed["headers"]["x-amz-security-token"] = "SECRET-session-token"
    echoed["headers"]["authorization"] = "AWS4-HMAC-SHA256 Credential=SECRET-key-id"
    response["body"] = base64.b64encode(json.dumps(echoed).encode()).decode()

    assert invoke_case(case) == {"interceptorOutputVersion": "1.0", "http": {}}
    event = responses.events[0]
    assert "SECRET" not in json.dumps(event)
    assert event["response_body"]["headers"]["x-amz-security-token"] == "[REDACTED]"


def test_a_secret_in_mcp_result_text_is_not_captured_but_is_echoed(responses):
    case = load_case("mcp-tools-call-lambda-response")
    content = case["input"]["mcp"]["gatewayResponse"]["body"]["result"]["content"][0]
    result = json.loads(content["text"])
    result["echo"]["api_key"] = "SECRET-api-key"
    content["text"] = json.dumps(result)
    sent = copy.deepcopy(case["input"]["mcp"]["gatewayResponse"])

    answer = invoke_case(case)

    assert answer["mcp"]["transformedGatewayResponse"]["body"] == sent["body"]
    assert "SECRET" not in json.dumps(responses.events[0])
    text = responses.events[0]["response_body"]["result"]["content"][0]["text"]
    assert json.loads(text)["echo"]["api_key"] == "[REDACTED]"


def test_the_module_reads_response_capture_at_import(monkeypatch):
    monkeypatch.setenv("CERBERUS_RESPONSE_CAPTURE", "true")
    reloaded = importlib.reload(handler_mod)
    assert reloaded.CONFIG.response_capture is True

    monkeypatch.undo()
    importlib.reload(handler_mod)
