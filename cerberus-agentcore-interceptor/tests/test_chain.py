"""Chaining: the customer's interceptor decides, and our failures never skip it."""

import base64
import copy
import importlib
import json
import logging
import socket
import struct
import threading

import pytest
from helpers import LambdaContext, load_case, runtime_encode
from test_handler import RecordingSink, TimedContext, _boom
from test_sink import _read_request

from cerberus_agentcore_interceptor import chain as chain_mod
from cerberus_agentcore_interceptor import envelope as env
from cerberus_agentcore_interceptor import handler as handler_mod
from cerberus_agentcore_interceptor import metrics
from cerberus_agentcore_interceptor.chain import ChainClient
from cerberus_agentcore_interceptor.config import Config, ConfigError

CHAIN_ARN = "arn:aws:lambda:us-west-2:123456789012:function:customer-auth:live"
GATEWAY_ID = "example-gateway-abcdefghij"
GATEWAY_ARN = f"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/{GATEWAY_ID}"


class FakeLambda:
    def __init__(self, payload=None, function_error=None, raises=None, raw=None):
        self.calls = []
        self._payload = payload
        self._function_error = function_error
        self._raises = raises
        self._raw = raw

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        if self._raises is not None:
            raise self._raises
        raw = self._raw if self._raw is not None else json.dumps(self._payload).encode()
        response = {"StatusCode": 200, "Payload": raw}
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


def client(payload=None, pass_headers=False, **kwargs):
    fake = FakeLambda(payload=payload, **kwargs)
    chain = ChainClient(
        CHAIN_ARN, 5000, pass_headers=pass_headers, client=fake, sleep=lambda _: None
    )
    return chain, fake


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
    chain, _ = client(raw=b"not json")
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


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class ThrottledUntil(FakeLambda):
    def __init__(self, clock, free_at):
        super().__init__(payload=mcp_output({}))
        self._clock = clock
        self._free_at = free_at

    def invoke(self, **kwargs):
        self._clock.now += 0.02
        if self._clock.now < self._free_at:
            self.calls.append(kwargs)
            raise Throttled()
        return super().invoke(**kwargs)


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(chain_mod, "monotonic", clock)
    return clock


@pytest.mark.parametrize("seconds", [0.2, 0.5, 1.0])
def test_a_throttle_the_gateway_would_have_outlasted_is_ridden_out(clock, seconds):
    fake = ThrottledUntil(clock, clock.now + seconds)
    chain = ChainClient(CHAIN_ARN, 5000, client=fake, sleep=clock.sleep)
    assert not chain.invoke({}, context(), parsed(), clock.now + 2.5).failed


def test_throttle_retries_never_wait_past_the_deadline(clock):
    fake = ThrottledUntil(clock, float("inf"))
    chain = ChainClient(CHAIN_ARN, 5000, client=fake, sleep=clock.sleep)
    deadline = clock.now + 1.0

    assert chain.invoke({}, context(), parsed(), deadline).failed
    assert len(fake.calls) == 2
    assert clock.now <= deadline


class ForgetfulLambda:
    """A local Invoke endpoint that, once told to forget, resets older connections."""

    def __init__(self):
        self.answer = json.dumps(mcp_output({})).encode()
        self.forget = threading.Event()
        self.connections = 0
        self.invokes = 0
        self.sock = socket.create_server(("127.0.0.1", 0))
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.sock.getsockname()[1]}"

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        opened_before = not self.forget.is_set()
        reader = conn.makefile("rb")
        while _read_request(reader):
            if opened_before and self.forget.is_set():
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                break
            self.invokes += 1
            head = f"HTTP/1.1 200 OK\r\nContent-Length: {len(self.answer)}\r\n"
            conn.sendall(head.encode() + b"Content-Type: application/json\r\n\r\n" + self.answer)
        reader.close()
        conn.close()


@pytest.fixture
def forgetful(monkeypatch, tmp_path):
    endpoint = ForgetfulLambda()
    env = {
        "AWS_ENDPOINT_URL_LAMBDA": endpoint.url,
        "AWS_DEFAULT_REGION": "us-west-2",
        "AWS_ACCESS_KEY_ID": "AKIDEXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "example",
        "AWS_CONFIG_FILE": str(tmp_path / "none"),
        "AWS_SHARED_CREDENTIALS_FILE": str(tmp_path / "none"),
        "AWS_EC2_METADATA_DISABLED": "true",
        "NO_PROXY": "127.0.0.1",
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    for name in ("AWS_PROFILE", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    yield endpoint
    endpoint.sock.close()


def test_an_idle_connection_is_not_reused(forgetful, clock):
    shipped = ChainClient(CHAIN_ARN, 5000)
    assert not shipped.invoke({}, context(), parsed()).failed
    forgetful.forget.set()
    clock.now += chain_mod.IDLE_CONNECTION_SECONDS

    assert not shipped.invoke({}, context(), parsed()).failed
    assert forgetful.connections == 2
    assert forgetful.invokes == 2


def test_a_recently_used_connection_is_kept(forgetful, clock):
    shipped = ChainClient(CHAIN_ARN, 5000)
    shipped.invoke({}, context(), parsed())
    clock.now += chain_mod.IDLE_CONNECTION_SECONDS - 1
    shipped.invoke({}, context(), parsed())

    assert forgetful.connections == 1
    assert forgetful.invokes == 2


def test_a_client_that_cannot_close_still_invokes(clock):
    chain, fake = client(mcp_output({}))
    chain.invoke({}, context(), parsed())
    clock.now += chain_mod.IDLE_CONNECTION_SECONDS

    assert not chain.invoke({}, context(), parsed()).failed
    assert len(fake.calls) == 2


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
    chain, fake = client(mcp_output({}), pass_headers=True)
    event = load_case("mcp-tools-call-lambda")["input"]
    chain.invoke(event, context(), parsed())
    assert json.loads(fake.calls[0]["Payload"]) == event


def event_with_arguments(arguments):
    event = copy.deepcopy(load_case("mcp-tools-call-lambda")["input"])
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"arguments": arguments}}
    event["mcp"]["gatewayRequest"]["body"] = body
    event["mcp"]["rawGatewayRequest"]["body"] = json.dumps(body, ensure_ascii=False)
    return event


@pytest.mark.parametrize(
    "text",
    ["日本語の文書" * 1000, "😀" * 1000, "plain words " * 1000],
    ids=["cjk", "emoji", "ascii"],
)
def test_the_forwarded_event_is_no_larger_than_the_gateway_sent_it(text):
    chain, fake = client(mcp_output({}), pass_headers=True)
    event = event_with_arguments({"document": text})
    chain.invoke(event, context(), parsed())

    sent = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(fake.calls[0]["Payload"]) <= len(sent)
    assert json.loads(fake.calls[0]["Payload"]) == event


def test_a_lone_surrogate_is_forwarded_escaped():
    chain, fake = client(mcp_output({}), pass_headers=True)
    event = event_with_arguments({"message": "Party \ud83c"})
    assert not chain.invoke(event, context(), parsed()).failed

    assert b"Party \\ud83c" in fake.calls[0]["Payload"]
    assert json.loads(fake.calls[0]["Payload"]) == event


@pytest.mark.parametrize("name", ["mcp-tools-call-lambda", "inference-chat"])
def test_without_pass_headers_the_chained_function_gets_no_headers(name):
    chain, fake = client(mcp_output({}))
    event = load_case(name)["input"]
    original = json.loads(json.dumps(event))
    chain.invoke(event, context(name), parsed(name))

    forwarded = json.loads(fake.calls[0]["Payload"])
    shape = "mcp" if "mcp" in event else "http"
    assert original[shape]["gatewayRequest"]["headers"]
    assert "headers" not in forwarded[shape]["gatewayRequest"]
    del original[shape]["gatewayRequest"]["headers"]
    assert forwarded == original
    assert event[shape]["gatewayRequest"]["headers"]


def test_without_pass_headers_no_level_of_the_event_keeps_its_headers():
    chain, fake = client(mcp_output({}))
    body = {"jsonrpc": "2.0", "id": 1, "params": {"arguments": {"headers": {"x-kept": "1"}}}}
    event = {
        "interceptorInputVersion": "2.0",
        "headers": {"Authorization": "Bearer event"},
        "mcp": {
            "headers": {"Authorization": "Bearer shape"},
            "gatewayRequest": {"headers": {"Authorization": "Bearer request"}, "body": body},
            "rawGatewayRequest": {"headers": {"Cookie": "session=raw"}, "body": json.dumps(body)},
            "gatewayResponse": None,
        },
    }
    chain.invoke(event, context(), parsed())

    payload = fake.calls[0]["Payload"]
    assert b"Bearer" not in payload
    assert b"session=raw" not in payload
    assert json.loads(payload)["interceptorInputVersion"] == "2.0"
    forwarded = json.loads(payload)["mcp"]
    assert forwarded["gatewayRequest"]["body"] == body
    assert forwarded["rawGatewayRequest"]["body"] == json.dumps(body)
    assert forwarded["gatewayResponse"] is None


# ============================================================================
# Configuration
# ============================================================================

MINIMAL = {"CERBERUS_FIREHOSE_STREAM": "s"}


def chain_env(gateway_ids=GATEWAY_ID, **overrides):
    return {
        **MINIMAL,
        "CERBERUS_CHAIN_REQUEST_ARN": CHAIN_ARN,
        "CERBERUS_GATEWAY_IDS": gateway_ids,
        "CERBERUS_CHAIN_READ_MS": "5000",
        "CERBERUS_CHAIN_PASS_HEADERS": "false",
        **overrides,
    }


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


@pytest.mark.parametrize(
    "value", ["customer-auth", "arn:aws:lambda:us-west-2:123456789012:layer:customer-auth"]
)
def test_a_chain_target_must_be_a_function_arn(value):
    with pytest.raises(ConfigError, match="Lambda function ARN") as raised:
        Config.from_env(chain_env(CERBERUS_CHAIN_REQUEST_ARN=value))
    assert value not in str(raised.value)
    assert "123456789012" not in str(raised.value)


def test_a_full_chain_configuration():
    config = Config.from_env(
        chain_env(f"{GATEWAY_ID}, other-gateway", CERBERUS_CHAIN_PASS_HEADERS="true")
    )
    assert config.chain_arn == CHAIN_ARN
    assert config.gateway_ids == (GATEWAY_ID, "other-gateway")
    assert config.chain_read_ms == 5000
    assert config.chain_pass_headers is True


@pytest.mark.parametrize("raw", ["", "  ", "maybe"])
def test_chaining_needs_an_explicit_pass_headers(raw):
    with pytest.raises(ConfigError, match="CERBERUS_CHAIN_PASS_HEADERS"):
        Config.from_env(chain_env(CERBERUS_CHAIN_PASS_HEADERS=raw))


@pytest.mark.parametrize(
    "setting",
    [
        {"CERBERUS_GATEWAY_IDS": GATEWAY_ID},
        {"CERBERUS_CHAIN_READ_MS": "5000"},
        {"CERBERUS_CHAIN_PASS_HEADERS": "false"},
        {"CERBERUS_CHAIN_ARN": CHAIN_ARN},
    ],
)
def test_a_chain_setting_without_the_chain_arn_fails_init(setting):
    with pytest.raises(ConfigError, match="set without CERBERUS_CHAIN_REQUEST_ARN"):
        Config.from_env({**MINIMAL, **setting})


def test_a_misspelled_chain_arn_fails_init_without_naming_the_function():
    env = chain_env()
    env["CERBERUS_CHAIN_REQUST_ARN"] = env.pop("CERBERUS_CHAIN_REQUEST_ARN")
    with pytest.raises(ConfigError) as raised:
        Config.from_env(env)
    assert "123456789012" not in str(raised.value)


def test_empty_chain_settings_do_not_count_as_set():
    config = Config.from_env({**MINIMAL, "CERBERUS_GATEWAY_IDS": " ", "CERBERUS_CHAIN_READ_MS": ""})
    assert config.chain_arn == ""
    assert config.capturing


def test_a_gateway_arn_is_read_as_its_id():
    config = Config.from_env(chain_env(f"{GATEWAY_ARN}, {GATEWAY_ID}, other-gateway"))
    assert config.gateway_ids == (GATEWAY_ID, "other-gateway")


@pytest.mark.parametrize(
    "value",
    [
        CHAIN_ARN,
        "arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/example-runtime",
        f"{GATEWAY_ARN}/extra",
        "gateway/example-gateway-abcdefghij",
    ],
)
def test_a_gateway_id_that_could_never_match_fails_init(value):
    with pytest.raises(ConfigError, match="CERBERUS_GATEWAY_IDS: entry 2 ") as raised:
        Config.from_env(chain_env(f"{GATEWAY_ID},{value}"))
    assert "123456789012" not in str(raised.value)


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


def test_a_body_transformed_to_null_is_not_captured_as_the_original(chained):
    chained(
        {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": None}}}
    )
    invoke()

    event = chained.sink.events[0]
    assert "body" not in event
    assert event["custom_data"]["agentcore"]["body"] == {"state": "omitted", "reason": "not_object"}
    assert event["custom_data"]["agentcore"]["chain"] == {"outcome": "transformed"}


def http_output(body):
    return {
        "interceptorOutputVersion": "1.0",
        "http": {"transformedGatewayRequest": {"body": body}},
    }


def test_a_transformed_http_body_is_decoded_and_captured(chained):
    request = load_case("inference-chat")["input"]["http"]["gatewayRequest"]
    transformed = dict(json.loads(base64.b64decode(request["body"])), max_tokens=64)
    answer = http_output(base64.b64encode(json.dumps(transformed).encode()).decode())
    chained(answer)

    assert invoke("inference-chat") == answer
    event = chained.sink.events[0]
    assert event["body"] == transformed
    assert event["custom_data"]["agentcore"]["body"] == {"state": "captured"}
    assert event["custom_data"]["agentcore"]["chain"] == {"outcome": "transformed"}


@pytest.mark.parametrize(
    ("name", "body", "reason"),
    [
        ("inference-chat", "not base64!", "decode_error"),
        ("inference-chat", base64.b64encode(b"[1, 2]").decode(), "not_object"),
        ("mcp-tools-call-lambda", '{"jsonrpc": "2.0"}', "not_object"),
    ],
)
def test_an_unreadable_transformed_body_is_noted(chained, name, body, reason):
    shape = "mcp" if name.startswith("mcp") else "http"
    chained(
        {"interceptorOutputVersion": "1.0", shape: {"transformedGatewayRequest": {"body": body}}}
    )
    invoke(name)

    event = chained.sink.events[0]
    assert "body" not in event
    assert event["custom_data"]["agentcore"]["body"] == {"state": "omitted", "reason": reason}


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


def test_a_refused_gateway_is_named_in_the_log(chained, caplog):
    chained(mcp_output({}))
    case = load_case("mcp-tools-call-lambda")
    context = dict(case["client_context"])
    context["GATEWAY_ARN"] = context["GATEWAY_ARN"].replace(GATEWAY_ID, "unlisted-gateway")

    with pytest.raises(handler_mod.InterceptorError):
        handler_mod.handler(case["input"], LambdaContext(context))
    assert any("unlisted-gateway" in record.getMessage() for record in caplog.records)


def test_a_gateway_listed_by_arn_is_served(chained, monkeypatch):
    config = Config.from_env(chain_env(GATEWAY_ARN))
    monkeypatch.setattr(handler_mod, "CONFIG", config)
    answer = mcp_output({"jsonrpc": "2.0", "id": 3, "method": "tools/call"})
    fake = chained(answer)

    assert invoke() == answer
    assert len(fake.calls) == 1


def test_the_error_text_names_nothing_a_customer_should_not_see(chained):
    chained(raises=RuntimeError("arn:aws:lambda:us-west-2:123456789012:function:secret"))
    with pytest.raises(handler_mod.InterceptorError) as raised:
        invoke()
    assert "arn:" not in str(raised.value)
    assert "123456789012" not in str(raised.value)


class UnreadableStream:
    def read(self):
        raise RuntimeError(f"Read timeout on endpoint URL: /functions/{CHAIN_ARN}/invocations")


def test_an_answer_that_cannot_be_read_is_refused_without_naming_the_function(chained, caplog):
    chained(raw=UnreadableStream())
    with caplog.at_level(logging.WARNING, logger="cerberus_agentcore_interceptor"):
        with pytest.raises(handler_mod.InterceptorError) as raised:
            invoke()

    assert "123456789012" not in str(raised.value)
    assert "chained interceptor failed: RuntimeError" in caplog.text
    assert "123456789012" not in caplog.text
    assert chained.sink.events[0]["custom_data"]["agentcore"]["chain"] == {"outcome": "error"}


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


@pytest.mark.parametrize(
    "name", ["mcp-tools-call-lambda-response", "inference-chat-sigv4-response"]
)
def test_the_response_phase_is_refused_when_chaining(chained, name):
    fake = chained(mcp_output({}))
    with pytest.raises(handler_mod.InterceptorError):
        invoke(name)
    assert fake.calls == []
    assert chained.sink.events == []


def test_an_invalid_chained_output_is_handed_back_as_it_came(chained):
    chained({"interceptorOutputVersion": "9.9"})
    assert invoke() == {"interceptorOutputVersion": "9.9"}
    assert chained.sink.events[0]["custom_data"]["agentcore"]["chain"] == {
        "outcome": "invalid_output"
    }


@pytest.mark.parametrize(
    "raw",
    [
        b"null",
        b"",
        b"not json",
        b"\xff\xfe",
        b"[]",
        b'"ok"',
        b"false",
        pytest.param(b"[" * 100_000, id="too-deep"),
    ],
)
def test_an_answer_that_is_not_an_object_refuses_the_request(chained, raw):
    fake = chained(raw=raw)
    with pytest.raises(handler_mod.InterceptorError):
        invoke()
    assert len(fake.calls) == 1
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
    monkeypatch.setenv("CERBERUS_CHAIN_PASS_HEADERS", "true")
    reloaded = importlib.reload(handler_mod)
    try:
        assert reloaded.CHAIN is not None
        assert reloaded.CONFIG.gateway_ids == (GATEWAY_ID,)
        fake = FakeLambda(payload=mcp_output({}))
        monkeypatch.setattr(reloaded.CHAIN, "_client", fake)
        monkeypatch.setattr(reloaded, "SINK", RecordingSink())
        reloaded.handler(load_case("mcp-tools-call-lambda")["input"], context())
        assert json.loads(fake.calls[0]["Payload"])["mcp"]["gatewayRequest"]["headers"]
    finally:
        monkeypatch.undo()
        importlib.reload(handler_mod)


def test_the_module_refuses_to_load_with_a_chain_but_no_arn(monkeypatch):
    monkeypatch.setenv("CERBERUS_FIREHOSE_STREAM", "s")
    monkeypatch.delenv("CERBERUS_CHAIN_REQUEST_ARN", raising=False)
    monkeypatch.setenv("CERBERUS_GATEWAY_IDS", GATEWAY_ID)
    monkeypatch.setenv("CERBERUS_CHAIN_READ_MS", "4000")
    monkeypatch.setenv("CERBERUS_CHAIN_PASS_HEADERS", "true")
    try:
        with pytest.raises(ConfigError):
            importlib.reload(handler_mod)
    finally:
        monkeypatch.undo()
        importlib.reload(handler_mod)


def test_capture_keeps_the_headers_the_chained_function_does_not_get(chained):
    fake = chained(mcp_output({}))
    invoke()

    assert "headers" not in json.loads(fake.calls[0]["Payload"])["mcp"]["gatewayRequest"]
    assert chained.sink.events[0]["user_agent"] == "python-requests/2.34.2"


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


def test_a_lone_surrogate_in_the_chained_answer_survives_the_runtime_encode(chained):
    chained(
        mcp_output(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "a\ud83c"}}
        )
    )
    wire = json.loads(runtime_encode(invoke()))
    assert wire["mcp"]["transformedGatewayRequest"]["body"]["params"]["name"] == "a�"


def test_with_capture_off_the_chained_answer_still_decides(chained, monkeypatch):
    answer = mcp_output({"jsonrpc": "2.0", "id": 7, "method": "tools/call"})
    fake = chained(answer)
    off = Config.from_env(chain_env(CERBERUS_FIREHOSE_STREAM=""))
    monkeypatch.setattr(handler_mod, "CONFIG", off)
    counts = []
    monkeypatch.setattr(
        handler_mod.metrics, "count", lambda name, reason="", **_: counts.append((name, reason))
    )

    assert invoke() == answer
    assert len(fake.calls) == 1
    assert chained.sink.events == []
    assert counts == [(metrics.CAPTURE_DROPPED, metrics.REASON_CONFIG)]


def test_a_throttled_chain_is_not_retried_past_the_functions_time(chained):
    fake = chained(raises=Throttled())
    case = load_case("mcp-tools-call-lambda")
    context = TimedContext(case["client_context"], handler_mod.ANSWER_MARGIN_MS + 300)

    with pytest.raises(handler_mod.InterceptorError):
        handler_mod.handler(case["input"], context)
    assert len(fake.calls) == 1


class UnreadableTimeContext(LambdaContext):
    def get_remaining_time_in_millis(self):
        raise RuntimeError("no clock")


def test_an_unreadable_remaining_time_still_chains(chained):
    answer = mcp_output({"jsonrpc": "2.0", "id": 8, "method": "tools/call"})
    fake = chained(answer)
    case = load_case("mcp-tools-call-lambda")
    context = UnreadableTimeContext(case["client_context"])

    assert handler_mod.handler(case["input"], context) == answer
    assert len(fake.calls) == 1


def test_capture_after_a_slow_chain_gives_up_and_the_answer_stands(chained):
    answer = mcp_output({"jsonrpc": "2.0", "id": 7, "method": "tools/call"})
    chained(answer)
    case = load_case("mcp-tools-call-lambda")
    context = TimedContext(case["client_context"], handler_mod.ANSWER_MARGIN_MS)

    assert handler_mod.handler(case["input"], context) == answer
    assert chained.sink.events == []


def test_the_chain_client_is_prepared_with_capture_off(monkeypatch):
    prepared = []
    monkeypatch.setattr(ChainClient, "prepare", lambda self: prepared.append(self))
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "interceptor")
    monkeypatch.setenv("CERBERUS_FIREHOSE_STREAM", "not a stream")
    monkeypatch.setenv("CERBERUS_CHAIN_REQUEST_ARN", CHAIN_ARN)
    monkeypatch.setenv("CERBERUS_GATEWAY_IDS", GATEWAY_ID)
    monkeypatch.setenv("CERBERUS_CHAIN_READ_MS", "4000")
    monkeypatch.setenv("CERBERUS_CHAIN_PASS_HEADERS", "true")
    reloaded = importlib.reload(handler_mod)
    try:
        assert not reloaded.CONFIG.capturing
        assert prepared == [reloaded.CHAIN]
    finally:
        monkeypatch.undo()
        importlib.reload(handler_mod)


def test_a_client_that_cannot_be_built_is_logged_by_error_type(monkeypatch, caplog):
    chain = ChainClient(CHAIN_ARN, 5000)

    def unbuildable():
        raise RuntimeError(f"no client for {CHAIN_ARN}")

    monkeypatch.setattr(chain, "_lambda", unbuildable)
    with caplog.at_level(logging.WARNING, logger="cerberus_agentcore_interceptor"):
        chain.prepare()

    assert "chain client not ready: RuntimeError" in caplog.text
    assert "123456789012" not in caplog.text
