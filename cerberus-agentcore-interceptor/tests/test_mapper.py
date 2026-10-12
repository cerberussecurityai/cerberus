import json
from dataclasses import replace

import pytest
from helpers import (
    FIXTURES,
    TIMESTAMP,
    LambdaContext,
    case_names,
    load_case,
    load_expected,
    map_case,
    options,
)

from cerberus_agentcore_interceptor import envelope as envelope_mod
from cerberus_agentcore_interceptor.mapper import (
    MAX_ENDPOINT_CHARS,
    MAX_SESSION_ID_CHARS,
    MAX_USER_ID_CHARS,
    source_event,
)

GOLDEN_CASES = [name for name in case_names() if (FIXTURES / f"{name}.event.json").exists()]


@pytest.mark.parametrize("name", GOLDEN_CASES)
def test_golden(name):
    assert map_case(name) == load_expected(name)


def test_every_request_phase_case_has_a_golden():
    for name in case_names():
        parsed = envelope_mod.parse(load_case(name)["input"])
        expected = parsed.phase == envelope_mod.REQUEST and parsed.supported_version
        assert (name in GOLDEN_CASES) is expected, name


def test_mcp_tool_call_carries_the_call_and_the_caller():
    event = map_case("mcp-tools-call-lambda")
    assert event["endpoint"] == "/mcp"
    assert event["method"] == "POST"
    assert event["scheme"] is True
    assert event["body"]["params"]["name"] == "echo___echo"
    assert event["user_id"] == "11111111-2222-3333-4444-555555555555"
    assert event["custom_data"]["integration"] == "agentcore-gateway"
    assert event["custom_data"]["agentcore"]["kind"] == "mcp"


def test_inference_path_keeps_the_stripped_prefix():
    # The gateway strips the caller's /inference prefix before we see it.
    assert map_case("inference-chat")["endpoint"] == "/v1/chat/completions"
    assert map_case("inference-messages")["endpoint"] == "/v1/messages"


def test_host_is_built_from_the_gateway_arn():
    event = map_case("inference-chat")
    assert event["host"] == (
        "example-gateway-abcdefghij.gateway.bedrock-agentcore.us-west-2.amazonaws.com"
    )


def test_session_id_moves_out_of_the_headers():
    event = map_case("mcp-tools-call-session")
    assert event["session_id"] == "00000000-0000-0000-0000-00000000beef"
    assert "Mcp-Session-Id" not in event["headers"]


def test_no_credential_reaches_the_event():
    for name in GOLDEN_CASES:
        serialized = json.dumps(load_expected(name))
        assert "Bearer" not in serialized, name
        assert "AWS4-HMAC-SHA256" not in serialized, name
        assert "eyJ" not in serialized, name


def test_capture_bodies_off_keeps_identity_and_routing():
    event = map_case("mcp-tools-call-lambda", capture_bodies=False)
    assert "body" not in event
    assert event["custom_data"]["agentcore"]["body"] == {"state": "disabled"}
    assert event["user_id"]
    assert event["endpoint"] == "/mcp"


def test_extra_sensitive_keys_are_redacted():
    event = map_case("mcp-tools-call-lambda", sensitive_keys=("canary",))
    assert event["body"]["params"]["arguments"]["canary"] == "[REDACTED]"
    assert event["body"]["params"]["arguments"]["message"] == "envelope"


def test_user_id_claim_is_configurable():
    event = map_case("mcp-tools-call-lambda", user_id_claim="username")
    assert event["user_id"] == "example-user"
    assert event["custom_data"]["agentcore"]["identity"]["claim"] == "username"


def test_over_length_fields_fit_their_columns():
    case = load_case("mcp-tools-call-lambda")
    request = case["input"]["mcp"]["gatewayRequest"]
    request["path"] = "/" + "p" * 900
    request["headers"]["Mcp-Session-Id"] = "s" * 400
    context = dict(case["client_context"])
    context["REQUEST_ID"] = "r" * 400

    event = source_event(
        envelope_mod.parse(case["input"]),
        envelope_mod.gateway_context(LambdaContext(context)),
        replace(options(case), user_id_claim="jti"),
        TIMESTAMP,
    )

    assert len(event["endpoint"]) == MAX_ENDPOINT_CHARS
    assert len(event["session_id"]) == MAX_SESSION_ID_CHARS
    assert len(event["event_id"]) == 255
    assert len(event["user_id"]) <= MAX_USER_ID_CHARS


def test_query_string_is_dropped_from_the_endpoint():
    case = load_case("passthrough-echo")
    case["input"]["http"]["gatewayRequest"]["path"] = "/passthru/echo?token=abc&x=1"
    event = source_event(
        envelope_mod.parse(case["input"]),
        envelope_mod.gateway_context(LambdaContext(case["client_context"])),
        options(case),
        TIMESTAMP,
    )
    assert event["endpoint"] == "/passthru/echo"


def test_timestamp_is_utc_with_microseconds():
    assert map_case("mcp-tools-call-lambda")["timestamp"] == "2026-09-20T06:24:30.123456+00:00"


def test_client_context_may_be_a_plain_mapping():
    case = load_case("mcp-tools-call-lambda")
    context = envelope_mod.gateway_context({"client_context": {"custom": case["client_context"]}})
    assert context.request_id == "request-id-01"
    assert context.gateway_id == "example-gateway-abcdefghij"


def test_missing_client_context_degrades_the_event_not_the_request():
    case = load_case("mcp-tools-call-lambda")
    event = source_event(
        envelope_mod.parse(case["input"]),
        envelope_mod.gateway_context(None),
        options(case),
        TIMESTAMP,
    )
    assert event["event_id"] == ""
    assert event["host"] == ""
    assert event["body"]["method"] == "tools/call"
