from helpers import load_capture

from cerberus_litellm import payload


def _slo(name: str) -> dict:
    return load_capture(name)["standard_logging_object"]


def test_get_walks_nested_paths_safely():
    slo = _slo("chat")
    assert payload.get(slo, "metadata", "user_api_key_alias") == "spike-key"
    assert payload.get(slo, "metadata", "nope", "deeper", default="d") == "d"
    assert payload.get("not a dict", "x") is None


def test_call_type_and_status():
    assert payload.call_type(_slo("chat")) == "acompletion"
    assert payload.status(_slo("chat")) == "ok"
    assert payload.status(_slo("failure_500")) == "error"
    assert payload.call_type({}) == ""


def test_identity_fields():
    ident = payload.identity(_slo("chat"))
    assert ident["litellm_key_alias"] == "spike-key"
    assert ident["litellm_team_alias"] == "spike-team"
    assert ident["litellm_user_id"] == "spike-user"
    assert ident["litellm_end_user_id"] == "end-user-42"
    assert ident["litellm_org_id"] is None
    assert len(ident["litellm_key_hash"]) == 64


def test_custom_headers_lowercased_strings_only():
    headers = payload.custom_headers(_slo("chat"))
    assert headers["x-litellm-session-id"] == "spike-session-0001"
    assert headers["x-cerberus-turn-id"] == "turn-1"
    junk = {"metadata": {"requester_custom_headers": {"X-A": 1, "X-B": "b"}}}
    assert payload.custom_headers(junk) == {"x-b": "b"}


def test_timestamps():
    slo = _slo("chat")
    assert payload.iso_timestamp(slo["startTime"]).endswith("+00:00")
    assert payload.iso_timestamp(None) is None
    assert payload.iso_timestamp("junk") is None
    assert payload.duration_ms(slo) is not None and payload.duration_ms(slo) > 0
    assert payload.duration_ms({"startTime": "x"}) is None


def test_non_finite_durations_are_none():
    assert payload.duration_ms({"startTime": float("nan"), "endTime": 1.0}) is None
    assert payload.duration_ms({"startTime": float("inf"), "endTime": 1.0}) is None
    assert payload.duration_ms({"startTime": 0.0, "endTime": float("inf")}) is None
    assert payload.ttft_ms({"startTime": 0.0, "completionStartTime": float("nan")}) is None


def test_oversized_int_timestamps_do_not_raise():
    assert payload.duration_ms({"startTime": 10**400, "endTime": 1.0}) is None
    assert payload.duration_ms({"startTime": 1.0, "endTime": 10**400}) is None
    assert payload.ttft_ms({"startTime": 1.0, "completionStartTime": 10**400}) is None


def test_ttft_only_when_completion_start_present():
    slo = dict(_slo("chat_stream_tools"))
    assert payload.ttft_ms(slo) is not None
    slo.pop("completionStartTime")
    assert payload.ttft_ms(slo) is None


def test_error_info():
    err = payload.error_info(_slo("failure_500"))
    assert err["error_class"] == "InternalServerError"
    assert err["error_code"] == "mock_500"
    assert err["error_normalized"] == "500_PROVIDER_INTERNAL_ERROR"
    assert "mock upstream exploded" in err["error_message"]
    assert payload.error_info(_slo("chat")) == {
        "error_message": None,
        "error_class": None,
        "error_code": None,
        "error_normalized": None,
    }


def test_user_id_precedence():
    slo = _slo("chat")
    assert payload.user_id(slo, ("end_user", "user_id", "key_alias")) == "end-user-42"
    assert payload.user_id(slo, ("user_id", "end_user")) == "spike-user"
    assert payload.user_id(slo, ("key_alias",)) == "spike-key"
    assert payload.user_id(slo, ("team_alias",)) == "spike-team"
    assert payload.user_id({}, ("end_user", "user_id")) is None


def test_session_id_prefers_payload_then_header():
    slo = dict(_slo("chat"))
    slo["session_id"] = "from-payload"
    assert payload.session_id(slo, "x-litellm-session-id") == "from-payload"  # beats header
    slo["session_id"] = 42  # non-string payload value is ignored
    assert payload.session_id(slo, "x-litellm-session-id") == "spike-session-0001"
    slo["session_id"] = None
    assert payload.session_id(slo, "x-litellm-session-id") == "spike-session-0001"  # header
    assert payload.session_id(slo, "x-other") is None


def test_turn_id_from_header():
    assert payload.turn_id(_slo("chat"), "x-cerberus-turn-id") == "turn-1"
    assert payload.turn_id(_slo("chat"), "x-missing") is None


def test_host_only():
    assert payload.host_only("http://mock-llm:9081/v1?key=secret") == "mock-llm"
    assert payload.host_only("https://user:pw@api.example.com/v1") == "api.example.com"
    assert payload.host_only(None) is None
    assert payload.host_only(42) is None


def test_w3c_trace_id():
    assert (
        payload.w3c_trace_id("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        == "4bf92f3577b34da6a3ce929d0e0e4736"
    )
    assert payload.w3c_trace_id("garbage") is None
    assert payload.w3c_trace_id(None) is None
