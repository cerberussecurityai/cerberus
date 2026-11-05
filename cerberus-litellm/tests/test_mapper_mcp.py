import copy
import json
from dataclasses import replace

from helpers import HEALTH_SEGMENTS, load_capture, load_expected

from cerberus_litellm.mapper_mcp import (
    map_mcp_event,
    map_schema_reports,
    result_text,
    split_namespaced,
)


def _map(name: str, config):
    return map_mcp_event(load_capture(name)["standard_logging_object"], config)


def test_tool_call_golden(config):
    assert _map("mcp_tool_call", config) == load_expected("mcp_tool_call")


def test_big_result_is_truncated_to_configured_chars(config):
    event = _map("mcp_tool_call_big", replace(config, mcp_result_max_chars=256))
    summary = event["custom_data"]["result_summary"]
    assert summary.endswith("...[TRUNCATED]")
    assert len(summary) <= 256 + len("...[TRUNCATED]")
    assert event["endpoint"] == "mcp://mockmcp/lookup_big"


def test_error_result_maps_to_error_and_summary(config):
    event = _map("mcp_tool_call_error", config)
    assert event["custom_data"]["error"] == "tool failed: spike"
    assert event["custom_data"]["result_summary"] == "tool failed: spike"
    assert event["custom_data"]["result_is_error"] is True
    assert event["custom_data"]["handler_name"] == "fail"


def test_results_flag_off(config):
    event = _map("mcp_tool_call", replace(config, capture_mcp_results=False))
    assert event["custom_data"]["result_summary"] is None
    assert event["custom_data"]["result_is_error"] is False  # metadata still recorded


def test_arguments_flag_off_handled_by_pipeline_not_mapper(config):
    # The mapper is lossless; pipeline.finalize applies capture_mcp_arguments.
    event = _map("mcp_tool_call", replace(config, capture_mcp_arguments=False))
    assert event["custom_data"]["arguments"] == {
        "message": "hi mcp",
        "api_key": "should-be-redacted",
    }


def test_result_text_joins_text_blocks_and_marks_others():
    content = [
        {"type": "text", "text": "a"},
        {"type": "image", "data": "..."},
        {"type": "text", "text": "b"},
    ]
    assert result_text(content, 100) == "a\n[image]\nb"
    assert result_text("plain", 100) == "plain"
    assert result_text(None, 100) is None
    assert result_text([], 100) is None


def test_split_namespaced():
    assert split_namespaced("mockmcp-echo", "litellm") == ("mockmcp", "echo")
    assert split_namespaced("mockmcp-lookup-big", "litellm") == ("mockmcp", "lookup-big")
    assert split_namespaced("echo", "litellm") == ("litellm", "echo")


def test_schema_reports_one_per_server(config):
    capture = load_capture("mcp_list_tools")
    events = map_schema_reports(capture["standard_logging_object"], capture["response_obj"], config)
    assert len(events) == 1
    event = events[0]
    assert event["endpoint"] == "mcp://mockmcp/__schema__"
    assert event["method"] == "mcp_schema_report"
    assert event["custom_data"]["event_type"] == "schema_report"
    names = [tool["name"] for tool in event["custom_data"]["tools"]]
    assert names == ["echo", "lookup_big", "fail"]
    assert event["custom_data"]["tools"][0]["input_schema"]["type"] == "object"
    assert event["custom_data"]["resources"] == []
    assert event["custom_data"]["prompts"] == []
    assert event["custom_data"]["litellm_key_alias"] == "spike-key"


def test_schema_reports_group_mixed_servers(config):
    tools = [
        {"name": "alpha-one", "description": "", "input_schema": {}},
        {"name": "beta-two", "description": "d", "input_schema": {"type": "object"}},
        {"name": "alpha-three", "description": "", "input_schema": None},
    ]
    slo = load_capture("mcp_list_tools")["standard_logging_object"]
    events = map_schema_reports(slo, tools, config)
    assert sorted(e["custom_data"]["mcp_server"] for e in events) == ["alpha", "beta"]


def test_schema_reports_ignore_junk(config):
    slo = load_capture("mcp_list_tools")["standard_logging_object"]
    assert map_schema_reports(slo, None, config) == []
    assert map_schema_reports(slo, "nope", config) == []
    assert map_schema_reports(slo, [{"no": "name"}], config) == []


def test_mapper_returns_none_without_tool_metadata(config):
    assert map_mcp_event({"call_type": "call_mcp_tool"}, config) is None


def test_no_mcp_event_matches_health_filter(config):
    endpoint = _map("mcp_tool_call", config)["endpoint"]
    assert endpoint.rsplit("/", 1)[-1] not in HEALTH_SEGMENTS


def test_health_named_tool_is_guarded_in_endpoint_only(config):
    slo = copy.deepcopy(load_capture("mcp_tool_call")["standard_logging_object"])
    slo["metadata"]["mcp_tool_call_metadata"]["name"] = "health"
    event = map_mcp_event(slo, config)
    assert event["endpoint"] == "mcp://mockmcp/health_tool"
    assert event["custom_data"]["handler_name"] == "health"


def test_health_named_server_is_guarded_in_endpoint_only(config):
    tools = [{"name": "readyz-echo", "description": "", "input_schema": {}}]
    slo = load_capture("mcp_list_tools")["standard_logging_object"]
    event = map_schema_reports(slo, tools, config)[0]
    assert event["endpoint"] == "mcp://readyz_tool/__schema__"
    assert event["custom_data"]["mcp_server"] == "readyz"


def test_tool_error_text_is_withheld_when_results_capture_is_off(config):
    event = _map("mcp_tool_call_error", replace(config, capture_mcp_results=False))
    assert event["custom_data"]["error"] == "[tool error: result capture disabled]"
    assert event["custom_data"]["result_is_error"] is True
    assert event["custom_data"]["result_summary"] is None
    assert "tool failed: spike" not in json.dumps(event)


def test_transport_error_keeps_message_when_results_capture_is_off(config):
    slo = copy.deepcopy(load_capture("mcp_tool_call_error")["standard_logging_object"])
    slo["error_information"]["error_class"] = "ConnectError"
    slo["error_information"]["error_message"] = "connection refused"
    event = map_mcp_event(slo, replace(config, capture_mcp_results=False))
    assert event["custom_data"]["error"] == "connection refused"


def test_error_text_obeys_result_cap_when_capture_is_on(config):
    slo = copy.deepcopy(load_capture("mcp_tool_call_error")["standard_logging_object"])
    slo["error_information"]["error_message"] = "x " * 500
    event = map_mcp_event(slo, replace(config, mcp_result_max_chars=64))
    assert event["custom_data"]["error"] == "x " * 32 + "...[TRUNCATED]"

    # One unbroken run longer than the redaction slice has no safe place to
    # end, so only the marker is kept.
    slo["error_information"]["error_message"] = "x" * 1000
    event = map_mcp_event(slo, replace(config, mcp_result_max_chars=64))
    assert event["custom_data"]["error"] == "...[TRUNCATED]"
