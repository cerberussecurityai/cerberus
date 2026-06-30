from helpers import load_expected, load_export, single_span

from cerberus_envoy_ai_gateway.mapper_mcp import map_mcp_span
from cerberus_envoy_ai_gateway.otlp import span_attributes


def _map(name: str, config):
    span = single_span(load_export(name))
    return map_mcp_span(span, span_attributes(span), config)


def test_tool_call_golden(config):
    assert _map("mcp_tool_call", config) == load_expected("mcp_tool_call")


def test_tool_call_satisfies_backend_mcp_detection(config):
    # event_process requires endpoint mcp://... AND method mcp_* to route
    # events into the MCP discovery pipeline.
    event = _map("mcp_tool_call", config)
    assert event["endpoint"].startswith("mcp://")
    assert event["method"].startswith("mcp_")
    assert isinstance(event["custom_data"]["arguments"], dict)


def test_resource_read(config):
    event = _map("mcp_resource_read", config)
    assert event["method"] == "mcp_resource_read"
    assert event["endpoint"] == "mcp://docs-mcp/file:///docs/readme.md"
    assert event["custom_data"]["handler_name"] == "file:///docs/readme.md"
    assert event["custom_data"]["event_type"] == "resource_read"
    assert event["custom_data"]["arguments"] == {}


def test_initialize_is_skipped(config):
    assert _map("mcp_initialize", config) is None


def test_tools_list_with_recorded_response_emits_schema_report(config):
    event = _map("mcp_tools_list_schema", config)
    assert event is not None
    assert event["method"] == "mcp_schema_report"
    assert event["endpoint"] == "mcp://weather-mcp/schema_report"
    [tool] = event["custom_data"]["tools"]
    assert tool["name"] == "get_weather"
    assert tool["input_schema"]["type"] == "object"
    assert event["custom_data"]["resources"] == []
    assert event["custom_data"]["prompts"] == []


def test_server_fallback_when_backend_attr_missing(config):
    # mcp_initialize has no backend attr; craft a tools/call without one by
    # reusing the prompt fixture pattern: simplest is to check fallback via
    # the resource fixture stripped of its backend attribute.
    request = load_export("mcp_tool_call")
    span = single_span(request)
    attrs = span_attributes(span)
    del attrs["mcp.backend.name"]
    event = map_mcp_span(span, attrs, config)
    assert event["endpoint"] == f"mcp://{config.mcp_server_fallback}/get_weather"
    assert event["custom_data"]["mcp_server"] == config.mcp_server_fallback


def test_nested_tool_call_arguments_unwrap(config):
    request = load_export("mcp_tool_call")
    span = single_span(request)
    attrs = span_attributes(span)
    attrs["mcp.tool.arguments"] = '{"name": "get_weather", "arguments": {"location": "NYC"}}'
    event = map_mcp_span(span, attrs, config)
    assert event["custom_data"]["arguments"] == {"location": "NYC"}


def test_per_argument_attribute_variant(config):
    request = load_export("mcp_tool_call")
    span = single_span(request)
    attrs = span_attributes(span)
    del attrs["mcp.tool.arguments"]
    attrs["mcp.request.argument.location"] = "Tokyo"
    attrs["mcp.request.argument.units"] = "imperial"
    event = map_mcp_span(span, attrs, config)
    assert event["custom_data"]["arguments"] == {"location": "Tokyo", "units": "imperial"}


def test_arguments_unwrap_jsonrpc_envelope():
    from cerberus_envoy_ai_gateway.mapper_mcp import _arguments

    attrs = {
        "input.value": (
            '{"jsonrpc": "2.0", "method": "tools/call", '
            '"params": {"name": "get_weather", "arguments": {"q": "NYC"}}}'
        )
    }
    assert _arguments(attrs) == {"q": "NYC"}


def test_arguments_drops_jsonrpc_envelope_without_arguments():
    from cerberus_envoy_ai_gateway.mapper_mcp import _arguments

    attrs = {"input.value": '{"jsonrpc": "2.0", "method": "initialize", "params": {}}'}
    assert _arguments(attrs) == {}


def test_long_request_id_capped(config):
    request = load_export("mcp_tool_call")
    span = single_span(request)
    attrs = span_attributes(span)
    attrs["mcp.request.id"] = "x" * 5000
    event = map_mcp_span(span, attrs, config)
    assert len(event["custom_data"]["request_id"]) <= 256
