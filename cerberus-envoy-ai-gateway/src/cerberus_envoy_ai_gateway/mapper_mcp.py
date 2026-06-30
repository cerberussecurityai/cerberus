"""Map an MCP span from the Envoy AI Gateway MCP proxy to a Cerberus event.

Attribute names verified against the ai-gateway v0.7.0 source
(internal/tracing/mcp.go): ``mcp.method.name``, ``mcp.tool.name``,
``mcp.prompt.name``, ``mcp.resource.uri``, ``mcp.request.id``,
``mcp.backend.name``, ``mcp.session.id``, ``mcp.client.name``,
``mcp.client.version``, ``mcp.protocol.version``, ``mcp.transport``.

v0.7.0 does NOT record tool-call arguments in span attributes (confirmed —
only ``CallToolParams.Name`` is captured), so gateway-observed tool calls
land in MCP discovery at tool-name granularity with empty
``arguments_observed``. The argument extraction below probes candidate keys
anyway so argument capture lights up if a future gateway version records
them — re-check with CERBERUS_DUMP_SPANS=true when bumping versions.

Events follow the cerberus-mcp contract (cerberus-mcp/src/cerberus_mcp/structs.py):
endpoint ``mcp://{server}/{handler}``, scheme ``"mcp"``, method ``mcp_*``, and
custom_data keys consumed by event_process's MCPDiscoveryUpdater.
"""

from typing import Any

from opentelemetry.proto.trace.v1.trace_pb2 import Span

from . import __version__
from .config import Config
from .spanfields import (
    duration_ms,
    error_message,
    first_attr,
    iso_timestamp,
    parse_json_value,
    raw_client_ip,
    span_user_agent,
    span_user_id,
)

# JSON-RPC method → (Cerberus event method, handler attribute keys)
_METHODS = {
    "tools/call": ("mcp_tool_call", ("mcp.tool.name",)),
    "resources/read": ("mcp_resource_read", ("mcp.resource.uri",)),
    "prompts/get": ("mcp_prompt_get", ("mcp.prompt.name",)),
}

_EVENT_TYPES = {
    "mcp_tool_call": "tool_call",
    "mcp_resource_read": "resource_read",
    "mcp_prompt_get": "prompt_get",
}

# Upstream MCP backend name: spans record `mcp.backend.name` (verified in
# RecordRouteToBackend, internal/tracing/mcp.go); `mcp.backend` is the
# metrics-side attribute, kept as a fallback.
_SERVER_KEYS = (
    "mcp.backend.name",
    "mcp.backend",
    "mcp.server.name",
)

_SESSION_KEYS = ("mcp.session.id", "session.id")
_CLIENT_NAME_KEYS = ("mcp.client.name",)
_CLIENT_VERSION_KEYS = ("mcp.client.version",)

# Candidate keys for tool/prompt arguments (full-JSON variants).
_ARGUMENT_KEYS = (
    "mcp.tool.arguments",
    "mcp.request.arguments",
    "mcp.tool.call.arguments",
    "input.value",
)
# Per-argument variant: mcp.request.argument.<name> = <value>.
_ARGUMENT_PREFIX = "mcp.request.argument."

# tools/list response payloads, if the gateway ever records them — enables
# mcp_schema_report events (currently a documented known gap).
_TOOL_LIST_KEYS = ("mcp.tools.list", "output.value")


def _arguments(attrs: dict[str, Any]) -> dict[str, Any]:
    """Extract handler arguments as a dict (MCPDiscoveryUpdater requires a dict)."""
    value = parse_json_value(first_attr(attrs, _ARGUMENT_KEYS))
    if isinstance(value, dict):
        # tools/call payloads nest as {"name": ..., "arguments": {...}}, or — if a
        # gateway records the full JSON-RPC request via input.value — under
        # {"params": {"arguments": {...}}}.
        inner = value.get("arguments")
        if not isinstance(inner, dict):
            params = value.get("params")
            inner = params.get("arguments") if isinstance(params, dict) else None
        if isinstance(inner, dict):
            return inner
        # Never forward a full JSON-RPC envelope as the arguments dict.
        if "jsonrpc" in value or "method" in value:
            return {}
        return value

    per_arg = {
        key[len(_ARGUMENT_PREFIX) :]: parse_json_value(raw)
        for key, raw in attrs.items()
        if key.startswith(_ARGUMENT_PREFIX)
    }
    return per_arg


def _schema_report_tools(attrs: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Tool declarations from a tools/list span, when the response is recorded."""
    value = parse_json_value(first_attr(attrs, _TOOL_LIST_KEYS))
    if isinstance(value, dict):
        value = value.get("tools")
    if not isinstance(value, list):
        return None
    tools = [
        {
            "name": item.get("name"),
            "description": item.get("description"),
            "input_schema": item.get("inputSchema") or item.get("input_schema"),
        }
        for item in value
        if isinstance(item, dict) and item.get("name")
    ]
    return tools or None


def map_mcp_span(span: Span, attrs: dict[str, Any], config: Config) -> dict[str, Any] | None:
    """Build a raw (pre-sanitization) MCPEventData-shaped event dict.

    Returns None for JSON-RPC methods that don't map to a Cerberus event
    (initialize, notifications, tools/list without a recorded response, ...).
    """
    jsonrpc_method = str(attrs.get("mcp.method.name") or "")
    server = str(first_attr(attrs, _SERVER_KEYS) or config.mcp_server_fallback)

    common = {
        # Backend expects 'remote_addr' (same rename cerberus-django /
        # cerberus-mcp / flex-gateway apply at the wire boundary).
        "remote_addr": raw_client_ip(attrs, config.client_ip_attribute),
        "scheme": "mcp",
        "timestamp": iso_timestamp(span),
        "headers": None,
        "query_params": None,
        "user_agent": span_user_agent(
            attrs, config.user_agent_attribute, f"cerberus-envoy-ai-gateway/{__version__}"
        ),
        "user_id": span_user_id(attrs, config.user_id_attribute),
    }

    if jsonrpc_method == "tools/list":
        tools = _schema_report_tools(attrs)
        if not tools:
            return None
        return {
            **common,
            "endpoint": f"mcp://{server}/schema_report",
            "method": "mcp_schema_report",
            "body": None,
            "custom_data": {
                "integration": "envoy-ai-gateway",
                "mcp_server": server,
                "event_type": "schema_report",
                "tools": tools,
                "resources": [],
                "prompts": [],
                "trace_id": span.trace_id.hex(),
            },
        }

    mapping = _METHODS.get(jsonrpc_method)
    if mapping is None:
        return None
    method, handler_keys = mapping

    handler = str(first_attr(attrs, handler_keys) or "unknown")
    error = error_message(span, attrs)
    arguments = _arguments(attrs)

    custom_data: dict[str, Any] = {
        "integration": "envoy-ai-gateway",
        "mcp_server": server,
        "handler_name": handler,
        "event_type": _EVENT_TYPES[method],
        "duration_ms": duration_ms(span),
        "arguments": arguments,
        "error": error,
        # Tool results are not recorded in gateway spans — documented gap.
        "result_summary": None,
        "session_id": first_attr(attrs, _SESSION_KEYS),
        # Recorded on initialize spans; usually absent on per-call spans.
        "client_name": first_attr(attrs, _CLIENT_NAME_KEYS),
        "client_version": first_attr(attrs, _CLIENT_VERSION_KEYS),
        "request_id": attrs.get("mcp.request.id"),
        "mcp_transport": attrs.get("mcp.transport"),
        "mcp_protocol_version": attrs.get("mcp.protocol.version"),
        "trace_id": span.trace_id.hex(),
    }

    return {
        **common,
        "endpoint": f"mcp://{server}/{handler}",
        "method": method,
        "body": arguments or None,
        "custom_data": custom_data,
    }
