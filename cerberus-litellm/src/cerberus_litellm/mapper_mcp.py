"""Map LiteLLM MCP-gateway logging payloads to Cerberus MCP events.

Two payload shapes, both verified on LiteLLM v1.105.1 (CER-346 spike):

* ``call_type == "call_mcp_tool"`` — one tool call. The tool, server and
  arguments are in ``metadata.mcp_tool_call_metadata``; the full
  ``CallToolResult`` is in ``response`` on success, while an ``isError``
  result arrives as a *failure* payload whose ``error_message`` holds the
  result text.
* ``call_type == "list_mcp_tools"`` — a tools/list. ``response_obj`` is the
  full tool list with ``input_schema``; it becomes one ``mcp_schema_report``
  per server, the same event cerberus-mcp emits from its own registry.

Events follow the cerberus-mcp contract: endpoint ``mcp://{server}/{tool}``,
scheme ``"mcp"``, method ``mcp_*``, discovery fields in ``custom_data``.
The mapper is lossless; pipeline.py sanitizes, truncates and caps.
"""

from collections.abc import Mapping
from typing import Any

from . import __version__, payload
from .config import Config
from .mapper_llm import endpoint_segment

MAX_LABEL_CHARS = 256
TRUNCATION_MARKER = "...[TRUNCATED]"


def split_namespaced(name: str, fallback: str) -> tuple[str, str]:
    """``{server}-{tool}`` → (server, tool). LiteLLM forbids ``-`` in server
    names, so the first dash is the namespace boundary; a bare tool name
    belongs to ``fallback``."""
    if "-" in name:
        server, tool = name.split("-", 1)
        if server and tool:
            return server[:MAX_LABEL_CHARS], tool[:MAX_LABEL_CHARS]
    return fallback[:MAX_LABEL_CHARS], name[:MAX_LABEL_CHARS]


def result_text(content: Any, limit: int) -> str | None:
    """Flatten MCP content blocks to text, bounded to ``limit`` characters."""
    if content is None:
        return None
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, Mapping) and block.get("type") == "text":
                value = block.get("text")
                parts.append(value if isinstance(value, str) else str(value))
            elif isinstance(block, Mapping):
                parts.append(f"[{block.get('type') or 'block'}]")
            else:
                parts.append(str(block))
        if not parts:
            return None
        text = "\n".join(parts)
    else:
        text = str(content)
    if len(text) > limit:
        return text[:limit] + TRUNCATION_MARKER
    return text


def _label(value: Any, fallback: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()[:MAX_LABEL_CHARS]
    return fallback


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _endpoint(server: str, tool: str) -> str:
    """``mcp://{server}/{tool}`` with both labels safe from the ingest health filter."""
    return f"mcp://{endpoint_segment(server, '_tool')}/{endpoint_segment(tool, '_tool')}"


def _common(slo: Mapping[str, Any], config: Config) -> dict[str, Any]:
    user_agent = payload.get(slo, "user_agent")
    return {
        "remote_addr": payload.get(slo, "requester_ip_address"),
        "scheme": "mcp",
        "timestamp": payload.iso_timestamp(payload.get(slo, "startTime")),
        "session_id": payload.session_id(slo, config.session_header),
        "headers": None,
        "query_params": None,
        "user_agent": (
            user_agent
            if isinstance(user_agent, str) and user_agent
            else f"cerberus-litellm/{__version__}"
        ),
        "user_id": payload.user_id(slo, config.user_id_source),
    }


def _correlation(slo: Mapping[str, Any], config: Config) -> dict[str, Any]:
    return {
        "route_path": payload.get(slo, "metadata", "user_api_key_request_route"),
        "trace_id": None,
        "litellm_trace_id": _str_or_none(payload.get(slo, "trace_id")),
        "litellm_call_id": _str_or_none(payload.get(slo, "litellm_call_id")),
        "turn_id": payload.turn_id(slo, config.turn_header),
    }


def map_mcp_event(slo: Mapping[str, Any], config: Config) -> dict[str, Any] | None:
    """Build a raw MCPEventData-shaped event for one tool call, or None."""
    if not isinstance(slo, Mapping):
        return None
    meta = payload.get(slo, "metadata", "mcp_tool_call_metadata")
    meta = meta if isinstance(meta, Mapping) else {}
    tool = meta.get("name")
    if not isinstance(tool, str) or not tool:
        return None
    server = _label(meta.get("mcp_server_name"), config.mcp_server_fallback)
    tool = tool[:MAX_LABEL_CHARS]
    arguments = meta.get("arguments")
    arguments = dict(arguments) if isinstance(arguments, Mapping) else {}
    status = payload.status(slo)
    errors = payload.error_info(slo)
    response = payload.get(slo, "response")
    response = response if isinstance(response, Mapping) else {}
    is_error = status == "error" or bool(response.get("is_error"))

    summary: str | None = None
    if config.capture_mcp_results:
        if status == "error":
            summary = result_text(errors["error_message"], config.mcp_result_max_chars)
        else:
            summary = result_text(response.get("content"), config.mcp_result_max_chars)

    custom_data: dict[str, Any] = {
        "integration": "litellm",
        "mcp_server": server,
        "handler_name": tool,
        "event_type": "tool_call",
        "duration_ms": payload.duration_ms(slo),
        "arguments": arguments,
        "error": errors["error_message"],
        "result_summary": summary,
        "result_is_error": is_error,
        "result_type": _str_or_none(response.get("result_type")),
        "session_id": _str_or_none(meta.get("mcp_session_id")),
        "litellm_session_id": payload.session_id(slo, config.session_header),
        "client_name": None,
        "client_version": None,
        "request_id": None,
        "namespaced_tool_name": _str_or_none(meta.get("namespaced_tool_name")),
        "mcp_server_host": payload.host_only(meta.get("mcp_server_resource")),
    }
    custom_data.update(_correlation(slo, config))
    custom_data.update(payload.identity(slo))

    return {
        **_common(slo, config),
        "endpoint": _endpoint(server, tool),
        "method": "mcp_tool_call",
        "body": arguments or None,
        "custom_data": custom_data,
    }


def map_schema_reports(
    slo: Mapping[str, Any], response_obj: Any, config: Config
) -> list[dict[str, Any]]:
    """One ``mcp_schema_report`` per server from a tools/list response."""
    if not isinstance(slo, Mapping) or not isinstance(response_obj, list):
        return []
    by_server: dict[str, list[dict[str, Any]]] = {}
    for item in response_obj:
        if not isinstance(item, Mapping):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name:
            continue
        server, tool = split_namespaced(name, config.mcp_server_fallback)
        schema = item.get("input_schema")
        if schema is None:
            schema = item.get("inputSchema")
        description = item.get("description")
        by_server.setdefault(server, []).append(
            {
                "name": tool,
                "description": description if isinstance(description, str) else "",
                "input_schema": schema if isinstance(schema, Mapping) else None,
            }
        )
    events: list[dict[str, Any]] = []
    for server, tools in by_server.items():
        custom_data: dict[str, Any] = {
            "integration": "litellm",
            "mcp_server": server,
            "event_type": "schema_report",
            "tools": tools,
            "resources": [],
            "prompts": [],
        }
        custom_data.update(_correlation(slo, config))
        custom_data.update(payload.identity(slo))
        events.append(
            {
                **_common(slo, config),
                "endpoint": f"mcp://{endpoint_segment(server, '_tool')}/__schema__",
                "method": "mcp_schema_report",
                "body": None,
                "custom_data": custom_data,
            }
        )
    return events
