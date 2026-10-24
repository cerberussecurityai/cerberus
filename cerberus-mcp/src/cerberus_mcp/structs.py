"""
Cerberus MCP Event Data Structures

Defines the MCPEventData dataclass that maps MCP server events to the
CoreData format expected by the Cerberus event_ingest pipeline.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Union


@dataclass
class MCPEventData:
    """Data structure for MCP server event metrics.

    Maps MCP tool/resource/prompt calls to the CoreData format used by
    the Cerberus event pipeline, so event_ingest requires no changes.

    Field mapping:
        - token: API key for authentication (from cerberus_config)
        - source_ip: Client IP for SSE/HTTP transports, "mcp-local" for stdio
        - endpoint: mcp://{server_name}/{handler_name}
        - scheme: "mcp" (distinguishes MCP transport from HTTP)
        - method: Event type (mcp_tool_call, mcp_resource_read, mcp_prompt_get,
          or mcp_schema_report)
        - timestamp: ISO 8601 UTC timestamp
        - custom_data: MCP-specific metadata (see below)
        - headers: None (MCP has no HTTP headers)
        - query_params: None (MCP has no query params)
        - body: Sanitized handler arguments dict
        - user_agent: "cerberus-mcp/{version}"
        - user_id: MCP client ID if available

    custom_data fields (handler calls; an mcp_schema_report event carries
    mcp_server, event_type "schema_report", and tools/resources/prompts lists):
        - mcp_server: Server name
        - handler_name: Tool/resource/prompt name
        - event_type: tool_call, resource_read, or prompt_get
        - duration_ms: Call duration in milliseconds
        - error: Error message if call failed
        - result_summary: Type and size of result
        - session_id: UUID per ServerSession
        - client_name: MCP client name from ClientInfo
        - client_version: MCP client version from ClientInfo
        - request_id: MCP request ID
        - mcp_client_id: MCP client ID from context
    """
    token: str
    source_ip: str
    endpoint: str
    scheme: Union[bool, str]
    method: str
    timestamp: str  # ISO 8601 format timestamp
    custom_data: Optional[Dict] = None

    # Additional fields matching CoreData
    headers: Optional[Dict] = None
    query_params: Optional[Dict] = None
    body: Optional[Dict] = None
    user_agent: Optional[str] = None
    user_id: Optional[str] = None
