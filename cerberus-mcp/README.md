# cerberus-mcp

MCP (Model Context Protocol) server instrumentation for [Cerberus](https://github.com/gpotrock/cerberus) API monitoring.

Drop-in replacement for `FastMCP` that captures tool, resource, and prompt call metrics and streams them to the Cerberus analytics pipeline.

## Installation

```bash
pip install cerberus-mcp
```

## Quick Start

Replace `FastMCP` with `CerberusMCP` — a single-line change:

```python
from cerberus_mcp import CerberusMCP

mcp = CerberusMCP(
    "my-server",
    cerberus_config={
        "token": "your-api-key",
        "client_id": "your-client-id",
        "ws_url": "wss://your-cerberus-backend:8765",
    }
)

@mcp.tool()
def get_weather(location: str) -> str:
    """Get weather for a location."""
    return f"Sunny in {location}"

@mcp.resource("config://settings")
def get_settings() -> str:
    """Return server settings."""
    return '{"theme": "dark"}'

@mcp.prompt()
def summarize(text: str) -> str:
    """Summarize text."""
    return f"Please summarize: {text}"
```

All tool calls, resource reads, and prompt invocations are automatically captured with:
- Execution timing (duration_ms)
- Sanitized arguments (sensitive values redacted)
- Error tracking
- Result summaries
- MCP client identity (name, version) and session correlation

Events are sent asynchronously via WebSocket to the Cerberus event_ingest backend using the same pipeline as `cerberus-django`.

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `token` | Yes | API key for Cerberus authentication |
| `client_id` | Yes | Client identifier for your MCP server |
| `ws_url` | Yes | WebSocket URL of your Cerberus event_ingest server |
| `server_name` | No | Override server name in events (defaults to MCP server name) |
| `secret_key` | No | HMAC key for pseudonymizing source IPs. **Without it, source IPs are transmitted in the clear** and the package logs a single warning. Share the same key across integrations so digests correlate. |

Set `CERBERUS_DEBUG=true` to enable verbose logging.

## How It Works

`CerberusMCP` subclasses `FastMCP` from the MCP Python SDK and wraps the `tool()`, `resource()`, and `prompt()` decorators. Each handler call is intercepted to capture timing, arguments, results, and errors. Events are queued into a thread-safe queue and sent via a background WebSocket connection — zero impact on your MCP server's response times.

## Requirements

- Python >= 3.10
- `mcp` >= 1.0 (MCP Python SDK)
- `websockets` >= 12.0
- A running Cerberus backend ([cerberus-int](https://github.com/gpotrock/cerberus))

## License

MIT
