"""Minimal MCP server (streamable HTTP, JSON responses) with one `echo` tool.

Implements just the JSON-RPC methods the gateway's MCP proxy exercises:
initialize, notifications/initialized, ping, tools/list, tools/call.
"""

import uvicorn
from fastapi import FastAPI, Response

app = FastAPI(title="mock-mcp")

TOOLS = [
    {
        "name": "echo",
        "description": "Echo a message back",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        },
    }
]


def _result(request_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


@app.post("/mcp")
async def mcp(payload: dict) -> Response:
    method = payload.get("method")
    request_id = payload.get("id")

    if method == "initialize":
        body = _result(
            request_id,
            {
                "protocolVersion": payload.get("params", {}).get(
                    "protocolVersion", "2025-06-18"
                ),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-mcp", "version": "0.1.0"},
            },
        )
    elif method == "tools/list":
        body = _result(request_id, {"tools": TOOLS})
    elif method == "tools/call":
        arguments = payload.get("params", {}).get("arguments", {})
        body = _result(
            request_id,
            {"content": [{"type": "text", "text": f"echo: {arguments.get('message', '')}"}]},
        )
    elif method == "ping":
        body = _result(request_id, {})
    else:
        # Notifications get a 202 with no body per streamable HTTP transport.
        if request_id is None:
            return Response(status_code=202)
        body = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"method not found: {method}"},
        }

    import json

    return Response(
        content=json.dumps(body),
        media_type="application/json",
        headers={"Mcp-Session-Id": "mock-session-1"},
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9082, log_level="warning")
