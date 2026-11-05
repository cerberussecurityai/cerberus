"""Mock MCP server (streamable HTTP, JSON responses) for the cerberus-litellm playground.

Three tools so result capture can be observed in each shape the gateway
has to handle:
- echo        small text result
- lookup_big  ~20 KB text result (does the result survive capture caps?)
- fail        MCP-level tool error (isError: true), not a transport error

GET /mcp returns 405 so an MCP SDK client skips the server-push stream;
DELETE /mcp returns 200 for session teardown.
"""

import json

import uvicorn
from fastapi import FastAPI, Response

app = FastAPI(title="playground-mock-mcp")

TOOLS = [
    {
        "name": "echo",
        "description": "Echo a message back",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}, "api_key": {"type": "string"}},
            "required": ["message"],
        },
    },
    {
        "name": "lookup_big",
        "description": "Return a large document",
        "inputSchema": {"type": "object", "properties": {"doc_id": {"type": "string"}}, "required": ["doc_id"]},
    },
    {
        "name": "fail",
        "description": "Always returns a tool error",
        "inputSchema": {"type": "object", "properties": {"reason": {"type": "string"}}},
    },
]


def _result(request_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _call(name: str, arguments: dict) -> dict:
    if name == "echo":
        return {"content": [{"type": "text", "text": f"echo: {arguments.get('message', '')}"}]}
    if name == "lookup_big":
        body = (f"document {arguments.get('doc_id', '?')} :: " + "the quick brown fox jumps over the lazy dog. ") * 400
        return {"content": [{"type": "text", "text": body[:20_000]}]}
    if name == "fail":
        return {"content": [{"type": "text", "text": f"tool failed: {arguments.get('reason', 'no reason')}"}], "isError": True}
    return {"content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True}


@app.get("/mcp")
async def mcp_get() -> Response:
    return Response(status_code=405)


@app.delete("/mcp")
async def mcp_delete() -> Response:
    return Response(status_code=200)


@app.post("/mcp")
async def mcp(payload: dict) -> Response:
    method = payload.get("method")
    request_id = payload.get("id")
    params = payload.get("params", {}) or {}

    if method == "initialize":
        body = _result(
            request_id,
            {
                "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "playground-mock-mcp", "version": "0.1.0"},
            },
        )
    elif method == "tools/list":
        body = _result(request_id, {"tools": TOOLS})
    elif method == "tools/call":
        body = _result(request_id, _call(params.get("name", ""), params.get("arguments", {}) or {}))
    elif method == "ping":
        body = _result(request_id, {})
    else:
        if request_id is None:  # notification
            return Response(status_code=202)
        body = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"method not found: {method}"}}

    return Response(content=json.dumps(body), media_type="application/json", headers={"Mcp-Session-Id": "mock-session-1"})


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9082, log_level="warning")
