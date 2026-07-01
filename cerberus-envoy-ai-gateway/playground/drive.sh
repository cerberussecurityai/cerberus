#!/usr/bin/env bash
# Drive traffic through the playground and show what reached the bridge.
#
#   ./drive.sh           # through the gateway (requires run.sh with aigw)
#   ./drive.sh --direct  # POST recorded OTLP fixtures straight to the bridge
set -euo pipefail
cd "$(dirname "$0")"

GATEWAY="http://127.0.0.1:1975"
BRIDGE="http://127.0.0.1:4318"

if [[ "${1:-}" == "--direct" ]]; then
  echo "==> Posting recorded OTLP fixtures directly to the bridge..."
  for fixture in llm_openai_chat mcp_tool_call; do
    curl -fsS -X POST "$BRIDGE/v1/traces" \
      -H 'Content-Type: application/json' \
      --data-binary "@../tests/fixtures/spans/$fixture.json" >/dev/null
    echo "    posted $fixture"
  done
else
  echo "==> LLM: chat completion through the gateway..."
  curl -fsS "$GATEWAY/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -H 'x-user-id: demo-user' \
    -H 'x-forwarded-for: 203.0.113.7' \
    -d '{"model": "mock-gpt", "messages": [{"role": "user", "content": "hello from the playground"}]}' \
    | head -c 400; echo

  echo "==> MCP: initialize + tools/call through the gateway..."
  SESSION=$(curl -fsS -D - -o /dev/null "$GATEWAY/mcp" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "drive.sh", "version": "0"}}}' \
    | tr -d '\r' | awk 'tolower($1) == "mcp-session-id:" {print $2}')
  echo "    session: ${SESSION:-<none>}"

  curl -fsS "$GATEWAY/mcp" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    ${SESSION:+-H "Mcp-Session-Id: $SESSION"} \
    -d '{"jsonrpc": "2.0", "method": "notifications/initialized"}' >/dev/null || true

  curl -fsS "$GATEWAY/mcp" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H 'x-user-id: demo-user' \
    ${SESSION:+-H "Mcp-Session-Id: $SESSION"} \
    -d '{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "mock-mcp__echo", "arguments": {"message": "hi mcp", "api_key": "should-be-redacted"}}}' \
    | head -c 400; echo
fi

echo "==> Waiting for the bridge to flush..."
sleep 3
echo "==> Bridge stats:"
curl -fsS "$BRIDGE/stats"; echo
echo "==> Events that reached the stub ingest:"
docker compose logs --no-log-prefix stub-ingest | tail -60
