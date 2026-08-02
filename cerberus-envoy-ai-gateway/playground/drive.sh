#!/usr/bin/env bash
# Drive traffic through the playground and show what reached the bridge.
#
#   ./drive.sh           # through the gateway (requires run.sh with aigw)
#   ./drive.sh --direct  # POST recorded OTLP fixtures straight to the bridge
#   ./drive.sh --traceparent 00-<32hex>-<16hex>-00   # unsampled upstream parent
#
# --traceparent sends the same W3C context on BOTH carriers the gateway reads:
# an HTTP header (the only one the LLM path looks at) and the JSON-RPC
# params._meta map (the only one the MCP path looks at). Ending it in -00 is how
# you reproduce the sampling drop documented in the README's known-gaps table.
set -euo pipefail
cd "$(dirname "$0")"

GATEWAY="http://127.0.0.1:1975"
BRIDGE="http://127.0.0.1:4318"

TRACEPARENT=""
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --traceparent)
      [[ $# -ge 2 && -n "$2" ]] || { echo "--traceparent needs a value" >&2; exit 2; }
      TRACEPARENT="$2"; shift 2 ;;
    --traceparent=*)
      TRACEPARENT="${1#*=}"
      [[ -n "$TRACEPARENT" ]] || { echo "--traceparent needs a value" >&2; exit 2; }
      shift ;;
    --direct) ARGS+=("$1"); shift ;;
    # Reject unknown options rather than passing them through. A mistyped
    # --tracepatent (or --traceparent=X before the alias above existed) would
    # otherwise be swallowed as a positional and the run would proceed with no
    # trace context at all — a clean, silent run that tested nothing, which is
    # the same false pass the --direct guard below exists to prevent.
    -*)
      echo "unknown option: $1" >&2
      echo "usage: drive.sh [--direct] [--traceparent <2hex>-<32hex>-<16hex>-<2hex>]" >&2
      exit 2 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done
set -- ${ARGS[@]+"${ARGS[@]}"}

# Validate before use. The value is spliced into a JSON body below, so anything
# containing a quote would otherwise produce a malformed payload that curl still
# sends — you'd debug a confusing gateway error instead of a typo. Rejecting
# non-W3C input also means the splice can never introduce stray JSON structure.
TP_RE='^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'
if [[ -n "$TRACEPARENT" ]]; then
  if [[ ! "$TRACEPARENT" =~ $TP_RE ]]; then
    echo "--traceparent must be W3C format <2hex>-<32hex>-<16hex>-<2hex>, e.g." >&2
    echo "  00-11111111111111111111111111111111-2222222222222222-00" >&2
    exit 2
  fi
  # An all-zero trace or parent id is invalid per W3C and makes the gateway treat
  # the request as having NO parent — which here would look exactly like "the
  # unsampled parent wasn't dropped", the false pass this harness exists to catch.
  case "$TRACEPARENT" in
    *-00000000000000000000000000000000-*|*-0000000000000000-*)
      echo "--traceparent has an all-zero trace or parent id; the gateway would" >&2
      echo "treat this as no parent at all, silently invalidating the test." >&2
      exit 2 ;;
  esac
fi

# Injected into params._meta for MCP; leading comma only when actually set.
MCP_META=""
[[ -n "$TRACEPARENT" ]] && MCP_META=", \"_meta\": {\"traceparent\": \"$TRACEPARENT\"}"

# Refuse rather than warn: --direct never reaches the gateway, so it cannot
# exercise sampling at all. Accepting the combination would hand you a clean run
# that looks like "the unsampled parent was captured" while proving nothing —
# the exact false pass this flag exists to detect.
if [[ "${1:-}" == "--direct" && -n "$TRACEPARENT" ]]; then
  echo "--direct posts recorded fixtures straight to the bridge and never reaches" >&2
  echo "the gateway, so --traceparent cannot affect it. Drop one of the two." >&2
  exit 2
fi

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
    ${TRACEPARENT:+-H "traceparent: $TRACEPARENT"} \
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
    -d "{\"jsonrpc\": \"2.0\", \"id\": 2, \"method\": \"tools/call\", \"params\": {\"name\": \"mock-mcp__echo\", \"arguments\": {\"message\": \"hi mcp\", \"api_key\": \"should-be-redacted\"}$MCP_META}}" \
    | head -c 400; echo
fi

echo "==> Waiting for the bridge to flush..."
sleep 3
echo "==> Bridge stats:"
curl -fsS "$BRIDGE/stats"; echo
echo "==> Events that reached the stub ingest:"
docker compose logs --no-log-prefix stub-ingest | tail -60
