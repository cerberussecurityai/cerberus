#!/usr/bin/env bash
# Drive the capture-comparison scenarios through LiteLLM. Both capture paths observe the
# same calls; captures land in ./captures/{plugin,otel,events}.
#
#   docker compose down -v && docker compose up -d --build && ./drive.sh
#
# Scenario numbers are printed so capture files can be matched back.
set -eu
cd "$(dirname "$0")"

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/spike.XXXXXX")
KEY=""

# Idempotent; runs on every exit path so a failed run never leaves the
# throwaway virtual key in captures/. Does not alter the exit status.
scrub_captures() {
  [ -n "${KEY:-}" ] || return 0
  grep -rlF -- "$KEY" captures 2>/dev/null | while IFS= read -r f; do
    KEYVAL="$KEY" perl -pi -e 's/\Q$ENV{KEYVAL}\E/<redacted-virtual-key>/g' "$f"
  done
  return 0
}
cleanup() { scrub_captures; rm -rf "$TMPD"; }
trap cleanup EXIT

LITELLM="${LITELLM:-http://127.0.0.1:4000}"
MASTER="sk-spike-master"
SESSION="spike-session-0001"
TRACEPARENT="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

say() { printf '\n==> %s\n' "$*"; }
json() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1], ""))' "$1"; }

say "waiting for LiteLLM"
for _ in $(seq 1 90); do
  curl -fsS "$LITELLM/health/liveliness" >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS "$LITELLM/health/liveliness" >/dev/null || { echo "LiteLLM never became live" >&2; exit 1; }

say "S0 identity: team + virtual key (so key hash/alias/team/user are populated)"
TEAM_ID=$(curl -fsS "$LITELLM/team/new" -H "Authorization: Bearer $MASTER" -H 'Content-Type: application/json' \
  -d '{"team_alias": "spike-team", "metadata": {"org": "spike-org"}, "object_permission": {"mcp_servers": ["mockmcp"]}}' | json team_id)
echo "    team_id=$TEAM_ID"
KEY=$(curl -sS "$LITELLM/key/generate" -H "Authorization: Bearer $MASTER" -H 'Content-Type: application/json' \
  -d "{\"key_alias\": \"spike-key\", \"team_id\": \"$TEAM_ID\", \"user_id\": \"spike-user\", \"metadata\": {\"purpose\": \"capture-comparison\"}, \"object_permission\": {\"mcp_servers\": [\"mockmcp\"]}}" | json key)
echo "    key=${KEY:0:12}..."
[ -n "$KEY" ] || { echo "no virtual key issued" >&2; exit 1; }

set +e  # scenarios may legitimately fail; keep going
COMMON=(-H "Authorization: Bearer $KEY" -H 'Content-Type: application/json'
        -H "x-litellm-session-id: $SESSION" -H 'x-cerberus-turn-id: turn-1'
        -H "traceparent: $TRACEPARENT" -H "baggage: session.id=$SESSION,user.id=baggage-user"
        -H 'x-forwarded-for: 203.0.113.7' -H 'User-Agent: spike-agent/0.1'
        -H 'x-custom-secret: should-not-leak')

TOOLS='[{"type":"function","function":{"name":"get_weather","description":"Get weather","parameters":{"type":"object","properties":{"city":{"type":"string"},"unit":{"type":"string"}},"required":["city"]}}}]'
ATOOLS='[{"name":"get_weather","description":"Get weather","input_schema":{"type":"object","properties":{"city":{"type":"string"},"unit":{"type":"string"}},"required":["city"]}}]'

say "S1 chat non-stream"
curl -sS "$LITELLM/v1/chat/completions" "${COMMON[@]}" \
  -d '{"model":"mock-gpt","messages":[{"role":"user","content":"hello, my password is hunter2"}],"user":"end-user-42"}' | head -c 300; echo

say "S2 chat STREAM with tool calls (arguments split across deltas upstream)"
curl -sS -N "$LITELLM/v1/chat/completions" "${COMMON[@]}" \
  -d "{\"model\":\"mock-gpt\",\"stream\":true,\"stream_options\":{\"include_usage\":true},\"messages\":[{\"role\":\"user\",\"content\":\"weather in Reykjavik?\"}],\"tools\":$TOOLS,\"user\":\"end-user-42\"}" | tail -c 400; echo

say "S3 /v1/messages STREAM with tool_use (Anthropic wire shape)"
curl -sS -N "$LITELLM/v1/messages" "${COMMON[@]}" -H 'anthropic-version: 2023-06-01' \
  -d "{\"model\":\"mock-gpt\",\"max_tokens\":256,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"weather in Reykjavik?\"}],\"tools\":$ATOOLS}" | tail -c 400; echo

say "S4 /v1/responses"
curl -sS "$LITELLM/v1/responses" "${COMMON[@]}" \
  -d '{"model":"mock-gpt","input":"summarise this: token=abc123"}' | head -c 300; echo

say "S5 embeddings"
curl -sS "$LITELLM/v1/embeddings" "${COMMON[@]}" \
  -d '{"model":"mock-embed","input":"embed me"}' | head -c 200; echo

say "S6a upstream 500"
curl -sS "$LITELLM/v1/chat/completions" "${COMMON[@]}" \
  -d '{"model":"mock-error","messages":[{"role":"user","content":"boom"}]}' | head -c 300; echo
say "S6b upstream 429"
curl -sS "$LITELLM/v1/chat/completions" "${COMMON[@]}" \
  -d '{"model":"mock-429","messages":[{"role":"user","content":"slow down"}]}' | head -c 300; echo

say "S7a big completion (~48 KB) non-stream"
curl -sS "$LITELLM/v1/chat/completions" "${COMMON[@]}" \
  -d '{"model":"mock-big","messages":[{"role":"user","content":"give me everything"}]}' | wc -c
say "S7b big completion (~48 KB) STREAM"
curl -sS -N "$LITELLM/v1/chat/completions" "${COMMON[@]}" \
  -d '{"model":"mock-big","stream":true,"messages":[{"role":"user","content":"give me everything"}]}' | wc -c
say "S7c big PROMPT (~40 KB) non-stream"
BIGPROMPT=$(python3 -c 'print("prompt padding " * 2700)')
curl -sS "$LITELLM/v1/chat/completions" "${COMMON[@]}" \
  -d "{\"model\":\"mock-gpt\",\"messages\":[{\"role\":\"user\",\"content\":\"$BIGPROMPT\"}]}" | head -c 120; echo

say "S8 MCP on /mcp (aggregate): initialize, tools/list, tools/call x3"
MCPH=(-H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream'
      -H "x-litellm-session-id: $SESSION" -H "traceparent: $TRACEPARENT" -H 'x-forwarded-for: 203.0.113.7' -H 'User-Agent: spike-mcp-client/0.1')
MCPSESS=$(curl -sS -D - -o "$TMPD/init.out" "$LITELLM/mcp" "${MCPH[@]}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"spike-client","version":"0.1"}}}' \
  | tr -d '\r' | awk 'tolower($1)=="mcp-session-id:" {print $2}')
echo "    mcp session: ${MCPSESS:-<none>}"; head -c 300 "$TMPD/init.out"; echo
curl -sS "$LITELLM/mcp" "${MCPH[@]}" ${MCPSESS:+-H "Mcp-Session-Id: $MCPSESS"} \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null || true
curl -sS "$LITELLM/mcp" "${MCPH[@]}" ${MCPSESS:+-H "Mcp-Session-Id: $MCPSESS"} \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | head -c 400; echo
for call in \
  '{"name":"mockmcp-echo","arguments":{"message":"hi mcp","api_key":"should-be-redacted"}}' \
  '{"name":"mockmcp-lookup_big","arguments":{"doc_id":"doc-7"}}' \
  '{"name":"mockmcp-fail","arguments":{"reason":"spike"}}'; do
  curl -sS "$LITELLM/mcp" "${MCPH[@]}" ${MCPSESS:+-H "Mcp-Session-Id: $MCPSESS"} \
    -d "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":$call}" | head -c 300; echo
done

say "S9 MCP on the server-scoped route"
for route in "/mcp/mockmcp" "/mockmcp/mcp"; do
  printf '    %s initialize -> ' "$route"
  RSESS=$(curl -sS -D - -o "$TMPD/route.out" "$LITELLM$route" "${MCPH[@]}" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"spike-client","version":"0.1"}}}' \
    | tr -d '\r' | awk 'tolower($1)=="mcp-session-id:" {print $2}')
  echo "session=${RSESS:-<none>}"; head -c 160 "$TMPD/route.out"; echo
  curl -sS "$LITELLM$route" "${MCPH[@]}" ${RSESS:+-H "Mcp-Session-Id: $RSESS"} \
    -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null || true
  printf '    %s tools/call echo -> ' "$route"
  curl -sS -o "$TMPD/route.out" -w '%{http_code}' "$LITELLM$route" "${MCPH[@]}" ${RSESS:+-H "Mcp-Session-Id: $RSESS"} \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"message":"scoped route"}}}'
  echo; head -c 160 "$TMPD/route.out"; echo
  printf '    %s tools/call mockmcp-echo -> ' "$route"
  curl -sS -o "$TMPD/route.out" -w '%{http_code}' "$LITELLM$route" "${MCPH[@]}" ${RSESS:+-H "Mcp-Session-Id: $RSESS"} \
    -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mockmcp-echo","arguments":{"message":"scoped route namespaced"}}}'
  echo; head -c 160 "$TMPD/route.out"; echo
done

say "S10 second call in the same session (session continuity)"
curl -sS "$LITELLM/v1/chat/completions" "${COMMON[@]}" -H 'x-cerberus-turn-id: turn-2' \
  -d '{"model":"mock-gpt","messages":[{"role":"user","content":"turn two"}],"user":"end-user-42"}' | head -c 200; echo

say "waiting for OTel batch + bridge flush"
sleep 6
say "capture counts"
for d in plugin otel events; do printf '    %-7s %s\n' "$d" "$(ls captures/$d 2>/dev/null | wc -l | tr -d ' ')"; done
say "bridge stats"; curl -sS http://127.0.0.1:4318/stats; echo

say "redacting the throwaway virtual key from committed captures"
scrub_captures
echo "    remaining occurrences: $(grep -rlF -- "$KEY" captures 2>/dev/null | wc -l | tr -d ' ')"

say "final gate: virtual key must not appear anywhere under captures/"
if grep -rqF -- "$KEY" captures 2>/dev/null; then
  echo "ERROR: virtual key still present under captures/" >&2
  exit 1
fi
echo "    gate passed"
