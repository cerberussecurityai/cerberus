#!/usr/bin/env bash
# Boot the full playground: bridge + stub ingest + mocks (docker compose),
# then a standalone Envoy AI Gateway (`aigw run`) on the host wired to them.
#
# Prereqs: docker, and the aigw CLI for the full chain:
#   go install github.com/envoyproxy/ai-gateway/cmd/aigw@latest
# Without aigw you can still verify bridge -> ingest with ./drive.sh --direct
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Starting bridge, stub ingest, and mocks (docker compose)..."
docker compose up -d --build

echo "==> Waiting for the bridge to be ready..."
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:4318/ready >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS http://127.0.0.1:4318/ready >/dev/null || {
  echo "bridge did not become ready; check: docker compose logs bridge" >&2
  exit 1
}

if ! command -v aigw >/dev/null 2>&1; then
  cat >&2 <<'EOF'
==> aigw CLI not found — skipping the gateway.

   Install it:    go install github.com/envoyproxy/ai-gateway/cmd/aigw@latest
   Then re-run:   ./run.sh

   Meanwhile you can verify bridge -> stub ingest without a gateway:
                  ./drive.sh --direct
EOF
  exit 0
fi

echo "==> Starting Envoy AI Gateway (standalone) on :1975 ..."
# LLM route: aigw's default OpenAI config, pointed at the mock LLM.
export OPENAI_API_KEY="${OPENAI_API_KEY:-playground-dummy}"
export OPENAI_BASE_URL="http://127.0.0.1:9081/v1"
# Trace export -> the Cerberus bridge.
export OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:4318"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf"
export OTEL_TRACES_EXPORTER="otlp"
export OTEL_METRICS_EXPORTER="none"
export OTEL_TRACES_SAMPLER="parentbased_always_on"
export OTEL_BSP_SCHEDULE_DELAY="1000"
export OTEL_AIGW_SPAN_REQUEST_HEADER_ATTRIBUTES="x-forwarded-for:http.client_ip,x-user-id:user.id,user-agent:http.user_agent"
# Playground demonstrates sanitized content capture, so do NOT hide content:
unset OPENINFERENCE_HIDE_INPUTS OPENINFERENCE_HIDE_OUTPUTS || true

exec aigw run --mcp-config mcp-servers.json
