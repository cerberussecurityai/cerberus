#!/usr/bin/env bash
# Overhead probe for the LiteLLM capture comparison: LiteLLM with no Cerberus callbacks
# (OTel v2 off) vs LiteLLM with BOTH probes on (dump_logger + OTel v2 -> tee ->
# bridge). Same mock upstream, same request, ApacheBench on the host.
#
# The dump_logger writes two JSON files per request, which is far more work
# than a real plugin would do (bounded queue + batched POST), so the "both on"
# number is a ceiling, not an estimate of the plugin's cost.
#
#   ./bench.sh            # 1500 requests, concurrency 20
#   N=3000 C=50 ./bench.sh
set -eu
cd "$(dirname "$0")"
TMPD=$(mktemp -d "${TMPDIR:-/tmp}/spike.XXXXXX")
trap 'rm -rf "$TMPD"' EXIT
N="${N:-1500}"; C="${C:-20}"
MASTER="sk-spike-master"

body='{"model":"mock-gpt","messages":[{"role":"user","content":"bench"}],"user":"bench-user"}'
printf '%s' "$body" > "$TMPD/body.json"

wait_live() {
  for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1 && return 0; sleep 2; done
  echo "LiteLLM never became live" >&2; return 1
}

run_ab() {  # $1 = label
  KEY=$(curl -fsS http://127.0.0.1:4000/key/generate -H "Authorization: Bearer $MASTER" -H 'Content-Type: application/json' \
        -d '{"key_alias":"bench-'"$RANDOM"'"}' | jq -r .key)
  # warm-up
  ab -q -n 100 -c "$C" -p "$TMPD/body.json" -T application/json -H "Authorization: Bearer $KEY" \
     http://127.0.0.1:4000/v1/chat/completions >/dev/null
  echo "==> $1: ab -n $N -c $C"
  ab -q -n "$N" -c "$C" -p "$TMPD/body.json" -T application/json -H "Authorization: Bearer $KEY" \
     http://127.0.0.1:4000/v1/chat/completions | grep -E "Requests per second|Time per request.*mean\)|Failed requests|  50%|  95%|  99%|Non-2xx"
}

echo "==> stopping the normal litellm service"
docker compose stop litellm >/dev/null

echo "==> BASELINE: no callbacks, OTel v2 off"
docker compose run -d --rm --service-ports --name spike-baseline \
  -e LITELLM_OTEL_V2=false litellm --config /app/spike/config_baseline.yaml --port 4000 >/dev/null
wait_live; run_ab "baseline"
docker rm -f spike-baseline >/dev/null

echo "==> HOOKS ONLY: no-op CustomLogger, OTel v2 off"
docker compose run -d --rm --service-ports --name spike-noop \
  -e LITELLM_OTEL_V2=false litellm --config /app/spike/config_noop.yaml --port 4000 >/dev/null
wait_live; run_ab "hooks only (no-op logger)"
docker rm -f spike-noop >/dev/null

echo "==> OTEL ONLY: OTel v2 -> tee -> bridge, no Python hooks"
docker compose run -d --rm --service-ports --name spike-otel \
  litellm --config /app/spike/config_otel_only.yaml --port 4000 >/dev/null
wait_live; run_ab "otel only"
docker rm -f spike-otel >/dev/null

echo "==> BOTH ON: dump_logger + OTel v2 -> tee -> bridge (dumps to a scratch dir, not captures/)"
docker compose run -d --rm --service-ports --name spike-full \
  -e SPIKE_CAPTURE_DIR=/tmp/spike-load litellm --config /app/spike/config.yaml --port 4000 >/dev/null
wait_live; run_ab "both on"
echo "    bridge stats after load:"; curl -fsS http://127.0.0.1:4318/stats; echo
docker rm -f spike-full >/dev/null

echo "==> restoring the normal litellm service"
docker compose up -d litellm >/dev/null
