#!/usr/bin/env bash
# Build the plugin image and boot the playground.
set -euo pipefail
cd "$(dirname "$0")/.."
make image
cd playground
docker compose down -v >/dev/null 2>&1 || true
rm -rf captures && mkdir -p captures
docker compose up -d --build
for _ in $(seq 1 60); do
  curl -fsS http://127.0.0.1:4000/health/liveliness >/dev/null 2>&1 && break; sleep 2
done
curl -fsS http://127.0.0.1:4000/health/liveliness >/dev/null || { echo "LiteLLM never became live; docker compose logs litellm" >&2; exit 1; }
echo "ready: ./drive.sh"
