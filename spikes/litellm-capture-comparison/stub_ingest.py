"""Stand-in Cerberus ingest for the LiteLLM capture comparison.

Same HTTP surface as the Envoy playground stub (POST /v1/ingest/batch with
X-API-Key, GET /api/secret-key), but every accepted event is also written to
$SPIKE_CAPTURE_DIR (default /captures/events) as NNN_<method>.json so the
bridge's output can be diffed against the plugin dumps.
"""

import json
import os
import re
import threading

import uvicorn
from fastapi import FastAPI, Header, HTTPException

API_KEY = "sk_test_playground"
SECRET_KEY = "playground-hmac-secret"
CAPTURE_DIR = os.environ.get("SPIKE_CAPTURE_DIR", "/captures/events")
HEALTH_SEGMENTS = {
    "health", "healthz", "healthcheck", "health_check", "health-check",
    "ready", "readyz", "readiness", "live", "livez", "liveness",
}

app = FastAPI(title="spike-stub-ingest")
_SAFE = re.compile(r"[^A-Za-z0-9_-]")


def _safe_name(value: object) -> str:
    """Request-derived text is reduced to [A-Za-z0-9_-], max 40 chars."""
    cleaned = _SAFE.sub("_", str(value or ""))[:40]
    return cleaned or "unknown"

_seq = 0
_lock = threading.Lock()


def _require_key(x_api_key: str | None) -> None:
    if x_api_key is None:
        raise HTTPException(status_code=401, detail="missing API key")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="invalid API key")


@app.get("/api/secret-key")
async def secret_key(x_api_key: str | None = Header(None)) -> dict:
    _require_key(x_api_key)
    return {"secret_key": SECRET_KEY}


@app.post("/v1/ingest/batch")
async def ingest_batch(payload: dict, x_api_key: str | None = Header(None)) -> dict:
    global _seq
    _require_key(x_api_key)
    events = payload.get("events", [])
    if len(events) > 1000:
        raise HTTPException(status_code=413, detail="batch too large")
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    accepted = skipped = 0
    for event in events:
        endpoint = (event.get("endpoint") or "") if isinstance(event, dict) else ""
        if endpoint.rstrip("/").rsplit("/", 1)[-1].lower() in HEALTH_SEGMENTS:
            skipped += 1
            continue
        accepted += 1
        with _lock:
            _seq += 1
            seq = _seq
        name = f"{seq:03d}_{_safe_name(event.get('method'))}.json"
        with open(os.path.join(CAPTURE_DIR, name), "w", encoding="utf-8") as fh:
            json.dump(event, fh, indent=2, sort_keys=True)
        print(f"[stub_ingest] {name} {endpoint} bytes={len(json.dumps(event))}", flush=True)
    print(f"[stub_ingest] batch accepted={accepted} skipped={skipped}", flush=True)
    return {"accepted": accepted, "skipped": skipped, "errors": [], "warnings": []}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9089, log_level="warning")
