"""Stand-in Cerberus ingest for the cerberus-litellm playground.

Same HTTP surface as the Envoy playground stub (POST /v1/ingest/batch with
X-API-Key, GET /api/secret-key), but every accepted event is also written to
$CAPTURE_DIR (default /captures) as NNN_<method>.json, and printed, so
the wire shape can be inspected.
"""

import json
import os
import re
import threading

from fastapi import FastAPI, Header, HTTPException

API_KEY = "sk_test_playground"
SECRET_KEY = "playground-hmac-secret"
CAPTURE_DIR = os.environ.get("CAPTURE_DIR", "/captures")
# Path segments the stub skips (same list as tests/helpers.py).
HEALTH_SEGMENTS = {
    "health", "healthz", "healthcheck", "health_check", "health-check",
    "ready", "readyz", "readiness", "live", "livez", "liveness",
}

app = FastAPI(title="playground-stub-ingest")
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
        if not isinstance(event, dict):
            skipped += 1
            continue
        endpoint = event.get("endpoint") or ""
        if endpoint.rstrip("/").rsplit("/", 1)[-1].lower() in HEALTH_SEGMENTS:
            skipped += 1
            continue
        accepted += 1
        with _lock:
            _seq += 1
            seq = _seq
        # The method comes straight off the wire: allowlist the characters in the
        # file name, then refuse anything that still resolves outside the capture dir.
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(event.get("method") or "unknown"))[:64]
        name = f"{seq:03d}_{safe or 'unknown'}.json"
        target = os.path.realpath(os.path.join(CAPTURE_DIR, name))
        if not target.startswith(os.path.realpath(CAPTURE_DIR) + os.sep):
            raise HTTPException(status_code=400, detail="capture path escapes the capture dir")
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(event, fh, indent=2, sort_keys=True)
        print(f"[stub_ingest] {name} {endpoint} bytes={len(json.dumps(event))}", flush=True)
    print(f"[stub_ingest] batch accepted={accepted} skipped={skipped}", flush=True)
    return {"accepted": accepted, "skipped": skipped, "errors": [], "warnings": []}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9089, log_level="warning")
