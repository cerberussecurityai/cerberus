"""Stand-in Cerberus backend for the playground.

Implements just enough of event_ingest's HTTP surface:
- POST /v1/ingest/batch — X-API-Key auth, health-endpoint skip, prints
  every accepted event as pretty JSON so you can eyeball the wire shape.
- GET /api/secret-key — serves the playground HMAC key so the bridge's
  startup fetch path is exercised end-to-end.
"""

import json

import uvicorn
from fastapi import FastAPI, Header, HTTPException

API_KEY = "sk_test_playground"
SECRET_KEY = "playground-hmac-secret"
# Kept standalone (this harness runs outside pytest); must stay identical to
# tests/helpers.py HEALTH_SEGMENTS and the backend's health filter.
HEALTH_SEGMENTS = {
    "health",
    "healthz",
    "healthcheck",
    "health_check",
    "health-check",
    "ready",
    "readyz",
    "readiness",
    "live",
    "livez",
    "liveness",
}

app = FastAPI(title="stub-cerberus-ingest")


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
    _require_key(x_api_key)
    events = payload.get("events", [])
    if len(events) > 1000:
        raise HTTPException(status_code=413, detail="batch too large")
    accepted = 0
    skipped = 0
    for event in events:
        endpoint = (event.get("endpoint") or "") if isinstance(event, dict) else ""
        if endpoint.rstrip("/").rsplit("/", 1)[-1].lower() in HEALTH_SEGMENTS:
            skipped += 1
            continue
        accepted += 1
        print(f"=== event {event.get('method')} {endpoint} ===")
        print(json.dumps(event, indent=2))
    print(f"--- batch done: accepted={accepted} skipped={skipped} ---", flush=True)
    return {"accepted": accepted, "skipped": skipped}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9089, log_level="warning")
