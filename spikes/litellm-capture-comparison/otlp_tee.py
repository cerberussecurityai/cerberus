"""OTLP/HTTP tee for the LiteLLM capture comparison.

Sits between LiteLLM's OTel v2 exporter and the unmodified Cerberus bridge:
records every export request to disk (raw body + a JSON decode) and forwards
it to the bridge untouched, returning the bridge's response. This is the
"path B" probe: the JSON decodes are the raw span captures, and whatever the
bridge then emits to the stub ingest is what today's bridge makes of them.

    LiteLLM  --OTLP-->  otlp_tee:4319  --OTLP-->  bridge:4318  -->  stub ingest
                            |
                            +--> /captures/otel/NNN.{pb,json}
"""

import json
import os
import threading

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from google.protobuf.json_format import MessageToDict
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

CAPTURE_DIR = os.environ.get("SPIKE_CAPTURE_DIR", "/captures/otel")
FORWARD_TO = os.environ.get("SPIKE_FORWARD_TO", "http://bridge:4318/v1/traces")

app = FastAPI(title="spike-otlp-tee")
_seq = 0
_lock = threading.Lock()


def _next() -> int:
    global _seq
    with _lock:
        _seq += 1
        return _seq


@app.post("/v1/traces")
async def traces(request: Request) -> Response:
    body = await request.body()
    content_type = request.headers.get("content-type", "")
    seq = _next()
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    ext = "json" if "json" in content_type else "pb"
    with open(os.path.join(CAPTURE_DIR, f"{seq:03d}.{ext}"), "wb") as fh:
        fh.write(body)
    if ext == "pb":
        try:
            msg = ExportTraceServiceRequest()
            msg.ParseFromString(body)
            decoded = MessageToDict(msg, preserving_proto_field_name=True)
            with open(os.path.join(CAPTURE_DIR, f"{seq:03d}.json"), "w", encoding="utf-8") as fh:
                json.dump(decoded, fh, indent=2, sort_keys=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[otlp_tee] decode failed for {seq}: {exc!r}", flush=True)
    headers = {k: v for k, v in request.headers.items() if k.lower() in ("content-type", "content-encoding", "authorization")}
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            upstream = await client.post(FORWARD_TO, content=body, headers=headers)
        except Exception as exc:  # noqa: BLE001
            print(f"[otlp_tee] forward failed for {seq}: {exc!r}", flush=True)
            return Response(status_code=502, content=b"{}", media_type="application/json")
    print(f"[otlp_tee] {seq:03d} {len(body)}B {content_type} -> bridge {upstream.status_code}", flush=True)
    return Response(
        status_code=upstream.status_code,
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "captured": _seq}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=4319, log_level="warning")
