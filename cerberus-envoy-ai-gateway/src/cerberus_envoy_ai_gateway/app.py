"""FastAPI application: OTLP/HTTP receiver + health/stats endpoints.

The Envoy AI Gateway extproc is pointed at this service with::

    OTEL_EXPORTER_OTLP_ENDPOINT=http://<bridge>:4318
    OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf

The receiver always acknowledges exports (a full-success OTLP response) —
queue pressure and ingest failures are absorbed here and surfaced via
/stats and logs, never as backpressure on the gateway's trace exporter.
"""

import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response

from . import __version__
from .config import Config
from .otlp import (
    OTLPDecodeError,
    decode_traces_request,
    iter_spans,
    span_to_debug_dict,
    success_response_body,
)
from .pipeline import Pipeline
from .queue import BoundedQueue
from .secret import resolve_secret_key
from .sink import Sink

logger = logging.getLogger(__name__)

# Reject OTLP request bodies above this size before buffering them — the
# receiver is unauthenticated (standard for in-cluster OTLP), so an unbounded
# `await request.body()` would let one giant POST exhaust pod memory. The
# stock OTel Collector uses a similar (~20MiB) default cap.
MAX_OTLP_BODY_BYTES = 16 * 1024 * 1024


def create_app(config: Config) -> FastAPI:
    logging.basicConfig(
        level=config.log_level.upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    state: dict = {"ready": False}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        secret_key = await resolve_secret_key(config)
        queue = BoundedQueue(config.queue_capacity)
        state["pipeline"] = Pipeline(config, queue, secret_key)
        state["sink"] = Sink(config, queue)
        state["sink"].start()
        state["ready"] = True
        logger.info(
            "cerberus-envoy-ai-gateway %s listening; ingest=%s pii_hashing=%s",
            __version__,
            config.ingest_service,
            "on" if secret_key else "OFF (raw IPs)",
        )
        yield
        state["ready"] = False
        await state["sink"].close()

    app = FastAPI(title="cerberus-envoy-ai-gateway", version=__version__, lifespan=lifespan)

    @app.post("/v1/traces")
    async def receive_traces(request: Request) -> Response:
        chunks: list[bytes] = []
        received = 0
        async for chunk in request.stream():
            received += len(chunk)
            if received > MAX_OTLP_BODY_BYTES:
                logger.warning("Rejecting OTLP request over %d bytes", MAX_OTLP_BODY_BYTES)
                return Response(content="body too large", status_code=413, media_type="text/plain")
            chunks.append(chunk)
        body = b"".join(chunks)

        content_type = request.headers.get("content-type")
        try:
            export = decode_traces_request(body, content_type)
        except OTLPDecodeError as exc:
            logger.warning("Rejecting undecodable OTLP request: %s", exc)
            return Response(content=str(exc), status_code=400, media_type="text/plain")

        state["pipeline"].process_export(export)

        # Debug dump runs after processing and is exception-guarded: a span
        # this dump can't serialize must never cost the export (the OTLP
        # exporter does not retry 5xx).
        if config.dump_spans:
            try:
                for scope_name, span in iter_spans(export):
                    print(
                        json.dumps(span_to_debug_dict(scope_name, span), default=repr), flush=True
                    )
            except Exception:
                logger.exception("CERBERUS_DUMP_SPANS failed to render a span")

        response_body, response_type = success_response_body(content_type)
        return Response(content=response_body, media_type=response_type)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/ready")
    async def ready() -> Response:
        if not state["ready"]:
            return Response(
                content='{"status": "starting"}', status_code=503, media_type="application/json"
            )
        return Response(content='{"status": "ready"}', media_type="application/json")

    @app.get("/stats")
    async def stats() -> dict:
        pipeline: Pipeline = state["pipeline"]
        sink: Sink = state["sink"]
        return {
            "queued": len(pipeline.queue),
            "events_llm": pipeline.events_llm,
            "events_mcp": pipeline.events_mcp,
            "spans_ignored": pipeline.spans_ignored,
            "dropped_queue_full": pipeline.queue.dropped_full,
            "dropped_oversize": pipeline.dropped_oversize,
            "posted": sink.posted,
            "post_failures": sink.post_failures,
            "server_accepted": sink.server_accepted,
            "server_skipped": sink.server_skipped,
        }

    return app
