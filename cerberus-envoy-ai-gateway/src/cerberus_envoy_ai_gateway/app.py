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
from starlette.requests import ClientDisconnect

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
        if config.dump_spans:
            logger.warning(
                "CERBERUS_DUMP_SPANS is enabled — raw span content (including LLM "
                "prompts/completions) is printed to stdout. Do NOT use in production."
            )
        yield
        state["ready"] = False
        await state["sink"].close()

    app = FastAPI(title="cerberus-envoy-ai-gateway", version=__version__, lifespan=lifespan)

    @app.post("/v1/traces")
    async def receive_traces(request: Request) -> Response:
        if not state.get("ready"):
            return Response(
                content='{"status": "starting"}', status_code=503, media_type="application/json"
            )
        chunks: list[bytes] = []
        received = 0
        try:
            async for chunk in request.stream():
                received += len(chunk)
                if received > MAX_OTLP_BODY_BYTES:
                    logger.warning("Rejecting OTLP request over %d bytes", MAX_OTLP_BODY_BYTES)
                    # Returning mid-stream without draining the rest is intentional:
                    # Uvicorn discards the unread body and the OTel exporter treats
                    # 413 as non-retryable, so the oversize export is dropped
                    # at-most-once. We deliberately do NOT drain the remainder —
                    # an unbounded drain would be a memory-exhaustion DoS vector.
                    return Response(
                        content="body too large", status_code=413, media_type="text/plain"
                    )
                chunks.append(chunk)
        except ClientDisconnect:
            # Gateway exporter hung up mid-stream — nothing to ingest and no one
            # to respond to; return quietly instead of a 500 + traceback.
            logger.debug("Client disconnected during OTLP upload")
            return Response(status_code=499)
        body = b"".join(chunks)

        content_type = request.headers.get("content-type")
        try:
            export = decode_traces_request(body, content_type)
        except OTLPDecodeError as exc:
            # Log the decode detail server-side but return a generic message, so
            # the exception text (and any nested parser internals) isn't exposed
            # to the unauthenticated caller.
            logger.warning("Rejecting undecodable OTLP request: %s", exc)
            return Response(
                content="invalid OTLP request", status_code=400, media_type="text/plain"
            )

        # Synchronous CPU-bound work (protobuf walk, sanitize, json.dumps) runs
        # on the event loop. Fine for the single-gateway v1; if high throughput
        # is ever needed, move to run_in_executor with a thread-safe pipeline.
        try:
            state["pipeline"].process_export(export)
        except Exception:
            # Never 5xx on a malformed/poison span: the OTel exporter retries
            # 5xx, looping forever on the same bad export. Drop it as a 400.
            logger.exception("Failed to process OTLP export; rejecting as 400")
            return Response(
                content="invalid OTLP request", status_code=400, media_type="text/plain"
            )

        # Debug dump runs after processing and is exception-guarded: a span
        # this dump can't serialize must never cost the export (the OTLP
        # exporter does not retry 5xx).
        if config.dump_spans:
            try:
                for scope_name, span in iter_spans(export):
                    # Raw JSON to stdout (NOT logger): one object per line,
                    # undecorated and on a separate stream, so `... | jq` works
                    # and operational logs (stderr) don't interleave.
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

    @app.get("/stats", response_model=None)
    async def stats() -> Response | dict:
        if not state.get("ready"):
            return Response(
                content='{"status": "starting"}', status_code=503, media_type="application/json"
            )
        pipeline: Pipeline = state["pipeline"]
        sink: Sink = state["sink"]
        return {
            "queued": len(pipeline.queue),
            "events_llm": pipeline.events_llm,
            "events_mcp": pipeline.events_mcp,
            "spans_ignored": pipeline.spans_ignored,
            "spans_filtered": pipeline.spans_filtered,
            "dropped_queue_full": pipeline.queue.dropped_full,
            "dropped_oversize": pipeline.dropped_oversize,
            "posted": sink.posted,
            "post_failures": sink.post_failures,
            "server_accepted": sink.server_accepted,
            "server_skipped": sink.server_skipped,
        }

    return app
