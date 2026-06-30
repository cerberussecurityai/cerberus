"""Sink tests against an in-process stub of the Cerberus ingest API.

The stub mirrors event_ingest's /v1/ingest/batch contract (see
cerberus-int/services/event_ingest/main.py and test/test_http_ingest.py):
X-API-Key auth (401 missing / 403 unknown), 413 over 1000 events,
health-endpoint skipping, and {"accepted": N, "skipped": M} responses.
"""

import asyncio
from dataclasses import replace

import httpx
import pytest
from fastapi import FastAPI, Header, HTTPException
from helpers import HEALTH_SEGMENTS

from cerberus_envoy_ai_gateway.queue import BoundedQueue
from cerberus_envoy_ai_gateway.sink import Sink

VALID_KEY = "sk_test_0123456789"


def make_stub_ingest(received: list) -> FastAPI:
    app = FastAPI()

    @app.post("/v1/ingest/batch")
    async def ingest_batch(payload: dict, x_api_key: str | None = Header(None)):
        if x_api_key is None:
            raise HTTPException(status_code=401, detail="missing API key")
        if x_api_key != VALID_KEY:
            raise HTTPException(status_code=403, detail="invalid API key")
        events = payload.get("events", [])
        if len(events) > 1000:
            raise HTTPException(status_code=413, detail="batch too large")
        accepted = 0
        skipped = 0
        for event in events:
            endpoint = (event.get("endpoint") or "") if isinstance(event, dict) else ""
            segment = endpoint.rstrip("/").rsplit("/", 1)[-1].lower()
            if segment in HEALTH_SEGMENTS:
                skipped += 1
                continue
            received.append(event)
            accepted += 1
        return {"accepted": accepted, "skipped": skipped}

    return app


def make_sink(config, queue, app: FastAPI) -> Sink:
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app))
    return Sink(config, queue, client=client)


@pytest.fixture
def queue():
    return BoundedQueue(10000)


async def test_flush_posts_batches_and_counts(config, queue):
    received: list = []
    sink = make_sink(config, queue, make_stub_ingest(received))
    for i in range(120):
        queue.append({"endpoint": f"llm://openai/gpt-{i}", "method": "llm_chat_completion"})
    await sink.flush_once()
    assert len(received) == 120
    assert sink.posted == 120
    assert sink.post_failures == 0
    assert len(queue) == 0
    # FIFO order preserved across batches.
    assert received[0]["endpoint"] == "llm://openai/gpt-0"
    assert received[-1]["endpoint"] == "llm://openai/gpt-119"


async def test_invalid_key_drops_batch(config, queue):
    received: list = []
    bad_config = replace(config, token="sk_test_wrong")
    sink = make_sink(bad_config, queue, make_stub_ingest(received))
    queue.append({"endpoint": "llm://openai/gpt-4o"})
    await sink.flush_once()
    assert received == []
    assert sink.post_failures == 1
    assert sink.posted == 0
    assert len(queue) == 0  # at-most-once: dropped, not retried


async def test_connection_error_drops_batch(config, queue):
    def raise_connect_error(request):
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(raise_connect_error))
    sink = Sink(config, queue, client=client)
    queue.append({"endpoint": "llm://openai/gpt-4o"})
    await sink.flush_once()
    assert sink.post_failures == 1
    assert len(queue) == 0


async def test_redirect_not_counted_as_delivered(config, queue):
    # A 3xx (e.g. an ingress/auth-proxy redirect) is NOT a successful ingest;
    # httpx doesn't follow redirects by default (and must not), so it's a dropped
    # batch — not silently counted as posted.
    def redirect(request):
        return httpx.Response(302, headers={"location": "https://elsewhere/v1/ingest/batch"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(redirect))
    sink = Sink(config, queue, client=client)
    queue.append({"endpoint": "llm://openai/gpt-4o"})
    await sink.flush_once()
    assert sink.post_failures == 1
    assert sink.posted == 0
    assert len(queue) == 0


async def test_health_endpoints_skipped_server_side(config, queue):
    received: list = []
    sink = make_sink(config, queue, make_stub_ingest(received))
    queue.append({"endpoint": "https://api.example.com/health"})
    queue.append({"endpoint": "llm://openai/gpt-4o"})
    await sink.flush_once()
    assert len(received) == 1
    assert received[0]["endpoint"] == "llm://openai/gpt-4o"
    # Server-side filtering is surfaced, not silent.
    assert sink.server_accepted == 1
    assert sink.server_skipped == 1


async def test_close_flushes_remaining(config, queue):
    received: list = []
    sink = make_sink(config, queue, make_stub_ingest(received))
    queue.append({"endpoint": "llm://openai/gpt-4o"})
    await sink.close()
    assert len(received) == 1


class _GatedClient:
    """Async client whose POST blocks until released — holds a batch in-flight
    while close() runs."""

    def __init__(self):
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.posted: list = []

    async def post(self, url, json, headers):
        self.started.set()
        await self.release.wait()
        self.posted.extend(json["events"])
        return httpx.Response(200, json={"accepted": len(json["events"]), "skipped": 0})

    async def aclose(self):
        pass


async def test_close_does_not_drop_in_flight_batch(config, queue):
    # Shutdown must not cancel a POST that has already drained a batch off the
    # queue; the in-flight batch should complete, not vanish.
    client = _GatedClient()
    sink = Sink(replace(config, flush_interval_ms=10), queue, client=client)
    for i in range(3):
        queue.append({"endpoint": f"llm://openai/gpt-{i}", "method": "llm_chat_completion"})
    sink.start()
    await asyncio.wait_for(client.started.wait(), timeout=2)
    close_task = asyncio.create_task(sink.close())
    await asyncio.sleep(0)
    client.release.set()
    await asyncio.wait_for(close_task, timeout=2)
    assert len(client.posted) == 3
    assert len(queue) == 0
