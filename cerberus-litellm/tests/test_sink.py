"""Sink tests against an in-process stub of the Cerberus ingest API.

The stub mirrors the documented /v1/ingest/batch contract: X-API-Key auth
(401 missing / 403 unknown), 413 over the batch limit, health-endpoint
skipping, and {"accepted": N, "skipped": M} responses.
"""

import asyncio
import json
import logging
from dataclasses import replace

import httpx
import pytest
from fastapi import FastAPI, Header, HTTPException
from helpers import HEALTH_SEGMENTS

from cerberus_litellm.queue import BoundedQueue
from cerberus_litellm.sink import Sink

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


async def test_ingest_error_body_is_logged_only_at_debug(config, queue, caplog):
    caplog.set_level(logging.DEBUG, logger="cerberus_litellm.sink")
    sink = make_sink(replace(config, token="sk_test_wrong"), queue, make_stub_ingest([]))
    queue.append({"endpoint": "llm://openai/gpt-4o"})
    await sink.flush_once()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    debugs = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert warnings and all("invalid API key" not in r.getMessage() for r in warnings)
    assert "403" in warnings[0].getMessage()
    assert any("invalid API key" in r.getMessage() for r in debugs)


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

    async def post(self, url, content, headers):
        self.started.set()
        await self.release.wait()
        events = json.loads(content)["events"]
        self.posted.extend(events)
        return httpx.Response(200, json={"accepted": len(events), "skipped": 0})

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


def _events(n=1):
    return [{"endpoint": f"llm://openai/m{i}", "method": "llm_chat_completion"} for i in range(n)]


async def test_nan_batch_is_dropped_and_counted_without_ending_the_loop(config, queue):
    seen = []
    transport = httpx.MockTransport(
        lambda request: seen.append(json.loads(request.content)) or httpx.Response(200, json={})
    )
    cfg = replace(config, flush_interval_ms=100, batch_size=1)
    sink = Sink(cfg, queue, client=httpx.AsyncClient(transport=transport))
    sink.start()
    queue.append({"endpoint": "llm://openai/bad", "x": float("nan")})
    await asyncio.sleep(0.3)
    queue.append(_events()[0])
    await asyncio.sleep(0.35)
    task_alive = sink._task is not None and not sink._task.done()
    await sink.close()
    assert task_alive
    assert sink.post_failures == 1
    assert sink.posted == 1
    assert len(seen) == 1  # only the good batch reached the wire


async def test_post_raising_value_error_does_not_end_the_sink_task(config, queue):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("boom")
        return httpx.Response(200, json={"accepted": 1, "skipped": 0})

    cfg = replace(config, flush_interval_ms=100, batch_size=1)
    sink = Sink(cfg, queue, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    sink.start()
    queue.append(_events()[0])
    await asyncio.sleep(0.3)
    queue.append(_events()[0])
    await asyncio.sleep(0.35)
    alive = not sink._task.done()
    await sink.close()
    assert alive
    assert sink.post_failures == 1
    assert sink.posted == 1


async def test_non_http_errors_are_logged_by_type_only(config, queue, caplog):
    caplog.set_level(logging.WARNING, logger="cerberus_litellm.sink")

    def handler(request: httpx.Request) -> httpx.Response:
        raise ValueError("secret-looking-detail")

    sink = Sink(config, queue, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    queue.append(_events()[0])
    await sink.flush_once()
    assert sink.post_failures == 1
    assert "ValueError" in caplog.text
    assert "secret-looking-detail" not in caplog.text
    await sink.close()


async def test_batch_is_posted_as_strict_json_with_content_type(config, queue):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["type"] = request.headers["content-type"]
        captured["body"] = request.content
        return httpx.Response(200, json={"accepted": 1, "skipped": 0})

    sink = Sink(config, queue, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    queue.append(_events()[0])
    await sink.flush_once()
    assert captured["type"] == "application/json"
    assert json.loads(captured["body"])["events"][0]["method"] == "llm_chat_completion"
    await sink.close()


def _blocking_sink(config, queue, handler, batch_size=1):
    cfg = replace(config, batch_size=batch_size)
    sink = Sink(cfg, queue, client=httpx.AsyncClient())
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return sink, client


def test_flush_blocking_sends_at_most_two_batches(config, queue):
    posts = []

    def handler(request: httpx.Request) -> httpx.Response:
        posts.append(json.loads(request.content)["events"])
        return httpx.Response(200, json={"accepted": 1, "skipped": 0})

    sink, client = _blocking_sink(config, queue, handler)
    for event in _events(5):
        queue.append(event)
    sent, left = sink.flush_blocking(2.0, client=client)
    assert (sent, left) == (2, 3)
    assert len(posts) == 2
    assert sink.posted == 2


def test_flush_blocking_respects_the_time_budget(config, queue):
    seen_timeouts = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_timeouts.append(request.extensions["timeout"]["read"])
        return httpx.Response(200, json={"accepted": 1, "skipped": 0})

    sink, client = _blocking_sink(config, queue, handler)
    for event in _events(2):
        queue.append(event)
    sink.flush_blocking(1.5, client=client)
    assert seen_timeouts and all(0 < t <= 1.5 for t in seen_timeouts)

    # A spent budget sends nothing and leaves the events queued.
    for event in _events(2):
        queue.append(event)
    assert sink.flush_blocking(0.0, client=client) == (0, 2)


def test_flush_blocking_counts_failures_and_never_raises(config, queue):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nope")

    sink, client = _blocking_sink(config, queue, handler)
    queue.append(_events()[0])
    sent, left = sink.flush_blocking(2.0, client=client)  # must not raise
    assert (sent, left) == (1, 0)
    assert sink.post_failures == 1
    assert sink.posted == 0


async def test_on_tick_runs_each_flush_and_survives_errors(config):
    calls = []

    def tick():
        calls.append(1)
        raise RuntimeError("stats exploded")

    queue = BoundedQueue(10)
    cfg = replace(config, flush_interval_ms=100)
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"accepted": 0, "skipped": 0})
    )
    sink = Sink(cfg, queue, client=httpx.AsyncClient(transport=transport), on_tick=tick)
    sink.start()
    await asyncio.sleep(0.35)
    await sink.close()
    assert len(calls) >= 2
