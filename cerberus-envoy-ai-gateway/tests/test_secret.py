"""Tests for the HMAC secret-key fetch: retry on transient failure, give up on
permanent failure, and the built-in-placeholder-key warning."""

import asyncio
from dataclasses import replace

import httpx
import pytest

from cerberus_envoy_ai_gateway import secret
from cerberus_envoy_ai_gateway.secret import resolve_secret_key


@pytest.fixture
def backend_config(config):
    # A config that triggers the backend fetch path (no inline secret).
    return replace(config, secret_key=None, backend_url="http://backend.test")


# Captured before _instant_backoff patches the module: a test that needs real
# elapsed time (the budget-bound one below) can't use the no-op sleep.
_REAL_SLEEP = asyncio.sleep


@pytest.fixture(autouse=True)
def _instant_backoff(monkeypatch):
    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(secret.asyncio, "sleep", _no_sleep)


def _mock_backend(monkeypatch, handler):
    """Route the fetch's AsyncClient through a MockTransport; returns a call list."""
    calls: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(len(calls), request)

    real_async_client = httpx.AsyncClient  # capture before patching to avoid recursion

    def factory(*_args, **_kwargs):
        return real_async_client(transport=httpx.MockTransport(wrapped))

    monkeypatch.setattr(secret.httpx, "AsyncClient", factory)
    return calls


async def test_inline_secret_key_skips_the_fetch(config, monkeypatch):
    calls = _mock_backend(monkeypatch, lambda n, r: httpx.Response(500))
    config = replace(config, secret_key="inline-key", backend_url="http://backend.test")
    assert await resolve_secret_key(config) == "inline-key"
    assert calls == []  # never hit the backend


async def test_success_returns_key(backend_config, monkeypatch):
    _mock_backend(monkeypatch, lambda n, r: httpx.Response(200, json={"secret_key": "abc"}))
    assert await resolve_secret_key(backend_config) == "abc"


async def test_transient_5xx_then_success(backend_config, monkeypatch):
    def handler(n, r):
        if n < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"secret_key": "abc"})

    calls = _mock_backend(monkeypatch, handler)
    assert await resolve_secret_key(backend_config) == "abc"
    assert len(calls) == 3  # two failures retried, third succeeds


async def test_transient_connect_error_is_retried_then_gives_up(backend_config, monkeypatch):
    def handler(n, r):
        raise httpx.ConnectError("refused", request=r)

    calls = _mock_backend(monkeypatch, handler)
    assert await resolve_secret_key(backend_config) is None
    assert len(calls) == backend_config.secret_fetch_attempts  # bounded


async def test_transient_429_then_success(backend_config, monkeypatch):
    # 429 (rate limited) is temporary — retry it, unlike other 4xx.
    def handler(n, r):
        if n < 2:
            return httpx.Response(429)
        return httpx.Response(200, json={"secret_key": "abc"})

    calls = _mock_backend(monkeypatch, handler)
    assert await resolve_secret_key(backend_config) == "abc"
    assert len(calls) == 2


async def test_transient_408_is_retried(backend_config, monkeypatch):
    calls = _mock_backend(monkeypatch, lambda n, r: httpx.Response(408))
    assert await resolve_secret_key(backend_config) is None
    assert len(calls) == backend_config.secret_fetch_attempts  # retried, not permanent


async def test_total_deadline_bails_to_unhashed(backend_config, monkeypatch, caplog):
    # The backstop: a stall that the per-attempt timeout can't interrupt at all
    # (here, a patched _fetch_once that ignores the timeout it's handed) would
    # otherwise keep the FastAPI lifespan blocking past the Kubernetes startup
    # budget. The retry loop's own accounting can't help — only the outer
    # wait_for can cut this one — and it falls back to unhashed.
    import logging

    async def _hang(*_args, **_kwargs):
        await asyncio.Event().wait()  # never completes

    monkeypatch.setattr(secret, "_fetch_once", _hang)
    tiny = replace(backend_config, secret_fetch_deadline_ms=20)
    with caplog.at_level(logging.WARNING):
        assert await resolve_secret_key(tiny) is None
    assert any("startup budget" in rec.message for rec in caplog.records)


async def test_slow_failures_are_bounded_by_the_budget_not_the_attempt_cap(
    backend_config, monkeypatch, caplog
):
    # Against a backend that accepts connections but never answers, the wall-clock
    # budget runs out before the attempt cap is reached — the two bounds are
    # independent and either can bind first (the connect-error test above covers
    # the cap binding on fast failures). The loop has to account for the budget
    # itself: hand each attempt only the time that's actually left instead of a
    # full-length timeout the backstop would cancel mid-flight, and name the bound
    # it hit so an operator who raised CERBERUS_SECRET_FETCH_ATTEMPTS can see why
    # they didn't get that many attempts.
    import logging

    timeouts: list[float] = []

    async def _hang(_url, _token, timeout_seconds):
        timeouts.append(timeout_seconds)
        await _REAL_SLEEP(timeout_seconds)
        raise secret._TransientFetchError()

    monkeypatch.setattr(secret, "_fetch_once", _hang)
    # A per-attempt timeout far larger than the whole budget makes the clamp the
    # only possible behaviour, so this asserts on logic rather than on how the
    # scheduler happens to slice up a tighter budget. 20 attempts are configured
    # and the budget affords one.
    slow = replace(
        backend_config,
        secret_fetch_attempts=20,
        secret_fetch_timeout_ms=5000,
        secret_fetch_deadline_ms=120,
    )
    with caplog.at_level(logging.WARNING):
        assert await resolve_secret_key(slow) is None

    assert 0 < len(timeouts) < slow.secret_fetch_attempts  # budget bound, not the cap
    # No attempt is handed more time than the budget has left, so the backstop
    # never has to cancel one mid-flight.
    assert max(timeouts) <= slow.secret_fetch_deadline_ms / 1000
    warning = next(rec.getMessage() for rec in caplog.records if rec.levelno >= logging.WARNING)
    assert f"{len(timeouts)} attempt" in warning  # reports what actually ran
    assert "budget" in warning  # ...and which bound stopped it


async def test_permanent_4xx_is_not_retried(backend_config, monkeypatch):
    calls = _mock_backend(monkeypatch, lambda n, r: httpx.Response(401))
    assert await resolve_secret_key(backend_config) is None
    assert len(calls) == 1  # auth failure won't fix on retry


async def test_empty_key_is_not_retried(backend_config, monkeypatch):
    calls = _mock_backend(monkeypatch, lambda n, r: httpx.Response(200, json={"secret_key": ""}))
    assert await resolve_secret_key(backend_config) is None
    assert len(calls) == 1


async def test_non_dict_body_is_not_retried(backend_config, monkeypatch):
    calls = _mock_backend(monkeypatch, lambda n, r: httpx.Response(200, json=[]))
    assert await resolve_secret_key(backend_config) is None
    assert len(calls) == 1


async def test_no_backend_and_no_key_returns_none(config):
    assert await resolve_secret_key(replace(config, secret_key=None, backend_url=None)) is None


async def test_public_default_key_is_used_but_warns(backend_config, monkeypatch, caplog):
    default = "default-hmac-secret-change-in-production"
    _mock_backend(monkeypatch, lambda n, r: httpx.Response(200, json={"secret_key": default}))
    import logging

    with caplog.at_level(logging.WARNING):
        result = await resolve_secret_key(backend_config)
    assert result == default  # still used, not refused
    assert any("placeholder" in rec.message for rec in caplog.records)


async def test_inline_default_key_also_warns(config, caplog):
    import logging

    default = "default-hmac-secret-change-in-production"
    with caplog.at_level(logging.WARNING):
        result = await resolve_secret_key(replace(config, secret_key=default))
    assert result == default
    assert any("placeholder" in rec.message for rec in caplog.records)
