"""Tests for the HMAC secret-key fetch: retry on transient failure, give up on
permanent failure, and the built-in-placeholder-key warning."""

from dataclasses import replace

import httpx
import pytest

from cerberus_envoy_ai_gateway import secret
from cerberus_envoy_ai_gateway.secret import resolve_secret_key


@pytest.fixture
def backend_config(config):
    # A config that triggers the backend fetch path (no inline secret).
    return replace(config, secret_key=None, backend_url="http://backend.test")


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
    assert len(calls) == secret.FETCH_MAX_ATTEMPTS  # bounded


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
