import asyncio
import copy
import importlib
import json
import logging
from dataclasses import replace

import httpx
import pytest
from helpers import load_capture

from cerberus_litellm.plugin import CerberusLogger, ensure_log_handler


def test_callback_path_resolves_like_litellm_loader(monkeypatch):
    """LiteLLM turns ``callbacks: ["cerberus_litellm.handler"]`` into
    ``getattr(import_module("cerberus_litellm"), "handler")``. Reproduce that
    exactly; the smoke ``import cerberus_litellm`` alone would not catch a
    missing package attribute."""
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.setenv("CERBERUS_TOKEN", "sk_test_0123456789")
    package = importlib.import_module("cerberus_litellm")
    # monkeypatch restores the singleton even if an assert below fails.
    monkeypatch.setattr(package, "_handler", None)
    instance = package.handler
    assert isinstance(instance, CerberusLogger)
    assert instance.disabled_reason is None
    assert package.handler is instance  # stable across lookups


def _kwargs(name: str) -> dict:
    capture = load_capture(name)
    return {"standard_logging_object": capture["standard_logging_object"]}


def _full_kwargs() -> dict:
    return load_capture("full_kwargs_chat")["kwargs"]


async def _drain(logger: CerberusLogger) -> list[dict]:
    # Hooks enqueue synchronously; read the queue without flushing to ingest.
    return logger.queue.drain(1000)


@pytest.fixture
def plugin(config):
    return CerberusLogger(replace(config, flush_interval_ms=60000))


async def test_success_llm_event_is_queued(plugin):
    await plugin.async_log_success_event(_kwargs("chat"), None, 0, 1)
    events = await _drain(plugin)
    assert len(events) == 1
    assert events[0]["endpoint"] == "llm://openai/mock-gpt"
    assert plugin.stats()["events_llm"] == 1


async def test_failure_llm_event_is_queued_with_error(plugin):
    await plugin.async_log_failure_event(_kwargs("failure_500"), None, 0, 1)
    events = await _drain(plugin)
    assert events[0]["custom_data"]["status"] == "error"


async def test_mcp_dispatch(plugin):
    await plugin.async_log_success_event(_kwargs("mcp_tool_call"), None, 0, 1)
    await plugin.async_log_failure_event(_kwargs("mcp_tool_call_error"), None, 0, 1)
    events = await _drain(plugin)
    assert [e["method"] for e in events] == ["mcp_tool_call", "mcp_tool_call"]
    assert events[1]["custom_data"]["result_is_error"] is True
    assert plugin.stats()["events_mcp"] == 2


async def test_schema_report_dispatch_and_dedupe(plugin):
    capture = load_capture("mcp_list_tools")
    kwargs = {"standard_logging_object": capture["standard_logging_object"]}
    await plugin.async_log_success_event(kwargs, capture["response_obj"], 0, 1)
    other = dict(capture["standard_logging_object"], litellm_call_id="other")
    await plugin.async_log_success_event(
        {"standard_logging_object": other}, capture["response_obj"], 0, 1
    )
    events = await _drain(plugin)
    assert [e["method"] for e in events] == ["mcp_schema_report"]
    assert plugin.stats()["events_schema"] == 1


async def test_missing_payload_is_skipped(plugin):
    await plugin.async_log_success_event({}, None, 0, 1)
    await plugin.async_log_success_event({"standard_logging_object": "nope"}, None, 0, 1)
    assert await _drain(plugin) == []
    assert plugin.stats()["skipped_no_payload"] == 2


async def test_duplicate_call_id_is_dropped(plugin):
    await plugin.async_log_failure_event(_kwargs("failure_500"), None, 0, 1)
    await plugin.async_log_failure_event(_kwargs("failure_500"), None, 0, 1)
    assert len(await _drain(plugin)) == 1
    assert plugin.stats()["deduplicated"] == 1


async def test_same_call_success_and_failure_are_both_kept(plugin):
    kwargs = _kwargs("chat")
    await plugin.async_log_success_event(kwargs, None, 0, 1)
    failed = {"standard_logging_object": dict(kwargs["standard_logging_object"], status="failure")}
    await plugin.async_log_failure_event(failed, None, 0, 1)
    assert len(await _drain(plugin)) == 2


async def test_malformed_payload_is_absorbed(plugin, caplog):
    caplog.set_level(logging.WARNING)
    junk = {
        "standard_logging_object": {
            "call_type": "acompletion",
            "messages": None,
            "response": "text",
            "metadata": [],
            "startTime": "x",
        }
    }
    await plugin.async_log_success_event(junk, None, 0, 1)  # must not raise
    events = await _drain(plugin)
    assert len(events) == 1  # mapper tolerates it; event still shipped
    assert plugin.stats()["errors"] == 0


async def test_exception_in_mapper_is_counted_not_raised(plugin, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("mapper bug")

    monkeypatch.setattr("cerberus_litellm.plugin.map_llm_event", boom)
    await plugin.async_log_success_event(_kwargs("chat"), None, 0, 1)
    assert plugin.stats()["errors"] == 1


async def test_no_secrets_in_emitted_events(plugin):
    needles = ("dummy-upstream-key", "sk-REDACTED-virtual-key", "should-not-leak", "Bearer ")
    # The capture is real, so it has no authorization header (LiteLLM strips it
    # before the logging hook). Plant the credential where a leak would
    # plausibly surface, so every needle is genuinely present in the input.
    kwargs = copy.deepcopy(_full_kwargs())
    params = kwargs.setdefault("litellm_params", {})
    for holder in (
        params.setdefault("proxy_server_request", {}).setdefault("headers", {}),
        params.setdefault("metadata", {}).setdefault("headers", {}),
    ):
        holder["authorization"] = "Bearer sk-REDACTED-virtual-key"
    kwargs["api_key"] = "sk-REDACTED-virtual-key"
    before = json.dumps(kwargs)
    for needle in needles:
        assert needle in before, f"input must carry {needle!r}"

    await plugin.async_log_success_event(kwargs, None, 0, 1)
    events = await _drain(plugin)
    assert events  # the event was produced; the needles are absent from it
    serialized = json.dumps(events)
    for needle in needles:
        assert needle not in serialized, needle


async def test_traceparent_is_read_from_request_headers(plugin):
    kwargs = _full_kwargs()
    await plugin.async_log_success_event(kwargs, None, 0, 1)
    event = (await _drain(plugin))[0]
    assert event["custom_data"]["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"


async def test_sampling(plugin, monkeypatch):
    sampled = CerberusLogger(replace(plugin.config, sample_rate=0.0, flush_interval_ms=60000))
    await sampled.async_log_success_event(_kwargs("chat"), None, 0, 1)
    assert await _drain(sampled) == []
    assert sampled.stats()["sampled_out"] == 1


async def test_sink_starts_lazily_on_running_loop(plugin):
    assert plugin.sink is None
    await plugin.async_log_success_event(_kwargs("chat"), None, 0, 1)
    assert plugin.sink is not None
    await plugin.sink.close()


async def test_disabled_on_config_error(monkeypatch, caplog):
    for key in ("CERBERUS_INGEST_SERVICE", "CERBERUS_TOKEN", "CERBERUS_TOKEN_FILE"):
        monkeypatch.delenv(key, raising=False)
    caplog.set_level(logging.ERROR)
    plugin = CerberusLogger()
    assert plugin.disabled_reason is not None
    assert "cerberus-litellm disabled" in caplog.text
    await plugin.async_log_success_event(_kwargs("chat"), None, 0, 1)  # no-op, no raise
    assert plugin.stats()["events_llm"] == 0


async def test_end_to_end_flush_posts_batch(config):
    seen = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"accepted": 1, "skipped": 0})

    plugin = CerberusLogger(replace(config, flush_interval_ms=100))
    plugin._client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    await plugin.async_log_success_event(_kwargs("chat"), None, 0, 1)
    await asyncio.sleep(0.3)
    await plugin.sink.close()
    assert seen and seen[0]["events"][0]["scheme"] == "llm"
    assert plugin.stats()["posted"] == 1


def test_log_handler_is_attached_only_when_the_chain_has_none(monkeypatch):
    # The LiteLLM proxy configures no handler for foreign loggers, so INFO
    # lines (loaded, stats) would be dropped without one.
    target = logging.getLogger("cerberus_litellm_handler_test")
    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    assert not target.hasHandlers()
    ensure_log_handler(target)
    ensure_log_handler(target)  # idempotent
    assert len(target.handlers) == 1
    target.handlers.clear()

    sentinel = logging.NullHandler()
    monkeypatch.setattr(logging.getLogger(), "handlers", [sentinel])
    ensure_log_handler(target)
    assert target.handlers == []  # an existing chain is left alone
