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
from cerberus_litellm.sink import Sink


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


async def test_dropped_or_shed_schema_report_does_not_suppress_the_next(config):
    capture = load_capture("mcp_list_tools")
    slo = capture["standard_logging_object"]
    tools = capture["response_obj"]

    def kwargs(call_id):
        return {"standard_logging_object": dict(slo, litellm_call_id=call_id)}

    # 1. The report is shed to a skeleton by the size cap: not committed, offered again.
    tight = CerberusLogger(replace(config, flush_interval_ms=60000, max_event_bytes=1100))
    await tight.async_log_success_event(kwargs("a"), tools, 0, 1)
    await tight.async_log_success_event(kwargs("b"), tools, 0, 1)
    events = await _drain(tight)
    assert [e["custom_data"].get("content_dropped_oversize") for e in events] == [True, True]
    assert tight.stats()["schema_reports_suppressed"] == 0

    # 2. The queue is full: the report is not committed either.
    full = CerberusLogger(replace(config, flush_interval_ms=60000, queue_max_bytes=100))
    await full.async_log_success_event(kwargs("a"), tools, 0, 1)
    assert full.stats()["queue_dropped_bytes"] == 1
    full.queue._max_bytes = None  # room again
    await full.async_log_success_event(kwargs("b"), tools, 0, 1)
    assert [e["method"] for e in await _drain(full)] == ["mcp_schema_report"]

    # 3. Queued intact: the next identical list is suppressed.
    ok = CerberusLogger(replace(config, flush_interval_ms=60000))
    await ok.async_log_success_event(kwargs("a"), tools, 0, 1)
    await ok.async_log_success_event(kwargs("b"), tools, 0, 1)
    assert len(await _drain(ok)) == 1
    assert ok.stats()["schema_reports_suppressed"] == 1


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


async def test_reused_caller_chosen_call_id_does_not_silence_later_calls(plugin):
    first = _kwargs("chat")["standard_logging_object"]
    later = dict(first, startTime=first["startTime"] + 5, endTime=first["endTime"] + 5)
    await plugin.async_log_success_event({"standard_logging_object": first}, None, 0, 1)
    await plugin.async_log_success_event({"standard_logging_object": later}, None, 0, 1)
    assert len(await _drain(plugin)) == 2  # same call id, different timestamps
    assert plugin.stats()["deduplicated"] == 0
    # An exact duplicate firing of the first call is still suppressed.
    await plugin.async_log_success_event({"standard_logging_object": first}, None, 0, 1)
    assert plugin.stats()["deduplicated"] == 1


async def test_queue_byte_budget_drops_and_counts(config):
    plugin = CerberusLogger(replace(config, flush_interval_ms=60000, queue_max_bytes=3000))
    await plugin.async_log_success_event(_kwargs("chat"), None, 0, 1)
    other = dict(_kwargs("chat")["standard_logging_object"], litellm_call_id="another")
    await plugin.async_log_success_event({"standard_logging_object": other}, None, 0, 1)
    stats = plugin.stats()
    assert stats["events_llm"] == 1
    assert stats["queue_dropped_bytes"] == 1
    assert stats["queue_dropped_full"] == 0
    assert 0 < stats["queued_bytes"] <= 3000
    await plugin.sink.close()


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


async def test_sampling_never_hides_tool_catalogues(plugin):
    sampled = CerberusLogger(replace(plugin.config, sample_rate=0.0, flush_interval_ms=60000))
    capture = load_capture("mcp_list_tools")
    kwargs = {"standard_logging_object": capture["standard_logging_object"]}
    await sampled.async_log_success_event(kwargs, capture["response_obj"], 0, 1)
    await sampled.async_log_success_event(_kwargs("chat"), None, 0, 1)
    assert [e["method"] for e in await _drain(sampled)] == ["mcp_schema_report"]
    assert sampled.stats()["sampled_out"] == 1  # the chat call, not the catalogue


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


async def test_invalid_utf8_token_file_disables_instead_of_aborting(monkeypatch, tmp_path, caplog):
    path = tmp_path / "token"
    path.write_bytes(b"\xff\xfe-secret-bytes-\x80")
    monkeypatch.setenv("CERBERUS_INGEST_SERVICE", "http://ingest.test")
    monkeypatch.delenv("CERBERUS_TOKEN", raising=False)
    monkeypatch.setenv("CERBERUS_TOKEN_FILE", str(path))
    caplog.set_level(logging.ERROR)
    plugin = CerberusLogger()  # must not raise
    assert plugin.disabled_reason is not None
    assert "secret-bytes" not in caplog.text
    await plugin.async_log_success_event(_kwargs("chat"), None, 0, 1)  # no-op


async def test_unexpected_config_exception_disables_and_logs_only_the_type(monkeypatch, caplog):
    def boom():
        raise RuntimeError("detail-that-must-not-be-logged")

    monkeypatch.setattr("cerberus_litellm.plugin.Config.from_env", staticmethod(boom))
    caplog.set_level(logging.ERROR)
    plugin = CerberusLogger()
    assert plugin.disabled_reason is not None
    assert "RuntimeError" in caplog.text
    assert "detail-that-must-not-be-logged" not in caplog.text


def _queued_plugin(config, n=1):
    """A plugin with ``n`` events queued and a sink that has never run (no loop needed)."""
    plugin = CerberusLogger(replace(config, flush_interval_ms=60000, batch_size=1))
    plugin.sink = Sink(plugin.config, plugin.queue, client=httpx.AsyncClient())
    for i in range(n):
        plugin.queue.append({"endpoint": f"llm://openai/m{i}", "scheme": "llm"}, 50)
    return plugin


def test_shutdown_flush_posts_queued_events_without_a_loop(config, caplog):
    seen = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"accepted": 1, "skipped": 0})

    caplog.set_level(logging.INFO, logger="cerberus_litellm")
    plugin = _queued_plugin(config, 2)
    plugin._shutdown_flush(client=httpx.Client(transport=httpx.MockTransport(respond)))
    assert len(seen) == 2
    assert plugin.stats()["posted"] == 2
    assert len(plugin.queue) == 0
    assert len([r for r in caplog.records if "shutdown flush" in r.getMessage()]) == 1


def test_shutdown_flush_after_the_event_loop_is_closed(config):
    seen = []

    async def start():
        plugin = CerberusLogger(replace(config, flush_interval_ms=60000))
        await plugin.async_log_success_event(_kwargs("chat"), None, 0, 1)
        return plugin

    plugin = asyncio.run(start())  # the loop is closed when this returns
    transport = httpx.MockTransport(
        lambda request: seen.append(1) or httpx.Response(200, json={"accepted": 1, "skipped": 0})
    )
    plugin._shutdown_flush(client=httpx.Client(transport=transport))
    assert seen == [1]
    assert plugin.stats()["posted"] == 1


def test_shutdown_flush_failure_does_not_raise_and_is_counted(config):
    def boom(request: httpx.Request) -> httpx.Response:
        raise ValueError("secret-looking-detail")

    plugin = _queued_plugin(config, 1)
    plugin._shutdown_flush(client=httpx.Client(transport=httpx.MockTransport(boom)))  # no raise
    assert plugin.stats()["post_failures"] == 1


def test_shutdown_flush_is_a_noop_with_nothing_queued_or_no_sink(config):
    plugin = CerberusLogger(config)
    plugin._shutdown_flush()  # no sink yet
    plugin = _queued_plugin(config, 0)
    plugin._shutdown_flush()  # empty queue


def test_shutdown_flush_is_registered_once_when_events_first_flow(config, exit_hooks):
    async def run():
        plugin = CerberusLogger(replace(config, flush_interval_ms=60000))
        assert exit_hooks == []
        await plugin.async_log_success_event(_kwargs("chat"), None, 0, 1)
        await plugin.async_log_success_event(_kwargs("failure_500"), None, 0, 1)
        await plugin.sink.close()
        return plugin

    plugin = asyncio.run(run())
    assert exit_hooks == [plugin._shutdown_flush]


@pytest.mark.parametrize(
    "url,warns",
    [
        ("http://ingest.example.com", True),
        ("http://203.0.113.9:8080", True),
        ("https://ingest.example.com", False),
        ("http://localhost:9089", False),
        ("http://127.0.0.1:9089", False),
        ("http://127.0.0.2", False),
        ("http://[::1]:9089", False),
    ],
)
def test_plain_http_to_a_remote_host_warns_once(config, caplog, url, warns):
    caplog.set_level(logging.WARNING, logger="cerberus_litellm")
    CerberusLogger(replace(config, ingest_service=url))
    messages = [r.getMessage() for r in caplog.records if "plain http" in r.getMessage()]
    assert len(messages) == (1 if warns else 0)
    if warns:
        assert "sk_test_0123456789" not in messages[0]
        assert "/v1/ingest" not in messages[0]


def test_plain_http_warning_names_the_host_only(config, caplog):
    caplog.set_level(logging.WARNING, logger="cerberus_litellm")
    CerberusLogger(replace(config, ingest_service="http://user:pw@ingest.example.com:81/path?k=v"))
    records = [r for r in caplog.records if "plain http" in r.getMessage()]
    assert len(records) == 1
    # The record's only argument is the host: compare it exactly rather than
    # searching the message for a hostname substring.
    assert records[0].args == ("ingest.example.com",)
    text = records[0].getMessage()
    assert "pw" not in text and "path" not in text and "k=v" not in text


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
