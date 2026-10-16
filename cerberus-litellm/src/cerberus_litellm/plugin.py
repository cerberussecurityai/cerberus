"""The LiteLLM CustomLogger that ships Cerberus events.

Observe-only: it implements the two terminal logging hooks and nothing on the
request path. It never raises, never blocks the proxy's event loop (events are
appended to a bounded queue; a background task posts batches), and never
serialises LiteLLM's ``kwargs`` — the customer's upstream provider key sits in
there. Exactly one header is read from the request copy: ``traceparent``.

Misconfiguration disables the plugin with one ERROR line rather than
aborting proxy startup. (An ImportError here *would* abort it — LiteLLM
fails closed on callback import — so this module imports nothing optional
at module level and touches no environment until ``CerberusLogger()`` runs.)
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import random
import time
from collections import OrderedDict
from collections.abc import Mapping
from typing import Any

try:  # the proxy is the host; tests and tooling run without it
    from litellm.integrations.custom_logger import CustomLogger
except ImportError:  # pragma: no cover - exercised only outside the proxy

    class CustomLogger:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass


import httpx

from . import __version__, payload
from .config import Config, ConfigError, plain_http_remote_host
from .logthrottle import LogThrottle
from .mapper_llm import map_llm_event
from .mapper_mcp import map_mcp_event
from .pipeline import Pipeline
from .queue import BoundedQueue
from .schema_reporter import SchemaReporter
from .sink import REQUEST_TIMEOUT_SECONDS, Sink

logger = logging.getLogger("cerberus_litellm")

DEDUPE_WINDOW = 4096
SHUTDOWN_FLUSH_BUDGET_S = 2.0


def warn_if_plain_http(ingest_service: str, target: logging.Logger) -> bool:
    """Warn once when the API key travels over plain http to a remote host.

    Reached only when CERBERUS_ALLOW_PLAIN_HTTP allowed it (otherwise the
    configuration is refused). Loopback hosts are exempt. Only the host is
    named. Returns True when a warning was logged.
    """
    host = plain_http_remote_host(ingest_service)
    if host is None:
        return False
    target.warning(
        "cerberus-litellm: the ingest URL uses plain http to %s; the API key and event "
        "content are sent unencrypted. Use https.",
        host,
    )
    return True


def ensure_log_handler(target: logging.Logger) -> None:
    """Give ``target`` a stderr handler when nothing in its chain has one.

    The LiteLLM proxy attaches handlers to its own loggers only, so without
    this the plugin's INFO lines (loaded, periodic stats) would be dropped.
    A host that does configure logging is left alone.
    """
    if target.hasHandlers():
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    target.addHandler(handler)


class CerberusLogger(CustomLogger):
    def __init__(self, config: Config | None = None) -> None:
        super().__init__()
        ensure_log_handler(logger)
        self.disabled_reason: str | None = None
        self.config: Config
        if config is None:
            try:
                config = Config.from_env()
            except ConfigError as exc:
                self.disabled_reason = str(exc)
            except Exception as exc:
                # Never abort proxy startup, and never print an unknown
                # exception's args (a decode error carries the offending bytes).
                self.disabled_reason = (
                    f"unexpected {type(exc).__name__} while reading the configuration"
                )
            if self.disabled_reason is not None:
                logger.error("cerberus-litellm disabled: %s", self.disabled_reason)
        if config is not None:
            self.config = config
            logging.getLogger("cerberus_litellm").setLevel(config.log_level.upper())
            self.queue = BoundedQueue(config.queue_capacity, config.queue_max_bytes)
            self.pipeline = Pipeline(config)
            self._schema = SchemaReporter(config)
            warn_if_plain_http(config.ingest_service, logger)
            captured = [
                label
                for enabled, label in (
                    (config.capture_llm_content, "LLM prompts and completions"),
                    (config.capture_mcp_arguments, "MCP tool arguments"),
                    (config.capture_mcp_results, "MCP tool results"),
                )
                if enabled
            ]
            if captured:
                logger.info("cerberus-litellm captures content: %s", ", ".join(captured))
        self.sink: Sink | None = None
        self._exit_hook_registered = False
        self._client: httpx.AsyncClient | None = None  # tests inject a mock transport
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._counts: dict[str, int] = {
            "events_llm": 0,
            "events_mcp": 0,
            "events_schema": 0,
            "skipped_no_payload": 0,
            "deduplicated": 0,
            "sampled_out": 0,
            "errors": 0,
        }
        self._throttle = LogThrottle()
        self._last_stats = time.monotonic()
        logger.info(
            "cerberus-litellm %s loaded%s",
            __version__,
            " (disabled)" if self.disabled_reason else "",
        )

    # ---- LiteLLM hooks -------------------------------------------------
    async def async_log_success_event(  # type: ignore[override]
        self, kwargs, response_obj, start_time, end_time
    ):
        await self._handle(kwargs, response_obj)

    async def async_log_failure_event(  # type: ignore[override]
        self, kwargs, response_obj, start_time, end_time
    ):
        await self._handle(kwargs, response_obj)

    # ---- internals -----------------------------------------------------
    async def _handle(self, kwargs: Any, response_obj: Any) -> None:
        if self.disabled_reason is not None:
            return
        try:
            slo = kwargs.get("standard_logging_object") if isinstance(kwargs, Mapping) else None
            if not isinstance(slo, Mapping):
                self._counts["skipped_no_payload"] += 1
                return
            # A call is marked seen only once it has been handled (mapped and
            # finalized, or sampled out on purpose: a sampled-out call is not
            # sent, so its repeat firing must not be either). If mapping or
            # finalizing raises, the id stays unmarked so a duplicate firing of
            # the same call gets another chance to deliver.
            dedupe_key = self._dedupe_key(slo)
            if dedupe_key is not None and dedupe_key in self._seen:
                self._counts["deduplicated"] += 1
                return
            # Tool catalogues are exempt from sampling: they are rare, already
            # de-duplicated per server, and losing one can hide a server's tools
            # for a whole report interval.
            sampled = (
                self.config.sample_rate < 1.0
                and payload.call_type(slo) != "list_mcp_tools"
                and random.random() >= self.config.sample_rate
            )
            if sampled:
                self._mark_seen(dedupe_key)
                self._counts["sampled_out"] += 1
                return
            self._ensure_sink()
            ready: list[tuple[str, dict[str, Any], int]] = []
            for kind, event in self._map(slo, response_obj, kwargs):
                result = self.pipeline.finalize(event, kind)
                if result is not None:
                    ready.append((kind, result[0], result[1]))
            self._mark_seen(dedupe_key)  # mapping and finalizing succeeded
            for kind, finalized, size in ready:
                # Drops are counted by the queue itself (by count or by bytes).
                if self.queue.append(finalized, size):
                    self._counts[f"events_{kind}"] += 1
                    # A catalogue counts as reported only if it was queued with
                    # its tools intact; a shed or dropped report is retried.
                    if kind == "schema" and not finalized["custom_data"].get(
                        "content_dropped_oversize"
                    ):
                        self._schema.commit(finalized)
        except Exception:
            self._counts["errors"] += 1
            self._warn_throttled("cerberus-litellm: failed to map an event")

    def _map(
        self, slo: Mapping[str, Any], response_obj: Any, kwargs: Mapping[str, Any]
    ) -> list[tuple[str, dict[str, Any]]]:
        call_type = payload.call_type(slo)
        if call_type == "call_mcp_tool":
            event = map_mcp_event(slo, self.config)
            return [("mcp", event)] if event is not None else []
        if call_type == "list_mcp_tools":
            return [("schema", event) for event in self._schema.events(slo, response_obj)]
        return [("llm", map_llm_event(slo, self.config, _request_headers(kwargs)))]

    @staticmethod
    def _dedupe_key(slo: Mapping[str, Any]) -> str | None:
        call_id = payload.get(slo, "litellm_call_id")
        if not isinstance(call_id, str) or not call_id:
            return None
        # The call id can be chosen by the caller (x-litellm-call-id), so it is not
        # enough on its own: a caller that reuses one id must not silence its own
        # later calls. LiteLLM's duplicate firings of one call share timestamps.
        start, end = payload.get(slo, "startTime"), payload.get(slo, "endTime")
        for stamp in (start, end):
            if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
                # Without both timestamps the id alone would be all that
                # identifies the call, and the caller chooses it: do not dedupe.
                return None
        return f"{call_id}:{payload.status(slo)}:{start}:{end}"

    def _mark_seen(self, key: str | None) -> None:
        if key is None:
            return
        self._seen[key] = None
        while len(self._seen) > DEDUPE_WINDOW:
            self._seen.popitem(last=False)

    def _ensure_sink(self) -> None:
        loop = asyncio.get_running_loop()
        if self.sink is not None:
            if self.sink.runs_on(loop):
                return
            # The event loop was replaced (a reload, a test harness): the old
            # flush task died with its loop. Keep the queued events and hand the
            # same queue to a new sink on the current loop.
            logger.warning(
                "cerberus-litellm: event loop changed; restarting the delivery task "
                "(%d queued events kept)",
                len(self.queue),
            )
            self.sink.abandon()
            self.sink = None
        client = self._client or httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS)
        self.sink = Sink(self.config, self.queue, client=client, on_tick=self._log_stats_if_due)
        self.sink.start()
        # LiteLLM v1.105.1 gives a callback no shutdown hook, so events still
        # queued when the process exits would be lost; register a best-effort
        # flush. Registered once, when events first flow (not at import), and
        # not again if the sink is later restarted on a new loop.
        if not self._exit_hook_registered:
            self._exit_hook_registered = True
            atexit.register(self._shutdown_flush)

    def _shutdown_flush(self, client: httpx.Client | None = None) -> None:
        """Best-effort synchronous flush at interpreter exit. Never raises.

        Works whether or not the event loop is still alive: it uses a blocking
        client, sends at most two batches and spends at most
        SHUTDOWN_FLUSH_BUDGET_S seconds.

        The queue is not thread-safe, so this assumes atexit runs after the
        server has stopped the event loop (uvicorn does that before the
        interpreter exits). If the sink's loop is somehow still running, the
        blocking drain is skipped rather than racing the flush task.
        """
        try:
            if self.sink is None:
                return
            queued = len(self.queue)
            if self.sink.loop_is_running():
                if queued:
                    logger.warning(
                        "cerberus-litellm shutdown flush skipped: event loop still running; "
                        "%d queued events left unsent",
                        queued,
                    )
                else:
                    logger.debug("cerberus-litellm shutdown flush skipped: event loop running")
                return
            if queued == 0:
                return
            sent, left = self.sink.flush_blocking(SHUTDOWN_FLUSH_BUDGET_S, client=client)
            logger.info(
                "cerberus-litellm shutdown flush: %d queued, %d batch(es) sent, %d left unsent",
                queued,
                sent,
                left,
            )
        except Exception:
            logger.debug("cerberus-litellm shutdown flush failed", exc_info=True)

    def _log_stats_if_due(self) -> None:
        interval = self.config.stats_log_interval_s
        if interval <= 0:
            return
        now = time.monotonic()
        if now - self._last_stats >= interval:
            self._last_stats = now
            logger.info("cerberus-litellm stats %s", self.stats())

    def _warn_throttled(self, message: str) -> None:
        self._throttle.warn(
            logger, "%s (errors so far: %d)", message, self._counts["errors"], exc_info=True
        )

    def stats(self) -> dict[str, int]:
        out = dict(self._counts)
        if self.disabled_reason is None:
            out["queued"] = len(self.queue)
            out["queued_bytes"] = self.queue.queued_bytes
            out["queue_dropped_full"] = self.queue.dropped_full
            out["queue_dropped_bytes"] = self.queue.dropped_bytes
            out["dropped_oversize"] = self.pipeline.dropped_oversize
            out["dropped_unserializable"] = self.pipeline.dropped_unserializable
            out["schema_reports_suppressed"] = self._schema.suppressed
            if self.sink is not None:
                out["posted"] = self.sink.posted
                out["post_failures"] = self.sink.post_failures
                out["server_accepted"] = self.sink.server_accepted
                out["server_skipped"] = self.sink.server_skipped
        return out


def _request_headers(kwargs: Mapping[str, Any]) -> dict[str, str]:
    """Read exactly one header from ``kwargs``: ``traceparent``.

    The session, turn and captured-header values come from the standard
    logging object, not from here. Everything else in ``litellm_params``
    (provider key, full request body, every other client header) is
    deliberately never looked at.
    """
    headers = payload.get(kwargs, "litellm_params", "proxy_server_request", "headers")
    if not isinstance(headers, Mapping):
        return {}
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == "traceparent" and isinstance(value, str):
            return {"traceparent": value}
    return {}
