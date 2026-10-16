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
from .config import Config, ConfigError
from .mapper_llm import map_llm_event
from .mapper_mcp import map_mcp_event
from .pipeline import Pipeline
from .queue import BoundedQueue
from .schema_reporter import SchemaReporter
from .sink import REQUEST_TIMEOUT_SECONDS, Sink

logger = logging.getLogger("cerberus_litellm")

DEDUPE_WINDOW = 4096
_WARN_EVERY_SECONDS = 60.0


class CerberusLogger(CustomLogger):
    def __init__(self, config: Config | None = None) -> None:
        super().__init__()
        self.disabled_reason: str | None = None
        self.config: Config
        if config is None:
            try:
                config = Config.from_env()
            except ConfigError as exc:
                self.disabled_reason = str(exc)
                logger.error("cerberus-litellm disabled: %s", exc)
        if config is not None:
            self.config = config
            logging.getLogger("cerberus_litellm").setLevel(config.log_level.upper())
            self.queue = BoundedQueue(config.queue_capacity)
            self.pipeline = Pipeline(config)
            self._schema = SchemaReporter(config)
        self.sink: Sink | None = None
        self._client: httpx.AsyncClient | None = None  # tests inject a mock transport
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._counts: dict[str, int] = {
            "events_llm": 0,
            "events_mcp": 0,
            "events_schema": 0,
            "skipped_no_payload": 0,
            "deduplicated": 0,
            "sampled_out": 0,
            "queue_dropped_full": 0,
            "errors": 0,
        }
        self._last_warning = 0.0
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
            if self._is_duplicate(slo):
                self._counts["deduplicated"] += 1
                return
            if self.config.sample_rate < 1.0 and random.random() >= self.config.sample_rate:
                self._counts["sampled_out"] += 1
                return
            self._ensure_sink()
            for kind, event in self._map(slo, response_obj, kwargs):
                finalized = self.pipeline.finalize(event, kind)
                if finalized is None:
                    continue
                if self.queue.append(finalized):
                    self._counts[f"events_{kind}"] += 1
                else:
                    self._counts["queue_dropped_full"] += 1
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

    def _is_duplicate(self, slo: Mapping[str, Any]) -> bool:
        call_id = payload.get(slo, "litellm_call_id")
        if not isinstance(call_id, str) or not call_id:
            return False
        key = f"{call_id}:{payload.status(slo)}"
        if key in self._seen:
            return True
        self._seen[key] = None
        while len(self._seen) > DEDUPE_WINDOW:
            self._seen.popitem(last=False)
        return False

    def _ensure_sink(self) -> None:
        if self.sink is not None:
            return
        client = self._client or httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS)
        self.sink = Sink(self.config, self.queue, client=client, on_tick=self._log_stats_if_due)
        self.sink.start()

    def _log_stats_if_due(self) -> None:
        interval = self.config.stats_log_interval_s
        if interval <= 0:
            return
        now = time.monotonic()
        if now - self._last_stats >= interval:
            self._last_stats = now
            logger.info("cerberus-litellm stats %s", self.stats())

    def _warn_throttled(self, message: str) -> None:
        now = time.monotonic()
        if now - self._last_warning >= _WARN_EVERY_SECONDS:
            self._last_warning = now
            logger.warning("%s (errors so far: %d)", message, self._counts["errors"], exc_info=True)

    def stats(self) -> dict[str, int]:
        out = dict(self._counts)
        if self.disabled_reason is None:
            out["queued"] = len(self.queue)
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
    """The one request header the plugin reads: ``traceparent``.

    Everything else in ``litellm_params`` (provider key, full request body,
    every client header) is deliberately never looked at.
    """
    headers = payload.get(kwargs, "litellm_params", "proxy_server_request", "headers")
    if not isinstance(headers, Mapping):
        return {}
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == "traceparent" and isinstance(value, str):
            return {"traceparent": value}
    return {}
