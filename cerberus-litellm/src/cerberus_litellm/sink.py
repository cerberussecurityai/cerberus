"""Batched delivery to the Cerberus backend.

POSTs ``{"events": [...]}`` to ``{ingestService}/v1/ingest/batch`` with the
API key in ``X-API-Key`` — the same wire contract the flex-gateway policy
uses (the server fans api_key/client_id/token into each event, so events
carry no credentials). Delivery is at-most-once: failed batches are dropped
and counted, matching the flex-gateway v1 posture (retry/backoff is a
documented known gap).
"""

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any

import httpx

from .config import Config
from .logthrottle import LogThrottle
from .queue import BoundedQueue

logger = logging.getLogger(__name__)

# Bound how many batches a single flush tick may post so a deep queue can't
# pin the loop; the next tick continues draining.
MAX_BATCHES_PER_FLUSH = 20

REQUEST_TIMEOUT_SECONDS = 10.0


def _safe_int(value: Any) -> int:
    """Coerce a server-returned counter to int, defaulting to 0 on junk."""
    try:
        return int(value or 0)
    except (ValueError, TypeError):
        return 0


class Sink:
    def __init__(
        self,
        config: Config,
        queue: BoundedQueue,
        client: httpx.AsyncClient | None = None,
        on_tick: Callable[[], None] | None = None,
    ):
        self.config = config
        self.queue = queue
        self.posted = 0
        self.post_failures = 0
        # Server-side filtering visibility: the ingest endpoint may skip
        # events (e.g. its health-endpoint filter) while returning 200.
        self.server_accepted = 0
        self.server_skipped = 0
        self._client = client or httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS)
        self._url = f"{config.ingest_service}/v1/ingest/batch"
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._on_tick = on_tick
        self._throttle = LogThrottle()

    def start(self) -> None:
        self._task = asyncio.get_running_loop().create_task(self._flush_loop())

    async def _flush_loop(self) -> None:
        interval = self.config.flush_interval_ms / 1000
        while not self._stop.is_set():
            # Sleep between ticks but wake immediately on shutdown, so close()
            # never cancels an in-flight POST (which would drop a batch already
            # drained from the queue but not yet delivered).
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                pass
            if self._stop.is_set():
                break
            try:
                await self.flush_once()
                if self._on_tick is not None:
                    self._on_tick()
            except Exception:
                logger.exception("Unexpected error during flush")

    async def flush_once(self) -> None:
        """Drain and post up to MAX_BATCHES_PER_FLUSH batches."""
        for _ in range(MAX_BATCHES_PER_FLUSH):
            batch = self.queue.drain(self.config.batch_size)
            if not batch:
                return
            await self._post(batch)

    async def _post(self, batch: list) -> None:
        try:
            # Serialise here rather than via httpx's json=: strict JSON (no NaN)
            # and a failure we can count instead of one that escapes.
            body = json.dumps({"events": batch}, allow_nan=False).encode("utf-8")
            response = await self._client.post(
                self._url,
                content=body,
                headers={"X-API-Key": self.config.token, "Content-Type": "application/json"},
            )
        except httpx.HTTPError as exc:
            self.post_failures += 1
            logger.warning("Dropping batch of %d events: %s", len(batch), exc)
            return
        except Exception as exc:
            # Anything else (bad URL, unencodable header, unserialisable batch)
            # must not end the flush loop; name the type only, never its args.
            self.post_failures += 1
            self._throttle.warn(
                logger,
                "Dropping batch of %d events: %s while sending",
                len(batch),
                type(exc).__name__,
            )
            return
        # Only a 2xx means the batch was ingested. A 3xx (redirect — httpx does
        # not follow by default, and we must not, or POST->GET would corrupt the
        # body) means it was NOT delivered; treat it as a failure, not success.
        # A 403 from the ingest is treated as rejected and not retried; see the
        # README troubleshooting section.
        if not (200 <= response.status_code < 300):
            self.post_failures += 1
            logger.warning(
                "Dropping batch of %d events: ingest returned %d",
                len(batch),
                response.status_code,
            )
            logger.debug("Ingest error body: %s", response.text[:200])
            return
        self.posted += len(batch)
        try:
            result = response.json()
        except ValueError:
            return
        if not isinstance(result, dict):
            return
        # Parse each counter independently so one malformed field doesn't drop
        # both (e.g. accepted="25 events" must not zero a valid skipped).
        self.server_accepted += _safe_int(result.get("accepted"))
        skipped = _safe_int(result.get("skipped"))
        self.server_skipped += skipped
        if skipped:
            logger.warning(
                "Ingest skipped %d of %d events in batch (server-side filter)",
                skipped,
                len(batch),
            )

    async def close(self) -> None:
        """Signal the flush loop to stop (without interrupting an in-flight POST)
        and best-effort drain remaining events."""
        self._stop.set()
        if self._task is not None:
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        flush_cap = self.config.batch_size * MAX_BATCHES_PER_FLUSH
        remaining = len(self.queue)
        if remaining > flush_cap:
            logger.warning(
                "Shutdown: %d events queued but the final flush delivers at most "
                "%d; ~%d will be dropped (at-most-once delivery)",
                remaining,
                flush_cap,
                remaining - flush_cap,
            )
        try:
            await self.flush_once()
        except asyncio.CancelledError:
            # Grace period expired mid-flush; warn, then let the finally close the
            # client (so the connection pool isn't leaked) before propagating.
            logger.warning("Shutdown cancelled mid-flush; remaining events dropped")
            raise
        except Exception:
            logger.exception("Final flush failed; remaining events dropped")
        finally:
            await self._client.aclose()
