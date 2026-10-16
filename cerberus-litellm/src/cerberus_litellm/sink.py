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
import time
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
        # events while returning 200.
        self.server_accepted = 0
        self.server_skipped = 0
        self._client = client or httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS)
        self._url = f"{config.ingest_service}/v1/ingest/batch"
        self._task: asyncio.Task | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop = asyncio.Event()
        self._on_tick = on_tick
        self._throttle = LogThrottle()

    def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._task = self._loop.create_task(self._flush_loop())

    def loop_is_running(self) -> bool:
        """True while the event loop this sink started on is still running."""
        return self._loop is not None and self._loop.is_running()

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

    def _request_parts(self, batch: list) -> tuple[bytes, dict[str, str]]:
        # Serialise here rather than via httpx's json=: strict JSON (no NaN)
        # and a failure we can count instead of one that escapes.
        body = json.dumps({"events": batch}, allow_nan=False).encode("utf-8")
        return body, {"X-API-Key": self.config.token, "Content-Type": "application/json"}

    async def _post(self, batch: list) -> None:
        try:
            body, headers = self._request_parts(batch)
            response = await self._client.post(self._url, content=body, headers=headers)
        except Exception as exc:
            self._record_failure(batch, exc)
            return
        self._record_response(batch, response)

    def _record_failure(self, batch: list, exc: Exception) -> None:
        self.post_failures += 1
        if isinstance(exc, httpx.HTTPError):
            # The error text can name the request URL: keep it out of the
            # warning (type only) and available at debug level.
            logger.warning("Dropping batch of %d events: %s", len(batch), type(exc).__name__)
            logger.debug("Batch error detail: %s", exc)
            return
        # Anything else (bad URL, unencodable header, unserialisable batch)
        # must not end the flush loop; name the type only, never its args.
        self._throttle.warn(
            logger,
            "Dropping batch of %d events: %s while sending",
            len(batch),
            type(exc).__name__,
        )

    def flush_blocking(
        self, budget_s: float = 2.0, client: httpx.Client | None = None
    ) -> tuple[int, int]:
        """Best-effort synchronous drain for interpreter exit. Never raises.

        At exit the event loop may already be closed, so this uses a blocking
        client. It sends at most two batches and never spends more than
        ``budget_s`` seconds in total (each request's timeout is the time
        left). Outcomes go into the same counters as the async path. Returns
        (batches sent, events still queued).
        """
        sent = 0
        own_client = client is None
        try:
            deadline = time.monotonic() + budget_s
            if client is None:
                client = httpx.Client()
            for _ in range(2):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                batch = self.queue.drain(self.config.batch_size)
                if not batch:
                    break
                try:
                    body, headers = self._request_parts(batch)
                    response = client.post(
                        self._url, content=body, headers=headers, timeout=remaining
                    )
                except Exception as exc:
                    self._record_failure(batch, exc)
                    continue
                self._record_response(batch, response)
                if 200 <= response.status_code < 300:
                    sent += 1  # only an acknowledged POST counts as sent
        except Exception:
            logger.debug("Shutdown flush stopped early", exc_info=True)
        finally:
            if own_client and client is not None:
                try:
                    client.close()
                except Exception:
                    pass
        return sent, len(self.queue)

    def _record_response(self, batch: list, response: httpx.Response) -> None:
        # Only a 2xx means the batch was ingested. A 3xx (redirect — httpx does
        # not follow by default, and we must not, or POST->GET would corrupt the
        # body) means it was NOT delivered; treat it as a failure, not success.
        # A 403 from the ingest is treated as rejected and not retried; see the
        # README troubleshooting section.
        if not (200 <= response.status_code < 300):
            self.post_failures += 1
            self._throttle.warn(
                logger,
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
