"""Batched delivery to the Cerberus backend.

POSTs ``{"events": [...]}`` to ``{ingestService}/v1/ingest/batch`` with the
API key in ``X-API-Key`` — the same wire contract the flex-gateway policy
uses (the server fans api_key/client_id/token into each event, so events
carry no credentials). Delivery is at-most-once: failed batches are dropped
and counted, matching the flex-gateway v1 posture (retry/backoff is a
documented known gap).
"""

import asyncio
import logging

import httpx

from .config import Config
from .queue import BoundedQueue

logger = logging.getLogger(__name__)

# Bound how many batches a single flush tick may post so a deep queue can't
# pin the loop; the next tick continues draining.
MAX_BATCHES_PER_FLUSH = 20

REQUEST_TIMEOUT_SECONDS = 10.0


class Sink:
    def __init__(
        self, config: Config, queue: BoundedQueue, client: httpx.AsyncClient | None = None
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

    def start(self) -> None:
        self._task = asyncio.get_running_loop().create_task(self._flush_loop())

    async def _flush_loop(self) -> None:
        interval = self.config.flush_interval_ms / 1000
        while True:
            await asyncio.sleep(interval)
            try:
                await self.flush_once()
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
            response = await self._client.post(
                self._url,
                json={"events": batch},
                headers={"X-API-Key": self.config.token},
            )
        except httpx.HTTPError as exc:
            self.post_failures += 1
            logger.warning("Dropping batch of %d events: %s", len(batch), exc)
            return
        if response.status_code >= 400:
            self.post_failures += 1
            logger.warning(
                "Dropping batch of %d events: ingest returned %d %s",
                len(batch),
                response.status_code,
                response.text[:200],
            )
            return
        self.posted += len(batch)
        try:
            result = response.json()
            accepted = int(result.get("accepted") or 0)
            skipped = int(result.get("skipped") or 0)
        except (ValueError, TypeError, AttributeError):
            return
        self.server_accepted += accepted
        self.server_skipped += skipped
        if skipped:
            logger.warning(
                "Ingest skipped %d of %d events in batch (server-side filter)",
                skipped,
                len(batch),
            )

    async def close(self) -> None:
        """Stop the flush loop and best-effort drain remaining events."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        try:
            await self.flush_once()
        except Exception:
            logger.exception("Final flush failed; remaining events dropped")
        await self._client.aclose()
