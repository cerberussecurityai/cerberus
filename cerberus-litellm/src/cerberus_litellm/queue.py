"""Bounded in-memory event queue.

Mirrors the flex-gateway policy's queue semantics: drop NEW events when
full (never block, never evict already-queued events) and count the drops.
The queue is bounded two ways: by event count and by total encoded bytes,
because the queue lives inside the proxy process and a slow ingest must not
be able to grow it without limit. LiteLLM runs the hooks and the background
flush on one asyncio loop, so no locking is needed.
"""

from collections import deque
from typing import Any


class BoundedQueue:
    def __init__(self, capacity: int, max_bytes: int | None = None):
        self._capacity = capacity
        self._max_bytes = max_bytes
        self._items: deque[tuple[dict[str, Any], int]] = deque()
        self._bytes = 0
        self.dropped_full = 0
        self.dropped_bytes = 0

    def __len__(self) -> int:
        return len(self._items)

    @property
    def queued_bytes(self) -> int:
        """Sum of the encoded sizes of the queued events."""
        return self._bytes

    def append(self, event: dict[str, Any], size: int = 0) -> bool:
        """Queue an event of ``size`` encoded bytes.

        Returns False (and counts the drop) when the queue is at capacity or
        when the event would take it over its byte budget. The size is
        measured once by the pipeline and carried here, not recomputed.

        Not thread-safe: the check-then-append relies on single-threaded
        event-loop access (see module docstring). If the hooks ever move to a
        thread executor, this needs a lock.
        """
        if len(self._items) >= self._capacity:
            self.dropped_full += 1
            return False
        if self._max_bytes is not None and self._bytes + size > self._max_bytes:
            self.dropped_bytes += 1
            return False
        self._items.append((event, size))
        self._bytes += size
        return True

    def drain(self, max_items: int) -> list[dict[str, Any]]:
        """Remove and return up to ``max_items`` oldest events."""
        batch: list[dict[str, Any]] = []
        while self._items and len(batch) < max_items:
            event, size = self._items.popleft()
            self._bytes -= size
            batch.append(event)
        return batch
