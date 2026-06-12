"""Bounded in-memory event queue.

Mirrors the flex-gateway policy's queue semantics: drop NEW events when
full (never block, never evict already-queued events) and count the drops.
The bridge runs single-event-loop (uvicorn + asyncio background flush), so
no locking is needed.
"""

from collections import deque
from typing import Any


class BoundedQueue:
    def __init__(self, capacity: int):
        self._capacity = capacity
        self._items: deque[dict[str, Any]] = deque()
        self.dropped_full = 0

    def __len__(self) -> int:
        return len(self._items)

    def append(self, event: dict[str, Any]) -> bool:
        """Queue an event; returns False (and counts) when at capacity."""
        if len(self._items) >= self._capacity:
            self.dropped_full += 1
            return False
        self._items.append(event)
        return True

    def drain(self, max_items: int) -> list[dict[str, Any]]:
        """Remove and return up to ``max_items`` oldest events."""
        batch: list[dict[str, Any]] = []
        while self._items and len(batch) < max_items:
            batch.append(self._items.popleft())
        return batch
