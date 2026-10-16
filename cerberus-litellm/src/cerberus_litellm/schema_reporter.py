"""Emit mcp_schema_report events only when a server's catalogue changes.

LiteLLM logs every tools/list, and MCP clients list tools on every session,
so without this every client connect would re-send the whole catalogue.
A report goes out when the per-server tool-list hash changes or the
configured interval has elapsed. State is per process and bounded.
"""

import hashlib
import json
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from .config import Config
from .mapper_mcp import map_schema_reports

MAX_TRACKED_SERVERS = 1024


class SchemaReporter:
    def __init__(self, config: Config, clock: Callable[[], float] = time.monotonic):
        self.config = config
        self._clock = clock
        self._last: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._pending: dict[str, tuple[str, float]] = {}
        self.suppressed = 0

    @staticmethod
    def _digest(tools: list[dict[str, Any]]) -> str:
        return hashlib.sha256(json.dumps(tools, sort_keys=True, default=str).encode()).hexdigest()

    def events(self, slo: Any, response_obj: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        self._pending.clear()
        now = self._clock()
        for event in map_schema_reports(slo, response_obj, self.config):
            server = event["custom_data"]["mcp_server"]
            digest = self._digest(event["custom_data"]["tools"])
            previous = self._last.get(server)
            interval = self.config.schema_report_interval_s
            if previous is not None and interval > 0:
                last_digest, last_at = previous
                if last_digest == digest and now - last_at < interval:
                    self.suppressed += 1
                    continue
            # Not recorded yet: the caller calls commit() once the report is
            # actually queued, so a dropped or truncated report is retried.
            self._pending[server] = (digest, now)
            out.append(event)
        return out

    def commit(self, event: dict[str, Any]) -> None:
        """Record that ``event`` (a report from the last events() call) was queued."""
        custom_data = event.get("custom_data")
        server = custom_data.get("mcp_server") if isinstance(custom_data, dict) else None
        if not isinstance(server, str):
            return
        pending = self._pending.pop(server, None)
        if pending is None:
            return
        self._last[server] = pending
        self._last.move_to_end(server)
        while len(self._last) > MAX_TRACKED_SERVERS:
            self._last.popitem(last=False)
