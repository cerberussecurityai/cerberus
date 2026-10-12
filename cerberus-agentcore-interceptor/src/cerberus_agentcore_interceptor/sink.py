"""The Firehose sink: one PutRecord per interception.

Capture is never worth latency on the caller's request, so the timeouts are short
and botocore retries nothing. The one resend is for a connection closed under the
request, most often a pooled one closed while idle. A connection that closed after
the record landed gets it written twice.
"""

from __future__ import annotations

import logging
import zlib
from time import monotonic
from typing import Any

from .bounding import serialize
from .metrics import (
    REASON_DEADLINE,
    REASON_OVERSIZE,
    REASON_SINK,
    REASON_THROTTLE,
    REASON_TIMEOUT,
)

logger = logging.getLogger(__name__)

# Firehose refuses a record over 1,000 KiB; the ladder keeps events far below it.
MAX_RECORD_BYTES = 1000 * 1024

THROTTLE_ERRORS = ("ServiceUnavailableException", "LimitExceededException", "ThrottlingException")


class FirehoseSink:
    """Writes source events to one of the configured delivery streams."""

    def __init__(self, streams: tuple[str, ...], connect_ms: int, read_ms: int, client: Any = None):
        self._streams = streams
        self._client = client
        self._connect_ms = connect_ms
        self._read_ms = read_ms

    def prepare(self) -> None:
        """Build the client before the first request rather than during it."""
        try:
            self._firehose()
        except Exception as exc:
            logger.warning("firehose client not ready: %s", exc)

    def stream_for(self, key: str) -> str:
        """Pick a stream by key, stably across processes."""
        if len(self._streams) == 1:
            return self._streams[0]
        digest = zlib.crc32(key.encode("utf-8"))
        return self._streams[digest % len(self._streams)]

    def put(self, event: dict[str, Any], key: str, deadline: float | None = None) -> str:
        """Write one event. Returns '' on success, or the reason it was dropped.

        Skips the write unless a full connect and read would end by deadline, a
        time.monotonic() value, and resends once, under the same condition, when
        the connection was closed under the request.
        """
        record = serialize(event) + b"\n"
        if len(record) > MAX_RECORD_BYTES:
            return REASON_OVERSIZE
        if not self._has_time(deadline):
            return REASON_DEADLINE

        stream = self.stream_for(key)
        try:
            self._send(stream, record)
        except Exception as exc:
            if not (_connection_closed(exc) and self._has_time(deadline)):
                return _dropped(exc)
            # urllib3 has discarded the dead socket, so this goes out on a new one.
            try:
                self._send(stream, record)
            except Exception as again:
                return _dropped(again)
        return ""

    def _send(self, stream: str, record: bytes) -> None:
        self._firehose().put_record(DeliveryStreamName=stream, Record={"Data": record})

    def _has_time(self, deadline: float | None) -> bool:
        budget = (self._connect_ms + self._read_ms) / 1000
        return deadline is None or monotonic() + budget <= deadline

    def _firehose(self) -> Any:
        if self._client is None:
            import boto3
            from botocore.config import Config as BotoConfig

            self._client = boto3.client(
                "firehose",
                config=BotoConfig(
                    connect_timeout=self._connect_ms / 1000,
                    read_timeout=self._read_ms / 1000,
                    retries={"total_max_attempts": 1},
                ),
            )
        return self._client


def _connection_closed(exc: Exception) -> bool:
    """Whether the connection was reset or closed with the request unanswered."""
    # urllib3 reports any socket or HTTP error on a reused connection as a
    # ProtocolError, which botocore raises as ConnectionClosedError.
    from botocore.exceptions import ConnectionClosedError

    return isinstance(exc, ConnectionClosedError)


def _dropped(exc: Exception) -> str:
    reason = _reason(exc)
    logger.warning("capture dropped: %s (%s)", reason, type(exc).__name__)
    return reason


def _reason(exc: Exception) -> str:
    name = type(exc).__name__
    if "Timeout" in name:
        return REASON_TIMEOUT
    response = getattr(exc, "response", None)
    code = ""
    if isinstance(response, dict):
        error = response.get("Error")
        code = str(error.get("Code", "")) if isinstance(error, dict) else ""
    if code in THROTTLE_ERRORS or name in THROTTLE_ERRORS:
        return REASON_THROTTLE
    return REASON_SINK
