"""The Firehose sink: one PutRecord per interception, one attempt.

Capture is never worth latency on the caller's request, so the client retries
nothing and the timeouts are short. A lost record is a lost capture, and the
stream's own backup keeps the customer's copy.
"""

from __future__ import annotations

import logging
import zlib
from typing import Any

from .bounding import serialize
from .metrics import REASON_OVERSIZE, REASON_SINK, REASON_THROTTLE, REASON_TIMEOUT

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

    def put(self, event: dict[str, Any], key: str) -> str:
        """Write one event. Returns '' on success, or the reason it was dropped."""
        record = serialize(event) + b"\n"
        if len(record) > MAX_RECORD_BYTES:
            return REASON_OVERSIZE

        stream = self.stream_for(key)
        try:
            self._firehose().put_record(DeliveryStreamName=stream, Record={"Data": record})
        except Exception as exc:
            reason = _reason(exc)
            logger.warning("capture dropped: %s (%s)", reason, type(exc).__name__)
            return reason
        return ""

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
