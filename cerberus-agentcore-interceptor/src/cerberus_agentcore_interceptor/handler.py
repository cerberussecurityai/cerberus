"""The Lambda entry point.

The gateway fails closed on interceptor failure, so every step that builds a
capture runs under its own guard, and capture gives up short of the function's
timeout: whatever goes wrong here, the caller's request is returned unchanged.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from time import monotonic
from typing import Any

from . import __version__, metrics, output
from .bounding import CaptureDeadlineExceeded
from .config import Config
from .envelope import REQUEST, Envelope, gateway_context, parse
from .mapper import source_event
from .sink import FirehoseSink

# What capture leaves of the function's timeout for answering the gateway.
ANSWER_MARGIN_MS = 500

CONFIG = Config.from_env()
SINK = FirehoseSink(CONFIG.streams, CONFIG.firehose_connect_ms, CONFIG.firehose_read_ms)
OPTIONS = CONFIG.mapper_options(__version__)

# The Lambda runtime owns the root logger's handler and its request-id prefix.
logger = logging.getLogger("cerberus_agentcore_interceptor")
logger.setLevel(CONFIG.log_level)

if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") and CONFIG.capturing:
    SINK.prepare()


def handler(event: Any, context: Any = None) -> dict[str, Any]:
    """Capture one interception and return the request unchanged."""
    envelope = _parse(event)
    if envelope is None:
        return output.http_passthrough()

    if envelope.phase != REQUEST:
        # This version is a REQUEST interceptor. Attached at RESPONSE it captures
        # nothing and hands the response straight back.
        metrics.count(metrics.UNEXPECTED_PHASE)
        return _output(envelope)

    if not envelope.supported_version:
        metrics.count(metrics.UNKNOWN_INPUT_VERSION, version=envelope.version)
        return _output(envelope)

    if not envelope.kind:
        metrics.count(metrics.UNKNOWN_SHAPE, shape=envelope.shape_key)

    _capture(envelope, context)
    return _output(envelope)


def _parse(event: Any) -> Envelope | None:
    try:
        return parse(event)
    except Exception:
        logger.exception("interceptor input could not be read")
        metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER)
        return None


def _capture(envelope: Envelope, context: Any) -> None:
    if not CONFIG.capturing:
        metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_CONFIG)
        return
    request_id = ""
    try:
        deadline = _deadline(context)
        gateway = gateway_context(context)
        request_id = gateway.request_id
        event = source_event(envelope, gateway, OPTIONS, datetime.now(UTC), deadline=deadline)
        if event is None:
            metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_OVERSIZE)
            return
        reason = SINK.put(event, gateway.gateway_arn or gateway.request_id, deadline)
        if reason:
            metrics.count(metrics.CAPTURE_DROPPED, reason, request_id=request_id)
            return
        metrics.count(metrics.CAPTURED)
    except CaptureDeadlineExceeded:
        metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_DEADLINE, request_id=request_id)
    except Exception:
        logger.exception("capture failed")
        metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER)


def _deadline(context: Any) -> float | None:
    """The time.monotonic() at which capture gives up. None without a Lambda context."""
    remaining = getattr(context, "get_remaining_time_in_millis", None)
    if remaining is None:
        return None
    return monotonic() + (float(remaining()) - ANSWER_MARGIN_MS) / 1000


def _output(envelope: Envelope) -> dict[str, Any]:
    try:
        return output.passthrough(envelope)
    except Exception:
        logger.exception("output could not be built")
        return output.http_passthrough()
