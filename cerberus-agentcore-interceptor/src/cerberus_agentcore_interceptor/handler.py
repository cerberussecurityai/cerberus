"""The Lambda entry point.

The gateway fails closed on interceptor failure, so every step that builds a
capture runs under its own guard: whatever goes wrong here, the caller's request
is returned unchanged.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

from . import __version__, metrics, output
from .config import Config
from .envelope import REQUEST, Envelope, gateway_context, parse
from .mapper import source_event
from .sink import FirehoseSink

CONFIG = Config.from_env()
SINK = FirehoseSink(CONFIG.streams, CONFIG.firehose_connect_ms, CONFIG.firehose_read_ms)
OPTIONS = CONFIG.mapper_options(__version__)

# The Lambda runtime owns the root logger's handler and its request-id prefix.
logger = logging.getLogger("cerberus_agentcore_interceptor")
logger.setLevel(CONFIG.log_level)

if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    SINK.prepare()


def handler(event: Any, context: Any = None) -> dict[str, Any]:
    """Capture one interception and return the request unchanged."""
    envelope = _parse(event)

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


def _parse(event: Any) -> Envelope:
    try:
        return parse(event)
    except Exception:
        logger.exception("interceptor input could not be read")
        metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER)
        return Envelope()


def _capture(envelope: Envelope, context: Any) -> None:
    try:
        gateway = gateway_context(context)
        event = source_event(envelope, gateway, OPTIONS, datetime.now(UTC))
        if event is None:
            metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_OVERSIZE)
            return
        reason = SINK.put(event, gateway.gateway_arn or gateway.request_id)
        if reason:
            metrics.count(metrics.CAPTURE_DROPPED, reason, request_id=gateway.request_id)
            return
        metrics.count(metrics.CAPTURED)
    except Exception:
        logger.exception("capture failed")
        metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER)


def _output(envelope: Envelope) -> dict[str, Any]:
    try:
        return output.passthrough(envelope)
    except Exception:
        logger.exception("output could not be built")
        return output.http_passthrough()
