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
from .chain import ChainClient, ChainResult
from .config import Config
from .envelope import REQUEST, Envelope, GatewayContext, gateway_context, parse
from .mapper import source_event
from .sink import FirehoseSink

CONFIG = Config.from_env()
SINK = FirehoseSink(CONFIG.streams, CONFIG.firehose_connect_ms, CONFIG.firehose_read_ms)
OPTIONS = CONFIG.mapper_options(__version__)
CHAIN = ChainClient(CONFIG.chain_arn, CONFIG.chain_read_ms) if CONFIG.chain_arn else None

# The Lambda runtime owns the root logger's handler and its request-id prefix.
logger = logging.getLogger("cerberus_agentcore_interceptor")
logger.setLevel(CONFIG.log_level)

if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    SINK.prepare()
    if CHAIN is not None:
        CHAIN.prepare()


class InterceptorError(RuntimeError):
    """Raised when the request must not be served. Its text can reach callers."""


def handler(event: Any, context: Any = None) -> dict[str, Any]:
    """Capture one interception and return the caller's payload unchanged."""
    envelope = _parse(event)
    gateway = _gateway(context)

    if envelope.phase != REQUEST:
        # This version is a REQUEST interceptor. Attached at RESPONSE it captures
        # nothing, chains nothing, and hands the response straight back.
        metrics.count(metrics.UNEXPECTED_PHASE)
        return _output(envelope)

    chain = _chain(event, context, envelope, gateway)

    if envelope.supported_version:
        if not envelope.kind:
            metrics.count(metrics.UNKNOWN_SHAPE, shape=envelope.shape_key)
        _capture(envelope, gateway, chain)
    else:
        metrics.count(metrics.UNKNOWN_INPUT_VERSION, version=envelope.version)

    return _answer(envelope, chain)


def _parse(event: Any) -> Envelope:
    try:
        return parse(event)
    except Exception:
        logger.exception("interceptor input could not be read")
        metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER)
        return Envelope()


def _gateway(context: Any) -> GatewayContext:
    try:
        return gateway_context(context)
    except Exception:
        logger.exception("client context could not be read")
        return GatewayContext()


def _chain(
    event: Any, context: Any, envelope: Envelope, gateway: GatewayContext
) -> ChainResult | None:
    if CHAIN is None:
        return None
    if gateway.gateway_id not in CONFIG.gateway_ids:
        # An unlisted gateway may have had its own interceptor before us, and we
        # cannot serve its request without running whatever that was.
        raise InterceptorError("interceptor is not configured for this gateway")
    return CHAIN.invoke(event, context, envelope)


def _capture(envelope: Envelope, gateway: GatewayContext, chain: ChainResult | None) -> None:
    try:
        event = source_event(
            envelope,
            gateway,
            OPTIONS,
            datetime.now(UTC),
            chain=chain.note if chain is not None else None,
            body_override=chain.body if chain is not None else None,
        )
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


def _answer(envelope: Envelope, chain: ChainResult | None) -> dict[str, Any]:
    if chain is None:
        return _output(envelope)
    if chain.failed:
        raise InterceptorError("upstream interceptor did not answer")
    if chain.output is not None:
        return chain.output
    return _output(envelope)


def _output(envelope: Envelope) -> dict[str, Any]:
    try:
        return output.passthrough(envelope)
    except Exception:
        logger.exception("output could not be built")
        return output.http_passthrough()
