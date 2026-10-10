"""The Lambda entry point.

The gateway fails closed on interceptor failure, so every step that builds a
capture runs under its own guard, and capture gives up short of the function's
timeout: whatever goes wrong here, the caller's request is returned unchanged.
"""

from __future__ import annotations

import logging
import os
import traceback
from datetime import UTC, datetime
from time import monotonic
from typing import Any

from . import __version__, metrics, output
from .bounding import CaptureDeadlineExceeded
from .chain import ChainClient, ChainResult
from .config import Config
from .envelope import REQUEST, Envelope, GatewayContext, gateway_context, parse
from .mapper import source_event
from .sink import FirehoseSink

# What capture leaves of the function's timeout for answering the gateway.
ANSWER_MARGIN_MS = 500

CONFIG = Config.from_env()
SINK = FirehoseSink(CONFIG.streams, CONFIG.firehose_connect_ms, CONFIG.firehose_read_ms)
OPTIONS = CONFIG.mapper_options(__version__)
CHAIN = (
    ChainClient(CONFIG.chain_arn, CONFIG.chain_read_ms, pass_headers=CONFIG.chain_pass_headers)
    if CONFIG.chain_arn
    else None
)

# The Lambda runtime owns the root logger's handler and its request-id prefix.
logger = logging.getLogger("cerberus_agentcore_interceptor")
logger.setLevel(CONFIG.log_level)

if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    if CONFIG.capturing:
        SINK.prepare()
    if CHAIN is not None:
        CHAIN.prepare()


class InterceptorError(RuntimeError):
    """Raised when the request must not be served. Its text can reach callers."""


def handler(event: Any, context: Any = None) -> dict[str, Any]:
    """Capture one interception and return the caller's payload unchanged."""
    envelope = _parse(event)
    gateway = _gateway(context)
    if envelope is None:
        # Nothing to capture, but a chained interceptor still has to run.
        unread = Envelope()
        return _answer(unread, _chain(event, context, unread, gateway))

    if envelope.phase != REQUEST:
        # This version is a REQUEST interceptor. Attached at RESPONSE it captures
        # nothing and hands the response straight back, unless it chains: then
        # the slot may have held their interceptor, which we would be skipping.
        metrics.count(metrics.UNEXPECTED_PHASE)
        if CHAIN is not None:
            raise InterceptorError("interceptor is not configured for the response phase")
        return _output(envelope)

    chain = _chain(event, context, envelope, gateway)

    if envelope.supported_version:
        if not envelope.kind:
            metrics.count(metrics.UNKNOWN_SHAPE, shape=envelope.shape_key)
        _capture(envelope, gateway, chain, context)
    else:
        metrics.count(metrics.UNKNOWN_INPUT_VERSION, version=envelope.version)

    return _answer(envelope, chain)


def _parse(event: Any) -> Envelope | None:
    try:
        return parse(event)
    except Exception as exc:
        _log_failure("interceptor input could not be read", exc)
        metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER)
        return None


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
        logger.error("gateway %r is not in CERBERUS_GATEWAY_IDS", gateway.gateway_id)
        raise InterceptorError("interceptor is not configured for this gateway")
    return CHAIN.invoke(event, context, envelope)


def _capture(
    envelope: Envelope, gateway: GatewayContext, chain: ChainResult | None, context: Any
) -> None:
    if not CONFIG.capturing:
        metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_CONFIG)
        return
    request_id = gateway.request_id
    try:
        deadline = _deadline(context)
        event = source_event(
            envelope,
            gateway,
            OPTIONS,
            datetime.now(UTC),
            chain=chain.note if chain is not None else None,
            body_override=chain.body if chain is not None else None,
            deadline=deadline,
        )
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
    except Exception as exc:
        _log_failure("capture failed", exc)
        metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER)


def _deadline(context: Any) -> float | None:
    """The time.monotonic() at which capture gives up. None without a Lambda context."""
    remaining = getattr(context, "get_remaining_time_in_millis", None)
    if remaining is None:
        return None
    return monotonic() + (float(remaining()) - ANSWER_MARGIN_MS) / 1000


def _answer(envelope: Envelope, chain: ChainResult | None) -> dict[str, Any]:
    if chain is None:
        return _output(envelope)
    if chain.failed:
        raise InterceptorError("upstream interceptor did not answer")
    if not isinstance(chain.output, dict):
        # The gateway refuses an answer that is not an object. Our own
        # pass-through in its place would serve what their function did not.
        raise InterceptorError("upstream interceptor did not answer with an object")
    return chain.output


def _output(envelope: Envelope) -> dict[str, Any]:
    try:
        return output.passthrough(envelope)
    except Exception as exc:
        _log_failure("output could not be built", exc)
        return output.http_passthrough()


def _log_failure(what: str, exc: Exception) -> None:
    """Log a failure with its type and stack but not its message, which can quote the request."""
    stack = "".join(traceback.format_tb(exc.__traceback__)).rstrip()
    logger.error("%s: %s\n%s", what, type(exc).__name__, stack)
