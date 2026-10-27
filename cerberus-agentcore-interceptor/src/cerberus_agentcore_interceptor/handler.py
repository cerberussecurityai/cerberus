"""The Lambda entry point, at REQUEST and at RESPONSE.

The gateway fails closed on interceptor failure, so every step that builds a
capture runs under its own guard, and capture gives up short of the function's
timeout: whatever goes wrong here, the gateway gets its payload back unchanged.
"""

from __future__ import annotations

import logging
import os
import traceback
from dataclasses import replace
from datetime import UTC, datetime
from time import monotonic
from typing import Any

from . import __version__, metrics, output
from .bounding import CaptureDeadlineExceeded
from .chain import OUTCOME_ERROR, ChainClient, ChainResult
from .config import Config
from .envelope import REQUEST, RESPONSE, Envelope, GatewayContext, gateway_context, parse
from .mapper import ORIGINAL_BODY, response_event, source_event
from .sink import FirehoseSink

# What capture leaves of the function's timeout for answering the gateway.
ANSWER_MARGIN_MS = 500


def _chain_clients(config: Config) -> dict[str, ChainClient]:
    """A chain client for each phase that chains, one shared when both would invoke alike."""
    chains: dict[str, ChainClient] = {}
    if config.chain_request_arn:
        chains[REQUEST] = ChainClient(
            config.chain_request_arn, config.chain_read_ms, pass_headers=config.chain_pass_headers
        )
    if config.chain_response_arn:
        request = (config.chain_request_arn, config.chain_pass_headers)
        if (config.chain_response_arn, config.chain_response_pass_headers) == request:
            chains[RESPONSE] = chains[REQUEST]
        else:
            chains[RESPONSE] = ChainClient(
                config.chain_response_arn,
                config.chain_read_ms,
                pass_headers=config.chain_response_pass_headers,
            )
    return chains


CONFIG = Config.from_env()
SINK = FirehoseSink(CONFIG.streams, CONFIG.firehose_connect_ms, CONFIG.firehose_read_ms)
OPTIONS = CONFIG.mapper_options(__version__)
CHAINS = _chain_clients(CONFIG)

# The Lambda runtime owns the root logger's handler and its request-id prefix.
logger = logging.getLogger("cerberus_agentcore_interceptor")
logger.setLevel(CONFIG.log_level)

# At DEBUG, botocore and urllib3 log each request they send, botocore with its
# payload: the caller's raw body in a PutRecord or a chained invoke.
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    if CONFIG.capturing:
        SINK.prepare()
    for chain_client in dict.fromkeys(CHAINS.values()):
        chain_client.prepare()


class InterceptorError(RuntimeError):
    """Raised when the call must not go on. Its text can reach callers."""


def handler(event: Any, context: Any = None) -> dict[str, Any]:
    """Capture one interception and hand the gateway its payload back unchanged."""
    envelope = _parse(event)
    gateway = _gateway(context)
    if envelope is None:
        # Nothing to capture, but a chained interceptor still has to run.
        return _answer(event, None, _chain(event, context, None, gateway))

    chain = _chain(event, context, envelope, gateway)
    if envelope.phase == RESPONSE and not CONFIG.response_capture:
        if RESPONSE not in CHAINS:
            metrics.count(metrics.UNEXPECTED_PHASE)
        return _answer(event, envelope, chain)

    if envelope.supported_version:
        if not envelope.kind:
            metrics.count(metrics.UNKNOWN_SHAPE, shape=envelope.shape_key)
        _capture(envelope, gateway, chain, context)
    else:
        metrics.count(metrics.UNKNOWN_INPUT_VERSION, version=envelope.version)

    return _answer(event, envelope, chain)


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
    except Exception as exc:
        _log_failure("client context could not be read", exc)
        return GatewayContext()


def _chain(
    event: Any, context: Any, envelope: Envelope | None, gateway: GatewayContext
) -> ChainResult | None:
    if not CHAINS:
        return None
    if gateway.gateway_id not in CONFIG.gateway_ids:
        # An unlisted gateway may have had its own interceptor before us, and we
        # cannot serve its call without running whatever that was.
        logger.error("gateway %r is not in CERBERUS_GATEWAY_IDS", gateway.gateway_id)
        raise InterceptorError("interceptor is not configured for this gateway")
    if envelope is None:
        clients = list(dict.fromkeys(CHAINS.values()))
        if len(clients) > 1:
            # Either of two functions may be the one this input is for.
            raise InterceptorError("interceptor could not read its input")
        client: ChainClient | None = clients[0]
        envelope = Envelope()
    else:
        client = CHAINS.get(envelope.phase)
    if client is None:
        return None
    try:
        deadline = _deadline(context)
    except Exception as exc:
        _log_failure("remaining time could not be read", exc)
        deadline = None
    try:
        return client.invoke(event, context, envelope, deadline)
    except Exception as exc:
        # Botocore's message can name the function's ARN. The call is refused
        # like any other failed invoke.
        _log_failure("chained interceptor failed", exc)
        return ChainResult(OUTCOME_ERROR, note={"outcome": OUTCOME_ERROR})


def _capture(
    envelope: Envelope, gateway: GatewayContext, chain: ChainResult | None, context: Any
) -> None:
    phase = envelope.phase
    if not CONFIG.capturing:
        metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_CONFIG, phase=phase)
        return
    request_id = gateway.request_id
    try:
        deadline = _deadline(context)
        event = _event(envelope, gateway, chain, deadline)
        if event is None:
            metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_OVERSIZE, phase=phase)
            return
        reason = SINK.put(event, gateway.gateway_arn or gateway.request_id, deadline)
        if reason:
            metrics.count(metrics.CAPTURE_DROPPED, reason, phase=phase, request_id=request_id)
            return
        metrics.count(metrics.CAPTURED, phase=phase)
    except CaptureDeadlineExceeded:
        metrics.count(
            metrics.CAPTURE_DROPPED, metrics.REASON_DEADLINE, phase=phase, request_id=request_id
        )
    except Exception as exc:
        _log_failure("capture failed", exc)
        metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_HANDLER, phase=phase)


def _event(
    envelope: Envelope, gateway: GatewayContext, chain: ChainResult | None, deadline: float | None
) -> dict[str, Any] | None:
    now = datetime.now(UTC)
    note = chain.note if chain is not None else None
    if envelope.phase == RESPONSE:
        if chain is not None and chain.response is not None:
            envelope = replace(envelope, response=chain.response)
        # The RESPONSE input holds the caller's request as it was before their
        # REQUEST interceptor, which may have removed parts of it.
        return response_event(
            envelope,
            gateway,
            OPTIONS,
            now,
            chain=note,
            deadline=deadline,
            request_side=REQUEST not in CHAINS,
        )
    return source_event(
        envelope,
        gateway,
        OPTIONS,
        now,
        chain=note,
        body_override=chain.body if chain is not None and chain.transformed else ORIGINAL_BODY,
        deadline=deadline,
        response_expected=CONFIG.response_capture and not (chain is not None and chain.ends_call),
    )


def _deadline(context: Any) -> float | None:
    """The time.monotonic() at which capture gives up. None without a Lambda context."""
    remaining = getattr(context, "get_remaining_time_in_millis", None)
    if remaining is None:
        return None
    return monotonic() + (float(remaining()) - ANSWER_MARGIN_MS) / 1000


def _answer(event: Any, envelope: Envelope | None, chain: ChainResult | None) -> dict[str, Any]:
    if chain is None:
        return _output(event, envelope)
    if chain.failed:
        raise InterceptorError("upstream interceptor did not answer")
    if not isinstance(chain.output, dict):
        # The gateway refuses an answer that is not an object. Our own
        # pass-through in its place would serve what their function did not.
        raise InterceptorError("upstream interceptor did not answer with an object")
    return chain.output


def _output(event: Any, envelope: Envelope | None) -> dict[str, Any]:
    if envelope is not None:
        try:
            return output.passthrough(envelope)
        except Exception as exc:
            _log_failure("output could not be built", exc)
    try:
        response = output.mcp_response(event)
    except Exception as exc:
        _log_failure("raw input could not be read", exc)
        response = None
    if response is None:
        # The http form passes through anything not known to be an mcp RESPONSE.
        return output.http_passthrough()
    try:
        return output.response_echo(response)
    except Exception as exc:
        _log_failure("pass-through could not be built", exc)
        raise InterceptorError("interceptor could not return the response") from None


def _log_failure(what: str, exc: Exception) -> None:
    """Log a failure with its type and stack but not its message, which can quote the request."""
    stack = "".join(traceback.format_tb(exc.__traceback__)).rstrip()
    logger.error("%s: %s\n%s", what, type(exc).__name__, stack)
