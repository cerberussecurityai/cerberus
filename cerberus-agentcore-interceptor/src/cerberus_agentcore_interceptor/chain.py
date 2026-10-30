"""Invoking the customer's own interceptor, at REQUEST or at RESPONSE.

When the gateway's slot is already taken, their function runs first and its
answer is returned as it came, so our failures can never skip or alter it.
Headers reach it only when its pass-headers setting is true, and a lone
surrogate in its answer becomes U+FFFD.
"""

from __future__ import annotations

import base64
import json
import logging
import random
import time
from dataclasses import dataclass, field
from time import monotonic
from typing import Any

from .envelope import MCP, RESPONSE, Envelope
from .output import encodable, finite, is_valid_output

logger = logging.getLogger(__name__)

OUTCOME_ERROR = "error"
OUTCOME_INVALID_OUTPUT = "invalid_output"
OUTCOME_SHORT_CIRCUIT = "short_circuit"
OUTCOME_TRANSFORMED = "transformed"
OUTCOME_PASSED = "passed"

# Lambda's cap on the base64 ClientContext.
MAX_CLIENT_CONTEXT_BYTES = 3583

THROTTLE_ERRORS = ("TooManyRequestsException", "ThrottlingException")
THROTTLE_ATTEMPTS = 3
# Retry n waits a random 50 to 100% of this times 2**n: about 1 to 2 s in all,
# close to how long the gateway itself retries a throttled interceptor.
THROTTLE_BACKOFF_SECONDS = 0.7

# Lambda's network path drops an idle connection without a close the pool can
# see, and an invoke sent on it fails with no retry.
IDLE_CONNECTION_SECONDS = 60


@dataclass(frozen=True)
class ChainResult:
    """What the customer's interceptor answered, and what we do about it."""

    outcome: str
    output: dict[str, Any] | None = None
    body: Any = None
    # At RESPONSE, the response the caller receives once their function answered.
    response: dict[str, Any] | None = None
    note: dict[str, Any] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.outcome == OUTCOME_ERROR

    @property
    def transformed(self) -> bool:
        return self.outcome == OUTCOME_TRANSFORMED

    @property
    def ends_call(self) -> bool:
        """True when the gateway goes no further with the call: a refusal or an invalid output."""
        return self.outcome in (OUTCOME_ERROR, OUTCOME_INVALID_OUTPUT)


class ChainClient:
    """One invoke of the chained function per interception."""

    def __init__(
        self,
        arn: str,
        read_ms: int,
        pass_headers: bool = False,
        client: Any = None,
        sleep: Any = time.sleep,
    ):
        self._arn = arn
        self._read_ms = read_ms
        self._pass_headers = pass_headers
        self._client = client
        self._sleep = sleep
        self._used_at: float | None = None

    def prepare(self) -> None:
        """Build the client before the first request rather than during it."""
        try:
            self._lambda()
        except Exception as exc:
            logger.warning("chain client not ready: %s", type(exc).__name__)

    def invoke(
        self, event: Any, context: Any, envelope: Envelope, deadline: float | None = None
    ) -> ChainResult:
        """Run the chained interceptor and classify what it answered.

        A throttle is retried only while the wait ends before deadline, a
        time.monotonic() value.
        """
        response = self._invoke_with_throttle_retries(event, context, deadline)
        if response is None:
            return ChainResult(OUTCOME_ERROR, note={"outcome": OUTCOME_ERROR})

        if response.get("FunctionError"):
            # Invoke answers 200 even when the function raised or timed out.
            logger.warning("chained interceptor failed: %s", response.get("FunctionError"))
            return ChainResult(OUTCOME_ERROR, note={"outcome": OUTCOME_ERROR})

        output = _payload(response)
        if not is_valid_output(output):
            # The gateway fails closed on it; returning it unchanged keeps that
            # decision with the function that made it.
            return ChainResult(
                OUTCOME_INVALID_OUTPUT, output=output, note={"outcome": OUTCOME_INVALID_OUTPUT}
            )

        return _classify(output, envelope)

    def _invoke_with_throttle_retries(
        self, event: Any, context: Any, deadline: float | None
    ) -> dict[str, Any] | None:
        forwarded = event if self._pass_headers else _without_headers(event)
        payload = _serialized(forwarded)
        client_context = _client_context(context)
        self._drop_idle_connections()
        for attempt in range(THROTTLE_ATTEMPTS):
            try:
                request: dict[str, Any] = {"FunctionName": self._arn, "Payload": payload}
                if client_context:
                    request["ClientContext"] = client_context
                return self._send(request)
            except Exception as exc:
                if not _is_throttle(exc) or attempt == THROTTLE_ATTEMPTS - 1:
                    logger.warning("chained invoke failed: %s", type(exc).__name__)
                    return None
                delay = THROTTLE_BACKOFF_SECONDS * 2**attempt * random.uniform(0.5, 1.0)
                if deadline is not None and monotonic() + delay >= deadline:
                    logger.warning("chained invoke throttled with no time left to retry")
                    return None
                self._sleep(delay)
        return None

    def _send(self, request: dict[str, Any]) -> dict[str, Any]:
        client = self._lambda()
        try:
            response: dict[str, Any] = client.invoke(**request)
            return response
        finally:
            self._used_at = monotonic()

    def _drop_idle_connections(self) -> None:
        """Close pooled connections idle long enough to have been dropped."""
        if self._used_at is None or monotonic() - self._used_at < IDLE_CONNECTION_SECONDS:
            return
        try:
            # The client stays usable and opens a new connection on its next call.
            self._client.close()
        except Exception as exc:
            logger.warning("chain client connections not closed: %s", type(exc).__name__)

    def _lambda(self) -> Any:
        if self._client is None:
            import boto3
            from botocore.config import Config as BotoConfig

            self._client = boto3.client(
                "lambda",
                config=BotoConfig(
                    connect_timeout=self._read_ms / 1000,
                    read_timeout=self._read_ms / 1000,
                    # One attempt: a retry would run the customer's interceptor
                    # twice for one request.
                    retries={"total_max_attempts": 1},
                ),
            )
        return self._client


def _classify(output: dict[str, Any], envelope: Envelope) -> ChainResult:
    shape = output.get(envelope.shape_key) if envelope.shape_key else None
    shape = shape if isinstance(shape, dict) else {}
    if envelope.phase == RESPONSE:
        return _classify_response(output, shape, envelope)

    response = shape.get("transformedGatewayResponse")
    if isinstance(response, dict):
        note = {"outcome": OUTCOME_SHORT_CIRCUIT}
        status = response.get("statusCode")
        if status is not None:
            note["status_code"] = status
        return ChainResult(OUTCOME_SHORT_CIRCUIT, output=output, note=note)

    request = shape.get("transformedGatewayRequest")
    if isinstance(request, dict) and "body" in request:
        body = request["body"]
        if _differs(body, (envelope.request or {}).get("body")):
            return ChainResult(
                OUTCOME_TRANSFORMED, output=output, body=body, note={"outcome": OUTCOME_TRANSFORMED}
            )

    return ChainResult(OUTCOME_PASSED, output=output, note={"outcome": OUTCOME_PASSED})


def _classify_response(
    output: dict[str, Any], shape: dict[str, Any], envelope: Envelope
) -> ChainResult:
    """At RESPONSE an answer passes or transforms the response; nothing is short-circuited.

    The outcome is read from the body alone, and the response kept is the one
    the caller receives.
    """
    original = envelope.response or {}
    answer = shape.get("transformedGatewayResponse")
    answer = answer if isinstance(answer, dict) else {}
    # An absent or null field keeps the target's, except an mcp body: without
    # one the caller gets {}.
    changed = {key: value for key, value in answer.items() if value is not None}
    if envelope.kind == MCP and "body" not in changed and original.get("body") is not None:
        changed["body"] = {}
    transformed = "body" in changed and _differs(changed["body"], original.get("body"))
    outcome = OUTCOME_TRANSFORMED if transformed else OUTCOME_PASSED
    return ChainResult(
        outcome, output=output, response={**original, **changed}, note={"outcome": outcome}
    )


def _differs(body: Any, original: Any) -> bool:
    # The function was handed non-finite numbers as strings, and a lone surrogate
    # in its answer became U+FFFD, so an echo of either is no change.
    return bool(body != original and body != encodable(original))


def _payload(response: dict[str, Any]) -> Any:
    body: Any = response.get("Payload")
    raw = body.read() if hasattr(body, "read") else body
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if not isinstance(raw, str):
        return raw
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    # JSON text can escape a lone surrogate that our runtime then cannot encode.
    return encodable(value, raw)


def _serialized(event: Any) -> bytes:
    """event as compact UTF-8 JSON, about the size of the invoke the gateway made."""
    try:
        return _json(event, ensure_ascii=False)
    except UnicodeEncodeError:
        # A lone surrogate has no UTF-8 form; escaped, it arrives as it reached us.
        return _json(event, ensure_ascii=True)


def _json(event: Any, ensure_ascii: bool) -> bytes:
    try:
        text = json.dumps(event, ensure_ascii=ensure_ascii, separators=(",", ":"), allow_nan=False)
    except ValueError:
        # A bare Infinity is not JSON, and the chained function may parse strictly.
        text = json.dumps(finite(event), ensure_ascii=ensure_ascii, separators=(",", ":"))
    return text.encode("utf-8")


def _without_headers(value: Any, levels: int = 3) -> Any:
    """A copy of an event with no request headers in it, its shapes, or any part of a shape.

    The chain also runs on input versions we do not know, which may carry headers
    beside the shapes or beside gatewayRequest. A body sits a level deeper and keeps
    its own keys. gatewayResponse keeps its headers, which the gateway hands a
    RESPONSE interceptor whatever passRequestHeaders says.
    """
    if not isinstance(value, dict) or levels == 0:
        return value
    return {
        key: part if key == "gatewayResponse" else _without_headers(part, levels - 1)
        for key, part in value.items()
        if key != "headers"
    }


def _client_context(context: Any) -> str:
    """The gateway's own client context, forwarded unchanged."""
    custom = getattr(getattr(context, "client_context", None), "custom", None)
    if not isinstance(custom, dict):
        return ""
    encoded = base64.b64encode(json.dumps({"custom": custom}).encode("utf-8")).decode("ascii")
    if len(encoded) > MAX_CLIENT_CONTEXT_BYTES:
        logger.warning("client context too large to forward (%d bytes)", len(encoded))
        return ""
    return encoded


def _is_throttle(exc: Exception) -> bool:
    if type(exc).__name__ in THROTTLE_ERRORS:
        return True
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    error = response.get("Error")
    return isinstance(error, dict) and str(error.get("Code", "")) in THROTTLE_ERRORS
