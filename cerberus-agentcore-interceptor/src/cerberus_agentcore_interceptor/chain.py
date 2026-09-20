"""Invoking the customer's own REQUEST interceptor.

A gateway has one REQUEST slot. When it is already taken, their function runs
first on the raw input and its answer is returned unchanged, so our failures can
never skip or alter it.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from .envelope import Envelope
from .output import is_valid_output

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
THROTTLE_BACKOFF_SECONDS = 0.05


@dataclass(frozen=True)
class ChainResult:
    """What the customer's interceptor answered, and what we do about it."""

    outcome: str
    output: dict[str, Any] | None = None
    body: Any = None
    note: dict[str, Any] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.outcome == OUTCOME_ERROR


class ChainClient:
    """One invoke of the chained function per interception."""

    def __init__(self, arn: str, read_ms: int, client: Any = None, sleep: Any = time.sleep):
        self._arn = arn
        self._read_ms = read_ms
        self._client = client
        self._sleep = sleep

    def prepare(self) -> None:
        """Build the client before the first request rather than during it."""
        try:
            self._lambda()
        except Exception as exc:
            logger.warning("chain client not ready: %s", exc)

    def invoke(self, event: Any, context: Any, envelope: Envelope) -> ChainResult:
        """Run the chained interceptor and classify what it answered."""
        response = self._invoke_with_throttle_retries(event, context)
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

    def _invoke_with_throttle_retries(self, event: Any, context: Any) -> dict[str, Any] | None:
        payload = json.dumps(event).encode("utf-8")
        client_context = _client_context(context)
        for attempt in range(THROTTLE_ATTEMPTS):
            try:
                request: dict[str, Any] = {"FunctionName": self._arn, "Payload": payload}
                if client_context:
                    request["ClientContext"] = client_context
                response: dict[str, Any] = self._lambda().invoke(**request)
                return response
            except Exception as exc:
                if not _is_throttle(exc) or attempt == THROTTLE_ATTEMPTS - 1:
                    logger.warning("chained invoke failed: %s", type(exc).__name__)
                    return None
                self._sleep(THROTTLE_BACKOFF_SECONDS * (2**attempt))
        return None

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
        if body != (envelope.request or {}).get("body"):
            return ChainResult(
                OUTCOME_TRANSFORMED, output=output, body=body, note={"outcome": OUTCOME_TRANSFORMED}
            )

    return ChainResult(OUTCOME_PASSED, output=output, note={"outcome": OUTCOME_PASSED})


def _payload(response: dict[str, Any]) -> Any:
    body: Any = response.get("Payload")
    raw = body.read() if hasattr(body, "read") else body
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except ValueError:
        return None


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
