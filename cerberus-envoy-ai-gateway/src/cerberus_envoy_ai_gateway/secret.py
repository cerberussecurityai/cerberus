"""Startup fetch of the shared HMAC secret key.

Same semantics as the flex-gateway policy's init-time fetch: a GET to
``{backendUrl}/api/secret-key`` authenticated with the API key. On success the
key is used to hash PII; if it can't be obtained the bridge falls back to
emitting PII unhashed (normalized raw IPs).

The fetch is retried with exponential backoff on **transient** failures
(connection errors, timeouts, 5xx, 408/429), so a backend that's briefly
unavailable at pod start doesn't leave the bridge in raw-PII mode for its whole
lifetime. **Permanent** failures (auth 4xx, empty/malformed body) are not
retried. The whole thing is bounded by a total wall-clock deadline
(``CERBERUS_SECRET_FETCH_DEADLINE_MS``) so the FastAPI lifespan can't outrun the
Kubernetes startup budget and get the pod killed mid-fetch. That deadline wins
over the attempt count when the two don't fit — see :func:`_fetch_with_retries`.
"""

import asyncio
import logging

import httpx

from .config import Config

logger = logging.getLogger(__name__)

FETCH_BACKOFF_BASE_SECONDS = 0.5
FETCH_BACKOFF_CAP_SECONDS = 4.0
# Transient client statuses (as opposed to auth/config 4xx): request timeout and
# rate limiting are explicitly temporary, so retry them.
_RETRYABLE_CLIENT_STATUSES = frozenset({408, 429})

# The built-in placeholder the backend returns when no HMAC key is configured.
# Warn if we receive it so operators know to configure a real key — but don't
# refuse service; running without a configured key is a valid (unhashed) mode.
_KNOWN_DEFAULT_KEY = "default-hmac-secret-change-in-production"

# _fetch_with_retries enforces the configured deadline itself, clamping its last
# attempt to exactly the budget left — which would tie with an outer bound set to
# the same instant. The backstop is deliberately a little looser so the loop wins
# that race and reports the specific bound it hit; the backstop then only fires
# for a stall the per-attempt timeout couldn't interrupt at all.
_DEADLINE_BACKSTOP_GRACE_SECONDS = 0.5


class _TransientFetchError(Exception):
    """A key-fetch failure worth retrying (network, timeout, 5xx, 408/429)."""


def _safe_reason(exc: Exception) -> str:
    """A log-safe description of a fetch failure.

    Never the exception's own string: the request carries the ``X-API-Key``
    header, so an httpx exception's rendering could in principle echo request
    detail, and static analysis rightly treats it as possibly-sensitive. The
    status code and the exception class name carry none of that.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    return type(exc).__name__


async def _fetch_once(url: str, token: str, timeout_seconds: float) -> str | None:
    """One fetch attempt.

    Returns the key on success, ``None`` on a **permanent** failure (already
    logged), or raises :class:`_TransientFetchError` for a retryable one.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.get(url, headers={"X-API-Key": token})
            response.raise_for_status()
            secret = response.json().get("secret_key")
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status >= 500 or status in _RETRYABLE_CLIENT_STATUSES:
            # Log the reason here (via the sanitizer) so the retry loop never
            # has to reference an exception object — the object's provenance
            # traces back to the request's X-API-Key header.
            logger.info("HMAC secret fetch from %s failed transiently (%s)", url, _safe_reason(exc))
            raise _TransientFetchError() from None
        logger.warning(
            "HMAC secret fetch from %s rejected (%s) — source IPs will be sent unhashed",
            url,
            _safe_reason(exc),
        )
        return None
    except httpx.HTTPError as exc:
        # Transport-level: connection refused, DNS, read timeout, etc.
        logger.info("HMAC secret fetch from %s failed transiently (%s)", url, _safe_reason(exc))
        raise _TransientFetchError() from None
    # AttributeError guards a valid-JSON non-dict body (e.g. a load balancer
    # returning `[]` or an HTML error page parsed as a JSON string) — .get()
    # on a non-dict would otherwise escape and crash lifespan startup. ValueError
    # is a non-JSON body. Both are permanent for this endpoint.
    except (ValueError, AttributeError) as exc:
        logger.warning(
            "HMAC secret fetch from %s returned an unusable body (%s) — "
            "source IPs will be sent unhashed",
            url,
            _safe_reason(exc),
        )
        return None

    if not secret:
        logger.warning(
            "Backend %s returned an empty secret key — source IPs will be sent unhashed", url
        )
        return None
    return str(secret)


async def _fetch_with_retries(url: str, token: str, config: Config) -> str | None:
    """Retry until the fetch resolves, the attempt cap is hit, or the budget runs out.

    Those last two are independent bounds and either can bind first, depending
    on how the backend fails. Fast failures (connection refused) spend attempts
    while barely touching the clock; slow ones (connection accepted, never
    answered) spend the clock instead — with the defaults, 4 × 5s of attempts
    can't fit in a 10s budget, so a hanging backend stops around attempt 2
    rather than reaching the cap. That's the intended priority (the budget
    protects the pod's startup probe, and hashing is a fallback rather than a
    gate), but it does mean ``CERBERUS_SECRET_FETCH_ATTEMPTS`` is a ceiling and
    not a promise.

    Tracking the budget here, rather than leaving it entirely to the outer
    ``wait_for``, is what lets that be visible: each attempt is clamped to the
    time actually left, a backoff we can't afford is skipped instead of being
    cancelled mid-sleep, and the give-up log names the bound that stopped us.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + config.secret_fetch_deadline_ms / 1000
    timeout_seconds = config.secret_fetch_timeout_ms / 1000
    attempts_run = 0

    for attempt in range(1, config.secret_fetch_attempts + 1):
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        attempts_run = attempt
        try:
            secret = await _fetch_once(url, token, min(timeout_seconds, remaining))
        except _TransientFetchError:
            # The reason was already logged in _fetch_once; this branch only
            # orchestrates retries, and deliberately logs no exception object.
            if attempt == config.secret_fetch_attempts:
                break
            backoff = min(
                FETCH_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)), FETCH_BACKOFF_CAP_SECONDS
            )
            if loop.time() + backoff >= deadline:
                break  # nothing would be left for the attempt on the other side
            logger.info(
                "HMAC secret fetch from %s failed (attempt %d) — retrying in %.1fs",
                url,
                attempt,
                backoff,
            )
            await asyncio.sleep(backoff)
            continue
        # Permanent failure (None) or success — either way, stop retrying.
        if secret is None:
            return None
        logger.info("Fetched HMAC secret key from backend")
        return _warn_if_default(secret)

    # Log the loop counter, not config.secret_fetch_attempts: the latter's name
    # matches CodeQL's clear-text-logging heuristic (it contains "secret") and
    # would flag an integer as a secret.
    bound = "attempt limit" if attempts_run == config.secret_fetch_attempts else "startup budget"
    logger.warning(
        "HMAC secret fetch from %s gave up after %d attempt(s) — %s reached; "
        "source IPs will be sent unhashed",
        url,
        attempts_run,
        bound,
    )
    return None


async def resolve_secret_key(config: Config) -> str | None:
    """Return the HMAC key from config, the backend, or None (raw-PII mode)."""
    if config.secret_key:
        return _warn_if_default(config.secret_key)
    if not config.backend_url:
        logger.warning(
            "No CERBERUS_SECRET_KEY or CERBERUS_BACKEND_URL configured — "
            "source IPs will be sent unhashed"
        )
        return None

    url = f"{config.backend_url}/api/secret-key"
    deadline_seconds = config.secret_fetch_deadline_ms / 1000
    # _fetch_with_retries tracks this budget itself and normally returns before
    # the wait_for fires; wait_for stays as the hard backstop for a stall the
    # per-attempt timeout can't interrupt, which is why this path logs its own
    # (less specific) message.
    try:
        return await asyncio.wait_for(
            _fetch_with_retries(url, config.token, config),
            deadline_seconds + _DEADLINE_BACKSTOP_GRACE_SECONDS,
        )
    except TimeoutError:
        logger.warning(
            "HMAC secret fetch from %s stalled past its %.1fs startup budget — "
            "source IPs will be sent unhashed",
            url,
            deadline_seconds,
        )
        return None


def _warn_if_default(secret: str) -> str:
    if secret == _KNOWN_DEFAULT_KEY:
        logger.warning(
            "HMAC secret is the built-in placeholder %r — configure a real "
            "HMAC key on the backend for PII hashing to be effective.",
            _KNOWN_DEFAULT_KEY,
        )
    return secret
