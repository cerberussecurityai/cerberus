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
Kubernetes startup budget and get the pod killed mid-fetch.
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


class _TransientFetchError(Exception):
    """A key-fetch failure worth retrying (network, timeout, 5xx, 408/429)."""


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
            raise _TransientFetchError(str(exc)) from exc
        logger.warning(
            "HMAC secret fetch from %s rejected (%s) — source IPs will be sent unhashed",
            url,
            exc,
        )
        return None
    except httpx.HTTPError as exc:
        # Transport-level: connection refused, DNS, read timeout, etc.
        raise _TransientFetchError(str(exc)) from exc
    # AttributeError guards a valid-JSON non-dict body (e.g. a load balancer
    # returning `[]` or an HTML error page parsed as a JSON string) — .get()
    # on a non-dict would otherwise escape and crash lifespan startup. ValueError
    # is a non-JSON body. Both are permanent for this endpoint.
    except (ValueError, AttributeError) as exc:
        logger.warning(
            "HMAC secret fetch from %s returned an unusable body (%s) — "
            "source IPs will be sent unhashed",
            url,
            exc,
        )
        return None

    if not secret:
        logger.warning(
            "Backend %s returned an empty secret key — source IPs will be sent unhashed", url
        )
        return None
    return str(secret)


async def _fetch_with_retries(url: str, token: str, config: Config) -> str | None:
    timeout_seconds = config.secret_fetch_timeout_ms / 1000
    for attempt in range(1, config.secret_fetch_attempts + 1):
        try:
            secret = await _fetch_once(url, token, timeout_seconds)
        except _TransientFetchError as exc:
            if attempt == config.secret_fetch_attempts:
                logger.warning(
                    "HMAC secret fetch from %s failed after %d attempts (%s) — "
                    "source IPs will be sent unhashed",
                    url,
                    config.secret_fetch_attempts,
                    exc,
                )
                return None
            backoff = min(
                FETCH_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)), FETCH_BACKOFF_CAP_SECONDS
            )
            logger.info(
                "HMAC secret fetch from %s failed (attempt %d/%d: %s) — retrying in %.1fs",
                url,
                attempt,
                config.secret_fetch_attempts,
                exc,
                backoff,
            )
            await asyncio.sleep(backoff)
            continue
        # Permanent failure (None) or success — either way, stop retrying.
        if secret is None:
            return None
        logger.info("Fetched HMAC secret key from backend")
        return _warn_if_default(secret)
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
    try:
        return await asyncio.wait_for(
            _fetch_with_retries(url, config.token, config), deadline_seconds
        )
    except TimeoutError:
        logger.warning(
            "HMAC secret fetch from %s exceeded the %.1fs startup budget — "
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
