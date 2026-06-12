"""Startup fetch of the shared HMAC secret key.

Same semantics as the flex-gateway policy's init-time fetch: one GET to
``{backendUrl}/api/secret-key`` authenticated with the API key, 5-second
timeout, and on any failure a one-time warning + fallback to emitting
PII unhashed (normalized raw IPs).
"""

import logging

import httpx

from .config import Config

logger = logging.getLogger(__name__)

FETCH_TIMEOUT_SECONDS = 5.0


async def resolve_secret_key(config: Config) -> str | None:
    """Return the HMAC key from config, the backend, or None (raw-PII mode)."""
    if config.secret_key:
        return config.secret_key
    if not config.backend_url:
        logger.warning(
            "No CERBERUS_SECRET_KEY or CERBERUS_BACKEND_URL configured — "
            "source IPs will be sent unhashed"
        )
        return None

    url = f"{config.backend_url}/api/secret-key"
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT_SECONDS) as client:
            response = await client.get(url, headers={"X-API-Key": config.token})
            response.raise_for_status()
            secret = response.json().get("secret_key")
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning(
            "Failed to fetch HMAC secret from %s (%s) — source IPs will be sent unhashed",
            url,
            exc,
        )
        return None

    if not secret:
        logger.warning(
            "Backend %s returned an empty secret key — source IPs will be sent unhashed", url
        )
        return None
    logger.info("Fetched HMAC secret key from backend")
    return str(secret)
