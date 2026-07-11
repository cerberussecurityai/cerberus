"""
Cerberus Django Middleware

Captures HTTP request metrics and sends them asynchronously to a backend
analytics server via WebSocket.

This middleware is designed to work in both WSGI (synchronous) and ASGI
(asynchronous) Django deployments without requiring an event loop at import time.

Architecture:
- Middleware (sync): Captures request data and puts it in a thread-safe queue
- Background thread: Runs its own event loop to process queue and send via WebSocket
"""

import asyncio
import atexit
import json
import logging
import os
import queue as thread_queue
import threading
from datetime import datetime, timezone

import websockets
from django.conf import settings

from cerberus_core import REDACTED, SENSITIVE_HEADERS, SENSITIVE_KEYS, hash_pii, normalize_ip, sanitize_dict
from .structs import CoreData
from .utils import fetch_secret_key

# Configure logging
logger = logging.getLogger(__name__)

# Enable debug logging via environment variable
DEBUG_ENABLED = os.getenv('CERBERUS_DEBUG', 'false').lower() in ('true', '1', 'yes')

# Thread-safe queue for events (bounded to prevent unbounded memory growth)
event_queue = thread_queue.Queue(maxsize=10_000)

# Response-body capture sizing (head+tail cap): when a sanitized response body
# exceeds head+tail, ship the first head_bytes plus the last tail_bytes of its
# serialized form with explicit truncation markers instead of the whole body.
# Tail is generous relative to head because LLM providers put usage/finish
# data at the end of responses. Overridable via CERBERUS_CONFIG
# response_head_bytes / response_tail_bytes; defaults match the caps planned
# for the flex-gateway policy.
RESPONSE_HEAD_BYTES_DEFAULT = 24 * 1024
RESPONSE_TAIL_BYTES_DEFAULT = 16 * 1024

# Background thread management
_background_thread = None
_thread_lock = threading.Lock()


class AsyncWebSocketClient:
    """WebSocket client for sending events to the backend.

    This client is used within the background thread's event loop,
    so it can safely use asyncio primitives.
    """

    def __init__(self, ws_url, api_key, client_id):
        self.ws_url = ws_url
        self.api_key = api_key
        self.client_id = client_id
        self.websocket = None
        self._async_lock = None  # Created on first use within the event loop thread

    async def connect(self):
        """Establish WebSocket connection to the backend."""
        try:
            if DEBUG_ENABLED:
                logger.info(f"[Cerberus] Connecting to WebSocket: {self.ws_url}")
            self.websocket = await websockets.connect(self.ws_url)
            if DEBUG_ENABLED:
                logger.info("[Cerberus] WebSocket connected successfully")
        except Exception as e:
            self.websocket = None
            logger.error(f"[Cerberus] Failed to connect to WebSocket: {e}")

    async def send(self, event_data):
        """Send event data to backend via WebSocket.

        Args:
            event_data: CoreData object to send
        """
        # Create lock on first use — safe because the event loop is
        # single-threaded so no concurrent coroutine can interleave here
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        async with self._async_lock:
            # Connect if not already connected
            if self.websocket is None:
                await self.connect()

            if self.websocket:
                try:
                    # Format data as expected by backend
                    # api_key: client credential used by event_ingest for authentication
                    # token: duplicated from event_data for backward compat; backend uses api_key
                    payload = {
                        'api_key': self.api_key,
                        'client_id': self.client_id,
                        'token': event_data.token,
                        'remote_addr': event_data.source_ip,  # Backend expects 'remote_addr'
                        'endpoint': event_data.endpoint,
                        'scheme': event_data.scheme,
                        'method': event_data.method,
                        'timestamp': event_data.timestamp,
                        'custom_data': event_data.custom_data,
                        # Additional request details
                        'headers': event_data.headers,
                        'query_params': event_data.query_params,
                        'body': event_data.body,
                        # Unknown to older ingest deployments, which pass it
                        # through verbatim into event_data (the batch/WS
                        # contract tolerates extra fields)
                        'response_body': event_data.response_body,
                        'user_agent': event_data.user_agent,
                        'user_id': event_data.user_id,
                    }

                    json_data = json.dumps(payload)

                    if DEBUG_ENABLED:
                        logger.info(
                            f"[Cerberus] Sending event: "
                            f"{event_data.method} {event_data.endpoint} ({len(json_data)} bytes)"
                        )

                    await self.websocket.send(json_data)

                    # Wait for acknowledgment
                    response = await asyncio.wait_for(self.websocket.recv(), timeout=5.0)

                    if DEBUG_ENABLED:
                        logger.info(f"[Cerberus] Backend acknowledged ({len(response)} bytes)")

                except asyncio.TimeoutError:
                    logger.warning("[Cerberus] Timeout waiting for backend response")
                except websockets.exceptions.ConnectionClosed:
                    logger.warning("[Cerberus] WebSocket connection closed, will reconnect on next send")
                    self.websocket = None
                except Exception as e:
                    logger.error(f"[Cerberus] Error sending data: {e}")
                    if self.websocket:
                        try:
                            await self.websocket.close()
                        except Exception:
                            pass
                    self.websocket = None


# WebSocket client - initialized in middleware __init__, used by background thread
WS_CLIENT = None


def _queue_get_with_timeout():
    """Get an item from the queue with a 1-second timeout.

    This is a helper function for run_in_executor since we need to pass
    the timeout parameter.

    Returns:
        CoreData object or raises queue.Empty
    """
    return event_queue.get(block=True, timeout=1.0)


async def _process_queue_async():
    """Async coroutine that processes events from the thread-safe queue.

    Runs continuously in the background thread's event loop.
    """
    global WS_CLIENT

    if DEBUG_ENABLED:
        logger.info("[Cerberus] Background queue processor started")

    loop = asyncio.get_running_loop()

    while True:
        try:
            # Use run_in_executor to get from sync queue without blocking event loop
            data = await loop.run_in_executor(None, _queue_get_with_timeout)
        except thread_queue.Empty:
            # No events available, continue waiting
            continue
        except Exception as e:
            # During interpreter shutdown, daemon threads get errors like
            # "can't register atexit after shutdown" — exit silently
            if "atexit" in str(e) or "shutdown" in str(e):
                break
            logger.error(f"[Cerberus] Error getting from queue: {e}")
            continue

        # Check for shutdown signal (None means stop)
        if data is None:
            if DEBUG_ENABLED:
                logger.info("[Cerberus] Received shutdown signal, stopping processor")
            break

        try:
            # Read client reference under lock for thread safety
            with _thread_lock:
                client = WS_CLIENT
            if client:
                if DEBUG_ENABLED:
                    logger.info(f"[Cerberus] Processing event for endpoint: {data.endpoint}")
                await client.send(data)
            else:
                logger.warning("[Cerberus] WebSocket client not initialized, skipping event")
        except Exception as e:
            logger.error(f"[Cerberus] Failed to send event: {e}")
        finally:
            event_queue.task_done()


def _run_event_loop_in_thread():
    """Run the async event processing loop in a dedicated thread.

    Creates its own event loop, independent of any Django event loop.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if DEBUG_ENABLED:
        logger.info("[Cerberus] Background thread started with new event loop")

    try:
        loop.run_until_complete(_process_queue_async())
    except Exception as e:
        logger.error(f"[Cerberus] Background event loop error: {e}")
    finally:
        loop.close()
        if DEBUG_ENABLED:
            logger.info("[Cerberus] Background thread event loop closed")


def ensure_background_thread():
    """Start the background processing thread if not already running.

    Thread-safe: Uses a lock to prevent race conditions during startup.
    The thread is a daemon thread, so it will automatically stop when
    the main process exits.
    """
    global _background_thread

    with _thread_lock:
        if _background_thread is not None and _background_thread.is_alive():
            return

        _background_thread = threading.Thread(
            target=_run_event_loop_in_thread,
            name="cerberus-event-sender",
            daemon=True  # Auto-shutdown when main process exits
        )
        _background_thread.start()

        if DEBUG_ENABLED:
            logger.info("[Cerberus] Started background event sender thread")


def _shutdown():
    """Drain the event queue on process exit.

    Sends a shutdown sentinel (None) and waits briefly for the background
    thread to finish processing remaining events.
    """
    if _background_thread is not None and _background_thread.is_alive():
        try:
            event_queue.put_nowait(None)
        except thread_queue.Full:
            return
        _background_thread.join(timeout=2.0)


atexit.register(_shutdown)



def _extract_headers(request, secret_key=None):
    """Extract HTTP headers from Django request.

    Converts Django's META dict (with HTTP_ prefixed headers) to a clean dict.
    Redacts sensitive headers (Cookie, X-Api-Key, etc.).
    Hashes the Authorization header if secret_key is available; redacts otherwise.

    Args:
        request: Django HttpRequest object
        secret_key: Optional HMAC secret key for hashing sensitive headers

    Returns:
        Dict of header name -> value
    """
    headers = {}
    for key, value in request.META.items():
        if key.startswith('HTTP_'):
            header_name = key[5:].replace('_', '-').title()
            # Authorization gets HMAC-hashed for consistent user tracking;
            # all other sensitive headers are fully redacted
            if key == 'HTTP_AUTHORIZATION':
                headers[header_name] = hash_pii(value, secret_key) if secret_key else REDACTED
                continue
            if key in SENSITIVE_HEADERS:
                headers[header_name] = REDACTED
                continue
            headers[header_name] = value
        elif key in ('CONTENT_TYPE', 'CONTENT_LENGTH'):
            header_name = key.replace('_', '-').title()
            headers[header_name] = value
    return headers if headers else None


def _extract_query_params(request):
    """Extract query parameters from Django request.

    Redacts values for sensitive parameter names.

    Args:
        request: Django HttpRequest object

    Returns:
        Dict of query param name -> value (or list of values if multiple)
    """
    if not request.GET:
        return None

    params = {}
    for key in request.GET:
        if key.lower() in SENSITIVE_KEYS:
            params[key] = REDACTED
        else:
            values = request.GET.getlist(key)
            params[key] = values[0] if len(values) == 1 else values
    return params


def _matches_json_content_type(content_type):
    """Return True if content_type contains the substring ``application/json``.

    Case-insensitive: ``Application/JSON`` matches.
    ``application/vnd.api+json`` does NOT match — it has no ``application/json``
    substring; the ``json`` token follows ``+``, not ``/``.
    """
    return 'application/json' in content_type.lower()


def _extract_body(request):
    """Extract request body from Django request.

    Only attempts to parse JSON bodies. Redacts sensitive keys.
    Returns None for non-JSON content.

    Args:
        request: Django HttpRequest object

    Returns:
        Sanitized parsed JSON body as dict, or None
    """
    if request.method not in ('POST', 'PUT', 'PATCH'):
        return None

    content_type = request.content_type or ''
    if not _matches_json_content_type(content_type):
        return None

    try:
        if request.body:
            body = json.loads(request.body.decode('utf-8'))
            if isinstance(body, (dict, list)):
                return sanitize_dict(body)
            # Discard bare JSON primitives (strings, numbers) —
            # they can't be meaningfully sanitized and may contain secrets
            return None
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    except Exception as e:
        # RawPostDataException is expected for streaming/chunked ASGI requests;
        # anything else is unexpected and logged at WARNING for visibility
        exc_name = type(e).__name__
        if exc_name == 'RawPostDataException':
            logger.debug(f"[Cerberus] Could not read request body: {exc_name}")
        else:
            logger.warning(f"[Cerberus] Unexpected error reading request body: {exc_name}: {e}")

    return None


def _extract_response_body(response, head_bytes=RESPONSE_HEAD_BYTES_DEFAULT,
                           tail_bytes=RESPONSE_TAIL_BYTES_DEFAULT):
    """Extract the response body from a Django response, mirroring _extract_body.

    Only non-streaming, identity-encoded, JSON responses are captured. The
    parsed body is sanitized like the request side. If the sanitized body's
    serialized form exceeds head_bytes + tail_bytes, it ships as a head+tail
    slice with explicit truncation markers (body_truncated, body_bytes_total,
    body_bytes_dropped) so truncation is never silent; bodies that fit ship
    whole, with no marker. Compressed responses are never sliced (a byte slice
    of a gzip/br stream is undecodable at any layer) — they ship a
    body_skipped_encoding marker instead. Note middleware ordering: anything
    that compresses responses (e.g. GZipMiddleware) must sit ABOVE this
    middleware in MIDDLEWARE, or captured bodies will all be skipped as
    compressed.

    Args:
        response: Django HttpResponse object
        head_bytes: bytes of the serialized body to keep from the start
        tail_bytes: bytes of the serialized body to keep from the end

    Returns:
        Sanitized parsed JSON body as dict/list, a marker dict, or None
    """
    # StreamingHttpResponse (and its FileResponse subclass) have no
    # materialized .content — reading the iterator here would consume the
    # stream before the client sees it.
    if getattr(response, 'streaming', False):
        return None

    if not _matches_json_content_type(response.get('Content-Type') or ''):
        return None

    encoding = (response.get('Content-Encoding') or '').lower()
    if encoding and encoding != 'identity':
        return {'body_skipped_encoding': encoding}

    try:
        content = response.content
    except Exception as e:
        # e.g. ContentNotRenderedError on an unrendered TemplateResponse —
        # capture must never break the response path
        logger.debug(f"[Cerberus] Could not read response body: {type(e).__name__}")
        return None

    if not content:
        return None

    try:
        body = json.loads(content.decode('utf-8'))
        if not isinstance(body, (dict, list)):
            # Mirror the request side: bare JSON primitives are discarded
            return None
        sanitized = sanitize_dict(body)
        # Head+tail cap. Unlike a streaming gateway (which can only slice raw
        # wire bytes), the whole body is already in memory here, so sanitize
        # first and slice the sanitized serialized form — the
        # sanitize-before-transmit invariant holds even for truncated bodies.
        # The byte counts refer to that serialized form, which is the text the
        # backend parser resynchronizes over.
        serialized = json.dumps(sanitized).encode('utf-8')
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    except Exception as e:
        # json.loads is recursion-bound: attacker-controllable nesting raises
        # RecursionError (sanitize_dict depth-caps at 20 rather than raising,
        # so json.dumps only ever sees capped structures). Mirror
        # _extract_body's broad guard: capture failures degrade to "no body",
        # never to a broken response.
        logger.warning(f"[Cerberus] Unexpected error reading response body: {type(e).__name__}: {e}")
        return None
    total = len(serialized)
    if total <= head_bytes + tail_bytes:
        return sanitized

    head = serialized[:head_bytes] if head_bytes > 0 else b''
    tail = serialized[-tail_bytes:] if tail_bytes > 0 else b''
    return {
        'body_truncated': True,
        'body_bytes_total': total,
        'body_bytes_dropped': total - len(head) - len(tail),
        # errors='replace' because a byte slice may split a multi-byte
        # UTF-8 sequence at either cut point
        'head': head.decode('utf-8', errors='replace'),
        'tail': tail.decode('utf-8', errors='replace'),
    }


def _config_byte_knob(config, key, default):
    """Read a non-negative int sizing knob from CERBERUS_CONFIG, falling back
    to the default on a malformed value (middleware __init__ must never raise
    at Django startup over a bad tuning knob)."""
    try:
        return max(0, int(config.get(key, default)))
    except (TypeError, ValueError):
        logger.warning(f"[Cerberus] Invalid {key} in CERBERUS_CONFIG; using default {default}")
        return default


class CerberusMiddleware:
    """Django middleware for capturing and sending HTTP request metrics.

    Compatible with both WSGI and ASGI Django deployments.

    Configuration via CERBERUS_CONFIG in Django settings:
        - token: API key for authentication
        - client_id: Client identifier
        - ws_url: WebSocket URL for event_ingest backend
        - backend_url: HTTP URL for fetching secret key (optional)
        - secret_key: HMAC key for PII hashing (optional, auto-fetched if backend_url set)
        - capture_response_body: capture JSON response bodies (optional, default False)
        - response_head_bytes / response_tail_bytes: head+tail truncation caps
          for captured response bodies (optional; see _extract_response_body)
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.config = dict(getattr(settings, 'CERBERUS_CONFIG', {}))
        self._warned_no_secret_key = False

        # Response-body capture is OPT-IN.
        # TODO: from the first deploy with this enabled, customer response
        # content (e.g. LLM completions) is stored at rest in the backend's
        # processed_events.event_data, which today has no retention/TTL, no
        # per-org/per-key capture opt-out, and raw exposure through the
        # dashboard events API. The retention/opt-out story is a larger
        # product decision; until it exists this knob stays default-off.
        self.capture_response_body = bool(self.config.get('capture_response_body', False))
        self.response_head_bytes = _config_byte_knob(
            self.config, 'response_head_bytes', RESPONSE_HEAD_BYTES_DEFAULT)
        self.response_tail_bytes = _config_byte_knob(
            self.config, 'response_tail_bytes', RESPONSE_TAIL_BYTES_DEFAULT)

        if DEBUG_ENABLED:
            logger.info("[Cerberus] Middleware initializing...")
            logger.info(f"[Cerberus] Config keys: {list(self.config.keys())}")

        # Auto-fetch secret_key from backend if not configured locally
        if 'secret_key' not in self.config and 'backend_url' in self.config:
            if DEBUG_ENABLED:
                logger.info(f"[Cerberus] Fetching secret key from backend: {self.config['backend_url']}")
            secret_key = fetch_secret_key(
                self.config['backend_url'],
                self.config.get('token', '')
            )
            if secret_key:
                self.config['secret_key'] = secret_key
                logger.info(f"[Cerberus] Successfully fetched secret key from {self.config['backend_url']}")
            else:
                logger.warning("[Cerberus] Failed to fetch secret key. PII will not be hashed.")

        # Warn if WebSocket URL is not using TLS
        ws_url = self.config.get('ws_url', '')
        if ws_url.startswith('ws://'):
            logger.warning(
                "[Cerberus] WebSocket URL uses unencrypted ws:// scheme. "
                "Use wss:// in production to protect API keys and event data in transit."
            )

        # Initialize WebSocket client (protected by lock for thread safety)
        if 'ws_url' in self.config and 'token' in self.config and 'client_id' in self.config:
            with _thread_lock:
                global WS_CLIENT
                WS_CLIENT = AsyncWebSocketClient(
                    self.config['ws_url'],
                    self.config['token'],
                    self.config['client_id']
                )
            if DEBUG_ENABLED:
                logger.info(f"[Cerberus] WebSocket client initialized: {self.config['ws_url']}")
        else:
            logger.warning("[Cerberus] WebSocket client not initialized. Missing ws_url, token, or client_id in CERBERUS_CONFIG")

        # Start background thread for processing events
        ensure_background_thread()

    def __call__(self, request):
        """Process a request and queue metrics for async transmission.

        This method is synchronous and does not require an event loop.
        Events are placed in a thread-safe queue and processed by the
        background thread.
        """
        # Initialize custom_data attribute on the request object
        request.cerberus_metrics = {}

        # Extract request data BEFORE processing (body can only be read once)
        headers = _extract_headers(request, self.config.get('secret_key'))
        query_params = _extract_query_params(request)
        body = _extract_body(request)
        user_agent = request.META.get('HTTP_USER_AGENT')

        # Process the request
        response = self.get_response(request)

        # Extract user_id set by application (e.g., JWT auth decorators)
        user_id = getattr(request, 'cerberus_user_id', None)

        # Extract metrics from response if they exist (sanitize to prevent leaks)
        metrics = {}
        if hasattr(response, 'data') and isinstance(response.data, dict):
            if '_cerberus_metrics' in response.data:
                raw_metrics = response.data.pop('_cerberus_metrics')
                metrics = sanitize_dict(raw_metrics) if isinstance(raw_metrics, dict) else {}

        # Capture the response body (opt-in; see __init__ for the
        # data-retention caveat)
        response_body = None
        if self.capture_response_body:
            try:
                response_body = _extract_response_body(
                    response, self.response_head_bytes, self.response_tail_bytes
                )
            except Exception as e:
                # Backstop: capture must never break the response path
                logger.warning(f"[Cerberus] Response body capture failed: {type(e).__name__}: {e}")

        # Get source IP address, normalize, and hash for PII protection
        source_ip = normalize_ip(request.META.get('REMOTE_ADDR'))
        secret_key = self.config.get('secret_key')
        if secret_key and source_ip:
            source_ip = hash_pii(source_ip, secret_key)
        elif source_ip and not self._warned_no_secret_key:
            self._warned_no_secret_key = True
            logger.warning(
                "[Cerberus] Sending source IP in plaintext — no secret_key configured. "
                "Set secret_key in CERBERUS_CONFIG or configure backend_url to enable PII hashing."
            )

        # Create the event data with current timestamp
        d = CoreData(
            token=self.config.get('token', ''),
            source_ip=source_ip,
            endpoint=request.path,
            scheme=request.scheme == 'https',
            method=request.method,
            timestamp=datetime.now(timezone.utc).isoformat(),
            custom_data=metrics,
            headers=headers,
            query_params=query_params,
            body=body,
            response_body=response_body,
            user_agent=user_agent,
            user_id=user_id,
        )

        # Queue the event (non-blocking)
        try:
            event_queue.put_nowait(d)
            if DEBUG_ENABLED:
                logger.info(f"[Cerberus] Queued event: {request.method} {request.path}")
        except thread_queue.Full:
            logger.warning("[Cerberus] Event queue full, dropping event")

        return response
