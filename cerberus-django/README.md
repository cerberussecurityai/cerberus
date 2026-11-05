# Cerberus Django

[![PyPI version](https://badge.fury.io/py/cerberus-django.svg)](https://badge.fury.io/py/cerberus-django)
[![Python Versions](https://img.shields.io/pypi/pyversions/cerberus-django.svg)](https://pypi.org/project/cerberus-django/)
[![Django Versions](https://img.shields.io/badge/django-4.0%20%7C%204.1%20%7C%204.2%20%7C%205.0-blue.svg)](https://www.djangoproject.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Django middleware for capturing and streaming HTTP request metrics to a backend analytics server via WebSocket. Designed for high-performance, non-blocking operation in both WSGI and ASGI environments.

## Features

- **Non-blocking**: Events are queued and sent asynchronously via a background thread
- **WSGI & ASGI Compatible**: Works with both synchronous and asynchronous Django deployments
- **Privacy-First**: Built-in HMAC-SHA256 hashing for PII (IP addresses) before transmission
- **Custom Metrics**: Attach application-specific metrics to any request
- **Automatic Reconnection**: WebSocket client handles connection failures gracefully
- **Zero Configuration Required**: Sensible defaults with optional customization

## Installation

```bash
pip install cerberus-django
```

## Quick Start

### 1. Add to Django Settings

```python
# settings.py

INSTALLED_APPS = [
    # ... your apps
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # ... other middleware
    'cerberus_django.CerberusMiddleware',  # Add Cerberus
]

# Cerberus Configuration
CERBERUS_CONFIG = {
    'ws_url': 'wss://your-analytics-server.com/ws/events',
    'token': 'your-api-key',
    'client_id': 'your-client-id',
}
```

### 2. That's It!

Cerberus will now capture metrics for every HTTP request and send them to your analytics backend.

## Configuration

All configuration is done via the `CERBERUS_CONFIG` dictionary in your Django settings:

| Key | Required | Description |
|-----|----------|-------------|
| `ws_url` | Yes | WebSocket URL for the analytics backend |
| `token` | Yes | API key for authentication |
| `client_id` | Yes | Unique identifier for your application |
| `backend_url` | No | HTTP URL to auto-fetch the HMAC secret key |
| `secret_key` | No | HMAC secret key for PII hashing (auto-fetched if `backend_url` is set) |
| `capture_response_body` | No | Capture non-streaming JSON response bodies, sanitized like request bodies (default `False`) |
| `response_head_bytes` / `response_tail_bytes` | No | Size caps for captured response bodies: a sanitized body whose serialized form is larger than head + tail ships as its first and last bytes with truncation markers (defaults 24576 / 16384) |

### Example Configurations

**Basic (no PII hashing):**
```python
CERBERUS_CONFIG = {
    'ws_url': 'wss://analytics.example.com/ws/events',
    'token': 'sk-your-api-key',
    'client_id': 'my-django-app',
}
```

**With automatic secret key fetching:**
```python
CERBERUS_CONFIG = {
    'ws_url': 'wss://analytics.example.com/ws/events',
    'token': 'sk-your-api-key',
    'client_id': 'my-django-app',
    'backend_url': 'https://analytics.example.com',  # Will fetch secret from /api/secret-key
}
```

**With manual secret key:**
```python
CERBERUS_CONFIG = {
    'ws_url': 'wss://analytics.example.com/ws/events',
    'token': 'sk-your-api-key',
    'client_id': 'my-django-app',
    'secret_key': 'your-hmac-secret-key',  # For consistent PII hashing
}
```

## Custom Metrics

Attach custom metrics to any request by adding them to the response:

```python
from rest_framework.decorators import api_view
from rest_framework.response import Response

@api_view(['GET'])
def my_endpoint(request):
    # Your business logic
    items = process_items()

    response = Response({'items': items})

    # Add custom metrics (will be included in the event)
    response.data['_cerberus_metrics'] = {
        'items_processed': len(items),
        'cache_hit': True,
        'processing_time_ms': 42,
    }

    return response
```

The `_cerberus_metrics` key is automatically extracted from the response and included in the event payload. It will not be sent to the client.

## Event Payload

Each event sent to your analytics backend includes:

```json
{
    "api_key": "your-api-key",
    "client_id": "your-client-id",
    "token": "your-api-key",
    "remote_addr": "hashed-ip-address",
    "endpoint": "/api/users/",
    "scheme": true,
    "method": "POST",
    "headers": {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Cookie": "[REDACTED]",
        "Authorization": "[REDACTED]"
    },
    "query_params": {
        "page": "1",
        "api_key": "[REDACTED]"
    },
    "body": {
        "username": "alice",
        "password": "[REDACTED]"
    },
    "user_agent": "Mozilla/5.0 ...",
    "custom_data": {
        "items_processed": 10,
        "cache_hit": true
    }
}
```

## Privacy & Security

### PII Hashing

When a `secret_key` is configured, source IP addresses are hashed using HMAC-SHA256 before transmission:

- **Consistent**: Same IP always produces the same hash (enabling analytics)
- **Irreversible**: Original IP cannot be recovered from the hash
- **Secure**: Uses cryptographically strong HMAC-SHA256

### What's Captured

| Field | Description | Privacy |
|-------|-------------|---------|
| `remote_addr` | Client IP address | Hashed if `secret_key` configured |
| `endpoint` | Request path | Sent as-is |
| `method` | HTTP method (GET, POST, etc.) | Sent as-is |
| `scheme` | Whether HTTPS was used | Sent as-is |
| `headers` | HTTP request headers | Sensitive headers redacted (see below) |
| `query_params` | URL query parameters | Sensitive keys redacted |
| `body` | JSON request body (POST/PUT/PATCH only) | Sensitive keys redacted |
| `user_agent` | Browser/client user agent | Sent as-is |
| `custom_data` | Your custom metrics | Sent as-is |

### Automatic Sanitization

Sensitive values are automatically redacted before transmission:

- **Headers**: `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`, and `Proxy-Authorization` values are replaced with `[REDACTED]`. The `Authorization` header is hashed if `secret_key` is configured, otherwise redacted.
- **Query parameters**: Keys matching sensitive names (`password`, `token`, `api_key`, `secret`, `access_token`, etc.) have their values replaced with `[REDACTED]`.
- **Request body**: JSON bodies are recursively scanned and sensitive keys are redacted using the same key list.

### What's NOT Captured

- Response bodies, unless `capture_response_body` is enabled
- Non-JSON request bodies (form data, multipart uploads, etc.)
- Server-internal variables (only HTTP headers are extracted)

## Debug Mode

Enable debug logging to troubleshoot issues:

```bash
export CERBERUS_DEBUG=true
```

Or in your Django settings:

```python
import os
os.environ['CERBERUS_DEBUG'] = 'true'
```

This will log:
- Middleware initialization
- WebSocket connection attempts
- Events being queued and sent
- Any errors encountered

## Architecture

```
┌─────────────────────────┐     ┌──────────────────────────────┐
│   Django Request        │     │   Background Thread          │
│   (WSGI or ASGI)        │     │   (Daemon)                   │
├─────────────────────────┤     ├──────────────────────────────┤
│ CerberusMiddleware      │     │  Event Loop                  │
│   └── queue.put(event)  │────▶│    └── WebSocket.send()     │
└─────────────────────────┘     └──────────────────────────────┘
         │                                    │
         │  Thread-safe Queue                 │  Async WebSocket
         └────────────────────────────────────┘
```

- **Middleware**: Runs synchronously in the request/response cycle
- **Queue**: Thread-safe `queue.Queue` for passing events
- **Background Thread**: Daemon thread with its own event loop for async WebSocket communication

This architecture ensures:
- No blocking of HTTP requests
- No event loop conflicts in WSGI mode
- Automatic cleanup when the process exits (daemon thread)

## Requirements

- Python 3.9+
- Django 4.0+
- websockets 12.0+
- requests 2.28+

## Development

```bash
# Clone the repository
git clone https://github.com/gpotrock/cerberus.git
cd cerberus/cerberus-django

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src/
ruff check src/ --fix

# Type checking
mypy src/
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
