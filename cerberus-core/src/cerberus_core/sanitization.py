"""
Cerberus Core Sanitization

Shared sensitive key definitions, PII hashing, and recursive sanitization
logic used by both cerberus-django and cerberus-mcp to ensure consistent
data hygiene.
"""

import hashlib
import hmac
import ipaddress

# Sentinel value for redacted fields
REDACTED = '[REDACTED]'

# HTTP headers whose values should always be redacted
SENSITIVE_HEADERS = frozenset({
    'HTTP_AUTHORIZATION',
    'HTTP_COOKIE',
    'HTTP_SET_COOKIE',
    'HTTP_X_API_KEY',
    'HTTP_X_AUTH_TOKEN',
    'HTTP_PROXY_AUTHORIZATION',
})

# Keys (case-insensitive) whose values should be redacted in bodies,
# query parameters, and MCP arguments
SENSITIVE_KEYS = frozenset({
    'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
    'api_secret', 'access_token', 'refresh_token', 'authorization',
    'auth', 'credential', 'credentials', 'private_key', 'ssh_key',
    'session_id', 'session_token', 'cookie',
    'credit_card', 'card_number', 'cvv', 'ssn',
})


def _compress_ipv6(packed):
    """Format 16 packed bytes as compressed IPv6 text with hex groups only."""
    segments = [(packed[i] << 8) | packed[i + 1] for i in range(0, 16, 2)]
    best_start = best_len = 0
    run_start = run_len = 0
    for i, segment in enumerate(segments):
        if segment:
            run_len = 0
            continue
        if run_len == 0:
            run_start = i
        run_len += 1
        if run_len > best_len:
            best_start, best_len = run_start, run_len
    groups = [format(segment, 'x') for segment in segments]
    if best_len < 2:
        return ':'.join(groups)
    return '%s::%s' % (
        ':'.join(groups[:best_start]),
        ':'.join(groups[best_start + best_len:]),
    )


def normalize_ip(ip_string):
    """Normalize an IP address string for consistent hashing.

    Strips IPv6 zone IDs (e.g., ``fe80::1%eth0`` → ``fe80::1``) and
    compresses IPv6 addresses to their canonical form so the same
    logical address always produces the same hash.

    IPv6 text is built here rather than with ``str()``: CPython changed
    ``IPv6Address.__str__`` to print IPv4-mapped addresses as dotted quads
    (``::ffff:192.168.1.1``) and backported it into patch releases of 3.9
    through 3.14, so ``str()`` is not a stable canonical form. The hex form
    (``::ffff:c0a8:101``) is, and ``parity-fixtures/normalize_ip.yaml`` pins it.

    Args:
        ip_string: IP address string to normalize

    Returns:
        Normalized IP string, or the original string if parsing fails
    """
    if ip_string is None:
        return None
    try:
        address = ipaddress.ip_address(ip_string.split('%')[0].strip())
    except (ValueError, AttributeError):
        return ip_string
    if address.version == 6:
        return _compress_ipv6(address.packed)
    return str(address)


def hash_pii(value, secret_key):
    """Consistently hash PII using HMAC-SHA256 for pseudoanonymization.

    Produces a stable hex digest — the same input always yields the same hash,
    enabling analytics (e.g., "same user across requests") without storing
    the raw PII value.

    Args:
        value: The PII string to hash (e.g., IP address, auth token)
        secret_key: Secret key for HMAC (from cerberus config)

    Returns:
        Hex-encoded HMAC-SHA256 digest, or None if value is None
    """
    if value is None:
        return None

    if isinstance(value, str):
        value = value.encode('utf-8')
    if isinstance(secret_key, str):
        secret_key = secret_key.encode('utf-8')

    return hmac.new(secret_key, value, hashlib.sha256).hexdigest()


def sanitize_dict(data, extra_keys=None, _depth=0, _max_depth=20):
    """Recursively redact sensitive keys in a dict or list.

    Walks nested dicts and lists, replacing values whose keys match
    SENSITIVE_KEYS (case-insensitive) with REDACTED.  Recursion is
    capped at ``_max_depth`` levels to prevent stack overflow from
    adversarial deeply-nested payloads.

    ``extra_keys`` adds caller-supplied names for this call only.  The
    built-in set is a floor, names are trimmed and lowercased, blank
    entries are ignored, and a match redacts the whole value including any
    subtree — the contract ``parity-fixtures/custom_pii_rules.yaml`` pins
    for customSensitiveKeys.

    Args:
        data: Dict or list to sanitize
        extra_keys: Additional key names to redact, or None
        _depth: Current recursion depth (internal — do not set)
        _max_depth: Maximum recursion depth before redacting entire subtree

    Returns:
        New sanitized structure with sensitive values replaced
    """
    return _sanitize(data, _sensitive_key_set(extra_keys), _depth, _max_depth)


def _sensitive_key_set(extra_keys):
    """Union SENSITIVE_KEYS with the caller's extra names."""
    if not extra_keys:
        return SENSITIVE_KEYS
    extra = {
        key.strip().lower()
        for key in extra_keys
        if isinstance(key, str) and key.strip()
    }
    return SENSITIVE_KEYS | extra if extra else SENSITIVE_KEYS


def _sanitize(data, keys, depth, max_depth):
    if depth > max_depth:
        return REDACTED

    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if isinstance(key, str) and key.lower() in keys:
                sanitized[key] = REDACTED
            elif isinstance(value, (dict, list)):
                sanitized[key] = _sanitize(value, keys, depth + 1, max_depth)
            else:
                sanitized[key] = value
        return sanitized
    if isinstance(data, list):
        return [
            _sanitize(item, keys, depth + 1, max_depth) if isinstance(item, (dict, list)) else item
            for item in data
        ]
    return data
