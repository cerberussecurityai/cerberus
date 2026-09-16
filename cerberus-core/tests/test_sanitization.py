"""Tests for cerberus_core sanitization module."""

import pytest
from cerberus_core.sanitization import (
    REDACTED,
    SENSITIVE_HEADERS,
    SENSITIVE_KEYS,
    hash_pii,
    normalize_ip,
    sanitize_dict,
)


class TestSensitiveKeys:
    """Verify the sensitive keys set is comprehensive and consistent."""

    def test_password_variants_present(self):
        assert 'password' in SENSITIVE_KEYS
        assert 'passwd' in SENSITIVE_KEYS

    def test_token_variants_present(self):
        assert 'token' in SENSITIVE_KEYS
        assert 'access_token' in SENSITIVE_KEYS
        assert 'refresh_token' in SENSITIVE_KEYS
        assert 'session_token' in SENSITIVE_KEYS

    def test_api_key_variants_present(self):
        assert 'api_key' in SENSITIVE_KEYS
        assert 'apikey' in SENSITIVE_KEYS
        assert 'api_secret' in SENSITIVE_KEYS

    def test_pii_keys_present(self):
        assert 'credit_card' in SENSITIVE_KEYS
        assert 'card_number' in SENSITIVE_KEYS
        assert 'cvv' in SENSITIVE_KEYS
        assert 'ssn' in SENSITIVE_KEYS

    def test_session_keys_present(self):
        assert 'session_id' in SENSITIVE_KEYS
        assert 'cookie' in SENSITIVE_KEYS

    def test_auth_keys_present(self):
        assert 'authorization' in SENSITIVE_KEYS
        assert 'credential' in SENSITIVE_KEYS
        assert 'credentials' in SENSITIVE_KEYS
        assert 'private_key' in SENSITIVE_KEYS
        assert 'ssh_key' in SENSITIVE_KEYS


class TestSensitiveHeaders:
    """Verify HTTP headers that should always be redacted."""

    def test_cookie_headers(self):
        assert 'HTTP_COOKIE' in SENSITIVE_HEADERS
        assert 'HTTP_SET_COOKIE' in SENSITIVE_HEADERS

    def test_auth_headers(self):
        assert 'HTTP_AUTHORIZATION' in SENSITIVE_HEADERS
        assert 'HTTP_X_API_KEY' in SENSITIVE_HEADERS
        assert 'HTTP_X_AUTH_TOKEN' in SENSITIVE_HEADERS
        assert 'HTTP_PROXY_AUTHORIZATION' in SENSITIVE_HEADERS


class TestHashPii:
    """Test HMAC-SHA256 PII hashing."""

    def test_returns_hex_digest(self):
        result = hash_pii("192.168.1.1", "my-secret-key")
        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 hex digest length

    def test_none_returns_none(self):
        assert hash_pii(None, "secret") is None

    def test_deterministic(self):
        """Same input + same key = same hash."""
        a = hash_pii("192.168.1.1", "key")
        b = hash_pii("192.168.1.1", "key")
        assert a == b

    def test_different_values_different_hashes(self):
        a = hash_pii("192.168.1.1", "key")
        b = hash_pii("192.168.1.2", "key")
        assert a != b

    def test_different_keys_different_hashes(self):
        a = hash_pii("192.168.1.1", "key1")
        b = hash_pii("192.168.1.1", "key2")
        assert a != b

    def test_bytes_input(self):
        str_result = hash_pii("192.168.1.1", "key")
        bytes_result = hash_pii(b"192.168.1.1", b"key")
        assert str_result == bytes_result


class TestNormalizeIp:
    """Test IP address normalization."""

    def test_ipv4_passthrough(self):
        assert normalize_ip("192.168.1.1") == "192.168.1.1"

    def test_ipv6_compressed(self):
        assert normalize_ip("::1") == "::1"
        assert normalize_ip("0000:0000:0000:0000:0000:0000:0000:0001") == "::1"

    def test_ipv6_zone_id_stripped(self):
        assert normalize_ip("fe80::1%eth0") == "fe80::1"
        assert normalize_ip("fe80::1%25en0") == "fe80::1"

    def test_consistent_hash_with_and_without_zone_id(self):
        """Same logical IP with and without zone ID should hash identically."""
        ip_with_zone = normalize_ip("fe80::1%eth0")
        ip_without_zone = normalize_ip("fe80::1")
        h1 = hash_pii(ip_with_zone, "key")
        h2 = hash_pii(ip_without_zone, "key")
        assert h1 == h2

    def test_none_returns_none(self):
        assert normalize_ip(None) is None

    def test_invalid_ip_passthrough(self):
        assert normalize_ip("not-an-ip") == "not-an-ip"
        assert normalize_ip("") == ""

    def test_ipv4_mapped_ipv6(self):
        """IPv4-mapped IPv6 addresses are normalized to canonical hex form."""
        result = normalize_ip("::ffff:192.168.1.1")
        assert result == "::ffff:c0a8:101"

    def test_ipv4_mapped_ipv6_independent_of_str(self):
        """Hex form holds on interpreters whose str() emits dotted quads."""
        assert normalize_ip("::ffff:1.2.3.4") == "::ffff:102:304"
        assert normalize_ip("::ffff:c0a8:101") == "::ffff:c0a8:101"
        assert normalize_ip("::ffff:0.0.0.0") == "::ffff:0:0"
        assert normalize_ip("::ffff:192.168.1.1%eth0") == "::ffff:c0a8:101"

    def test_ipv6_embedded_ipv4_other_forms(self):
        assert normalize_ip("::1.2.3.4") == "::102:304"
        assert normalize_ip("::255.255.255.255") == "::ffff:ffff"
        assert normalize_ip("::ffff:0:1.2.3.4") == "::ffff:0:102:304"

    def test_ipv6_zero_run_compression(self):
        assert normalize_ip("1:0:0:1:0:0:1:1") == "1::1:0:0:1:1"
        assert normalize_ip("1:2:0:4:5:6:7:8") == "1:2:0:4:5:6:7:8"
        assert normalize_ip("1:2:3:4:5:6:0:0") == "1:2:3:4:5:6::"
        assert normalize_ip("::") == "::"


class TestSanitizeDict:
    """Test the recursive dict sanitization function."""

    def test_simple_dict_redaction(self):
        data = {"username": "alice", "password": "hunter2"}
        result = sanitize_dict(data)
        assert result["username"] == "alice"
        assert result["password"] == REDACTED

    def test_case_insensitive_matching(self):
        data = {"Password": "secret", "API_KEY": "sk-123"}
        result = sanitize_dict(data)
        assert result["Password"] == REDACTED
        assert result["API_KEY"] == REDACTED

    def test_nested_dict_redaction(self):
        data = {
            "user": {
                "name": "alice",
                "credentials": {"token": "abc123", "role": "admin"}
            }
        }
        result = sanitize_dict(data)
        assert result["user"]["name"] == "alice"
        assert result["user"]["credentials"] == REDACTED

    def test_deeply_nested_sensitive_key(self):
        data = {"level1": {"level2": {"password": "secret", "value": 42}}}
        result = sanitize_dict(data)
        assert result["level1"]["level2"]["password"] == REDACTED
        assert result["level1"]["level2"]["value"] == 42

    def test_list_of_dicts(self):
        """BUG 1 fix: lists containing dicts should be sanitized."""
        data = [
            {"username": "alice", "password": "hunter2"},
            {"username": "bob", "password": "pass123"},
        ]
        result = sanitize_dict(data)
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["username"] == "alice"
        assert result[0]["password"] == REDACTED
        assert result[1]["username"] == "bob"
        assert result[1]["password"] == REDACTED

    def test_dict_with_list_values(self):
        data = {
            "users": [
                {"name": "alice", "api_key": "key1"},
                {"name": "bob", "api_key": "key2"},
            ]
        }
        result = sanitize_dict(data)
        assert result["users"][0]["name"] == "alice"
        assert result["users"][0]["api_key"] == REDACTED
        assert result["users"][1]["name"] == "bob"
        assert result["users"][1]["api_key"] == REDACTED

    def test_list_with_non_dict_items(self):
        data = [1, "hello", True, None]
        result = sanitize_dict(data)
        assert result == [1, "hello", True, None]

    def test_mixed_list(self):
        data = [{"password": "secret"}, "plain_string", {"safe_key": "value"}]
        result = sanitize_dict(data)
        assert result[0]["password"] == REDACTED
        assert result[1] == "plain_string"
        assert result[2]["safe_key"] == "value"

    def test_empty_dict(self):
        assert sanitize_dict({}) == {}

    def test_empty_list(self):
        assert sanitize_dict([]) == []

    def test_non_dict_non_list_passthrough(self):
        assert sanitize_dict("string") == "string"
        assert sanitize_dict(42) == 42
        assert sanitize_dict(None) is None

    def test_preserves_non_sensitive_values(self):
        data = {"name": "alice", "age": 30, "active": True, "score": 9.5}
        result = sanitize_dict(data)
        assert result == data

    def test_non_string_keys_ignored(self):
        data = {1: "numeric_key", "password": "secret"}
        result = sanitize_dict(data)
        assert result[1] == "numeric_key"
        assert result["password"] == REDACTED

    def test_nested_list_of_lists(self):
        data = {"matrix": [[{"secret": "x"}], [{"value": "y"}]]}
        result = sanitize_dict(data)
        assert result["matrix"][0][0]["secret"] == REDACTED
        assert result["matrix"][1][0]["value"] == "y"

    def test_deep_nesting_does_not_crash(self):
        """Deeply nested input should not cause RecursionError."""
        # Build a 100-level deep nested dict
        data = {"value": "leaf"}
        for i in range(100):
            data = {"level": data}
        # Should not raise RecursionError
        result = sanitize_dict(data)
        assert result is not None

    def test_deep_nesting_redacts_beyond_max_depth(self):
        """Content beyond max_depth should be redacted."""
        data = {"value": "leaf"}
        for _ in range(25):
            data = {"level": data}
        result = sanitize_dict(data, _max_depth=20)
        # Walk 21 levels deep — depth 0-20 are processed normally,
        # depth 21 triggers the guard and returns REDACTED
        node = result
        for _ in range(21):
            assert isinstance(node, dict)
            node = node["level"]
        assert node == REDACTED

    def test_original_not_mutated(self):
        data = {"password": "hunter2", "nested": {"token": "abc"}}
        result = sanitize_dict(data)
        assert data["password"] == "hunter2"
        assert data["nested"]["token"] == "abc"
        assert result["password"] == REDACTED
        assert result["nested"]["token"] == REDACTED
