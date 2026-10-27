import itertools
import json
from pathlib import Path

import pytest
import yaml
from cerberus_core import SENSITIVE_HEADERS, sanitize_dict

from cerberus_agentcore_interceptor import CaptureDeadlineExceeded, bounding, sanitize

PARITY_FIXTURES = Path(__file__).resolve().parents[2] / "parity-fixtures"


def nested(depth, leaf):
    """leaf inside depth containers, dicts and lists in turn."""
    for level in range(depth):
        leaf = {"k": leaf, "token": "t"} if level % 2 else [leaf, "x"]
    return leaf


def test_every_core_sensitive_header_is_dropped():
    for name in SENSITIVE_HEADERS:
        wire = name[5:].replace("_", "-").lower() if name.startswith("HTTP_") else name.lower()
        assert wire in sanitize.ALWAYS_DROP, name


def test_allowlist_captures_under_its_own_spelling():
    captured = sanitize.capture_headers(
        {"user-agent": "OpenAI/Python", "CONTENT-TYPE": "application/json"},
        sanitize.DEFAULT_CAPTURE_HEADERS,
    )
    assert captured == {"User-Agent": "OpenAI/Python", "Content-Type": "application/json"}


def test_headers_outside_the_allowlist_are_dropped():
    captured = sanitize.capture_headers(
        {"X-Forwarded-For": "192.0.2.1", "Accept": "*/*"}, sanitize.DEFAULT_CAPTURE_HEADERS
    )
    assert captured == {}


def test_credential_headers_are_dropped_even_when_allowlisted():
    captured = sanitize.capture_headers(
        {"Authorization": "Bearer x", "x-api-key": "k", "X-Amz-Security-Token": "t"},
        ("Authorization", "X-Api-Key", "X-Amz-Security-Token"),
    )
    assert captured == {}


def test_gateway_infrastructure_headers_are_dropped():
    captured = sanitize.capture_headers(
        {"x-amzn-vpce-id": "vpce-1", "x-amzn-tls-version": "TLSv1.3"},
        ("x-amzn-vpce-id", "x-amzn-tls-version"),
    )
    assert captured == {}


def test_session_header_is_never_captured():
    captured = sanitize.capture_headers({"Mcp-Session-Id": "abc"}, ("Mcp-Session-Id", "User-Agent"))
    assert captured == {}


def test_header_values_are_capped():
    captured = sanitize.capture_headers({"User-Agent": "u" * 5000}, ("User-Agent",))
    assert len(captured["User-Agent"]) == sanitize.MAX_HEADER_VALUE_CHARS


def test_non_string_header_values_become_text():
    captured = sanitize.capture_headers(
        {"Content-Type": 7, "User-Agent": ["a"]}, ("Content-Type", "User-Agent")
    )
    assert captured == {"Content-Type": "7", "User-Agent": ""}


def test_session_id_prefers_mcp_then_runtime():
    assert sanitize.session_id({"Mcp-Session-Id": "mcp-1"}) == "mcp-1"
    assert sanitize.session_id({"x-amzn-bedrock-agentcore-runtime-session-id": "rt-1"}) == "rt-1"
    assert sanitize.session_id({}) == ""


def test_body_redaction_keeps_model_parameters():
    body = {
        "model": "openai.gpt-oss-20b",
        "max_tokens": 24,
        "api_key": "sk-live",
        "messages": [{"role": "user", "content": "hi", "password": "hunter2"}],
    }
    sanitized = sanitize.sanitize_body(body)
    assert sanitized["max_tokens"] == 24
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["messages"][0]["password"] == "[REDACTED]"
    assert sanitized["messages"][0]["content"] == "hi"


def test_extra_sensitive_keys():
    sanitized = sanitize.sanitize_body({"member_number": "M-1"}, ("member_number",))
    assert sanitized["member_number"] == "[REDACTED]"


@pytest.mark.parametrize(
    "body",
    [
        {"user": "alice", "Password": "p", "in": {"TOKEN": {"a": 1}, "ok": [1, 2.5, None, True]}},
        [{"api_key": "k"}, ["secret", {"session_id": "s"}], "plain", 7],
        {"a\x00": "b\x00", "\ud800": "\udc00x", "pair": "\ud83d\ude00", "é": "ü"},
        {"n": [float("nan"), float("inf"), -float("inf"), 1e308], "Authorization": "Bearer x"},
        {"member_number": "M-1", "x-custom": {"a": 1}, "HTTP_AUTHORIZATION": "x"},
        nested(sanitize.MAX_SANITIZE_DEPTH, "leaf"),
        nested(sanitize.MAX_SANITIZE_DEPTH + 1, "leaf"),
        nested(sanitize.MAX_SANITIZE_DEPTH + 3, {"password": "p"}),
    ],
)
def test_sanitize_storable_is_sanitize_body_then_storable(body):
    keys = ("member_number", " X-Custom ", *sanitize.ECHOED_HEADER_KEYS)
    expected = bounding.storable(sanitize_dict(body, extra_keys=keys))
    assert json.dumps(sanitize.sanitize_storable(body, keys)) == json.dumps(expected)


def parity_key_cases():
    """The parity-fixtures cases that redact by key alone."""
    cases = yaml.safe_load((PARITY_FIXTURES / "sanitize_dict.yaml").read_text())["cases"]
    custom = yaml.safe_load((PARITY_FIXTURES / "custom_pii_rules.yaml").read_text())["cases"]
    cases += [case for case in custom if not case.get("patterns")]
    return [pytest.param(case, id=case["name"]) for case in cases]


@pytest.mark.parametrize("case", parity_key_cases())
def test_sanitize_storable_matches_sanitize_dict_on_the_parity_cases(case):
    keys = tuple(case.get("custom_sensitive_keys", ()))
    expected = bounding.storable(sanitize_dict(case["input"], extra_keys=keys))
    assert sanitize.sanitize_storable(case["input"], keys) == expected


def test_sanitize_storable_checks_the_deadline_as_it_walks(monkeypatch):
    reads = itertools.count()
    monkeypatch.setattr(bounding, "monotonic", lambda: next(reads))
    with pytest.raises(CaptureDeadlineExceeded):
        sanitize.sanitize_storable([[]] * 10 * bounding.VALUES_PER_CHECK, (), bounding.Ticker(3))
    assert next(reads) == 4
