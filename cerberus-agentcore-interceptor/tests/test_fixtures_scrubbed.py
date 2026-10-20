"""The fixtures are recordings from a real gateway. These are the scrub rules."""

import base64
import binascii
import json
import re

import pytest
from helpers import FIXTURES

EXAMPLE_ACCOUNT = "123456789012"
# A 12-digit run that is not part of a longer number or a placeholder UUID.
ACCOUNT_LIKE = re.compile(r"(?<![0-9.\-])[0-9]{12}(?![0-9\-])")
VPC_ENDPOINT = re.compile(r"vpce-[0-9a-f]{8,}")
JWT_LIKE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.([A-Za-z0-9_.-]+)")
IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
SIGV4_SIGNATURE = re.compile(r"Signature=([^,\s\"\\]+)")
SECURITY_TOKEN = re.compile(r"(?i)x-amz-security-token\"?\s*[:=]\s*\"?([^\",\s\\]*)")
ACCESS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
INTERNAL_HOST = re.compile(r"\.(?:aws\.dev|a2z\.com|amazon\.com)\b")
UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
PLACEHOLDER_UUID = re.compile(r"0{8}-0{4}-0{4}-0{4}-[0-9a-f]{12}|11111111-2222-3333-4444-5{12}")
BEDROCK_MESSAGE_ID = re.compile(r"msg_bdrk_[0-9A-Za-z]+")

# RFC 5737 documentation ranges.
DOCUMENTATION_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")

FIXTURE_FILES = sorted(FIXTURES.glob("*.json"))


def texts(path):
    """The fixture's text, then each base64 body in it, decoded."""
    text = path.read_text()
    yield text
    for body in _string_bodies(json.loads(text)):
        try:
            yield base64.b64decode(body, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue


def _string_bodies(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "body" and isinstance(item, str):
                yield item
            else:
                yield from _string_bodies(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_bodies(item)


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda path: path.name)
def test_fixture_is_scrubbed(path):
    for text in texts(path):
        assert set(ACCOUNT_LIKE.findall(text)) <= {EXAMPLE_ACCOUNT}
        assert not VPC_ENDPOINT.findall(text)
        assert all(signature == "SIGNATURE-REMOVED" for signature in JWT_LIKE.findall(text))
        for address in IPV4.findall(text):
            assert address.startswith(DOCUMENTATION_PREFIXES), address
        assert set(SIGV4_SIGNATURE.findall(text)) <= {"REMOVED"}
        assert set(SECURITY_TOKEN.findall(text)) <= {"REMOVED", "[REDACTED]"}
        assert not ACCESS_KEY_ID.findall(text)
        assert not INTERNAL_HOST.findall(text)
        for uuid in UUID.findall(text):
            assert PLACEHOLDER_UUID.fullmatch(uuid), uuid
        assert set(BEDROCK_MESSAGE_ID.findall(text)) <= {"msg_bdrk_example"}


def test_base64_bodies_are_checked_decoded():
    raw, decoded = texts(FIXTURES / "passthrough-echo-response.input.json")
    assert "x-amz-security-token" not in raw
    assert SECURITY_TOKEN.findall(decoded) == ["REMOVED"]


def test_there_are_fixtures_to_check():
    assert len(FIXTURE_FILES) > 20
