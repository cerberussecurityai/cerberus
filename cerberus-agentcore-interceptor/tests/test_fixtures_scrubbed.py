"""The fixtures are recordings from a real gateway. These are the scrub rules."""

import re

import pytest
from helpers import FIXTURES

EXAMPLE_ACCOUNT = "123456789012"
# A 12-digit run that is not part of a longer number or a placeholder UUID.
ACCOUNT_LIKE = re.compile(r"(?<![0-9.\-])[0-9]{12}(?![0-9\-])")
VPC_ENDPOINT = re.compile(r"vpce-[0-9a-f]{8,}")
JWT_LIKE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.([A-Za-z0-9_.-]+)")
IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")

# RFC 5737 documentation ranges.
DOCUMENTATION_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")

FIXTURE_FILES = sorted(FIXTURES.glob("*.json"))


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda path: path.name)
def test_fixture_is_scrubbed(path):
    text = path.read_text()

    assert set(ACCOUNT_LIKE.findall(text)) <= {EXAMPLE_ACCOUNT}
    assert not VPC_ENDPOINT.findall(text)
    assert all(signature == "SIGNATURE-REMOVED" for signature in JWT_LIKE.findall(text))
    for address in IPV4.findall(text):
        assert address.startswith(DOCUMENTATION_PREFIXES), address


def test_there_are_fixtures_to_check():
    assert len(FIXTURE_FILES) > 20
