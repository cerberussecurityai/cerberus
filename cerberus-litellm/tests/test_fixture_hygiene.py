"""Committed fixtures are real captures, and this repository is public.

Fail on anything that looks like an internal host, a real credential or a
customer identifier, so a re-capture cannot reintroduce one unnoticed.
"""

import re
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
FILES = sorted([*FIXTURES.rglob("*.json"), *FIXTURES.rglob("*.yaml")])

# The masked display name LiteLLM shows for a key ("sk-" + "..." + last four).
MASKED_KEY_DISPLAY = "sk-...abcd"
ALLOWED_HOSTS = {"opentelemetry.io", "docs.litellm.ai"}
FORBIDDEN = (
    "cerberussecurity",
    "googleapis",
    "cerberus-int",
    "@",
    "sk_",
    "sk-",
    "AIza",
    "ghp_",
    "AKIA",
    "xox",
    "Bearer ",
    "gke",
    "gcp",
    ".internal",
)
HOSTNAME = re.compile(
    r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|ai|io|net|org|dev|internal|local|test)\b"
)


def test_fixtures_are_discovered():
    assert len(FILES) >= 15  # the guard below must not pass by checking nothing


def test_the_hostname_pattern_catches_what_it_should():
    found = {m.group(0) for m in HOSTNAME.finditer("see api.dev.example.com and docs.litellm.ai")}
    assert found == {"api.dev.example.com", "docs.litellm.ai"}
    assert not HOSTNAME.search("mock-llm:9081 and litellm.proxy.types")


@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(FIXTURES)))
def test_fixture_has_no_credentials_or_internal_names(path):
    text = path.read_text(encoding="utf-8").replace(MASKED_KEY_DISPLAY, "")
    for pattern in FORBIDDEN:
        assert pattern not in text, f"{path.name} contains {pattern!r}"
    hosts = {match.group(0) for match in HOSTNAME.finditer(text.lower())}
    assert hosts <= ALLOWED_HOSTS, f"{path.name} mentions {sorted(hosts - ALLOWED_HOSTS)}"
