"""Cross-implementation parity tests for cerberus-core sanitization primitives.

The same YAML fixtures consumed by these tests are the source of truth for
the Rust port of the same primitives in ``cerberus-flex-gateway`` (which
duplicates the constants and reimplements the logic for the Flex Gateway
WASM target).

If a case fails here AND in the Rust runner: a constant has drifted between
implementations and one of them needs to update.

If a case fails only here: the Python implementation has regressed and
the Rust port now diverges.

Fixtures live at ``cerberus/parity-fixtures/``. See the README there for
the file format and how to add cases.
"""

from pathlib import Path

import pytest
import yaml

from cerberus_core import hash_pii, normalize_ip, sanitize_dict

# parity-fixtures is a sibling of cerberus-django/, so we resolve relative
# to this file: cerberus/cerberus-django/tests/test_parity.py
# → cerberus/parity-fixtures/
FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "parity-fixtures"


def _load(filename):
    """Load fixture cases from a YAML file in parity-fixtures/.

    Returns a list of ``pytest.param`` so each case shows up in test
    output keyed by its ``name`` field.
    """
    path = FIXTURES_DIR / filename
    with path.open() as f:
        doc = yaml.safe_load(f)
    return [pytest.param(c, id=c["name"]) for c in doc["cases"]]


@pytest.mark.parametrize("case", _load("sanitize_dict.yaml"))
def test_sanitize_dict_parity(case):
    actual = sanitize_dict(case["input"])
    assert actual == case["expected"], (
        f"{case['name']!r}: got {actual!r}, expected {case['expected']!r}"
    )


@pytest.mark.parametrize("case", _load("normalize_ip.yaml"))
def test_normalize_ip_parity(case):
    actual = normalize_ip(case["input"])
    assert actual == case["expected"], (
        f"{case['name']!r}: got {actual!r}, expected {case['expected']!r}"
    )


@pytest.mark.parametrize("case", _load("hash_pii.yaml"))
def test_hash_pii_parity(case):
    actual = hash_pii(case["input"]["value"], case["input"]["secret_key"])
    assert actual == case["expected"], (
        f"{case['name']!r}: got {actual!r}, expected {case['expected']!r}"
    )


@pytest.mark.parametrize("case", _load("content_type.yaml"))
def test_content_type_parity(case):
    """Replicate Django's ``_extract_body`` substring check.

    Django uses ``'application/json' not in content_type`` to decide
    whether to parse the body. The Rust port must match this exactly,
    including the negative case for ``application/vnd.api+json``.
    """
    matches = "application/json" in case["content_type"]
    assert matches == case["expected_capture"], (
        f"{case['name']!r}: matches={matches}, "
        f"expected_capture={case['expected_capture']}"
    )
