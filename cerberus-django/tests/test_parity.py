"""Cross-implementation parity tests for cerberus-core sanitization primitives.

The same YAML fixtures consumed by these tests are the source of truth for
the Rust port of the same primitives in ``cerberus-flex-gateway`` (which
duplicates the constants and reimplements the logic for the Flex Gateway
WASM target). These tests exist to ensure the two implementations don't
drift silently.

Fixtures live at ``cerberus/parity-fixtures/``. See the README there for
the file format and how to add cases.
"""

from pathlib import Path

import pytest
import yaml

from cerberus_core import REDACTED, SENSITIVE_HEADERS, SENSITIVE_KEYS, hash_pii, normalize_ip, sanitize_dict
from cerberus_django.middleware import _matches_json_content_type

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
    if not path.exists():
        pytest.fail(f"Fixture file not found: {path}", pytrace=False)
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
    actual = _matches_json_content_type(case["content_type"])
    assert actual == case["expected_capture"], (
        f"{case['name']!r}: got {actual!r}, "
        f"expected {case['expected_capture']!r}"
    )


@pytest.mark.parametrize("case", _load("sensitive_headers.yaml"))
def test_sensitive_headers_parity(case):
    actual = case["header"] in SENSITIVE_HEADERS
    assert actual == case["expected_sensitive"], (
        f"{case['name']!r}: got {actual!r}, "
        f"expected {case['expected_sensitive']!r}"
    )


def test_path_filter_yaml_is_valid():
    """Rust-only fixture; parse it here so a YAML syntax error fails fast."""
    _load("path_filter.yaml")


def _walk_redacted_keys(input_obj, expected_obj):
    """Yield (lowercased) keys whose value in ``expected_obj`` is REDACTED."""
    if isinstance(input_obj, dict) and isinstance(expected_obj, dict):
        for key in input_obj:
            if key not in expected_obj:
                continue
            if expected_obj[key] == REDACTED and not isinstance(input_obj[key], (dict, list)):
                if isinstance(key, str):
                    yield key.lower()
            else:
                yield from _walk_redacted_keys(input_obj[key], expected_obj[key])
    elif isinstance(input_obj, list) and isinstance(expected_obj, list):
        for inp_item, exp_item in zip(input_obj, expected_obj):
            yield from _walk_redacted_keys(inp_item, exp_item)


def test_sensitive_keys_fully_covered_by_fixture():
    """Every SENSITIVE_KEYS entry must have a redaction case in sanitize_dict.yaml.

    Catches the case where a new key is added to SENSITIVE_KEYS without a
    corresponding fixture, which would otherwise silently leave the Rust
    port's parity unverified for that key.
    """
    covered = set()
    for param in _load("sanitize_dict.yaml"):
        case = param.values[0]
        covered.update(_walk_redacted_keys(case["input"], case["expected"]))
    missing = SENSITIVE_KEYS - covered
    assert not missing, (
        f"SENSITIVE_KEYS without a redaction case in sanitize_dict.yaml: "
        f"{sorted(missing)}"
    )


def test_sensitive_headers_fully_covered_by_fixture():
    """Every SENSITIVE_HEADERS entry must have a positive case in sensitive_headers.yaml."""
    covered = set()
    for param in _load("sensitive_headers.yaml"):
        case = param.values[0]
        if case["expected_sensitive"]:
            covered.add(case["header"])
    missing = SENSITIVE_HEADERS - covered
    assert not missing, (
        f"SENSITIVE_HEADERS without a fixture case in sensitive_headers.yaml: "
        f"{sorted(missing)}"
    )
