"""Shared test helpers: fixture loading."""

import json
from pathlib import Path
from typing import Any

import yaml

FIXTURES = Path(__file__).parent / "fixtures"


def load_capture(name: str) -> dict[str, Any]:
    """Load a trimmed LiteLLM hook payload captured by the CER-346 spike."""
    return json.loads((FIXTURES / "litellm" / f"{name}.json").read_text())


def load_expected(name: str) -> dict[str, Any]:
    """Load an expected-event golden fixture."""
    return yaml.safe_load((FIXTURES / "expected" / f"{name}.yaml").read_text())


# Path segments event ingest treats as health checks: events whose endpoint's
# last segment is one of these are skipped server-side. Used by the sink test's
# ingest stub; playground/stub_ingest.py keeps an identical standalone copy.
HEALTH_SEGMENTS = frozenset(
    {
        "health",
        "healthz",
        "healthcheck",
        "health_check",
        "health-check",
        "ready",
        "readyz",
        "readiness",
        "live",
        "livez",
        "liveness",
    }
)
