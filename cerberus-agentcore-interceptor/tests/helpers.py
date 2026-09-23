"""Fixture loading and the shared mapping call behind the golden cases."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cerberus_agentcore_interceptor import __version__
from cerberus_agentcore_interceptor import envelope as envelope_mod
from cerberus_agentcore_interceptor.mapper import MapperOptions, source_event

FIXTURES = Path(__file__).parent / "fixtures"

# Fixed so the goldens are byte-stable.
TIMESTAMP = datetime(2026, 9, 20, 6, 24, 30, 123456, tzinfo=UTC)


class ClientContext:
    """Stands in for the Lambda client context."""

    def __init__(self, custom: dict[str, Any]):
        self.custom = custom


class LambdaContext:
    """Stands in for the Lambda context object."""

    def __init__(self, custom: dict[str, Any]):
        self.client_context = ClientContext(custom)


def case_names() -> list[str]:
    return sorted(path.name[: -len(".input.json")] for path in FIXTURES.glob("*.input.json"))


def load_case(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.input.json").read_text())


def load_expected(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.event.json").read_text())


def options(case: dict[str, Any], **overrides: Any) -> MapperOptions:
    base = MapperOptions(
        identity_mode=case.get("options", {}).get("identity_mode", "jwt"),
        version=__version__,
    )
    return replace(base, **overrides) if overrides else base


def map_case(name: str, **overrides: Any) -> dict[str, Any] | None:
    """Map a fixture through the parser and mapper, as the handler would."""
    case = load_case(name)
    return source_event(
        envelope_mod.parse(case["input"]),
        envelope_mod.gateway_context(LambdaContext(case["client_context"])),
        options(case, **overrides),
        TIMESTAMP,
    )
