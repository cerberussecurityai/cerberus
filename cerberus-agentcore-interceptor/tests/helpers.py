"""Fixture loading and the shared mapping call behind the golden cases."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cerberus_agentcore_interceptor import __version__
from cerberus_agentcore_interceptor import envelope as envelope_mod
from cerberus_agentcore_interceptor.bounding import DEFAULT_MAX_EVENT_BYTES
from cerberus_agentcore_interceptor.mapper import MapperOptions, response_event, source_event

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


def runtime_encode(value: Any) -> bytes:
    """What the python3.13 Lambda runtime does with a handler's answer."""
    return json.dumps(value, ensure_ascii=False, allow_nan=True).encode("utf-8")


def options(case: dict[str, Any], **overrides: Any) -> MapperOptions:
    given = case.get("options", {})
    base = MapperOptions(
        identity_mode=given.get("identity_mode", "jwt"),
        max_event_bytes=given.get("max_event_bytes", DEFAULT_MAX_EVENT_BYTES),
        version=__version__,
    )
    return replace(base, **overrides) if overrides else base


def map_case(name: str, **overrides: Any) -> dict[str, Any] | None:
    """Map a fixture through the parser and the mapper for its phase, as the handler would."""
    case = load_case(name)
    envelope = envelope_mod.parse(case["input"])
    build = response_event if envelope.phase == envelope_mod.RESPONSE else source_event
    return build(
        envelope,
        envelope_mod.gateway_context(LambdaContext(case["client_context"])),
        options(case, **overrides),
        TIMESTAMP,
    )
