"""Shared test helpers: fixture loading and span extraction."""

from pathlib import Path

import yaml
from google.protobuf import json_format
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

FIXTURES = Path(__file__).parent / "fixtures"


def load_export(name: str) -> ExportTraceServiceRequest:
    """Load an OTLP/JSON span fixture as an ExportTraceServiceRequest."""
    request = ExportTraceServiceRequest()
    json_format.Parse((FIXTURES / "spans" / f"{name}.json").read_text(), request)
    return request


def load_expected(name: str) -> dict:
    """Load an expected-event golden fixture."""
    return yaml.safe_load((FIXTURES / "expected" / f"{name}.yaml").read_text())


def single_span(request: ExportTraceServiceRequest):
    """Return the only span in a fixture (asserts exactly one)."""
    spans = [
        span
        for resource_spans in request.resource_spans
        for scope_spans in resource_spans.scope_spans
        for span in scope_spans.spans
    ]
    assert len(spans) == 1, f"fixture has {len(spans)} spans, expected 1"
    return spans[0]
