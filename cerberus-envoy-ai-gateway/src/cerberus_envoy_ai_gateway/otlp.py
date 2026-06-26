"""OTLP/HTTP trace request decoding.

The Envoy AI Gateway extproc exports OTLP traces; with
``OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`` they arrive here as
``ExportTraceServiceRequest`` protobuf bodies on ``POST /v1/traces``.
OTLP/JSON bodies are also accepted for tests and ad-hoc senders.

Note on OTLP/JSON ids: the OTLP spec encodes trace/span ids as hex in JSON,
while protobuf's canonical JSON mapping uses base64 for bytes fields. We
parse with the protobuf mapping (base64). The gateway exports protobuf, so
this only matters for hand-written JSON payloads — our fixtures use base64.
"""

from collections.abc import Iterator
from typing import Any

from google.protobuf import json_format
from google.protobuf.message import DecodeError
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)
from opentelemetry.proto.common.v1.common_pb2 import AnyValue
from opentelemetry.proto.trace.v1.trace_pb2 import Span

PROTOBUF_CONTENT_TYPE = "application/x-protobuf"
JSON_CONTENT_TYPE = "application/json"


class OTLPDecodeError(ValueError):
    """Raised when an OTLP request body cannot be decoded."""


def decode_traces_request(body: bytes, content_type: str | None) -> ExportTraceServiceRequest:
    """Decode an OTLP/HTTP traces request body (protobuf or JSON)."""
    request = ExportTraceServiceRequest()
    base_type = (content_type or PROTOBUF_CONTENT_TYPE).split(";")[0].strip().lower()
    if base_type == JSON_CONTENT_TYPE:
        try:
            json_format.Parse(body.decode("utf-8"), request)
        except (json_format.ParseError, UnicodeDecodeError) as exc:
            raise OTLPDecodeError(f"invalid OTLP/JSON body: {exc}") from exc
    else:
        try:
            request.ParseFromString(body)
        except DecodeError as exc:
            raise OTLPDecodeError(f"invalid OTLP protobuf body: {exc}") from exc
    return request


def success_response_body(content_type: str | None) -> tuple[bytes, str]:
    """Build the (body, content_type) for a full-success OTLP export response."""
    base_type = (content_type or PROTOBUF_CONTENT_TYPE).split(";")[0].strip().lower()
    if base_type == JSON_CONTENT_TYPE:
        return b"{}", JSON_CONTENT_TYPE
    return ExportTraceServiceResponse().SerializeToString(), PROTOBUF_CONTENT_TYPE


def any_value_to_python(value: AnyValue) -> Any:
    """Convert an OTLP AnyValue to the equivalent Python value."""
    kind = value.WhichOneof("value")
    if kind == "string_value":
        return value.string_value
    if kind == "int_value":
        return value.int_value
    if kind == "double_value":
        return value.double_value
    if kind == "bool_value":
        return value.bool_value
    if kind == "bytes_value":
        return value.bytes_value
    if kind == "array_value":
        return [any_value_to_python(item) for item in value.array_value.values]
    if kind == "kvlist_value":
        return {kv.key: any_value_to_python(kv.value) for kv in value.kvlist_value.values}
    return None


def span_attributes(span: Span) -> dict[str, Any]:
    """Flatten a span's attributes into a plain dict."""
    return {kv.key: any_value_to_python(kv.value) for kv in span.attributes}


def span_event_attributes(span: Span) -> dict[str, Any]:
    """Flatten attributes across all of a span's events into one dict.

    Envoy AI Gateway records MCP route info (mcp.backend.name, mcp.session.id) as
    span-event attributes via span.AddEvent, not top-level span.attributes, so a
    real MCP span's backend/session live here. Later events win on key collision.
    """
    merged: dict[str, Any] = {}
    for event in span.events:
        for kv in event.attributes:
            merged[kv.key] = any_value_to_python(kv.value)
    return merged


def iter_spans(request: ExportTraceServiceRequest) -> Iterator[tuple[str, Span]]:
    """Yield (instrumentation_scope_name, span) for every span in the request."""
    for resource_spans in request.resource_spans:
        for scope_spans in resource_spans.scope_spans:
            scope_name = scope_spans.scope.name
            for span in scope_spans.spans:
                yield scope_name, span


def span_to_debug_dict(scope_name: str, span: Span) -> dict[str, Any]:
    """Render a span as a JSON-friendly dict for CERBERUS_DUMP_SPANS output."""
    return {
        "scope": scope_name,
        "name": span.name,
        "trace_id": span.trace_id.hex(),
        "span_id": span.span_id.hex(),
        "parent_span_id": span.parent_span_id.hex(),
        "start_time_unix_nano": span.start_time_unix_nano,
        "end_time_unix_nano": span.end_time_unix_nano,
        "status": {"code": span.status.code, "message": span.status.message},
        "attributes": {
            key: (value.decode("utf-8", "replace") if isinstance(value, bytes) else value)
            for key, value in span_attributes(span).items()
        },
    }
