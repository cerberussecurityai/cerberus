import pytest
from helpers import load_export, single_span
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from cerberus_envoy_ai_gateway.otlp import (
    OTLPDecodeError,
    decode_traces_request,
    iter_spans,
    span_attributes,
    success_response_body,
)


def test_decode_protobuf_round_trip():
    original = load_export("llm_openai_chat")
    decoded = decode_traces_request(original.SerializeToString(), "application/x-protobuf")
    assert decoded == original


def test_decode_json_content_type():
    original = load_export("mcp_tool_call")
    from google.protobuf import json_format

    body = json_format.MessageToJson(original).encode("utf-8")
    decoded = decode_traces_request(body, "application/json; charset=utf-8")
    assert decoded == original


def test_decode_defaults_to_protobuf_when_content_type_missing():
    original = load_export("llm_error")
    decoded = decode_traces_request(original.SerializeToString(), None)
    assert decoded == original


def test_decode_garbage_raises():
    with pytest.raises(OTLPDecodeError):
        decode_traces_request(b"\xff\xfenot-protobuf-at-all\x00\x01" * 3, "application/x-protobuf")
    with pytest.raises(OTLPDecodeError):
        decode_traces_request(b"{not json", "application/json")


def test_span_attributes_flatten_types():
    span = single_span(load_export("llm_openai_chat"))
    attrs = span_attributes(span)
    assert attrs["llm.model_name"] == "gpt-4o-mini"  # string
    assert attrs["llm.token_count.prompt"] == 42  # int64
    assert attrs["openinference.span.kind"] == "LLM"


def test_any_value_conversion_covers_all_kinds():
    from opentelemetry.proto.common.v1.common_pb2 import AnyValue, ArrayValue, KeyValue

    from cerberus_envoy_ai_gateway.otlp import any_value_to_python

    assert any_value_to_python(AnyValue(double_value=0.7)) == 0.7
    assert any_value_to_python(AnyValue(bool_value=True)) is True
    assert any_value_to_python(AnyValue(bytes_value=b"\x01")) == b"\x01"
    array = AnyValue(
        array_value=ArrayValue(values=[AnyValue(int_value=1), AnyValue(string_value="two")])
    )
    assert any_value_to_python(array) == [1, "two"]
    kvlist = AnyValue()
    kvlist.kvlist_value.values.append(KeyValue(key="k", value=AnyValue(string_value="v")))
    assert any_value_to_python(kvlist) == {"k": "v"}
    assert any_value_to_python(AnyValue()) is None


def test_any_value_depth_capped():
    # any_value_to_python bounds its own recursion: beyond MAX_ATTR_DEPTH the
    # value is truncated to None rather than recursing (defense in depth on top
    # of protobuf's own ~100-deep parse limit).
    from opentelemetry.proto.common.v1.common_pb2 import AnyValue, ArrayValue

    from cerberus_envoy_ai_gateway.otlp import MAX_ATTR_DEPTH, any_value_to_python

    value = AnyValue(string_value="deep")
    for _ in range(MAX_ATTR_DEPTH + 10):  # past the cap, within protobuf's limit
        value = AnyValue(array_value=ArrayValue(values=[value]))
    node = any_value_to_python(value)  # must not raise RecursionError
    for _ in range(MAX_ATTR_DEPTH):
        assert isinstance(node, list)
        node = node[0]
    assert node is None  # truncated beyond the cap; the leaf is never reached


def test_deeply_nested_json_body_rejected_not_500():
    # A deeply nested JSON body must surface as OTLPDecodeError (-> 400), not an
    # uncaught RecursionError (-> 500 -> exporter retry loop).
    depth = 5000
    body = ("[" * depth + "]" * depth).encode("utf-8")
    with pytest.raises(OTLPDecodeError):
        decode_traces_request(body, "application/json")


def test_iter_spans_yields_scope_names():
    request = load_export("mcp_tool_call")
    [(scope_name, span)] = list(iter_spans(request))
    assert scope_name == "envoyproxy/ai-gateway/mcp"
    assert span.name == "tools/call get_weather"


def test_success_response_matches_request_content_type():
    body, content_type = success_response_body("application/json")
    assert body == b"{}"
    assert content_type == "application/json"
    body, content_type = success_response_body("application/x-protobuf")
    assert content_type == "application/x-protobuf"
    # An empty ExportTraceServiceResponse serializes to zero bytes — what
    # matters is that it parses back cleanly.
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceResponse,
    )

    ExportTraceServiceResponse().ParseFromString(body)


def test_empty_request_has_no_spans():
    assert list(iter_spans(ExportTraceServiceRequest())) == []
