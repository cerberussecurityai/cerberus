import json
import re
from dataclasses import replace

import pytest
from cerberus_core import REDACTED
from helpers import load_export

from cerberus_envoy_ai_gateway.classify import KIND_MCP
from cerberus_envoy_ai_gateway.config import ConfigError
from cerberus_envoy_ai_gateway.pipeline import Pipeline, truncate_values
from cerberus_envoy_ai_gateway.queue import BoundedQueue

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _run(name: str, config, secret_key=None, capacity=100):
    queue = BoundedQueue(capacity)
    pipeline = Pipeline(config, queue, secret_key)
    queued = pipeline.process_export(load_export(name))
    return pipeline, queue, queued


def _with_attr(fixture: str, key: str, value: str):
    export = load_export(fixture)
    span = export.resource_spans[0].scope_spans[0].spans[0]
    attr = span.attributes.add()
    attr.key = key
    attr.value.string_value = value
    return export


def test_remote_addr_hashed_with_secret(config):
    _, queue, queued = _run("llm_openai_chat", config, secret_key="test-secret")
    assert queued == 1
    [event] = queue.drain(10)
    assert HEX64.match(event["remote_addr"])


def test_remote_addr_normalized_without_secret(config):
    _, queue, _ = _run("llm_anthropic_messages", config)
    [event] = queue.drain(10)
    # IPv6 zone id stripped by normalize_ip; no hashing without a secret.
    assert event["remote_addr"] == "2001:db8::1"


def test_missing_remote_addr_becomes_unknown(config):
    _, queue, _ = _run("llm_error", config)
    [event] = queue.drain(10)
    assert event["remote_addr"] == "unknown"


def test_same_ip_same_hash(config):
    _, queue_a, _ = _run("llm_openai_chat", config, secret_key="k")
    _, queue_b, _ = _run("llm_openai_chat", config, secret_key="k")
    assert queue_a.drain(1)[0]["remote_addr"] == queue_b.drain(1)[0]["remote_addr"]


def test_mcp_arguments_sanitized(config):
    _, queue, _ = _run("mcp_tool_call", config)
    [event] = queue.drain(10)
    arguments = event["custom_data"]["arguments"]
    assert arguments["location"] == "SF"
    assert arguments["api_key"] == REDACTED
    assert event["body"] == arguments


def test_mcp_arguments_flag_off(config):
    config = replace(config, capture_mcp_arguments=False)
    _, queue, _ = _run("mcp_tool_call", config)
    [event] = queue.drain(10)
    assert event["custom_data"]["arguments"] == {}
    assert event["body"] is None


def test_mcp_route_event_attributes_resolve_backend_and_session(config):
    """Real ai-gateway MCP spans carry mcp.backend.name / mcp.session.id as span-
    EVENT attributes (RecordRouteToBackend's span.AddEvent), not top-level. The
    pipeline merges span-event attributes before mapping, so the span resolves the
    real backend/session instead of the 'envoy-ai-gateway' fallback."""
    _, queue, queued = _run("mcp_tool_call_route_events", config)
    assert queued == 1
    [event] = queue.drain(10)
    assert event["endpoint"] == "mcp://weather-mcp/get_weather"
    assert event["custom_data"]["mcp_server"] == "weather-mcp"
    assert event["custom_data"]["session_id"] == "sess-1"


def test_llm_content_sanitized_when_captured(config):
    config = replace(config, capture_llm_content=True)
    _, queue, _ = _run("llm_openai_chat", config)
    [event] = queue.drain(10)
    assert event["body"]["input"]["api_key"] == REDACTED
    assert event["body"]["input"]["messages"][0]["content"] == "hello"


def test_llm_content_flag_off_no_body(config):
    config = replace(config, capture_llm_content=False)
    _, queue, _ = _run("llm_openai_chat", config)
    [event] = queue.drain(10)
    assert event["body"] is None


def test_mcp_protocol_spans_filtered_not_ignored(config):
    # mcp initialize/ping/notifications classify as MCP but don't map to an
    # event — expected protocol overhead, counted as spans_filtered, not
    # spans_ignored (reserved for truly unclassified spans).
    pipeline, queue, queued = _run("mcp_initialize", config)
    assert queued == 0
    assert len(queue) == 0
    assert pipeline.spans_filtered == 1
    assert pipeline.spans_ignored == 0


def test_unclassified_span_counted_as_ignored(config):
    # A span with no MCP/LLM markers is truly unclassified — spans_ignored.
    request = load_export("mcp_initialize")
    span = request.resource_spans[0].scope_spans[0].spans[0]
    span.ClearField("attributes")
    span.ClearField("events")
    pipeline = Pipeline(config, BoundedQueue(10), None)
    pipeline.process_export(request)
    assert pipeline.spans_ignored == 1
    assert pipeline.spans_filtered == 0


def test_queue_full_drops_and_counts(config):
    queue = BoundedQueue(0)  # immediately full
    pipeline = Pipeline(config, queue, None)
    pipeline.process_export(load_export("llm_openai_chat"))
    assert queue.dropped_full == 1


def test_oversize_event_sheds_content_first(config):
    config = replace(config, capture_mcp_arguments=True, max_event_bytes=1024)
    queue = BoundedQueue(10)
    pipeline = Pipeline(config, queue, None)
    request = load_export("mcp_tool_call")
    span = request.resource_spans[0].scope_spans[0].spans[0]
    for kv in span.attributes:
        if kv.key == "mcp.tool.arguments":
            kv.value.string_value = json.dumps({"blob": "x" * 4000})
    pipeline.process_export(request)
    [event] = queue.drain(10)
    assert event["custom_data"]["arguments"] == {}
    assert event["body"] is None
    assert event["custom_data"]["content_dropped_oversize"] is True
    assert pipeline.dropped_oversize == 0


def test_event_serialized_size_within_cap(config):
    config = replace(config, capture_llm_content=True)
    _, queue, _ = _run("llm_openai_chat", config)
    [event] = queue.drain(10)
    assert len(json.dumps(event).encode()) <= config.max_event_bytes


def test_truncate_values():
    data = {"long": "a" * 10000, "nested": [{"also_long": "b" * 9000}], "n": 5}
    result = truncate_values(data, limit=8192)
    assert result["long"].endswith("...[TRUNCATED]")
    assert len(result["long"]) == 8192 + len("...[TRUNCATED]")
    assert result["nested"][0]["also_long"].endswith("...[TRUNCATED]")
    assert result["n"] == 5


def test_oversized_header_fields_truncated_not_dropped(config):
    # A client-controlled header (user-agent / x-user-id) larger than the
    # event cap must not let that client suppress its own events.
    queue = BoundedQueue(10)
    pipeline = Pipeline(config, queue, None)
    request = load_export("llm_openai_chat")
    span = request.resource_spans[0].scope_spans[0].spans[0]
    for kv in span.attributes:
        if kv.key == "http.user_agent":
            kv.value.string_value = "A" * 70000
        if kv.key == "user.id":
            kv.value.string_value = "u" * 5000
    pipeline.process_export(request)
    [event] = queue.drain(10)
    assert len(event["user_agent"]) <= 1024 + len("...[TRUNCATED]")
    assert len(event["user_id"]) <= 256 + len("...[TRUNCATED]")
    assert pipeline.dropped_oversize == 0


def _schema_report_event(
    tools: list, resources: list | None = None, prompts: list | None = None
) -> dict:
    return {
        "remote_addr": None,
        "endpoint": "mcp://srv/schema_report",
        "scheme": "mcp",
        "method": "mcp_schema_report",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "headers": None,
        "query_params": None,
        "user_agent": "ua",
        "user_id": None,
        "body": None,
        "custom_data": {
            "integration": "envoy-ai-gateway",
            "mcp_server": "srv",
            "event_type": "schema_report",
            "tools": tools,
            "resources": resources or [],
            "prompts": prompts or [],
            "trace_id": "",
        },
    }


def test_schema_report_tools_sanitized(config):
    # Schema-report tool schemas skip the argument-sanitization branch, but
    # credential-shaped example values inside them must still be redacted.
    pipeline = Pipeline(config, BoundedQueue(10), None)
    event = _schema_report_event(
        [
            {
                "name": "lookup",
                "description": "find",
                "input_schema": {"example": {"api_key": "sk-x"}},
            }
        ]
    )
    finalized = pipeline._finalize(event, KIND_MCP)
    tools = finalized["custom_data"]["tools"]
    assert len(tools) == 1
    assert tools[0]["input_schema"]["example"]["api_key"] == REDACTED


def test_oversize_schema_report_sheds_tools_but_keeps_skeleton(config):
    # A large tool catalogue has no body/arguments to shed, so without shedding
    # tools/resources/prompts it would be dropped whole; it should instead land
    # as a schema_only skeleton the backend can still record.
    config = replace(config, max_event_bytes=1024)
    pipeline = Pipeline(config, BoundedQueue(10), None)
    big_tools = [
        {"name": f"tool_{i}", "description": "x" * 500, "input_schema": {}} for i in range(40)
    ]
    finalized = pipeline._finalize(_schema_report_event(big_tools), KIND_MCP)
    assert finalized is not None
    assert finalized["custom_data"]["tools"] == []
    assert finalized["custom_data"]["content_dropped_oversize"] is True
    assert finalized["custom_data"]["mcp_server"] == "srv"
    assert pipeline.dropped_oversize == 0


def test_schema_report_resources_and_prompts_sanitized(config):
    # The sanitize contract must cover all three declaration lists, not just
    # tools — matching what _enforce_size sheds.
    pipeline = Pipeline(config, BoundedQueue(10), None)
    event = _schema_report_event(
        [],
        resources=[{"name": "r", "input_schema": {"example": {"token": "t-secret"}}}],
        prompts=[{"name": "p", "arguments": {"password": "p-secret"}}],
    )
    finalized = pipeline._finalize(event, KIND_MCP)
    assert finalized["custom_data"]["resources"][0]["input_schema"]["example"]["token"] == REDACTED
    assert finalized["custom_data"]["prompts"][0]["arguments"]["password"] == REDACTED


def test_schema_report_sanitized_regardless_of_capture_arguments_flag(config):
    # Schema reports must be redacted even with MCP argument capture off — they
    # carry tool declarations, not runtime arguments.
    config = replace(config, capture_mcp_arguments=False)
    pipeline = Pipeline(config, BoundedQueue(10), None)
    event = _schema_report_event([{"name": "t", "input_schema": {"example": {"api_key": "sk-x"}}}])
    finalized = pipeline._finalize(event, KIND_MCP)
    assert finalized["custom_data"]["tools"][0]["input_schema"]["example"]["api_key"] == REDACTED


def test_raw_malformed_ip_bounded(config):
    # Raw-IP mode (no secret): a giant malformed XFF must be length-capped, not
    # left to push the unsheddable remote_addr over the event cap.
    queue = BoundedQueue(10)
    pipeline = Pipeline(config, queue, None)
    request = load_export("llm_openai_chat")
    span = request.resource_spans[0].scope_spans[0].spans[0]
    for kv in span.attributes:
        if kv.key == "http.client_ip":
            kv.value.string_value = "z" * 5000
    pipeline.process_export(request)
    [event] = queue.drain(10)
    assert len(event["remote_addr"]) <= 64
    assert pipeline.dropped_oversize == 0


def test_extra_attributes_copied_into_custom_data(config):
    config = replace(config, extra_attributes=("tenant.id",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    pipeline.process_export(_with_attr("llm_openai_chat", "tenant.id", "acme"))
    [event] = queue.drain(10)
    assert event["custom_data"]["tenant_id"] == "acme"


def test_extra_attributes_apply_to_mcp_events_too(config):
    # The whole point is correlating the two paths, so both must carry them.
    config = replace(config, extra_attributes=("corr.session",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    pipeline.process_export(_with_attr("mcp_tool_call", "corr.session", "abc"))
    [event] = queue.drain(10)
    assert event["custom_data"]["corr_session"] == "abc"


def test_extra_attributes_never_overwrite_mapper_keys(config):
    # Gateway telemetry outranks operator config: a mapping that collides with
    # a mapper-set key is skipped, not applied.
    config = replace(config, extra_attributes=("trace.id",))
    _, queue, _ = _run("llm_openai_chat", config)
    [event] = queue.drain(10)
    # trace_id stays the span's real trace id, not the "trace.id" attribute.
    assert event["custom_data"]["trace_id"] == "0102030405060708090a0b0c0d0e0f10"


def test_extra_attributes_absent_from_span_are_skipped(config):
    config = replace(config, extra_attributes=("not.present",))
    _, queue, _ = _run("llm_openai_chat", config)
    [event] = queue.drain(10)
    assert "not_present" not in event["custom_data"]


def test_extra_attributes_sanitized_by_key_name(config):
    # A mapped attribute whose derived key looks credential-shaped is redacted
    # like any other captured value.
    config = replace(config, extra_attributes=("api.key",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    export = load_export("llm_openai_chat")
    span = export.resource_spans[0].scope_spans[0].spans[0]
    attr = span.attributes.add()
    attr.key = "api.key"
    attr.value.string_value = "super-secret"
    pipeline.process_export(export)
    [event] = queue.drain(10)
    assert event["custom_data"]["api_key"] == REDACTED


def test_extra_attributes_truncated(config):
    config = replace(config, extra_attributes=("big.value",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    export = load_export("llm_openai_chat")
    span = export.resource_spans[0].scope_spans[0].spans[0]
    attr = span.attributes.add()
    attr.key = "big.value"
    attr.value.string_value = "x" * 5000
    pipeline.process_export(export)
    [event] = queue.drain(10)
    assert event["custom_data"]["big_value"].endswith("...[TRUNCATED]")
    assert len(event["custom_data"]["big_value"]) < 5000


def test_no_extra_attributes_configured_is_a_no_op(config):
    _, queue_off, _ = _run("llm_openai_chat", config)
    _, queue_on, _ = _run("llm_openai_chat", replace(config, extra_attributes=()))
    assert queue_off.drain(1)[0]["custom_data"] == queue_on.drain(1)[0]["custom_data"]


def test_extra_attributes_redacts_namespaced_sensitive_names(config):
    # sanitize_dict matches whole keys, so http.request.header.authorization
    # flattens to a key matching nothing — it must still be redacted.
    config = replace(config, extra_attributes=("http.request.header.authorization",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    export = load_export("llm_openai_chat")
    span = export.resource_spans[0].scope_spans[0].spans[0]
    attr = span.attributes.add()
    attr.key = "http.request.header.authorization"
    attr.value.string_value = "Bearer super-secret"
    pipeline.process_export(export)
    [event] = queue.drain(10)
    assert event["custom_data"]["http_request_header_authorization"] == REDACTED


def test_extra_attributes_redacts_dotted_sensitive_suffix(config):
    config = replace(config, extra_attributes=("auth.access.token",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    export = load_export("llm_openai_chat")
    span = export.resource_spans[0].scope_spans[0].spans[0]
    attr = span.attributes.add()
    attr.key = "auth.access.token"
    attr.value.string_value = "tok-123"
    pipeline.process_export(export)
    [event] = queue.drain(10)
    assert event["custom_data"]["auth_access_token"] == REDACTED


def test_extra_attributes_non_sensitive_names_still_pass_through(config):
    # The redaction guard must not swallow ordinary correlation attributes.
    config = replace(config, extra_attributes=("tenant.id",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    export = load_export("llm_openai_chat")
    span = export.resource_spans[0].scope_spans[0].spans[0]
    attr = span.attributes.add()
    attr.key = "tenant.id"
    attr.value.string_value = "acme-42"
    pipeline.process_export(export)
    [event] = queue.drain(10)
    assert event["custom_data"]["tenant_id"] == "acme-42"


def _with_kvlist(fixture: str, key: str, pairs: dict):
    export = load_export(fixture)
    span = export.resource_spans[0].scope_spans[0].spans[0]
    attr = span.attributes.add()
    attr.key = key
    for k, v in pairs.items():
        kv = attr.value.kvlist_value.values.add()
        kv.key = k
        kv.value.string_value = v
    return export


def test_extra_attributes_sanitize_nested_credential_keys(config):
    # Serializing a structured value before sanitize_dict would hide the inner
    # key from it and ship the secret under a benign-looking outer key.
    config = replace(config, extra_attributes=("request.metadata",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    pipeline.process_export(
        _with_kvlist("llm_openai_chat", "request.metadata", {"api_key": "sk-SECRET"})
    )
    [event] = queue.drain(10)
    assert "sk-SECRET" not in json.dumps(event)
    assert REDACTED in event["custom_data"]["request_metadata"]


def test_extra_attributes_bounded_by_encoded_bytes_not_characters(config):
    # json.dumps escapes non-ASCII, so a character cap lets an emoji value cost
    # ~12x its length and push the event past max_event_bytes.
    config = replace(config, extra_attributes=tuple(f"e{i}.v" for i in range(5)))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    export = load_export("llm_openai_chat")
    span = export.resource_spans[0].scope_spans[0].spans[0]
    for i in range(5):
        attr = span.attributes.add()
        attr.key = f"e{i}.v"
        attr.value.string_value = "\U0001f600" * 2000
    queued = pipeline.process_export(export)
    assert queued == 1
    assert pipeline.dropped_oversize == 0
    [event] = queue.drain(10)
    assert len(json.dumps(event).encode()) <= config.max_event_bytes


def test_selecting_a_bridge_owned_attribute_is_rejected(config):
    # The bridge copies mcp.session.id into custom_data["session_id"] itself, so
    # selecting it would leave the raw value beside the captured/hashed one.
    # Refused at startup rather than scrubbed, which never caught every alias.
    with pytest.raises(ConfigError, match="already read by the bridge"):
        Pipeline(replace(config, extra_attributes=("mcp.session.id",)), BoundedQueue(10), "k")


def test_endpoint_embedded_sources_are_rejected(config):
    # provider/model build llm://{provider}/{model}; hashing them would either
    # corrupt the endpoint or leave the raw value inside it.
    for name in ("llm.system", "llm.model_name"):
        with pytest.raises(ConfigError, match="already read by the bridge"):
            Pipeline(replace(config, extra_attributes=(name,)), BoundedQueue(10), "k")


def test_configured_header_attributes_are_rejected(config):
    # user_agent/client_ip/user_id land in top-level fields the extras path
    # doesn't touch, so selecting them dual-writes.
    config = replace(config, user_id_attribute="corr.id")
    for name in ("http.user_agent", "http.client_ip", "corr.id"):
        with pytest.raises(ConfigError, match="already read by the bridge"):
            Pipeline(replace(config, extra_attributes=(name,)), BoundedQueue(10), "k")


def test_extra_attributes_redacts_kebab_case_sensitive_compound(config):
    # x-api-key is the spelling HTTP headers actually use, and this codebase
    # already treats it as sensitive via SENSITIVE_HEADERS. Segment-wise
    # matching missed it: neither "api" nor "key" is sensitive alone, and the
    # compound never survives as its own segment under any single split.
    config = replace(config, extra_attributes=("http.request.header.x-api-key",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    pipeline.process_export(
        _with_attr("llm_openai_chat", "http.request.header.x-api-key", "sk-SECRET")
    )
    [event] = queue.drain(10)
    assert "sk-SECRET" not in json.dumps(event)
    assert event["custom_data"]["http_request_header_x_api_key"] == REDACTED


def test_multiword_sensitive_compounds_detected_in_both_spellings():
    from cerberus_envoy_ai_gateway.pipeline import is_sensitive_attribute

    # Compounds whose individual words are not sensitive on their own — these
    # are the ones segment matching let through.
    for compound in ("api-key", "private-key", "ssh-key", "credit-card", "card-number"):
        assert is_sensitive_attribute(f"http.request.header.x-{compound}"), compound
        assert is_sensitive_attribute(f"req.{compound.replace('-', '_')}"), compound


def test_operator_correlation_names_are_not_over_redacted():
    from cerberus_envoy_ai_gateway.pipeline import is_sensitive_attribute

    # The documented examples must stay usable, or the wider match breaks the
    # configuration the README tells operators to use.
    for name in ("corr.session", "tenant.id", "request.id", "corr.trace"):
        assert not is_sensitive_attribute(name), name


def test_shared_helper_attributes_are_rejected(config):
    # error.type is read by spanfields.error_message(), which both mappers call,
    # and feeds custom_data["error"] — a different key than the derived one, so
    # neither the startup set nor the runtime collision check saw it.
    with pytest.raises(ConfigError, match="already read by the bridge"):
        Pipeline(replace(config, extra_attributes=("error.type",)), BoundedQueue(10), "k")


def test_mapper_request_params_are_rejected(config):
    # gen_ai.request.temperature lands in custom_data["temperature"] — again a
    # different key than the derived gen_ai_request_temperature.
    for name in ("gen_ai.request.temperature", "gen_ai.request.top_p"):
        with pytest.raises(ConfigError, match="already read by the bridge"):
            Pipeline(replace(config, extra_attributes=(name,)), BoundedQueue(10), "k")


def test_fit_encoded_never_exceeds_a_tiny_budget():
    from cerberus_envoy_ai_gateway.pipeline import fit_encoded

    # Latent if MAX_EXTRA_VALUE_BYTES is ever lowered below the marker length.
    for budget in (4, 8, 16):
        assert len(json.dumps(fit_encoded("x" * 500, budget))) <= budget


def test_key_collision_within_one_list_is_rejected(config):
    # tenant-id and tenant.id both derive custom_data["tenant_id"]; which value
    # wins would otherwise depend on iteration order.
    with pytest.raises(ConfigError, match="both map to custom_data key"):
        Pipeline(
            replace(config, extra_attributes=("tenant-id", "tenant.id")), BoundedQueue(10), "k"
        )


def test_operator_owned_attributes_are_still_accepted(config):
    # Over-rejection would make the feature useless; the intended shape works.
    Pipeline(replace(config, extra_attributes=("corr.session", "tenant.id")), BoundedQueue(10), "k")


def test_extra_attributes_distinct_bytes_stay_distinct(config):
    # Lossy UTF-8 replacement mapped b"\xff" and b"\xfe" both to U+FFFD, so two
    # distinct correlation keys collapsed to the same stored value and
    # correlated unrelated events. Encoding is now lossless.
    outputs = []
    for raw in (b"\xff", b"\xfe"):
        config2 = replace(config, extra_attributes=("corr.blob",))
        queue = BoundedQueue(100)
        pipeline = Pipeline(config2, queue, None)
        export = load_export("llm_openai_chat")
        span = export.resource_spans[0].scope_spans[0].spans[0]
        attr = span.attributes.add()
        attr.key = "corr.blob"
        attr.value.bytes_value = raw
        pipeline.process_export(export)
        outputs.append(queue.drain(10)[0]["custom_data"]["corr_blob"])
    assert outputs[0] != outputs[1]
    # valid UTF-8 still stored as readable text, not base64
    config3 = replace(config, extra_attributes=("corr.blob",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config3, queue, None)
    export = load_export("llm_openai_chat")
    span = export.resource_spans[0].scope_spans[0].spans[0]
    attr = span.attributes.add()
    attr.key = "corr.blob"
    attr.value.bytes_value = b"plain-text-id"
    pipeline.process_export(export)
    assert queue.drain(10)[0]["custom_data"]["corr_blob"] == "plain-text-id"


def test_extra_attributes_redacts_slash_separated_sensitive_name(config):
    # Attribute names are operator-controlled arbitrary text; a slash-separated
    # credential name evaded the dot/hyphen/underscore-only word split.
    config = replace(config, extra_attributes=("http/request/header/authorization",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    pipeline.process_export(
        _with_attr("llm_openai_chat", "http/request/header/authorization", "Bearer SECRET")
    )
    [event] = queue.drain(10)
    assert "SECRET" not in json.dumps(event)
    assert event["custom_data"]["http_request_header_authorization"] == REDACTED


def test_extra_attributes_redacts_nested_namespaced_credential_key(config):
    # A kvlist with a benign outer name but a nested namespaced credential key —
    # sanitize_dict matches whole keys, so the nested one evaded it.
    config = replace(config, extra_attributes=("request.metadata",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    pipeline.process_export(
        _with_kvlist(
            "llm_openai_chat",
            "request.metadata",
            {"http.request.header.authorization": "Bearer SECRET"},
        )
    )
    [event] = queue.drain(10)
    assert "SECRET" not in json.dumps(event)
    assert REDACTED in event["custom_data"]["request_metadata"]


def test_extras_shed_before_dropping_a_whole_event(config):
    # With a small max_event_bytes, a bounded extra could otherwise sink an
    # otherwise-valid event. The extra is shed; the event survives.
    config = replace(config, extra_attributes=("corr.x",), max_event_bytes=1024)
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    pipeline.process_export(_with_attr("llm_openai_chat", "corr.x", "y" * 900))
    assert pipeline.dropped_oversize == 0
    [event] = queue.drain(10)
    assert "corr_x" not in event["custom_data"]
    assert event["custom_data"]["extras_dropped_oversize"] is True
    assert len(json.dumps(event).encode()) <= config.max_event_bytes


def test_extra_attributes_redacts_camelcase_sensitive_name(config):
    # camelCase carries no separators; case boundaries must be broken or the
    # word scan never sees the sensitive word.
    config = replace(config, extra_attributes=("httpRequestHeaderAuthorization",))
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    pipeline.process_export(
        _with_attr("llm_openai_chat", "httpRequestHeaderAuthorization", "Bearer SECRET")
    )
    [event] = queue.drain(10)
    assert "SECRET" not in json.dumps(event)
    assert event["custom_data"]["http_request_header_authorization"] == REDACTED


def test_camelcase_multiword_sensitive_compounds():
    from cerberus_envoy_ai_gateway.pipeline import is_sensitive_attribute

    for name in ("xApiKey", "userPrivateKey", "reqSessionId", "creditCardNumber"):
        assert is_sensitive_attribute(name), name


def test_mcp_argument_prefix_attribute_is_rejected(config):
    # The per-argument prefix is a mapper read; selecting one dual-writes.
    # Also guards the deduplicated prefix constant against silent breakage.
    with pytest.raises(ConfigError, match="already read by the bridge"):
        Pipeline(
            replace(config, extra_attributes=("mcp.request.argument.location",)),
            BoundedQueue(10),
            "k",
        )


def test_extra_attributes_redacts_acronym_prefixed_sensitive_name(config):
    # HTTPAuthorization / HTTPPrivateKey: the acronym→word boundary the
    # two-rule splitter missed, so the credential shipped in cleartext.
    for name, key in (
        ("HTTPAuthorization", "http_authorization"),
        ("HTTPPrivateKey", "http_private_key"),
    ):
        config2 = replace(config, extra_attributes=(name,))
        queue = BoundedQueue(100)
        pipeline = Pipeline(config2, queue, None)
        pipeline.process_export(_with_attr("llm_openai_chat", name, "Bearer SECRET"))
        [event] = queue.drain(10)
        assert "SECRET" not in json.dumps(event), name
        assert event["custom_data"][key] == REDACTED, name


def test_extras_shed_never_deletes_a_mapper_key(config):
    # A configured extra that collides with a mapper key (trace.id -> trace_id)
    # is skipped at insert; the oversized-shed must not then delete the mapper's
    # real trace_id along with the actually-added extra.
    config = replace(config, extra_attributes=("trace.id", "corr.x"), max_event_bytes=1024)
    queue = BoundedQueue(100)
    pipeline = Pipeline(config, queue, None)
    pipeline.process_export(_with_attr("llm_openai_chat", "corr.x", "y" * 900))
    assert pipeline.dropped_oversize == 0
    [event] = queue.drain(10)
    # the mapper's trace_id survives; only the real extra (corr_x) is shed
    assert event["custom_data"]["trace_id"]  # present and non-empty
    assert "corr_x" not in event["custom_data"]


def test_concatenated_sensitive_name_is_a_documented_limit():
    # Honest boundary: a name with no internal separator can't be word-split
    # without a dictionary, so it is NOT caught. Locks the known limitation so a
    # future reader doesn't mistake it for a bug (or silently "fix" it wrong).
    from cerberus_envoy_ai_gateway.pipeline import is_sensitive_attribute

    assert is_sensitive_attribute("private.key")  # separated: caught
    assert not is_sensitive_attribute("privatekey")  # fused: not caught, by design
