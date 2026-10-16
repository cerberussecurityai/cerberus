import pytest
from helpers import finalized, load_capture
from shape import detection_shape, shape_problem

from cerberus_litellm.mapper_llm import map_llm_event
from cerberus_litellm.mapper_mcp import map_mcp_event, map_schema_reports
from cerberus_litellm.pipeline import Pipeline

LLM = (
    "chat",
    "chat_stream_tools",
    "messages_stream_tools",
    "responses",
    "embeddings",
    "failure_500",
    "failure_429",
    "big_completion",
    "big_prompt",
)
MCP = ("mcp_tool_call", "mcp_tool_call_big", "mcp_tool_call_error")


def _llm_event(name, config):
    slo = load_capture(name)["standard_logging_object"]
    return finalized(Pipeline(config), map_llm_event(slo, config), "llm")


@pytest.mark.parametrize("name", LLM)
def test_llm_events_meet_the_ingest_contract(name, config):
    event = _llm_event(name, config)
    assert shape_problem(event, config.max_event_bytes) is None
    # The metadata the dashboard and discovery read must actually be there —
    # an event whose mapper forgot custom_data still passes shape_problem.
    cd = event["custom_data"]
    assert cd["integration"] == "litellm"
    assert cd["provider"] and cd["model"]
    assert cd["status"] in ("ok", "error")
    assert "tokens_prompt" in cd and "duration_ms" in cd
    assert cd["litellm_key_alias"] == "spike-key"


@pytest.mark.parametrize(
    "name",
    (
        "chat",
        "chat_stream_tools",
        "messages_stream_tools",
        "responses",
        "big_completion",
        "big_prompt",
    ),
)
def test_successful_llm_events_are_detection_scorable(name, config):
    assert detection_shape(_llm_event(name, config)) == "ok"


def test_failures_and_embeddings_carry_input_but_no_output(config):
    for name in ("failure_500", "embeddings"):
        assert detection_shape(_llm_event(name, config)) == "output_missing"


@pytest.mark.parametrize("name", MCP)
def test_mcp_events_meet_the_ingest_contract(name, config):
    slo = load_capture(name)["standard_logging_object"]
    event = finalized(Pipeline(config), map_mcp_event(slo, config), "mcp")
    assert shape_problem(event, config.max_event_bytes) is None
    assert event["method"].startswith("mcp_")


def test_schema_report_meets_the_ingest_contract(config):
    capture = load_capture("mcp_list_tools")
    events = map_schema_reports(capture["standard_logging_object"], capture["response_obj"], config)
    assert events
    for event in events:
        out = finalized(Pipeline(config), event, "schema")
        assert shape_problem(out, config.max_event_bytes) is None
