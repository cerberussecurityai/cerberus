import copy
import json

from helpers import TIMESTAMP, LambdaContext, load_case, options

from cerberus_agentcore_interceptor import bounding
from cerberus_agentcore_interceptor import envelope as envelope_mod
from cerberus_agentcore_interceptor.mapper import source_event

MAX = bounding.DEFAULT_MAX_EVENT_BYTES


def map_with_body(case_name: str, body, **overrides):
    """Map a fixture with its request body replaced."""
    case = load_case(case_name)
    shape = case["input"]["mcp" if "mcp" in case["input"] else "http"]
    shape["gatewayRequest"]["body"] = body
    shape.pop("rawGatewayRequest", None)
    return source_event(
        envelope_mod.parse(case["input"]),
        envelope_mod.gateway_context(LambdaContext(case["client_context"])),
        options(case, **overrides),
        TIMESTAMP,
    )


def note(event):
    return event["custom_data"]["agentcore"]["body"]


def chat(messages, **extra):
    return {
        "model": "openai.gpt-oss-20b",
        "stream": False,
        "max_tokens": 24,
        "messages": messages,
        **extra,
    }


def test_a_small_event_is_untouched():
    event = map_with_body("mcp-tools-call-lambda", {"jsonrpc": "2.0", "method": "ping", "id": 1})
    assert note(event) == {"state": "captured"}
    assert bounding.size(event) <= MAX


def test_long_strings_are_capped_before_anything_is_dropped():
    body = chat([{"role": "user", "content": "x" * 80000}])
    event = map_with_body("inference-chat", body)
    assert note(event)["state"] == "capped"
    assert len(event["body"]["messages"][0]["content"]) == bounding.MAX_STRING_CHARS
    assert event["body"]["model"] == "openai.gpt-oss-20b"
    assert bounding.size(event) <= MAX


def test_a_long_llm_conversation_keeps_the_newest_messages_and_the_system_prompt():
    messages = [{"role": "system", "content": "be brief"}]
    messages += [{"role": "user", "content": f"{index}:" + "y" * 4000} for index in range(60)]
    event = map_with_body("inference-chat", chat(messages, tools=[{"name": "t"}] * 50))

    body = event["body"]
    assert note(event)["state"] == "reduced"
    assert note(event)["kind"] == "llm"
    assert note(event)["messages_dropped"] > 0
    assert body["model"] == "openai.gpt-oss-20b"
    assert body["max_tokens"] == 24
    assert "tools" not in body
    assert body["messages"][0] == {"role": "system", "content": "be brief"}
    assert body["messages"][-1]["content"].startswith("59:")
    assert all("role" in message for message in body["messages"])
    assert bounding.size(event) <= MAX


def test_a_responses_style_string_input_survives_reduction():
    body = {
        "model": "gpt-5",
        "input": "z" * 200000,
        "instructions": "be brief",
        "tools": ["t" * 200] * 900,
    }
    event = map_with_body("inference-chat", body)
    assert note(event)["state"] == "reduced"
    assert isinstance(event["body"]["input"], str)
    assert event["body"]["model"] == "gpt-5"
    assert "tools" not in event["body"]
    assert bounding.size(event) <= MAX


def test_mcp_arguments_are_truncated_then_dropped():
    arguments = {f"blob{index}": "q" * 20000 for index in range(40)}
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "t___big", "arguments": arguments},
    }
    event = map_with_body("mcp-tools-call-lambda", body)

    assert note(event)["state"] == "reduced"
    assert note(event)["kind"] == "mcp"
    assert event["body"]["method"] == "tools/call"
    assert event["body"]["params"]["name"] == "t___big"
    assert note(event)["arguments"] == "truncated"
    assert bounding.size(event) <= MAX


def test_mcp_arguments_are_dropped_when_truncation_is_not_enough():
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "t___wide", "arguments": {f"k{i}": "v" * 200 for i in range(4000)}},
    }
    event = map_with_body("mcp-tools-call-lambda", body)
    assert note(event) == {"state": "reduced", "kind": "mcp", "arguments": "dropped"}
    assert event["body"]["params"] == {"name": "t___wide"}


def test_an_unclassifiable_body_is_shed_whole():
    body = {f"key{index}": "v" * 900 for index in range(400)}
    event = map_with_body("mcp-tools-call-lambda", body)
    assert "body" not in event
    assert note(event) == {"state": "shed", "reason": "size"}
    assert bounding.size(event) <= MAX


def test_a_two_hundred_kilobyte_chat_still_classifies():
    messages = [{"role": "user", "content": "w" * 200000}]
    event = map_with_body("inference-chat", chat(messages))
    assert event["body"]["model"] == "openai.gpt-oss-20b"
    assert event["body"]["messages"][0]["role"] == "user"
    assert bounding.size(event) <= MAX


def test_a_two_hundred_kilobyte_tool_call_still_classifies():
    body = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "files___read",
            "arguments": {"path": "/etc/hosts", "blob": "b" * 200000},
        },
    }
    event = map_with_body("mcp-tools-call-lambda", body)
    assert event["body"]["params"]["name"] == "files___read"
    assert bounding.size(event) <= MAX


def test_an_event_that_cannot_be_bounded_is_dropped():
    case = load_case("mcp-tools-call-lambda")
    context = dict(case["client_context"])
    context["GATEWAY_ARN"] = "arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/" + "g" * 200
    event = source_event(
        envelope_mod.parse(case["input"]),
        envelope_mod.gateway_context(LambdaContext(context)),
        options(case, max_event_bytes=200),
        TIMESTAMP,
    )
    assert event is None


def test_a_custom_cap_is_honoured():
    messages = [{"role": "user", "content": "x" * 30000}]
    event = map_with_body("inference-chat", chat(messages), max_event_bytes=4096)
    assert bounding.size(event) <= 4096


def test_cap_strings_counts_only_what_it_cut():
    value = {"a": "x" * 10, "b": ["y" * 100, "z"], "c": 5}
    capped, count = bounding.cap_strings(value, 20)
    assert count == 1
    assert capped["a"] == "x" * 10
    assert capped["b"][0] == "y" * 20
    assert capped["c"] == 5


def test_cap_strings_leaves_the_original_alone():
    value = {"a": {"b": ["x" * 100]}}
    original = copy.deepcopy(value)
    bounding.cap_strings(value, 5)
    assert value == original


def test_serialize_is_what_the_ladder_measures():
    event = {"a": "é"}
    assert bounding.serialize(event) == b'{"a":"\\u00e9"}'
    assert bounding.size(event) == len(bounding.serialize(event))


def test_padded_headers_cannot_push_an_event_out_of_capture():
    # Headers are capped in bytes as well as characters, so a caller cannot pad
    # them until the event no longer fits.
    case = load_case("mcp-tools-call-lambda")
    request = case["input"]["mcp"]["gatewayRequest"]
    for name in ("User-Agent", "Content-Type", "X-Amzn-Trace-Id", "anthropic-version"):
        request["headers"][name] = "\U0001f600" * 40000

    event = source_event(
        envelope_mod.parse(case["input"]),
        envelope_mod.gateway_context(LambdaContext(case["client_context"])),
        options(case),
        TIMESTAMP,
    )

    assert event is not None
    assert event["body"]["method"] == "tools/call"
    assert bounding.size(event) <= MAX


def test_headers_are_shed_before_the_body():
    case = load_case("mcp-tools-call-lambda")
    case["input"]["mcp"]["gatewayRequest"]["headers"]["User-Agent"] = "u" * 900
    event = source_event(
        envelope_mod.parse(case["input"]),
        envelope_mod.gateway_context(LambdaContext(case["client_context"])),
        options(case, max_event_bytes=1000),
        TIMESTAMP,
    )

    assert event is not None
    assert "headers" not in event
    assert "user_agent" not in event
    assert event["body"]["method"] == "tools/call"
    assert event["custom_data"]["agentcore"]["headers"]["state"] == "shed"


def test_a_large_messages_body_sheds_the_system_prompt_before_the_conversation():
    body = {
        "model": "anthropic.claude-haiku-4-5",
        "max_tokens": 64,
        "system": "s" * 200000,
        "messages": [{"role": "user", "content": "hello"}],
    }
    event = map_with_body("inference-messages", body)

    assert event["body"]["messages"] == [{"role": "user", "content": "hello"}]
    assert event["body"]["model"] == "anthropic.claude-haiku-4-5"
    assert len(event["body"]["system"]) == bounding.MAX_STRING_CHARS
    assert bounding.size(event) <= MAX


def test_the_system_prompt_goes_before_the_conversation_does():
    body = {
        "model": "anthropic.claude-haiku-4-5",
        "system": "s" * 200000,
        "messages": [{"role": "user", "content": "hello"}],
    }
    event = map_with_body("inference-messages", body, max_event_bytes=1400)

    assert "system" not in event["body"]
    assert event["body"]["messages"] == [{"role": "user", "content": "hello"}]
    assert note(event)["system"] == "dropped"


def test_a_capped_body_that_is_then_reduced_keeps_both_facts():
    messages = [{"role": "user", "content": f"{index}:" + "y" * 40000} for index in range(40)]
    event = map_with_body("inference-chat", chat(messages))
    assert note(event)["state"] == "reduced"
    assert note(event)["strings"] > 0


def test_a_reduced_body_is_never_empty():
    body = {"model": "m", "messages": [{"role": "user", "content": "x" * 100}], "tools": ["t"] * 50}
    event = map_with_body("inference-chat", body, max_event_bytes=1024)
    assert event is None or event.get("body") is None or event["body"]


def test_an_mcp_body_without_params_keeps_its_method():
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "extra": {"x": "y" * 200000}}
    event = map_with_body("mcp-tools-call-lambda", body)
    assert event["body"]["method"] == "tools/list"
    assert "params" not in event["body"]


def test_clip_text_bounds_bytes_as_well_as_characters():
    assert bounding.clip_text("abc", 10) == "abc"
    assert bounding.clip_text("a" * 50, 10) == "a" * 10

    emoji = bounding.clip_text("\U0001f600" * 50, 10)
    assert len(emoji) < 10
    assert len(json.dumps(emoji)) - 2 <= 10 * bounding.BYTES_PER_CAPPED_CHAR
