"""Regenerate tests/fixtures/litellm/*.json from captured LiteLLM payloads.

Usage: python tests/fixtures/trim_captures.py <dir-with-NNN_*.json>

Each capture holds the whole hook payload (kwargs included). The
plugin only ever reads standard_logging_object + response_obj, so the test
fixtures keep just those (plus the timestamps). One capture is kept whole
(full_kwargs_chat.json) so test_handler can prove nothing from kwargs leaks.
"""

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
OUT = HERE / "litellm"
KEEP = ("standard_logging_object", "response_obj", "start_time", "end_time")

TRIMMED = {
    "chat.json": "002_success_acompletion.json",
    "chat_stream_tools.json": "004_success_acompletion.json",
    "messages_stream_tools.json": "006_success_anthropic_messages.json",
    "responses.json": "008_success_aresponses.json",
    "embeddings.json": "010_success_aembedding.json",
    "failure_500.json": "012_failure_acompletion.json",
    "failure_429.json": "014_failure_acompletion.json",
    "big_completion.json": "016_success_acompletion.json",
    "big_prompt.json": "020_success_acompletion.json",
    "mcp_list_tools.json": "021_success_list_mcp_tools.json",
    "mcp_tool_call.json": "024_success_call_mcp_tool.json",
    "mcp_tool_call_big.json": "027_success_call_mcp_tool.json",
    "mcp_tool_call_error.json": "030_failure_call_mcp_tool.json",
}
WHOLE = {"full_kwargs_chat.json": "002_success_acompletion.json"}


def main(source: pathlib.Path) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, capture in TRIMMED.items():
        data = json.loads((source / capture).read_text())
        trimmed = {key: data.get(key) for key in KEEP}
        (OUT / name).write_text(json.dumps(trimmed, indent=2, sort_keys=True) + "\n")
        print(f"wrote {name} <- {capture}")
    for name, capture in WHOLE.items():
        data = json.loads((source / capture).read_text())
        (OUT / name).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        print(f"wrote {name} <- {capture} (untrimmed)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(pathlib.Path(sys.argv[1]))
