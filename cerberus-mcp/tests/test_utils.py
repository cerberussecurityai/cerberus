"""Tests for cerberus_mcp utility functions."""

import pytest

from cerberus_core import REDACTED
from cerberus_mcp.utils import sanitize_arguments, summarize_result, _truncate_value
from cerberus_mcp.config import MAX_ARG_STRING_LENGTH


class TestSanitizeArguments:
    """Tests for argument sanitization before event capture."""

    def test_redacts_sensitive_keys(self):
        args = {"query": "hello", "password": "secret", "api_key": "sk-123"}
        result = sanitize_arguments(args)
        assert result["query"] == "hello"
        assert result["password"] == REDACTED
        assert result["api_key"] == REDACTED

    def test_case_insensitive_key_matching(self):
        args = {"Password": "secret", "API_KEY": "key"}
        result = sanitize_arguments(args)
        assert result["Password"] == REDACTED
        assert result["API_KEY"] == REDACTED

    def test_truncates_long_strings(self):
        long_str = "x" * (MAX_ARG_STRING_LENGTH + 100)
        args = {"text": long_str}
        result = sanitize_arguments(args)
        assert len(result["text"]) < len(long_str)
        assert "chars" in result["text"]

    def test_preserves_short_strings(self):
        args = {"name": "alice"}
        result = sanitize_arguments(args)
        assert result["name"] == "alice"

    def test_preserves_numeric_values(self):
        args = {"count": 42, "ratio": 3.14, "flag": True}
        result = sanitize_arguments(args)
        assert result["count"] == 42
        assert result["ratio"] == 3.14
        assert result["flag"] is True

    def test_returns_none_for_empty_input(self):
        assert sanitize_arguments(None) is None
        assert sanitize_arguments({}) is None

    def test_non_dict_input_wrapped(self):
        result = sanitize_arguments("raw string")
        assert "_raw" in result
        assert result["_raw"] == "raw string"

    def test_non_string_keys_do_not_crash(self):
        args = {0: "positional", "query": "hello"}
        result = sanitize_arguments(args)
        assert result[0] == "positional"
        assert result["query"] == "hello"

    def test_sanitizes_nested_dicts(self):
        args = {"config": {"token": "abc", "host": "localhost"}}
        result = sanitize_arguments(args)
        assert result["config"]["token"] == REDACTED
        assert result["config"]["host"] == "localhost"

    def test_sanitizes_nested_lists(self):
        args = {"items": [{"password": "secret"}, {"name": "alice"}]}
        result = sanitize_arguments(args)
        assert result["items"][0]["password"] == REDACTED
        assert result["items"][1]["name"] == "alice"

    def test_sanitizes_tuple_values(self):
        args = {"data": ({"password": "secret"}, {"name": "alice"})}
        result = sanitize_arguments(args)
        assert isinstance(result["data"], list)
        assert result["data"][0]["password"] == REDACTED
        assert result["data"][1]["name"] == "alice"


class TestTruncateValue:
    """Tests for _truncate_value helper."""

    @pytest.mark.parametrize(
        "value",
        [None, True, False, 42, 3.14, "hello"],
        ids=["none", "true", "false", "int", "float", "short-string"],
    )
    def test_scalar_passthrough(self, value):
        assert _truncate_value(value) is value

    def test_long_string_truncated(self):
        s = "a" * (MAX_ARG_STRING_LENGTH + 50)
        result = _truncate_value(s)
        assert result == "a" * MAX_ARG_STRING_LENGTH + f"... ({len(s)} chars)"

    @pytest.mark.parametrize(
        "value, expected",
        [
            ([1, 2, 3], "[list, len=3]"),
            ({"a": 1, "b": 2}, "[dict, keys=2]"),
            (b"hello", "[bytes, len=5]"),
            (object(), "[object]"),
        ],
        ids=["list", "dict", "bytes", "unknown-type"],
    )
    def test_container_summarized(self, value, expected):
        assert _truncate_value(value) == expected


class _CustomSeq:
    def __len__(self):
        return 5


class _Custom:
    pass


class TestSummarizeResult:
    """Tests for result summarization."""

    @pytest.mark.parametrize(
        "result, expected",
        [
            (None, "None"),
            ("hello world", "str(len=11)"),
            ([1, 2, 3], "list(len=3)"),
            ({"a": 1}, "dict(keys=1)"),
            (b"data", "bytes(len=4)"),
            (True, "True"),
            (False, "False"),
            (42, "42"),
            (3.14, "3.14"),
            (_CustomSeq(), "_CustomSeq(len=5)"),
            (_Custom(), "_Custom"),
        ],
        ids=[
            "none", "str", "list", "dict", "bytes", "true", "false", "int", "float",
            "custom-with-len", "custom-without-len",
        ],
    )
    def test_summary(self, result, expected):
        assert summarize_result(result) == expected
