"""Guard against CONSUMED_ATTRIBUTES drifting behind what the mappers read.

The rejection in ``pipeline._reject_bridge_owned_attributes`` is only as good as
these declarations. They were hand-written once and silently omitted all 14
token-count attributes, so an operator could hash ``llm.token_count.prompt``
while the mapper copied its raw value into ``custom_data.tokens_prompt`` — the
exact dual write the rejection exists to prevent.

This scans each mapper for attribute-shaped string literals and asserts every
one is declared. Adding a new attribute read without declaring it fails here.
"""

import ast
import pathlib
import re

from cerberus_envoy_ai_gateway import mapper_llm, mapper_mcp

# Dotted, lower-case, no scheme/slashes — matches OTel attribute names and not
# mime types, URL templates, or method names.
ATTRIBUTE_SHAPED = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")


def _literals(module) -> set[str]:
    source = pathlib.Path(module.__file__).read_text()
    return {
        node.value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Constant)
        if isinstance(node.value, str)
        if ATTRIBUTE_SHAPED.match(node.value)
    }


def _declared(module) -> set[str]:
    return set(module.CONSUMED_ATTRIBUTES)


def test_llm_mapper_declares_every_attribute_it_reads():
    prefixes = mapper_llm.CONSUMED_ATTRIBUTE_PREFIXES
    undeclared = {
        name
        for name in _literals(mapper_llm) - _declared(mapper_llm)
        if not name.startswith(prefixes)
    }
    assert not undeclared, (
        f"mapper_llm reads {sorted(undeclared)} but does not declare them in "
        "CONSUMED_ATTRIBUTES, so an operator could select them and dual-write"
    )


def test_mcp_mapper_declares_every_attribute_it_reads():
    undeclared = _literals(mapper_mcp) - _declared(mapper_mcp)
    assert not undeclared, (
        f"mapper_mcp reads {sorted(undeclared)} but does not declare them in "
        "CONSUMED_ATTRIBUTES, so an operator could select them and dual-write"
    )


def test_token_attributes_are_declared():
    # The specific omission that motivated this file.
    for candidates in mapper_llm._TOKEN_FIELDS.values():
        for candidate in candidates:
            assert candidate in mapper_llm.CONSUMED_ATTRIBUTES
