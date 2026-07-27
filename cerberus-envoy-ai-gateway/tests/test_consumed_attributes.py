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

from cerberus_envoy_ai_gateway import mapper_llm, mapper_mcp, spanfields

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


def test_shared_spanfields_declares_every_attribute_it_reads():
    """Both mappers call into spanfields, so its reads need declaring too.

    Scanning only the mapper modules missed "error.type" (read by
    error_message()), leaving the declaration surface narrower than the actual
    read surface.
    """
    undeclared = _literals(spanfields) - _declared(spanfields)
    assert not undeclared, (
        f"spanfields reads {sorted(undeclared)} but does not declare them in "
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


def _fstring_attribute_prefixes(module) -> set[str]:
    """Static leading text of every f-string in the module that names an attribute.

    ``attrs.get(f"gen_ai.request.{param}")`` assembles a name at runtime, so the
    literal scan above cannot see it — which is exactly how the three
    ``gen_ai.request.*`` parameters stayed undeclared through the scan's own
    introduction. Requiring the static prefix to be declared covers the whole
    family without enumerating suffixes.
    """
    source = pathlib.Path(module.__file__).read_text()
    prefixes = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.JoinedStr) or not node.values:
            continue
        head = node.values[0]
        if isinstance(head, ast.Constant) and isinstance(head.value, str) and "." in head.value:
            prefixes.add(head.value)
    return prefixes


def test_dynamically_built_attribute_names_are_declared_by_prefix():
    """A runtime-assembled name must have its prefix in CONSUMED_ATTRIBUTE_PREFIXES.

    Deliberately does *not* accept "some declared attribute happens to start with
    this prefix" as coverage: ``gen_ai.request.input`` is declared via
    ``_INPUT_KEYS``, and accepting that vouched for the whole
    ``gen_ai.request.*`` family — including the three parameters that were
    actually undeclared. The suffix is unknown at import time, so only a prefix
    declaration genuinely covers the family.
    """
    for module in (mapper_llm, mapper_mcp):
        declared = tuple(getattr(module, "CONSUMED_ATTRIBUTE_PREFIXES", ()))
        for prefix in _fstring_attribute_prefixes(module):
            assert declared and prefix.startswith(declared), (
                f"{module.__name__} builds attribute names starting {prefix!r} at runtime "
                "but CONSUMED_ATTRIBUTE_PREFIXES does not cover it — a literal scan cannot "
                "see these, so the prefix must be declared explicitly"
            )
