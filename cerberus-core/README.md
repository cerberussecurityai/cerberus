# cerberus-core

Shared utilities for the [Cerberus](https://github.com/gpotrock/cerberus) monitoring ecosystem.

This package provides common sanitization logic and sensitive key definitions used by:
- [cerberus-django](https://pypi.org/project/cerberus-django/) — Django middleware
- [cerberus-mcp](https://pypi.org/project/cerberus-mcp/) — MCP server instrumentation

## Installation

```bash
pip install cerberus-core
```

You typically don't need to install this directly — it's pulled in automatically as a dependency of `cerberus-django` or `cerberus-mcp`.

## Usage

```python
from cerberus_core import sanitize_dict, SENSITIVE_KEYS, REDACTED

data = {"username": "alice", "password": "hunter2", "nested": {"token": "abc"}}
clean = sanitize_dict(data)
# {"username": "alice", "password": "[REDACTED]", "nested": {"token": "[REDACTED]"}}
```

## What's Included

- **`SENSITIVE_KEYS`** — Unified set of key names whose values should be redacted (passwords, tokens, API keys, PII identifiers, etc.)
- **`SENSITIVE_HEADERS`** — HTTP headers that should always be redacted
- **`REDACTED`** — The sentinel string `[REDACTED]`
- **`sanitize_dict(data, extra_keys=None)`** — Recursively redacts sensitive keys in dicts and lists; `extra_keys` adds caller-supplied names on top of `SENSITIVE_KEYS`
