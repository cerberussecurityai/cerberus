# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cerberus is a monorepo of client-side instrumentation packages that ship request/event metadata to the Cerberus backend. Four Python packages and one Rust crate:

```
cerberus/
├── cerberus-core/             # Shared Python sanitization utilities
│   ├── pyproject.toml
│   ├── src/cerberus_core/sanitization.py
│   └── tests/
├── cerberus-django/           # Django middleware (HTTP, WebSocket transport)
│   ├── pyproject.toml
│   └── src/cerberus_django/
├── cerberus-mcp/              # MCP server instrumentation
│   ├── pyproject.toml
│   └── src/cerberus_mcp/
├── cerberus-envoy-ai-gateway/ # OTLP trace bridge for Envoy AI Gateway (LLM + MCP)
│   ├── pyproject.toml
│   ├── Makefile
│   ├── Dockerfile
│   ├── src/cerberus_envoy_ai_gateway/
│   ├── deploy/                # K8s manifests + gateway-side env block
│   ├── playground/            # local harness (aigw standalone + docker compose)
│   └── tests/                 # golden OTLP span fixtures
├── cerberus-flex-gateway/     # Rust → WASM custom policy for MuleSoft Flex Gateway
│   ├── Cargo.toml
│   ├── Makefile               # incl. `make bundle` (customer tarball)
│   ├── rust-toolchain.toml    # pinned build toolchain (build-side only)
│   ├── install.sh             # customer installer → their own org's Exchange
│   ├── INSTALL.md             # customer install guide (ships in the bundle)
│   ├── scripts/bundle.sh      # `make bundle` staging logic
│   ├── definition/gcl.yaml    # operator-facing config schema
│   ├── src/                   # lib.rs, sanitize.rs, hash.rs, etc.
│   ├── tests/parity_runner.rs # consumes parity-fixtures/
│   └── README.md              # operator-facing deployment guide
├── parity-fixtures/           # YAML fixtures shared by Python + Rust parity runners
│   ├── README.md
│   ├── sanitize_dict.yaml
│   ├── normalize_ip.yaml
│   ├── hash_pii.yaml
│   ├── content_type.yaml
│   ├── sensitive_headers.yaml
│   └── path_filter.yaml       # Rust-only (Django scopes per-app)
├── CLAUDE.md
├── LICENSE
└── publish_package.sh
```

The four Python packages are published independently to PyPI:
- `cerberus-core` — shared sanitization logic and sensitive key definitions
- `cerberus-django` — Django middleware (depends on cerberus-core)
- `cerberus-mcp` — MCP server wrapper (depends on cerberus-core)
- `cerberus-envoy-ai-gateway` — Envoy AI Gateway OTLP bridge (depends on cerberus-core); also ships as a container image (`make image`)

`cerberus-flex-gateway` is **not** published to PyPI — it's a Rust crate that compiles to a `.wasm` artifact. Because custom Flex Gateway policies can't be shared across Anypoint orgs, distribution is **customer-side**: `make bundle` builds a prebuilt tarball (CI attaches it to a `flex-gateway-v*` GitHub Release), and each customer runs the bundled `install.sh --org-id <uuid>` to publish it into *their own* org's Exchange — no Rust required (see `cerberus-flex-gateway/INSTALL.md`). `make publish` / `make release` are the **maintainer** path into *our* org only. It can also be dropped onto a Flex Gateway pod as a `.wasm` (Local mode). See `cerberus-flex-gateway/README.md`.

## Packages

### cerberus-core

Shared utilities used by both cerberus-django and cerberus-mcp:
- `SENSITIVE_KEYS` — unified frozenset of key names to redact (passwords, tokens, PII, etc.)
- `SENSITIVE_HEADERS` — HTTP headers to always redact
- `REDACTED` — sentinel string `[REDACTED]`
- `sanitize_dict()` — recursive dict/list sanitization
- `hash_pii()` — HMAC-SHA256 pseudoanonymization for PII values

**Tests:** `cd cerberus-core && .venv/bin/python -m pytest tests/ -v`

### cerberus-django

Django middleware that intercepts HTTP requests/responses and streams metrics via WebSocket.

**Key behavior:**
- Captures headers, query params, body, user agent, source IP
- Sanitizes sensitive data using cerberus-core before transmission
- Hashes PII (source IP) with HMAC-SHA256 if secret_key is configured
- Background thread + async event loop for non-blocking WebSocket sends

**Configuration:** `CERBERUS_CONFIG` dict in Django settings with `token`, `client_id`, `ws_url`

### cerberus-mcp

Drop-in replacement for `FastMCP` that instruments MCP tool/resource/prompt calls.

**Key behavior:**
- Subclasses `FastMCP` — one-line change to instrument an MCP server
- Wraps handlers to capture timing, arguments, errors, results
- Extracts session/client identity from MCP Context objects
- Same WebSocket transport pattern as cerberus-django
- Schema reporting: on first event, introspects registered tools/resources/prompts via FastMCP internal registries (`_tool_manager`, `_resource_manager`, `_prompt_manager`) and emits a `mcp_schema_report` event with declared names, descriptions, `input_schema`, and prompt arguments
- Thread-safe schema reporting with `threading.Lock` to prevent duplicate reports from concurrent handlers
- Wrapper functions set `__wrapped__` attribute to preserve `inspect.signature()` chain for FastMCP parameter validation

**Configuration:** `CerberusMCP("name", cerberus_config={"token": ..., "client_id": ..., "ws_url": ...})`

**Key files:**
- `server.py` — `CerberusMCP` class, `_wrap_handler()`, `_emit_event()`, `_report_schema()`
- `structs.py` — `MCPEventData` dataclass
- `transport.py` — WebSocket transport
- `config.py` — Configuration handling

### cerberus-envoy-ai-gateway

Standalone OTLP/HTTP trace bridge for [Envoy AI Gateway](https://aigateway.envoyproxy.io). The gateway's extproc already emits OpenInference LLM spans and MCP spans; operators point `OTEL_EXPORTER_OTLP_ENDPOINT` (+ `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`) at the bridge, which maps spans to CoreData/MCPEventData-shaped events and batch-POSTs to `/v1/ingest/batch` — same wire contract as the flex-gateway policy. Never in the request path (trace export is async).

**Key behavior:**
- LLM spans (`llm.model_name`, `llm.system`, `llm.token_count.*`, `input.value`/`output.value`) → events with `endpoint=llm://{provider}/{model}`, `scheme="llm"`, `method=llm_chat_completion|llm_messages|llm_embeddings|llm_completion|llm_call`
- MCP spans (`mcp.method.name`, `mcp.tool.name`, `mcp.backend.name`, ...) → standard MCP events (`mcp://{server}/{handler}`, `mcp_tool_call` etc.) feeding the discovery tables. ai-gateway v0.7.0 does **not** record tool arguments in spans, so gateway-observed tool calls are name-level only (`arguments_observed` empty)
- Sanitization/hashing via **direct `cerberus-core` import** — an importer, not a port, so **no parity runner needed**
- Same operational pattern as flex-gateway: bounded queue (drop-on-full), batched POST, init-time HMAC secret fetch, at-most-once delivery
- Attribute names verified against ai-gateway v0.7.0 source; mappers probe candidate keys defensively — re-verify with `CERBERUS_DUMP_SPANS=true` via the playground when bumping supported gateway versions

**Build/test:**
```bash
cd cerberus-envoy-ai-gateway
make venv && make test    # pytest (golden span fixtures), ruff/black/mypy via make lint/typecheck
make run                  # playground: docker compose + standalone `aigw run`
```

**Key files:** `app.py` (OTLP receiver), `classify.py`, `mapper_llm.py`, `mapper_mcp.py`, `pipeline.py` (sanitize/hash/caps), `sink.py` (batch POST), `deploy/` (operator artifacts).

### cerberus-flex-gateway

Rust → WASM custom policy for MuleSoft Flex Gateway. Captures HTTP request metadata, sanitizes PII, batches events, and POSTs them to the Cerberus backend's batch ingest endpoint.

**Why a separate crate, not a Python wheel:** MuleSoft Flex Gateway custom policies must be written in Rust and compiled to WASM. The crate uses MuleSoft's PDK 1.8.0 toolchain, compiled to `wasm32-wasip1`.

**Build/test:**
```bash
cd cerberus-flex-gateway
make sync-fixtures   # symlink ../parity-fixtures into tests/fixtures (one-time)
make build           # compile to wasm32-wasip1
make test            # cargo test (parity + unit)
make run             # local Flex Gateway in Docker for dev
make bundle          # assemble the customer distribution tarball into dist/
```

**Deployment:** see `cerberus-flex-gateway/README.md` for Local-mode (copy `.wasm` + `gcl.yaml` onto pod), customer Connected-mode install (`INSTALL.md` — prebuilt bundle + `install.sh` into the customer's own org, no Rust), and the maintainer publish path (`make publish` / `make release` into our org).

**Parity guarantees:** the crate duplicates `SENSITIVE_KEYS` / `SENSITIVE_HEADERS` / sanitize/hash/normalize logic from `cerberus-core` (no shared crate; would force translating Python types). Drift is caught by `tests/parity_runner.rs` which consumes the same `../parity-fixtures/*.yaml` as `cerberus-django/tests/test_parity.py`. **If you change `SENSITIVE_KEYS` in `cerberus-core/src/cerberus_core/sanitization.py`, update the matching fixture file in the same PR.**

## Development

### Building packages
```bash
cd cerberus-core && uv build    # or cerberus-django / cerberus-mcp
```

### Publishing to PyPI
```bash
./publish_package.sh cerberus-core
./publish_package.sh cerberus-django
./publish_package.sh cerberus-mcp
./publish_package.sh cerberus-envoy-ai-gateway
```

### Running tests
```bash
cd cerberus-core && uv venv && uv pip install -e . pytest && .venv/bin/python -m pytest tests/ -v
```

### Debug logging
Set `CERBERUS_DEBUG=true` environment variable to enable verbose logging in both cerberus-django and cerberus-mcp.

## Architecture Notes

- Both cerberus-django and cerberus-mcp use the same event payload format (CoreData/MCPEventData) so event_ingest requires no changes
- MCP events use `mcp://` URI scheme in the `endpoint` field and `mcp_*` prefixed method names
- LLM events (cerberus-envoy-ai-gateway) use `llm://{provider}/{model}` endpoints, `scheme="llm"`, and `llm_*` prefixed methods — stored generically in `processed_events`; `llm_*` must never collide with the `mcp_*` routing prefix. Requires the cerberus-int AI-scheme guards: event_process excludes non-HTTP schemes from endpoint discovery (`llm_chat_completion` overflows `endpoint_discovery.method VARCHAR(10)` and would poison the discovery flush) and event_ingest exempts `mcp://`/`llm://` from the health-endpoint filter (a tool named `health` is real traffic)
- MCP-specific metadata (arguments, duration, session info) goes in `custom_data`
- Event queue is bounded (10,000 max for cerberus-mcp) to prevent unbounded memory growth
- WebSocket transport is shared pattern but not shared code (each package has its own copy for independence)

### MCP Event Methods

| Method | Description | Tracked In |
|--------|-------------|------------|
| `mcp_tool_call` | Tool invocation | `mcp_tool_discovery` |
| `mcp_resource_read` | Resource read | `mcp_resource_discovery` |
| `mcp_prompt_get` | Prompt invocation | `mcp_prompt_discovery` |
| `mcp_schema_report` | Schema introspection report (emitted once per server startup) | All three discovery tables (sets `description`, `input_schema`, `declared_arguments`, `schema_only=true`) |

### Schema Report Flow

1. `CerberusMCP._emit_event()` fires on the first actual tool/resource/prompt call
2. Thread-safe check via `_schema_report_lock` ensures `_report_schema()` runs exactly once
3. `_report_schema()` introspects FastMCP internals: `_tool_manager._tools`, `_resource_manager._resources`/`_templates`, `_prompt_manager._prompts`
4. Emits a single `mcp_schema_report` event with `custom_data` containing `tools`, `resources`, `prompts` arrays
5. `event_process` routes this to `MCPDiscoveryUpdater._handle_schema_report()` which creates `schema_only=True` records
6. On subsequent real calls, UPSERT clears `schema_only` to `False` via `existing AND EXCLUDED`
