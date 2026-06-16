# Cerberus — Client Instrumentation Packages

> Client-side instrumentation that captures HTTP request/event metadata and streams it to the **Cerberus** API monitoring & analytics platform.

This repository is a monorepo of the **client-side** Cerberus integrations — the libraries and gateway policy you add to your application (or place in front of it) to send request metrics to Cerberus. Each integration targets a different runtime but emits the **same event schema**, so they're interchangeable from the backend's point of view.

> Looking for the backend/platform (event ingestion, processing, dashboards, infrastructure)? That lives in the separate **`cerberus-int`** repository.

## Packages

| Package | What it's for | Runtime | Distribution |
|---|---|---|---|
| [**cerberus-core**](./cerberus-core/README.md) | Shared sanitization + PII-hashing utilities used by the Python integrations (`SENSITIVE_KEYS`, `sanitize_dict()`, `hash_pii()`) | Python | PyPI |
| [**cerberus-django**](./cerberus-django/README.md) | Django middleware that captures HTTP request/response metadata and streams it over WebSocket — a one-line `MIDDLEWARE` addition | Python · Django | PyPI |
| [**cerberus-mcp**](./cerberus-mcp/README.md) | Drop-in `FastMCP` replacement that instruments MCP tool / resource / prompt calls | Python · MCP (FastMCP) | PyPI |
| [**cerberus-flex-gateway**](./cerberus-flex-gateway/README.md) | Custom policy for MuleSoft Anypoint Flex Gateway — captures and forwards request metadata with no application code changes | Rust → WASM (`wasm32-wasip1`) | Prebuilt bundle → customer's own Anypoint Exchange ([INSTALL.md](./cerberus-flex-gateway/INSTALL.md)) |

**Shared test fixtures:** [**parity-fixtures**](./parity-fixtures/README.md) — language-agnostic YAML cases that keep the Python and Rust sanitization logic byte-for-byte consistent.

## Which one do I need?

- **Django app** → [`cerberus-django`](./cerberus-django/README.md) (depends on `cerberus-core`)
- **MCP server** (FastMCP) → [`cerberus-mcp`](./cerberus-mcp/README.md) (depends on `cerberus-core`)
- **Any API / non-Python stack / no code changes** → [`cerberus-flex-gateway`](./cerberus-flex-gateway/README.md) deployed in front of your service
- **Building a new integration** → reuse [`cerberus-core`](./cerberus-core/README.md)'s sanitization contract and the shared event schema

## How they fit together

- All integrations emit the **same event payload** (`CoreData` / `MCPEventData`), so the Cerberus backend (`event_ingest`) needs no per-client changes.
- PII (e.g. source IPs) is pseudonymized with **HMAC-SHA256** and sensitive headers/params are redacted **before** any data leaves the client — via `cerberus-core` (Python) or its ported equivalent in the Rust gateway.
- The gateway re-implements the sanitization logic in Rust (there is no shared crate across languages). **Parity is enforced** by [`parity-fixtures`](./parity-fixtures/README.md): `cerberus-flex-gateway/tests/parity_runner.rs` and `cerberus-django/tests/test_parity.py` consume the same YAML cases, so any drift fails CI.
  - ⚠️ If you change `SENSITIVE_KEYS` (or other sanitization rules) in `cerberus-core`, update the matching fixture in the **same PR**.

## Development & publishing

- The Python packages build with `uv build` and publish to PyPI via [`./publish_package.sh`](./publish_package.sh) `<package>` (e.g. `./publish_package.sh cerberus-core`).
- [`cerberus-flex-gateway`](./cerberus-flex-gateway/README.md) compiles to WASM and is distributed as a prebuilt bundle each customer publishes into **their own** Anypoint Exchange via the bundled `install.sh` (see [INSTALL.md](./cerberus-flex-gateway/INSTALL.md)). Maintainers build the bundle with `make bundle`; CI attaches it to a `flex-gateway-v*` GitHub Release. It can also be dropped onto a Flex Gateway pod as a `.wasm` (Local mode).
- Repo-wide guidance (architecture, commands, conventions) for contributors and AI assistants: [CLAUDE.md](./CLAUDE.md).

## License

See [LICENSE](./LICENSE).
