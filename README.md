# Cerberus — Client Instrumentation Packages

> Instrumentation for API and AI agent security monitoring: what your APIs served, what your agents called, and what your models spent.

These are the libraries and gateway policies you add to your application, or place in front of it, so that a request, an MCP tool call, or an LLM call becomes something you can see. Each integration targets a different runtime and they all emit the same event schema, so they are interchangeable and can be mixed in one deployment.

Values under known sensitive key names are redacted in the client before anything is transmitted, and bearer tokens are HMAC-pseudonymized rather than stored. Source IPs are not treated as PII: the Flex Gateway policy (0.6.0+) sends them as-is, and the Python integrations' legacy IP hashing is being removed to match.

> Looking for the backend/platform (event ingestion, processing, dashboards, infrastructure)? That lives in the separate **`cerberus-int`** repository.

## Guides

Background on what these packages are for, independent of which one you use:

- [**Securing MCP servers**](./docs/mcp-security.md): tool poisoning, prompt injection that becomes a tool call, excessive agency and exfiltration by chaining. Why network controls miss them, what to record, and how it maps to OWASP.

## Packages

| Package | What it's for | Runtime | Distribution |
|---|---|---|---|
| [**cerberus-core**](./cerberus-core/README.md) | Shared sanitization + PII-hashing utilities used by the Python integrations (`SENSITIVE_KEYS`, `sanitize_dict()`, `hash_pii()`) | Python | PyPI |
| [**cerberus-django**](./cerberus-django/README.md) | Django middleware that captures HTTP request/response metadata and streams it over WebSocket — a one-line `MIDDLEWARE` addition | Python · Django | PyPI |
| [**cerberus-mcp**](./cerberus-mcp/README.md) | Drop-in `FastMCP` replacement that instruments MCP tool / resource / prompt calls | Python · MCP (FastMCP) | PyPI |
| [**cerberus-flex-gateway**](./cerberus-flex-gateway/README.md) | Custom policy for MuleSoft Anypoint Flex Gateway — captures and forwards request metadata with no application code changes | Rust → WASM (`wasm32-wasip1`) | Prebuilt bundle → customer's own Anypoint Exchange ([INSTALL.md](./cerberus-flex-gateway/INSTALL.md)) |
| [**cerberus-envoy-ai-gateway**](./cerberus-envoy-ai-gateway/README.md) | OTLP trace bridge for Envoy AI Gateway — converts the gateway's LLM + MCP telemetry into Cerberus events, deployed beside the gateway with a few OTel env vars | Python · OTLP/HTTP | PyPI / container image |

**Shared test fixtures:** [**parity-fixtures**](./parity-fixtures/README.md) — language-agnostic YAML cases that keep the Python and Rust sanitization logic byte-for-byte consistent.

## Which one do I need?

- **Django app** → [`cerberus-django`](./cerberus-django/README.md) (depends on `cerberus-core`)
- **MCP server** (FastMCP) → [`cerberus-mcp`](./cerberus-mcp/README.md) (depends on `cerberus-core`)
- **Envoy AI Gateway** in front of LLM providers / MCP servers → [`cerberus-envoy-ai-gateway`](./cerberus-envoy-ai-gateway/README.md) (depends on `cerberus-core`)
- **Any API / non-Python stack / no code changes** → [`cerberus-flex-gateway`](./cerberus-flex-gateway/README.md) deployed in front of your service
- **Building a new integration** → reuse [`cerberus-core`](./cerberus-core/README.md)'s sanitization contract and the shared event schema

## How they fit together

- All integrations emit the **same event payload** (`CoreData` / `MCPEventData`), so the Cerberus backend (`event_ingest`) needs no per-client changes.
- Sanitization happens **before** any data leaves the client, via `cerberus-core` (Python) or its ported equivalent in the Rust gateway. Redaction matches **key names** against `SENSITIVE_KEYS`, so it catches the usual suspects rather than inspecting values. Source IPs are not treated as PII: the Flex Gateway policy sends the normalized client IP as-is, and the Python integrations' remaining HMAC-SHA256 IP hashing (when a secret key is configured) is being removed to match.
- The Flex Gateway policy re-implements the sanitization logic in Rust (there is no shared crate across languages). **Parity is enforced** by [`parity-fixtures`](./parity-fixtures/README.md): `cerberus-flex-gateway/tests/parity_runner.rs` and `cerberus-django/tests/test_parity.py` consume the same YAML cases, so any drift fails CI. (`cerberus-envoy-ai-gateway` *imports* `cerberus-core` directly, so it needs no parity runner.)
  - ⚠️ If you change `SENSITIVE_KEYS` (or other sanitization rules) in `cerberus-core`, update the matching fixture in the **same PR**.

## Development & publishing

- The Python packages build with `uv build` and publish to PyPI via [`./publish_package.sh`](./publish_package.sh) `<package>` (e.g. `./publish_package.sh cerberus-core`).
- [`cerberus-flex-gateway`](./cerberus-flex-gateway/README.md) compiles to WASM and is distributed as a prebuilt bundle each customer publishes into **their own** Anypoint Exchange via the bundled `install.sh` (see [INSTALL.md](./cerberus-flex-gateway/INSTALL.md)). Maintainers build the bundle with `make bundle`; CI attaches it to a `flex-gateway-v*` GitHub Release. It can also be dropped onto a Flex Gateway pod as a `.wasm` (Local mode).
- [`cerberus-envoy-ai-gateway`](./cerberus-envoy-ai-gateway/README.md) additionally ships as a container image (`make image`, push to your registry) with Kubernetes manifests in its `deploy/` directory.
- Repo-wide guidance (architecture, commands, conventions) for contributors and AI assistants: [CLAUDE.md](./CLAUDE.md).

## License

See [LICENSE](./LICENSE).
