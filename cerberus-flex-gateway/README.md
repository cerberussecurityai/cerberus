# Cerberus Flex Gateway Custom Policy

A MuleSoft Flex Gateway custom policy (Rust → WASM, built with the PDK)
that captures HTTP request metadata, sanitizes PII, and ships events to
the Cerberus backend.

## Status: **scaffold (v1)**

The Rust source compiles with PDK 1.8.0 (`make build` requires the
toolchain — see [Setup](#setup) below). The shipped policy provides:

- Request metadata capture (header / query / body sanitization, IP
  normalization + HMAC, source IP resolution, health-endpoint filter).
- Path scoping via `capturePaths` / `excludePaths` globs.
- Per-worker bounded queue with drop-on-full counter.
- Batched outbound POST to the Cerberus backend every `flushIntervalMs`.
- Init-time HMAC secret fetch with 5-second timeout.

### Known gaps in v1

| Gap | Why |
|---|---|
| `_cerberus_metrics` extraction (response body inspection) | Mutating response bodies interacts badly with `Content-Length` / `Content-Encoding` / streaming bodies / response signing. Customers who set `_cerberus_metrics` already install at the application layer. |
| Retry / backoff on backend failures | Currently at-most-once: failed batches are dropped. |
| Circuit breaker for sustained backend outages | Without one, every flush during an outage posts into a black hole. Currently logs and moves on. |
| Policy-side observability (queue depth, drop rate, ingest-failure rate) | Currently surfaces `dropped` count via `logger::warn!` only. |
| `status_code` / `latency_ms` capture | Trivially addable in `response_filter`. |
| Streaming-body capture for >1MB JSON payloads | PDK's default `into_body_state()` caps at 1MB. Currently silently truncated/dropped for large payloads. |
| Graceful shutdown / drain | proxy-wasm has no `on_drain` hook. Up to ~`flushIntervalMs` of buffered events are lost on every pod churn (rolling deploy, OOM, scale-down). Documented and accepted. |

## Configuration (`gcl.yaml`)

| Property | Required | Default | Purpose |
|---|:---:|---|---|
| `ingestService` | ✓ | — | Cerberus backend URL. The policy POSTs to `<ingestService>/v1/ingest/batch`. |
| `token` | ✓ | — | Cerberus API key. Sent as the `X-API-Key` header on outbound requests. Trimmed at config-parse time. |
| `secretKey` | | — | HMAC key for PII hashing. Inline alternative to `backendUrl`. |
| `backendUrl` | | — | Base URL to fetch HMAC key from at startup. 5-second timeout; failure logs and falls back to raw PII. Use `https://` in production. |
| `clientIpHeader` | | `X-Forwarded-For` | Header to read the client IP from (first hop). Falls back to Envoy connection source if absent. |
| `userIdHeader` | | unset | Header to read end-user identity from (e.g. `X-User-Id`). Required for per-end-user analytics; intentionally not defaulted so each deployment picks its own header. |
| `capturePaths` | | `[]` | Glob allowlist. Empty = capture everything. Primary lever for high-RPS scoping. |
| `excludePaths` | | `[]` | Glob denylist. Wins over `capturePaths` on overlap. |
| `captureRequestBody` | | `true` | Buffer + sanitize JSON request bodies (POST/PUT/PATCH only). Disable globally to skip the buffering cost; for per-route scoping use `capturePaths` / `excludePaths`. |
| `batchSize` | | `50` | Events per outbound POST (max 1000 — server-side cap). |
| `flushIntervalMs` | | `2000` | Flush cadence. Min 100ms (prevents tight-loop misconfig). |
| `queueCapacity` | | `10000` | Per-worker queue. Total memory ~ `workers × queueCapacity × ~5KB`. |
| `logLevel` | | `info` | One of: `debug`, `info`, `warn`, `error`. |

### Header semantics

Envoy presents headers as `(name, value)` pairs with name lowercased per
HTTP/2 conventions, and multi-valued headers (e.g. `Set-Cookie`,
comma-folded `X-Forwarded-For`) appear as multiple entries with the
same name. The policy:

1. Title-cases header names (`x-api-key` → `X-Api-Key`).
2. Collapses multi-valued headers with `, ` separator before storing
   in the event payload.

### Path scoping

`capturePaths` / `excludePaths` use `globset` syntax:

- `*` matches one path segment (no slashes).
- `**` matches any number of segments.
- Patterns are exact-match — trailing slashes matter. Add both
  variants if you want to capture both forms.

Example: scope to public-API endpoints, exclude internal admin paths.

```yaml
capturePaths:
  - "/api/v1/**"
  - "/api/v2/**"
excludePaths:
  - "/api/v*/admin/**"
```

Health endpoints (`/health`, `/health_check`, `/ready`) are always
skipped regardless of filter config.

## Setup

Prerequisites (PDK 1.8.0, April 2026):

```bash
# Rust toolchain
rustup target add wasm32-wasip1

# Anypoint CLI + PDK plugin
npm install -g anypoint-cli-v4
anypoint-cli-v4 plugins:install anypoint-pdk-plugin

# Anypoint cargo extensions (build / publish helpers)
cargo install --locked cargo-anypoint cargo-llvm-cov

# Sync parity fixtures (creates tests/fixtures -> ../parity-fixtures)
make sync-fixtures
```

## Build / test

```bash
make build   # compile to wasm32-wasip1; emits target/wasm32-wasip1/release/cerberus-flex-gateway.wasm
make test    # cargo test (parity + unit)
make run     # boots a local Flex Gateway in Docker Compose with the policy attached
```

`make sync-fixtures` is required before `make test` if you've never
run it — the parity test runner reads from `tests/fixtures/`, which is
a symlink to the repo-root `parity-fixtures/` directory.

## Deployment

Two operator-facing modes are supported in v1.

### Customer installation (Connected Mode) — **no Rust required**

This is how an end customer installs the policy. Custom Flex Gateway policies
can't be shared across Anypoint orgs, so each customer publishes the (identical,
prebuilt) policy into **their own** org's Exchange. We ship a distribution
bundle; the customer runs a one-line installer:

```bash
tar -xzf cerberus-flex-gateway-policy-<version>.tar.gz
cd cerberus-flex-gateway-policy-<version>
./install.sh --org-id <your-anypoint-org-uuid>     # try --dry-run first
```

The installer needs only **Node ≥ 18** + `anypoint-cli-v4` (the PDK plugin) and
an authenticated Anypoint session — **no `rustc`/`cargo`**. It stamps the
customer's org id into the prebuilt artifacts and publishes an immutable
Exchange release via `anypoint-cli-v4 pdk policy-project release`. Full
walkthrough (prerequisites, applying the policy in API Manager, upgrade,
uninstall, troubleshooting): **[INSTALL.md](./INSTALL.md)**.

Maintainers build the bundle with `make bundle`; CI attaches it to a GitHub
Release on a `flex-gateway-v*` tag.

### Maintainer publish (our own org)

`make publish` / `make release` publish from this repo into **our** Anypoint org
(the default `[package.metadata.anypoint] group_id` in `Cargo.toml`). These
require the Rust toolchain (via `make build`) and target our org — they are
**not** the customer path. ⚠️ `make release` is immutable; don't run it as a
test.

### Local mode (development + air-gapped operators)

1. `make build` → produces `bin/cerberus_flex_gateway.wasm` and the GCL
   manifests.
2. Copy `.wasm` and `gcl.yaml` onto every Flex Gateway pod (via
   ConfigMap / volume mount).
3. Apply a `PolicyBinding` CR scoped to your API instance with the
   policy's config values.
4. Verify with `kubectl logs` — should see policy `configure` log
   lines and a successful secret-key fetch (if `backendUrl` is set).

Reference:
<https://docs.mulesoft.com/gateway/latest/flex-local-deploy-custom-policy>.

### Applying the policy in API Manager

Once the policy is in an org's Exchange (customer install or maintainer
publish, above), apply it to an API instance via the API Manager UI (Custom tab
→ select policy → fill the form rendered from `gcl.yaml`) or via CLI:

```
anypoint-cli-v4 api-mgr policy apply \
  --apiInstanceId <id> \
  --policyId cerberus-flex-gateway \
  --config '{"ingestService":"...","token":"..."}'
```

Then verify in API Manager + gateway pod logs. The customer-facing version of
this walkthrough (with a config example) is in [INSTALL.md](./INSTALL.md).

References:
- Publishing: <https://docs.mulesoft.com/pdk/latest/policies-pdk-publish-policies>
- API Manager apply: <https://docs.mulesoft.com/api-manager/latest/policies-custom-task>

## Verification end-to-end

```bash
# Drive traffic
curl -X POST https://your-flex-gateway/api/v1/users \
     -H 'Content-Type: application/json' \
     -d '{"username": "alice", "password": "hunter2"}'

# Verify the event landed in the Cerberus dashboard for your client_id.
```

The `Authorization` header value should be either `[REDACTED]` (no
secret configured) or a 64-char lowercase hex digest (HMAC-SHA256).
The body should have `password` replaced by `[REDACTED]`.

## Parity testing

The crate duplicates `SENSITIVE_KEYS` / `SENSITIVE_HEADERS` /
`REDACTED` and reimplements `sanitize_dict` / `normalize_ip` /
`hash_pii` so the WASM target has no Python dependency. The Cerberus
implementations all consume the same YAML fixtures from
`../parity-fixtures/`:

- `cerberus-django/tests/test_parity.py` runs them against `cerberus_core`.
- `cerberus-flex-gateway/tests/parity_runner.rs` runs them against the
  Rust ports.

If you change a constant in `cerberus-core/src/cerberus_core/sanitization.py`,
update the fixture file in the **same PR** so the other implementations
are forced to follow.

## Layout

```
cerberus-flex-gateway/
├── Cargo.toml
├── Makefile                  # `make bundle` assembles the customer tarball
├── README.md (this file)
├── INSTALL.md                # customer install guide (also ships in the bundle)
├── install.sh                # customer installer (publishes into their org)
├── rust-toolchain.toml       # pinned build toolchain (build-side only)
├── scripts/
│   └── bundle.sh             # `make bundle` staging logic
├── definition/
│   └── gcl.yaml              # operator-facing config schema
├── playground/
│   ├── config/
│   │   ├── api.yaml          # Flex Gateway API definition
│   │   └── custom-policies/  # populated by `make run`
│   └── docker-compose.yaml   # local Flex Gateway harness
├── src/
│   ├── lib.rs                # entrypoint, request/response/flush handlers
│   ├── config.rs             # Config struct (mirrors gcl.yaml)
│   ├── event.rs              # CerberusEvent (CoreData mirror)
│   ├── sanitize.rs           # SENSITIVE_KEYS/HEADERS, sanitize_value
│   ├── hash.rs               # hash_pii, normalize_ip
│   ├── source_ip.rs          # XFF first-hop / stream fallback
│   ├── secret.rs             # init-time secret fetch
│   ├── path_filter.rs        # capturePaths / excludePaths globs
│   ├── queue.rs              # bounded RefCell<VecDeque>
│   └── sink.rs               # POST /v1/ingest/batch
└── tests/
    ├── fixtures              # symlink → ../../parity-fixtures (created by `make sync-fixtures`)
    └── parity_runner.rs      # consumes the YAML fixtures
```

## Architecture references

- [`pdk-custom-policy-examples`](https://github.com/mulesoft/pdk-custom-policy-examples) — `metrics/`, `certs/`, `ip-filter/`, `crypto/` are the closest stylistic precedents.
