# Development Guide

Maintainer-facing guide for the Cerberus Flex Gateway custom policy:
local dev-env setup (Anypoint account → `make run` → verify a sanitized
batch at the mock backend), build/test, parity testing, publishing, and
the deferred-work backlog. Setup instructions assume Apple Silicon
macOS.

Operator configuration and deployment guidance lives in
[README.md](./README.md); the customer install guide is
[INSTALL.md](./INSTALL.md).

## Prerequisites

```bash
# Node 18+ — the anypoint-pdk-plugin uses modern JS syntax that breaks on Node 16.
nvm install 20 && nvm use 20

# Rust + the wasm target.
brew install rustup
rustup target add wasm32-wasip1

# Cargo helpers used by the PDK build/publish pipeline.
cargo install --locked cargo-generate
cargo install --locked cargo-anypoint@1.8.0
cargo install --locked cargo-llvm-cov

# Docker Desktop with Rosetta enabled for x86_64 emulation.
# Settings → General → "Use Rosetta for x86/amd64 emulation on Apple Silicon".
# The mulesoft/flex-gateway image is amd64-only; running it on M-series
# Macs requires Rosetta. This option may not appear depending on your Docker
# version, in which case you can assume it's enabled.
```

## Anypoint Platform setup

1. **Create a free Anypoint trial:** https://anypoint.mulesoft.com/login/signup
2. Note your **Organization UUID** from Anypoint console → Access Management →
   Organization (it's a UUID, not the org name).
3. Note your **Sandbox Environment UUID** from Access Management → Environments.

### Create a Connected App

Anypoint console → Access Management → Connected Apps → **Create app**:

- Name: `cerberus-pdk-cli` (anything memorable)
- Type: **App acts on its own behalf** (client credentials grant) — *not* "on
  behalf of a user"
- Scopes (add for the **Sandbox** environment, not just root org):
  - **View Organization** *(Access Management group)*
  - **Read Servers** *(Runtime Manager group)*
  - **Manage Servers** *(Runtime Manager group)*
  - **Exchange Contributor** — needed for `make publish` / `make release`
  - **Manage APIs Configuration** — needed if you'll apply the policy via
    API Manager in connected mode

After saving, **copy the client_secret immediately** — it's only shown once.
If you lose it you'll need to rotate.

## Install the Anypoint CLI

```bash
npm install -g anypoint-cli-v4
anypoint-cli-v4 plugins:install anypoint-pdk-plugin   # NB: not "anypoint-cli-pdk-plugin"
```

The plugin was renamed in PDK 1.7.0 — older docs reference the wrong name.

## Configure CLI authentication

```bash
anypoint-cli-v4 conf client_id <connected-app-client-id>
anypoint-cli-v4 conf client_secret <connected-app-client-secret>
anypoint-cli-v4 conf organization <org-uuid>
anypoint-cli-v4 conf environment Sandbox
```

Smoke test (should print your org without prompting):

```bash
anypoint-cli-v4 account business-group list
anypoint-cli-v4 pdk get-token   # prints a bearer token
```

### Common 401 causes

- **`/accounts/login` in the error URL** → the CLI is falling back to
  username/password auth. Run `anypoint-cli-v4 conf username --delete` and
  `password --delete` to clear stale values from earlier setup.
- **Connected App scopes only granted at root org** → the picker requires
  selecting a business-group/environment when adding scopes. Re-grant for the
  specific Sandbox env you'll target.
- **Wrong `organization` UUID** → must be the org/BG where the Connected App
  scopes were granted.

## Generate the registration.yaml

The Flex Gateway docker image needs a `registration.yaml` to start, even in
local mode. Generate it once via `flexctl`:

```bash
cd cerberus-flex-gateway/playground/config

docker run --rm \
  --platform linux/amd64 \
  --entrypoint flexctl \
  -v "$(pwd)":/registration \
  -u $(id -u) \
  mulesoft/flex-gateway:1.10.0 \
  registration create \
  --client-id=<connected-app-client-id> \
  --client-secret=<connected-app-client-secret> \
  --organization=<org-uuid> \
  --environment=<sandbox-env-uuid> \
  --connected=false \
  --output-directory=/registration \
  cerberus-local-dev
```

**Critical flag:** `--connected=false`. With `--connected=true`, the gateway
rejects local `api.yaml` files (`the resource is not allowed in connected
mode`) — connected mode expects API definitions to come from API Manager.

If registration fails with *"an active target with the same name already
exists"*, either pick a different name (e.g. `cerberus-local-dev2`) or delete
the old entry in Anypoint → Runtime Manager → Flex Gateway.

The output (`registration.yaml` + `certificate.yaml`) is gitignored — it's
tied to a specific Connected App and Anypoint env, so don't commit it.

## Build and run

```bash
cd cerberus-flex-gateway

make sync-fixtures    # one-time: symlink ../parity-fixtures into tests/fixtures
make build            # compile to wasm32-wasip1 + emit GCL artifacts
make test             # cargo test (parity + unit)
make run              # docker compose up — blocks the terminal
```

`make run` boots two containers:

- `playground-local-flex-1` — Flex Gateway listening on `localhost:8081`
- `playground-echo-1` — `mendhak/http-https-echo` playing two roles:
  - the **upstream** the gateway routes traffic to
  - the **mock Cerberus backend** that the policy POSTs sanitized batches to
    (because `playground/config/api.yaml` sets `ingestService: http://echo:8080`)

Look for these in the logs to confirm a clean boot:

```
all dependencies initialized. starting workers
cerberus-flex-gateway: configured with token_len=9
```

## Verify end to end

In a second terminal, send a request that exercises sanitization:

```bash
curl -X POST 'http://localhost:8081/api/test?password=hunter2&user=alice' \
  -H 'Authorization: Bearer secret-token' \
  -H 'X-Forwarded-For: 1.2.3.4' \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"abc","note":"hi"}'
```

The upstream echoes the proxied request immediately (200 OK with the request
body). After ~2s the policy flushes a batch — find it with:

```bash
docker logs playground-echo-1 2>&1 | grep -B 1 -A 80 '"path": "/v1/ingest/batch"'
```

Expected sanitization in the batch payload:

| Field | Sent | In batch |
|---|---|---|
| `query.password` | `hunter2` | `[REDACTED]` |
| `query.user` | `alice` | `alice` (not sensitive) |
| `body.password` | `abc` | `[REDACTED]` |
| `body.email` | `alice@example.com` | passthrough (not in `SENSITIVE_KEYS`) |
| `Authorization` header | `Bearer secret-token` | HMAC-SHA256 hash |
| Source IP | `1.2.3.4` (from XFF) | HMAC-SHA256 hash |
| `endpoint` | — | `/api/test` |
| `timestamp` | — | RFC 3339 UTC, microsecond precision |

To test the no-secret fallback (PII passes through with a warn log), comment
out `secretKey:` in `playground/config/api.yaml` and `make run` again.

## Iteration loop

After editing Rust code: `make build` regenerates the wasm artifact and the
GCL implementation YAML. `make run` re-copies them into
`playground/config/custom-policies/` and restarts the gateway.

Editing `definition/gcl.yaml` regenerates `src/generated/config.rs` (commit
both files together — they're a paired set).

## Cleanup

```bash
docker compose -f playground/docker-compose.yaml down
```

To remove the registered server entry from Anypoint: console → Runtime Manager
→ Flex Gateway → find your gateway name → Delete. Stale entries block
re-registration with the same name.

## Known gotchas

- **Crate name uses underscores** (`cerberus_flex_gateway`) so
  `cargo anypoint get-name` matches the wasm artifact filename. Anypoint
  Exchange asset IDs in `[package.metadata.anypoint]` keep hyphens.
- **`src/generated/`** is committed (matches the `pdk policy-project create`
  scaffold convention). `make build-asset-files` regenerates `config.rs` from
  `definition/gcl.yaml` — diffs in PRs there are the signal that the GCL was
  edited.
- **`format: service`** on URL fields in `gcl.yaml` is what causes Flex to
  register an Envoy cluster for outbound dispatch. Without it,
  `dispatch_http_call` fails with `Proxy status problem: BadArgument`.
- **Node 16 breaks** the `anypoint-pdk-plugin` with an opaque `Unexpected
  token '{'` syntax error. Use Node 18+.

## Parity testing

The crate duplicates `SENSITIVE_KEYS` / `SENSITIVE_HEADERS` /
`REDACTED` and reimplements `sanitize_dict` / `normalize_ip` /
`hash_pii` so the WASM target has no Python dependency. The Cerberus
implementations all consume the same YAML fixtures from
`../parity-fixtures/`:

- `cerberus-django/tests/test_parity.py` runs them against `cerberus_core`.
- `cerberus-flex-gateway/tests/parity_runner.rs` runs them against the
  Rust ports.

`custom_pii_rules.yaml` (the customer rule engine) and
`path_filter.yaml` are Rust-only: this crate ships those features
first, and the fixtures are the contract the Python implementations
must match when they adopt them.

If you change a constant in `cerberus-core/src/cerberus_core/sanitization.py`,
update the fixture file in the **same PR** so the other implementations
are forced to follow.

## Publishing and releasing

### Customer distribution bundle

`make bundle` assembles
`dist/cerberus-flex-gateway-policy-<version>.tar.gz`: the prebuilt wasm
+ implementation GCL, the definition source, `install.sh`, and
`INSTALL.md` — no Rust sources. Our Anypoint group id is rewritten to a
placeholder that `install.sh` stamps with the customer's org id at
install time (see `scripts/bundle.sh`). CI builds the bundle and
attaches it to a GitHub Release on `flex-gateway-v*` tags; customers
publish it into their own org's Exchange per `INSTALL.md`.

### Maintainer publish (our own org)

`make publish` / `make release` publish from this repo into **our**
Anypoint org (the default `[package.metadata.anypoint] group_id` in
`Cargo.toml`). Both build first, so they need the Rust toolchain — they
are **not** the customer path. ⚠️ `make release` publishes an immutable
Exchange version; don't run it as a test.

## Planned improvements

None of these block production use — each was deliberately scoped out
of the initial release, with the current behavior documented and safe
(the customer-visible ones are summarized under "Operational notes" in
`README.md`). Each row records today's behavior and the reasoning.

| Improvement | Current behavior / why deferred |
|---|---|
| `_cerberus_metrics` extraction | Requires *stripping* the injected key before the client sees it — response mutation, which this policy never does (the observe-only guarantee is the point). Mutation interacts badly with `Content-Length` / `Content-Encoding` / streaming bodies / response signing. Customers who set `_cerberus_metrics` already install at the application layer. |
| Retry / backoff on backend failures | At-most-once today: failed batches are dropped. |
| Bounded cutoff for long-lived streams | With `captureResponseBody` on, an event ships when its response body *ends*, so a keep-alive `text/event-stream` holds its event (and reports `latency_ms` as the stream's lifetime) until the connection closes. Memory stays capped at head+tail and the client is unaffected. Future work: ship with a truncation marker after N bytes / N seconds. |
| Event-loss on upstream reset before response headers | If the upstream connection resets/times out before response headers exist, the response filter never runs and the request's event is lost (pre-existing behavior, unchanged by response capture). Fixing it means pushing at request time with a mutable-event queue. |
| Pre-flight event-size guard | A request body (up to the 1 MiB buffer) plus response head+tail can push a serialized event past the ingest endpoint's per-event size cap, dropping the whole event server-side. Sizing guidance is in the README; a gateway-side guard is future work. |
| Circuit breaker for sustained backend outages | Without one, every flush during an outage posts into a black hole. Currently logs and moves on. |
| Policy-side observability (queue depth, drop rate, ingest-failure rate) | Currently surfaces `dropped` count via `logger::warn!` only. |
| Streaming-body capture for >1MB JSON *request* payloads | PDK's default `into_body_state()` caps at 1MB; large request payloads are silently truncated/dropped. (Response bodies stream and are not subject to this cap.) |
| Semantic scrubbing for AI prompts/responses | `customPiiPatterns` value rules scrub anything regex-shaped inside prompt text, but free-form PII with no stable shape (names, addresses in prose) still can't be caught. `captureAiContent: false` is the zero-egress option. |
| Graceful shutdown / drain | proxy-wasm has no `on_drain` hook. Up to ~`flushIntervalMs` of buffered events are lost on every pod churn (rolling deploy, OOM, scale-down). Documented and accepted. |
| Body/path-derived session keys | Session handles that live in JSON bodies (A2A `contextId`, OpenAI Responses conversation ids, AG-UI `threadId`) or URL paths (`/threads/{id}`) are not sampling keys in v1 — using them means buffering the body (or adding a path-pattern config) *before* the sampling decision. That traffic falls to the principal/user tier: whole-per-user, coarser but safe. Decide-late on response-body-minted handles additionally requires `captureResponseBody`. |
| Per-user sampling knob for chat-shaped LLM traffic | Under `sampleBy: session`, well-known LLM paths without an explicit session key are hardcoded to per-request sampling (`sampling_decision` in lib.rs documents why: chat turns re-send their history, so whole-session capture is O(n²) bytes for no added content). A per-user mode would additionally preserve cross-turn ordering; deferred until a concrete need appears. |
| Queue drop preference for handshake events | `EventQueue` drops on overflow regardless of event kind, so under sustained overload a sampled MCP session can still lose its `initialize` (delivery is at-most-once; sampling guarantees a consistent *decision*, not delivery). Preferring to drop non-handshake events first would protect server attribution. |
| Backend consumption of `sample_rate` / `sample_key` | Events carry the fields, but nothing re-weights counts by `1/sample_rate` yet — a sampled deployment under-reports totals until the backend learns to re-inflate (tracked backend-side, together with billing policy for sampled events). |
| Epoch-rotation boundary splits | The weekly rotation on the principal/user tiers splits sessions that straddle a week boundary (~0.3% of 30-minute sessions). Accepted as the cost of avoiding permanent blind spots; a smoother scheme (e.g. dual-epoch grace) is possible if the split rate ever matters. |

## Source layout

```
cerberus-flex-gateway/
├── Cargo.toml
├── Makefile                  # `make bundle` assembles the customer tarball
├── README.md                 # operator-facing configuration + deployment guide
├── DEVELOPMENT.md (this file)
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
│   ├── ai_content.rs         # LLM/AI prompt detection (captureAiContent gate)
│   ├── config.rs             # Config struct (mirrors gcl.yaml)
│   ├── event.rs              # CerberusEvent (CoreData mirror)
│   ├── response_capture.rs   # head+tail accumulator, response_body finalization
│   ├── sanitize.rs           # SENSITIVE_KEYS/HEADERS, sanitize_value(_with)
│   ├── pii_rules.rs          # customSensitiveKeys / customPiiPatterns compiler
│   ├── hash.rs               # hash_pii, normalize_ip
│   ├── source_ip.rs          # XFF first-hop / stream fallback
│   ├── secret.rs             # init-time secret fetch
│   ├── path_filter.rs        # capturePaths / excludePaths globs
│   ├── sampler.rs            # sampleRate/sampleBy: keyed session sampler + coin
│   ├── queue.rs              # bounded RefCell<VecDeque>
│   ├── sink.rs               # POST /v1/ingest/batch
│   ├── pipeline_tests.rs     # in-crate request-pipeline tests (pdk-unit)
│   └── generated/            # toolchain-generated from definition/gcl.yaml (committed)
└── tests/
    ├── fixtures              # symlink → ../../parity-fixtures (created by `make sync-fixtures`)
    └── parity_runner.rs      # consumes the YAML fixtures
```

## Architecture references

- [`pdk-custom-policy-examples`](https://github.com/mulesoft/pdk-custom-policy-examples) — `metrics/`, `certs/`, `ip-filter/`, `crypto/` are the closest stylistic precedents.
