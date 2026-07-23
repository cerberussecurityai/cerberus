# Cerberus Flex Gateway Custom Policy

A MuleSoft Flex Gateway custom policy (Rust → WASM, built with the PDK)
that captures HTTP request metadata, sanitizes PII, and ships events to
the Cerberus backend.

## Status: **scaffold (v1)**

The Rust source compiles with PDK 1.8.0 (`make build` requires the
toolchain — see [Setup](#setup) below). The shipped policy provides:

- Request metadata capture (header / query / body sanitization, IP
  normalization + HMAC, source IP resolution, health-endpoint filter).
- Customer-configurable PII scrubbing via `customSensitiveKeys` (extra
  field names) and `customPiiPatterns` (regex rules with redact/hash
  actions) — additive to the built-in `SENSITIVE_KEYS` floor. See
  "Custom PII scrubbing".
- Header allowlisting via `captureHeaders` (only ship the headers you name).
- LLM/AI prompt-body capture toggle (`captureAiContent`) — AI request
  bodies are captured and sanitized by default; set it to `false` to
  withhold prompt content entirely. `customPiiPatterns` value rules
  reach inside captured prompt text. MCP traffic is unaffected.
- Path scoping via `capturePaths` / `excludePaths` globs.
- Probabilistic request sampling via `sampleRate` (load-shedding for
  high-RPS deployments).
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
| Semantic scrubbing for AI prompts/responses | `customPiiPatterns` value rules scrub anything regex-shaped (SSNs, emails, member IDs) inside prompt text, but free-form PII with no stable shape (names, addresses in prose) still can't be caught. For zero prompt egress, set `captureAiContent: false` to withhold AI request bodies entirely (they are captured by default). |
| Graceful shutdown / drain | proxy-wasm has no `on_drain` hook. Up to ~`flushIntervalMs` of buffered events are lost on every pod churn (rolling deploy, OOM, scale-down). Documented and accepted. |

## Configuration (`gcl.yaml`)

| Property | Required | Default | Purpose |
|---|:---:|---|---|
| `ingestService` | ✓ | — | Cerberus backend URL. The policy POSTs to `<ingestService>/v1/ingest/batch`. |
| `token` | ✓ | — | Cerberus API key. Sent as the `X-API-Key` header on outbound requests. Trimmed at config-parse time. |
| `secretKey` | | — | HMAC key for PII hashing. Inline alternative to `backendUrl`. |
| `backendUrl` | | — | Base URL to fetch HMAC key from at startup. 5-second timeout; failure logs and falls back to raw PII. Use `https://` in production. |
| `customSensitiveKeys` | | `[]` | Extra field names (case-insensitive) redacted in query params and JSON bodies, additive to the built-in `SENSITIVE_KEYS` floor. Matching a key redacts its entire value, subtrees included. |
| `customPiiPatterns` | | `[]` | Regex scrubbing rules (`{pattern, label, action: redact\|hash, scope: keys\|values\|both}`) applied to query params and JSON bodies. Invalid rules fail policy load. See "Custom PII scrubbing". |
| `clientIpHeader` | | `X-Forwarded-For` | Header to read the client IP from (first hop). Falls back to Envoy connection source if absent. |
| `userIdHeader` | | unset | Header to read end-user identity from (e.g. `X-User-Id`). Required for per-end-user analytics; intentionally not defaulted so each deployment picks its own header. |
| `captureHeaders` | | `[]` (all headers) | Allowlist of header names (case-insensitive). Non-empty = only these headers ship in the event's headers map; sanitization still applies to them. Empty = all headers. Dedicated fields (`user_agent`, `clientIpHeader`, `userIdHeader`) unaffected. |
| `capturePaths` | | `[]` | Glob allowlist. Empty = capture everything. Primary lever for high-RPS scoping. |
| `excludePaths` | | `[]` | Glob denylist. Wins over `capturePaths` on overlap. |
| `sampleRate` | | `1.0` | Fraction of capturable traffic to sample (0–1). Applied after path filters; unsampled requests do zero capture work. Non-crypto per-worker PRNG; out-of-range clamps with a warning. |
| `captureRequestBody` | | `true` | Buffer + sanitize JSON request bodies (POST/PUT/PATCH only). Disable globally to skip the buffering cost; for per-route scoping use `capturePaths` / `excludePaths`. |
| `captureAiContent` | | `true` | Capture LLM/AI request bodies (prompts). On by default: detected AI traffic ships the body, SENSITIVE_KEYS-sanitized (free-form prompt text still ships raw). Set to `false` to withhold prompt content — detected AI traffic then ships events without the body. MCP/JSON-RPC bodies are not treated as AI content. See "LLM/AI content handling". |
| `batchSize` | | `50` | Events per outbound POST (max 1000 — server-side cap). |
| `flushIntervalMs` | | `2000` | Flush cadence. Min 100ms (prevents tight-loop misconfig). |
| `queueCapacity` | | `10000` | Per-worker queue. Total memory ~ `workers × queueCapacity × ~5KB`. |
| `logLevel` | | `info` | One of: `debug`, `info`, `warn`, `error`. |

### Header semantics

Envoy presents headers as `(name, value)` pairs with name lowercased per
HTTP/2 conventions, and multi-valued headers (e.g. `Set-Cookie`,
comma-folded `X-Forwarded-For`) appear as multiple entries with the
same name. The policy:

1. Skips Envoy pseudo-headers (`:method`, `:path`, `:scheme`, ...) —
   their metadata is captured in dedicated event fields.
2. Applies the `captureHeaders` allowlist (if configured): headers not
   on the list are omitted from the event entirely.
3. Applies sensitivity handling: `Authorization` is HMAC'd (secret
   configured) or `[REDACTED]` (no secret); other `SENSITIVE_HEADERS`
   are `[REDACTED]`.
4. Title-cases header names (`x-api-key` → `X-Api-Key`).
5. Collapses multi-valued headers with `, ` separator before storing
   in the event payload.

The allowlist controls which headers are *present*; sanitization
controls their *values* — listing `Authorization` or `Cookie` in
`captureHeaders` does not bypass redaction. The dedicated `user_agent`
event field is populated regardless of the allowlist. Allowlist
entries are trimmed and blank entries ignored; a list containing only
blank entries counts as empty, so all headers are captured and the
policy logs a startup warning.

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

### Sampling

`sampleRate` (0–1, default `1.0`) sheds capture *volume*: each request
gets a uniform per-request coin flip, and requests that lose it do no
capture work at all — no header/body extraction, no sanitization, no
event — and pass through untouched. It sits last in the decision order
(health-endpoint filter → `capturePaths` / `excludePaths` → sampling),
so it reads as "fraction of otherwise-captured traffic".

Use `capturePaths` / `excludePaths` to scope *which* routes are
captured, and `sampleRate` to shed volume uniformly across whatever
remains. The sampled subset is unbiased, but event counts become
estimates — multiply observed counts by `1/sampleRate`. Sampling is
per-request and memoryless: there is no per-client or per-session
stickiness, so a given caller's requests land in the sample
independently.

### Custom PII scrubbing

The built-in sanitization contract is fixed: `SENSITIVE_KEYS` matching
by key name only. Customers carry domain-specific PII the fixed list
can't know about — internal member numbers, custom token field names —
and PII embedded in *values* (an SSN inside a free-text note) that
key-name matching can never reach. Two config properties close both
gaps. Rules only ever **add** scrubbing: the built-in `SENSITIVE_KEYS`
/ `SENSITIVE_HEADERS` floor always applies and cannot be removed or
weakened by customer rules.

`customSensitiveKeys` — extra field names, matched case-insensitively
exactly like the built-in list. A matching key's entire value (nested
objects/arrays included) becomes `[REDACTED]`:

```yaml
customSensitiveKeys:
  - member_number
  - internal_customer_id
```

`customPiiPatterns` — regex rules applied to query params and JSON
request bodies (including captured LLM/AI prompt bodies — this is the
mechanism that reaches inside free-form prompt text):

```yaml
customPiiPatterns:
  - pattern: '\b\d{3}-\d{2}-\d{4}\b'   # US SSN
    label: ssn
    action: redact                     # default
    scope: values                      # default
  - pattern: '^MBR-\d{8}$'
    label: member-id
    action: hash                       # HMAC instead of redacting
  - pattern: 'x_acme_'
    label: acme-internal-fields
    scope: keys                        # match field NAMES
```

Per-rule knobs:

- `action` — `redact` (default) replaces matches with `[REDACTED]`.
  `hash` replaces each match with its HMAC-SHA256 hex digest, keyed on
  the policy's secret (`secretKey` / `backendUrl` fetch) — use it for
  stable identifiers where "same value across requests" keeps analytics
  value. If no secret is available, `hash` falls back to redact and the
  policy logs a startup warning: matched PII never ships raw.
- `scope` — `values` (default) rewrites matched substrings inside
  string values, preserving surrounding text (`"ssn is 123-45-6789"` →
  `"ssn is [REDACTED]"`). `keys` matches field *names* and replaces the
  entire value, like `customSensitiveKeys` but regex (a `hash` action
  on a non-string value redacts instead — there is no cross-language-
  stable subtree serialization to hash). `both` does both.
- `label` — optional name used in startup logs and config error
  messages; never appears in event output.

Semantics worth knowing:

- Rules apply after built-in key redaction, in declaration order; each
  value rule scans the previous rule's output. A value already replaced
  wholesale by key matching is not pattern-scanned.
- Patterns match **case-insensitively by default** (a PII net that
  misses `SSN` because the rule said `ssn` is a leak); prefix a pattern
  with `(?-i)` to opt out.
- The engine is linear-time (`regex-lite`) — catastrophic-backtracking
  ReDoS is structurally impossible, and compiled-pattern size is
  capped. Character classes `\d` `\w` `\s` are ASCII-only.
- Pattern matching is text-only: an SSN stored as a JSON *number*
  (`123456789`) will not match; numbers, bools, and null pass through.
- A rule that fails to compile (bad regex, unknown `action`/`scope`,
  empty `pattern`) **fails policy load** with a descriptive error
  rather than silently not scrubbing.
- Scrubbing applies to query params and JSON bodies — the literal
  customer ask. Header values are governed by `captureHeaders` + the
  fixed `SENSITIVE_HEADERS` set and are not pattern-scanned.
- Matching cost is O(rules × body size) on the request path. Keep rule
  counts modest on high-RPS APIs; `capturePaths` / `sampleRate` scope
  the traffic that pays it.

The rule engine is pinned by `parity-fixtures/custom_pii_rules.yaml`
(Rust-only for now — the fixture is the contract the Python
integrations must match when they adopt the feature).

### LLM/AI content handling

LLM prompts and responses are free-form text with high PII potential.
By default the policy captures LLM/AI request bodies and sanitizes them
like any other JSON body (`captureAiContent: true`): built-in
sanitization is key-matching only, so prompt text ships raw unless
`customPiiPatterns` value rules are configured — those rewrite matched
substrings inside prompt strings (SSNs, emails, account numbers), but
PII with no stable shape (names in prose) still passes. Set
`captureAiContent: false` to withhold detected LLM/AI request bodies
entirely.

When `captureAiContent: false` and a request is detected as LLM/AI
traffic, its event still ships with everything except `body`: endpoint,
method, sanitized headers and query params, source IP, timestamp, user
agent, and user id — so AI endpoint discovery and traffic analytics keep
working; only the prompt content is withheld.

The detection heuristic below governs which requests are withheld when
`captureAiContent: false`. It is biased toward recall: a false positive
only costs body capture for one event, while a false negative ships
prompt text. A request counts as LLM/AI traffic if either matches:

- **Path** (lowercased, query-stripped): ends with `/completions` or
  `/embeddings`; contains `/v1/messages`, `generatecontent` (Gemini
  `:generateContent` / `:streamGenerateContent`), or `/v1/responses`;
  ends with `/converse` or `/converse-stream` (Bedrock Converse);
  contains `/model/` and ends with `/invoke` or
  `/invoke-with-response-stream` (Bedrock InvokeModel); or contains a
  Vertex AI custom method (`:predict`, `:rawPredict`,
  `:streamRawPredict` — the colon keeps ordinary `/predict` business
  routes out). Path-matched requests skip body buffering entirely —
  prompts are the largest bodies the gateway sees.
- **Body shape** (parsed JSON): a `messages` array whose elements carry
  a `role`; a `model` key alongside `prompt` / `input` / `messages` /
  `contents` / `message` / `chat_history` / `texts` (the last three are
  Cohere-style); a Gemini-style `contents` array whose elements carry
  `parts`; `prompt` alongside a generation parameter (`max_tokens`,
  `max_tokens_to_sample`, `temperature`, `top_p`); `anthropic_version`
  (Bedrock-Anthropic); `inputText` + `textGenerationConfig` (Bedrock
  Titan); or a bare top-level array of `{role, content}` messages.

**MCP traffic is never treated as AI content.** Bodies that look like
JSON-RPC (a top-level object with a `jsonrpc` key) are captured
normally: MCP bodies are well-structured (method names + typed
params), standard `SENSITIVE_KEYS` sanitization handles them, and MCP
discovery depends on the captured arguments. One caveat, and only when
`captureAiContent: false`: this carve-out applies to bodies that get
buffered, but requests on the well-known LLM API paths above skip
buffering before the body can be inspected, so an MCP server mounted on
such a path (e.g. a mount containing `/v1/messages`) ships its events
without a body — real MCP mounts don't collide with provider API path
shapes.

Leaving `captureAiContent` at its `true` default means prompt content
(sanitized for `SENSITIVE_KEYS` and any `customPiiPatterns`, but
otherwise raw free-form text) leaves the gateway; keep it enabled only
if you accept that. Set it to `false` to withhold AI request bodies
entirely.

Response bodies are not captured by the policy at all yet; when
response capture lands, it will respect this same flag.

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

### Customer installation (Connected Mode)

This is how an end customer installs the policy. Custom Flex Gateway policies
can't be shared across Anypoint orgs, so each customer publishes the prebuilt
policy into **their own** org's Exchange. We ship a distribution bundle; the
customer runs a one-line installer:

```bash
tar -xzf cerberus-flex-gateway-policy-<version>.tar.gz
cd cerberus-flex-gateway-policy-<version>
./install.sh --org-id <your-anypoint-org-uuid>     # try --dry-run first
```

The installer needs **Node ≥ 18** + `anypoint-cli-v4` (the PDK plugin) and an
authenticated Anypoint session. It regenerates the Exchange asset files stamped
with the customer's org id (`pdk policy-project build-asset-files`) from the
prebuilt wasm + definition source, then publishes an immutable Exchange release
via `anypoint-cli-v4 pdk policy-project release`. Full walkthrough
(prerequisites, applying the policy in API Manager, upgrade, uninstall,
troubleshooting): **[INSTALL.md](./INSTALL.md)**.

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

`custom_pii_rules.yaml` (the customer rule engine) and
`path_filter.yaml` are Rust-only: this crate ships those features
first, and the fixtures are the contract the Python implementations
must match when they adopt them.

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
│   ├── ai_content.rs         # LLM/AI prompt detection (captureAiContent gate)
│   ├── config.rs             # Config struct (mirrors gcl.yaml)
│   ├── event.rs              # CerberusEvent (CoreData mirror)
│   ├── sanitize.rs           # SENSITIVE_KEYS/HEADERS, sanitize_value(_with)
│   ├── pii_rules.rs          # customSensitiveKeys / customPiiPatterns compiler
│   ├── hash.rs               # hash_pii, normalize_ip
│   ├── source_ip.rs          # XFF first-hop / stream fallback
│   ├── secret.rs             # init-time secret fetch
│   ├── path_filter.rs        # capturePaths / excludePaths globs
│   ├── sampler.rs            # sampleRate coin flip (SplitMix64)
│   ├── queue.rs              # bounded RefCell<VecDeque>
│   └── sink.rs               # POST /v1/ingest/batch
└── tests/
    ├── fixtures              # symlink → ../../parity-fixtures (created by `make sync-fixtures`)
    └── parity_runner.rs      # consumes the YAML fixtures
```

## Architecture references

- [`pdk-custom-policy-examples`](https://github.com/mulesoft/pdk-custom-policy-examples) — `metrics/`, `certs/`, `ip-filter/`, `crypto/` are the closest stylistic precedents.
