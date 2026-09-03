# Cerberus Flex Gateway Custom Policy

A MuleSoft Flex Gateway custom policy (Rust → WASM, built with PDK
1.8.0) that captures HTTP request metadata, sanitizes PII, and ships
events to the Cerberus backend.

The policy is distributed prebuilt: bundles are attached to
`flex-gateway-v*` GitHub Releases and install without a Rust toolchain.

## Features

- Request metadata capture: sanitized headers, query params, and JSON
  bodies; source-IP resolution with normalization + HMAC;
  health-endpoint filtering; `status_code` and `latency_ms` on every
  event.
- Opt-in response-body observation (`captureResponseBody`) — a strictly
  read-only tap on `application/json` and `text/event-stream`
  responses. The response the client receives is never modified,
  buffered, or delayed.
- Response-header capture (`captureResponseHeaders`), defaulting to
  `mcp-session-id` for MCP session correlation.
- Custom PII scrubbing: `customSensitiveKeys` (extra field names) and
  `customPiiPatterns` (regex rules with redact/hash actions), additive
  to the built-in `SENSITIVE_KEYS` floor.
- LLM/AI prompt and model-output capture toggle (`captureAiContent`).
- Traffic scoping: `captureHeaders` allowlist, `capturePaths` /
  `excludePaths` globs, session-consistent `sampleRate` load-shedding (`sampleBy`).
- Batched delivery: per-worker bounded queue, POSTed to the Cerberus
  batch ingest endpoint every `flushIntervalMs`.

## Installation

### Connected Mode (standard customer install)

Custom Flex Gateway policies can't be shared across Anypoint orgs, so
you publish the prebuilt policy into **your own** org's Exchange.
Download the bundle from the GitHub Release and run the installer:

```bash
tar -xzf cerberus-flex-gateway-policy-<version>.tar.gz
cd cerberus-flex-gateway-policy-<version>
./install.sh --org-id <your-anypoint-org-uuid>     # try --dry-run first
```

Requirements: Node ≥ 18, `anypoint-cli-v4` with the PDK plugin, and an
authenticated Anypoint session — no Rust. The full walkthrough
(prerequisites, installer flags, upgrade, uninstall, troubleshooting)
is in **[INSTALL.md](./INSTALL.md)**.

### Local Mode (air-gapped deployments)

1. Take `cerberus_flex_gateway.wasm` and `gcl.yaml` from the bundle's
   `policy/` directory (or build from source — see
   [DEVELOPMENT.md](./DEVELOPMENT.md)).
2. Copy them onto every Flex Gateway pod (ConfigMap / volume mount).
3. Apply a `PolicyBinding` CR scoped to your API instance with the
   policy's config values.
4. Verify with `kubectl logs`: look for policy `configure` log lines
   and a successful secret-key fetch (if `backendUrl` is set).

When upgrading in Local mode, copy the new `.wasm` before (or together
with) a config that sets newer options — the schema rejects unknown
fields, so an old `.wasm` given a new config fails policy load.

Reference:
<https://docs.mulesoft.com/gateway/latest/flex-local-deploy-custom-policy>.

### Applying the policy in API Manager

Once the policy is in your org's Exchange, apply it to an API instance
via the API Manager UI (Policies → Add policy → **Custom** tab → select
the policy → fill the form) or via CLI:

```
anypoint-cli-v4 api-mgr policy apply \
  --apiInstanceId <id> \
  --policyId cerberus-flex-gateway \
  --config '{"ingestService":"...","token":"..."}'
```

`ingestService` and `token` are the only required values — see the
configuration table below for everything else. Then drive traffic and
confirm events land in your Cerberus dashboard (see
[Verification](#verification)).

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
| `captureHeaders` | | `[]` (all headers) | Allowlist of header names (case-insensitive). Non-empty = only these headers ship in the event's headers map (sanitization still applies). Empty = all headers. Dedicated fields (`user_agent`, `clientIpHeader`, `userIdHeader`) unaffected. |
| `capturePaths` | | `[]` | Glob allowlist. Empty = capture everything. Primary lever for high-RPS scoping. |
| `excludePaths` | | `[]` | Glob denylist. Wins over `capturePaths` on overlap. |
| `sampleRate` | | `1.0` | Fraction of capturable traffic to sample (0–1). Applied after path filters; unsampled requests do no capture work. Out-of-range values clamp with a warning. See "Sampling". |
| `sampleBy` | | `session` | Sampling unit when `sampleRate` < 1: `session` = deterministic keyed decision, consistent per session/identity and identical on every replica; `request` = independent per-request coin (the pre-0.5.0 behavior). See "Sampling". |
| `sessionKeyHeader` | | `[]` | Extra request headers to use as the session sampling key when no MCP session id is present (e.g. `traceparent`, `X-Conversation-Id`). First present header wins. Used in memory only — never shipped. |
| `captureRequestBody` | | `true` | Buffer + sanitize JSON request bodies (POST/PUT/PATCH only). Disable globally to skip the buffering cost; for per-route scoping use `capturePaths` / `excludePaths`. |
| `captureAiContent` | | `true` | Capture LLM/AI request bodies (prompts) and — with `captureResponseBody` on — LLM/AI response bodies (model output). `true`: detected AI traffic ships the body, sanitized. `false`: detected AI traffic ships events without bodies. MCP/JSON-RPC is never treated as AI content. See "LLM/AI content handling". |
| `captureResponseBody` | | `false` | Observe `application/json` + `text/event-stream` response bodies. **Read-only tap** — the client's response is never modified, buffered, or delayed. See "Response body capture". |
| `captureResponseHeaders` | | `["mcp-session-id"]` | Allowlist of **response** header names captured into the event's `response_headers` map. Read-only, independent of `captureResponseBody`, pure opt-in (empty = none). Sanitized like request headers. |
| `responseHeadBytes` | | `24576` | First N bytes of a captured response body retained (max 49152). See sizing guidance under "Response body capture". |
| `responseTailBytes` | | `16384` | Rolling last N bytes retained (max 49152) — stream terminators (usage, finish reasons) live in the tail. Same sizing guidance. |
| `batchSize` | | `50` | Events per outbound POST (max 1000 — server-side cap). |
| `flushIntervalMs` | | `2000` | Flush cadence. Min 100ms (prevents tight-loop misconfig). |
| `queueCapacity` | | `10000` | Per-worker queue. Memory ~ `workers × queueCapacity × ~5KB`, plus up to `responseHeadBytes + responseTailBytes` per event carrying a response body. Size for the worst case — the queue only fills during a backend outage. |
| `logLevel` | | `info` | One of: `debug`, `info`, `warn`, `error`. |

### Header semantics

Header names arrive lowercased (HTTP/2 convention) and multi-valued
headers appear as repeated entries. For each request the policy:

1. Skips Envoy pseudo-headers (`:method`, `:path`, ...) — their values
   ship in dedicated event fields.
2. Applies the `captureHeaders` allowlist, if configured.
3. Applies sensitivity handling: `Authorization` is HMAC'd (secret
   configured) or `[REDACTED]` (no secret); other `SENSITIVE_HEADERS`
   are `[REDACTED]`.
4. Title-cases names (`x-api-key` → `X-Api-Key`) and collapses
   multi-valued headers with `, `.

Response headers captured via `captureResponseHeaders` go through the
same steps, so the two directions cannot drift.

The allowlist controls which headers are *present*; sanitization
controls their *values* — listing `Authorization` or `Cookie` in
`captureHeaders` does not bypass redaction. The dedicated `user_agent`
field ships regardless of the allowlist. Allowlist entries are trimmed;
a list of only blank entries counts as empty (all headers captured,
with a startup warning).

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

`sampleRate` (0–1, default `1.0`) sheds capture *volume*. It applies
last (health filter → path filters → sampling), so it reads as
"fraction of otherwise-captured traffic": unsampled requests skip all
capture work (no header/body extraction, no sanitization, no event)
and pass through untouched — the decision itself costs at most two
HMAC-SHA256 computations. Use path filters to scope *which* routes are
captured and `sampleRate` to shed volume across whatever remains. The
sample is unbiased but event counts become estimates — multiply
observed counts by `1/sampleRate` (each event carries the rate, see
below).

`sampleBy` picks the sampling unit:

- **`session` (default).** A deterministic keyed decision: requests
  carrying the same key are kept or dropped together, and every
  gateway replica reaches the same verdict with no shared state or
  coordination. The key is, in order:

  1. the MCP session id (`Mcp-Session-Id` request header, or the
     legacy `?sessionId=` / `?session_id=` query parameter),
  2. an operator-configured `sessionKeyHeader`,
  3. the authenticated principal set by an upstream MuleSoft auth
     policy (Client ID Enforcement, JWT validation, OAuth2, ...) —
     requires that policy to be ordered *before* this one,
  4. the `userIdHeader` value,
  5. the `Authorization` header,
  6. an independent per-request coin, when nothing above is present.

  A session is decided by exactly one tier, so it is captured whole or
  not at all — an MCP session's `initialize` (which carries the
  server's self-declared name) lands together with its `tools/call`s.
  Because `initialize` itself carries no session id yet, it is
  captured speculatively and decided on the session id the server
  mints in its response.

  The identity tiers (3 and 4) reshuffle weekly, so no principal or
  user is permanently unobserved at a fixed rate. Session-id keys
  never rotate — every new session is a fresh draw.

  **Exception:** requests to well-known LLM API paths (chat
  completions, messages, embeddings, ...) that carry no explicit
  session key are sampled per-request even in session mode. Chat-style
  APIs resend the full conversation on every call, so any single
  sampled request already contains the session so far — capturing
  every turn would ship the same history over and over for no added
  information. An explicit key takes precedence: an MCP session id or
  a configured `sessionKeyHeader` (e.g. `traceparent`) keys these
  requests like any others, so an agent run keyed by trace context
  keeps its LLM calls together with its tool calls.

- **`request`.** Every request gets an independent coin flip — the
  pre-0.5.0 behavior.

When sampling is active (`sampleRate` < 1), each event carries
`sample_rate` (re-weight counts by `1/sample_rate`) and `sample_key`
(which tier decided: `session_request` | `session_response` |
`session_header` | `principal` | `user_id` | `authorization` |
`request`), and session-keyed events carry the session id in the
top-level `session_id` field. At `sampleRate: 1.0` none of these
fields are added — the wire shape is unchanged. `sample_key` doubles
as a health signal: if every event says `request`, no usable
session/identity keys are reaching the policy — check the auth
policy's ordering and `userIdHeader`.

Sampling decisions always read raw headers, so `captureHeaders` /
`captureResponseHeaders` settings never change a decision. Keys are
hashed in memory only and never leave the gateway; the one exception
is the MCP session id, which ships in `session_id` because the backend
indexes it for correlation.

### Custom PII scrubbing

Built-in sanitization matches the fixed `SENSITIVE_KEYS` list by key
name. Two properties extend it for domain-specific PII — internal
member numbers, custom token fields, PII embedded in free-text values.
Rules only ever **add** scrubbing: the built-in `SENSITIVE_KEYS` /
`SENSITIVE_HEADERS` floor always applies and cannot be weakened.

`customSensitiveKeys` — extra field names, matched case-insensitively
like the built-in list. A matching key's entire value (nested
subtrees included) becomes `[REDACTED]`:

```yaml
customSensitiveKeys:
  - member_number
  - internal_customer_id
```

`customPiiPatterns` — regex rules applied to query params and JSON
request bodies, including captured LLM/AI prompt text (this is the
mechanism that reaches inside free-form prompts):

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
  the policy's secret — use it for stable identifiers where "same value
  across requests" keeps analytics value. With no secret available,
  `hash` falls back to redact and logs a startup warning: matched PII
  never ships raw.
- `scope` — `values` (default) rewrites matched substrings inside
  string values, preserving surrounding text. `keys` matches field
  *names* and replaces the entire value, like `customSensitiveKeys` but
  regex (a `hash` action on a non-string value redacts instead).
  `both` does both.
- `label` — optional name used in logs and config errors; never
  appears in event output.

Semantics worth knowing:

- Rules apply after built-in key redaction, in declaration order; each
  value rule scans the previous rule's output.
- Patterns match **case-insensitively by default**; prefix `(?-i)` to
  opt out. Character classes `\d` `\w` `\s` are ASCII-only.
- The engine is linear-time (no catastrophic backtracking) with a
  capped compiled-pattern size.
- Matching is text-only: an SSN stored as a JSON *number*
  (`123456789`) will not match; numbers, bools, and null pass through.
- A rule that fails to compile (bad regex, unknown `action`/`scope`,
  empty `pattern`) **fails policy load** with a descriptive error
  rather than silently not scrubbing.
- Headers are not pattern-scanned — they are governed by
  `captureHeaders` and the fixed `SENSITIVE_HEADERS` set.
- Matching cost is O(rules × body size) on the request path. Keep rule
  counts modest on high-RPS APIs; `capturePaths` / `sampleRate` scope
  the traffic that pays it.

### LLM/AI content handling

By default (`captureAiContent: true`) the policy captures LLM/AI
request bodies and sanitizes them like any other JSON body. Built-in
sanitization matches key names only, so free-form prompt text ships
raw unless `customPiiPatterns` value rules scrub it — and PII with no
stable shape (names in prose) is beyond regex too. Keep the default
only if you accept prompt content leaving the gateway; set
`captureAiContent: false` to withhold it.

With `captureAiContent: false`, a request detected as LLM/AI traffic
ships its event without `body` — endpoint, method, sanitized headers
and query params, source IP, timestamp, user agent, and user id still
ship, so AI endpoint discovery and traffic analytics keep working.

Detection is biased toward recall (a false positive costs one event's
body; a false negative ships prompt text). A request counts as LLM/AI
if either matches:

- **Path** (lowercased, query-stripped): ends with `/completions`,
  `/embeddings`, `/converse`, or `/converse-stream` (Bedrock Converse);
  contains `/v1/messages`, `/v1/responses`, or `generatecontent`
  (Gemini); contains `/model/` and ends with `/invoke` or
  `/invoke-with-response-stream` (Bedrock InvokeModel); or contains a
  Vertex AI custom method (`:predict`, `:rawPredict`,
  `:streamRawPredict` — the colon keeps ordinary `/predict` routes
  out). Path-matched requests skip body buffering entirely.
- **Body shape** (parsed JSON): a `messages` array whose elements carry
  a `role`; a `model` key alongside `prompt` / `input` / `messages` /
  `contents` / `message` / `chat_history` / `texts`; a Gemini-style
  `contents` array whose elements carry `parts`; `prompt` alongside a
  generation parameter (`max_tokens`, `max_tokens_to_sample`,
  `temperature`, `top_p`); `anthropic_version` (Bedrock-Anthropic);
  `inputText` + `textGenerationConfig` (Bedrock Titan); or a bare
  top-level array of `{role, content}` messages.

**MCP traffic is never treated as AI content.** JSON-RPC bodies (a
top-level `jsonrpc` key) are captured normally — they are
well-structured, standard sanitization handles them, and MCP discovery
depends on the captured arguments. One caveat when
`captureAiContent: false`: requests on the well-known LLM paths above
skip buffering before the body can be inspected, so an MCP server
mounted on such a path (e.g. a mount containing `/v1/messages`) ships
its events without a body.

The same flag governs the response side. With `captureResponseBody` on
and `captureAiContent: false`, model output is withheld when any of
three signals fires: the request hit a well-known LLM path (the
response stream is never opened); the request body was itself withheld
as prompt-shaped (the decision carries over, SSE or JSON); or the
response body looks like model output — a structural check on whole
JSON bodies (OpenAI `choices[]` / Responses-API `output[]`, Anthropic
`type: message` + `content[]` / `stop_reason`, Gemini `candidates[]`,
embeddings `data[].embedding`, Bedrock Converse `stopReason` / Titan
`results[].outputText`, Cohere `finish_reason` + `text`/`message`),
and a signature sniff over the first 2 KiB for text that cannot be
parsed (SSE streams, truncated bodies). JSON-RPC always wins: an MCP
result is never treated as AI content, even one carrying model text.
Like the request side this is shape-based and recall-biased — a
provider whose output matches none of these shapes, on a custom path
whose request wasn't detected, would not be caught.

### Response body capture

`captureResponseBody` (default `false`) observes `application/json`
and `text/event-stream` response bodies.

**The policy is a read-only tap.** The response delivered to the
client is never modified, buffered, or delayed — chunks pass through
exactly as they arrive from the upstream, and the policy retains only
a bounded copy as they stream past.

What ships in `response_body`:

- **Whole body** — when it fits within `responseHeadBytes` +
  `responseTailBytes`. JSON is parsed and sanitized exactly like a
  request body (`SENSITIVE_KEYS` + custom rules). An SSE stream ships
  as one string, sanitized per `data:` frame — JSON frames are
  key-sanitized in place, all other lines get `customPiiPatterns`
  value rules — with framing preserved.
- **Truncation marker** — when the body exceeds the budget:
  `{"body_truncated": true, "body_bytes_total": N,
  "body_bytes_dropped": M, "head": "...", "tail": "..."}` — the first
  `responseHeadBytes` plus the rolling last `responseTailBytes`,
  middle discarded as it streams. Truncation is never silent. The tail
  is sized generously because stream terminators (token usage, finish
  reasons) arrive last.
- **Compression marker** — `{"body_skipped_encoding": "<enc>"}` when
  `Content-Encoding` is anything other than `identity`; a compressed
  stream is never sliced or read.

`status_code` and `latency_ms` ship on every event regardless of this
setting. Body-less responses (204/304/HEAD) produce no `response_body`.

**Sizing.** The ingest endpoint enforces a per-event size cap and
drops oversized events server-side. Size `responseHeadBytes +
responseTailBytes` so the response slices, the request body, and the
rest of the event stay under it — the defaults (24 KiB + 16 KiB) leave
headroom for typical events. Setting both to `0` gives a valid
"response size telemetry" mode: markers with byte counts, empty
slices.

**PII caveat.** Full key-based sanitization applies to whole JSON
bodies and complete SSE data frames. Truncated head/tail slices, the
SSE frame split by each truncation cut, and an SSE payload spread
across multiple `data:` lines are unparseable text — only
`customPiiPatterns` value rules run over them (regex-shaped PII such
as SSNs and account numbers is still scrubbed). Prose PII with no
stable shape (a name in generated text) is beyond key matching or
regex in every case — the same limit that applies to captured prompts.
For zero model-output egress, set `captureAiContent: false`.

**Memory.** Capture memory is capped at head+tail per in-flight
response regardless of body size — long or unbounded streams cannot
grow it.

### Response header capture

`captureResponseHeaders` names the response headers to copy into the
event's `response_headers` map — independent of body capture, same
read-only guarantee, same sanitization as request headers (sensitive
headers redact even when listed). Unlike `captureHeaders` it is a pure
opt-in allowlist: empty means no response headers are captured.

The default `["mcp-session-id"]` captures the session id that stateful
APIs such as MCP assign in a response header, letting the backend
correlate a session's events (clients echo it as a request header,
which normal request capture already sees). Set the list to `[]` to
disable.

Two scoping notes: the allowlist is matched on every response, not
only MCP traffic — a non-MCP route that sets an allowlisted header
ships it too. And only the response *headers* phase is read; a value
sent as an HTTP trailer is not observed (MCP assigns `mcp-session-id`
in the initial headers, so this does not affect it).

### TLS to the Cerberus backend

Outbound POSTs to `ingestService` use the gateway's default outbound-policy
TLS context (TLS 1.2–1.3; negotiates 1.3 against the Cerberus production
endpoint, which rejects < 1.2). Operators who must *guarantee* TLS ≥ 1.3 can
pin `defaultTLS.outboundPolicyCalls.minversion: "1.3"` in a gateway
`Configuration` resource — see `INSTALL.md` ("Enforcing TLS 1.3 to Cerberus")
for the YAML and the gateway-wide scope caveat.

## Verification

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

## Operational notes

- **Delivery is at-most-once.** Failed batch POSTs are dropped without
  retry, and up to ~`flushIntervalMs` of buffered events are lost when
  a gateway pod restarts or scales down.
- **Queue overflow drops events.** During a backend outage the bounded
  per-worker queue fills and further events are dropped; the drop
  count is logged.
- **Upstream resets.** If the upstream connection resets or times out
  before response headers exist, that request's event is not shipped.
- **Long-lived streams ship late.** With `captureResponseBody` on, an
  event ships when its response body ends. A keep-alive
  `text/event-stream` (e.g. an MCP notification stream) holds its
  event until the connection closes, and `latency_ms` then reads as
  the stream's lifetime. The client is unaffected — the event is just
  late.
- **Per-event size cap.** Events whose serialized form exceeds the
  ingest endpoint's cap are dropped server-side — see "Sizing" above.
- **Large request bodies.** JSON request bodies above 1 MB are not
  captured in full (platform buffering cap). Response bodies stream
  and are not subject to this.

## Fronting an MCP server

Putting this policy in front of an MCP server surfaces a gotcha that has
nothing to do with the policy itself: Flex Gateway rewrites the `Host` header
to the upstream address it proxies to (a Kubernetes service DNS name, an
internal hostname, whatever the route target is). The Python `mcp` SDK
(FastMCP in 1.10+, `MCPServer` in 2.x) auto-enables DNS-rebinding protection
for servers bound to the default host (`127.0.0.1` / `localhost`), and that
protection's allow-list only contains `localhost:*`, `127.0.0.1:*`, and `[::1]:*`. Every
proxied request gets `421 Misdirected Request` — a direct health probe on the
server's own port stays green, so the failure only shows up once traffic goes
through the gateway, and Cerberus faithfully captures the resulting all-421
traffic.

The server log line to look for is `Invalid Host header: <upstream>`. Fix it
on the MCP server side by giving the SDK an explicit allow-list that names
the upstream address the gateway sends (`allowed_hosts`) **and**, if browser
clients call the server, the origins those browser apps are served from
(`allowed_origins` — the SDK checks a present `Origin` separately and
answers 403 when it is missing from the list, so an allow-list that only
covers the rewritten `Host` turns a browser client's 421 into a 403):

```python
from mcp.server.transport_security import TransportSecuritySettings

security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    # what the gateway sends as Host, plus the SDK's own loopback defaults
    allowed_hosts=["<upstream-name>", "<upstream-name>:*", "localhost:*", "127.0.0.1:*", "[::1]:*"],
    # the Origin a browser client presents = the site the browser app is served from,
    # e.g. https://app.example (add the gateway's own origin only when the app is served
    # from the gateway itself); non-browser clients send no Origin and are unaffected
    allowed_origins=["https://<browser-app-origin>", "http://localhost:*", "http://127.0.0.1:*", "http://[::1]:*"],
)

# mcp 1.x (FastMCP): the settings object carries it.
mcp.settings.transport_security = security

# mcp 2.x (FastMCP was renamed MCPServer): pass it to the transport entry point.
app = mcp.streamable_http_app(transport_security=security)   # or mcp.run(..., transport_security=security)
```

`<upstream-name>` is whatever the route's upstream address is (`mcp-weather`
in a compose network, a Kubernetes service DNS name, a hostname). The
loopback entries reproduce the SDK's defaults so direct health probes over
IPv4 or IPv6 keep working; drop them once nothing calls the server directly.

Alternatives: construct the server with `host="0.0.0.0"` (both majors then
skip the protection entirely — weaker), or rewrite `Host` back to the
server's public name on the gateway route. The TypeScript SDK
(`@modelcontextprotocol/sdk`) has the equivalent `enableDnsRebindingProtection`
/ `allowedHosts` / `allowedOrigins` options on `StreamableHTTPServerTransport`,
off by default.

Cross-origin deployments (a browser app on one origin calling an MCP server
behind the gateway on another) are still subject to the browser's CORS
preflight — that is a separate configuration on the gateway or server, not
covered here.

## Development

Building from source, running tests, the local playground, parity
testing, and the release process are covered in
[DEVELOPMENT.md](./DEVELOPMENT.md).
