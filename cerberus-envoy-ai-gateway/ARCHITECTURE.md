# Architecture — cerberus-envoy-ai-gateway

Maintainer-facing design notes. For install/config/deployment, see the
[README](./README.md); this document explains **how the bridge works inside
and why it's built this way**.

## What it is, in one paragraph

The bridge is a small, stateless Python service that turns the
[Envoy AI Gateway](https://aigateway.envoyproxy.io)'s OpenTelemetry traces
into Cerberus events. The gateway's extproc already emits a span per LLM call
(OpenInference conventions) and per MCP call; the bridge receives those spans
over OTLP/HTTP, maps the AI-relevant ones to the same event shape every other
Cerberus integration produces (`CoreData` / `MCPEventData`), sanitizes and
pseudonymizes them, and batch-POSTs them to the Cerberus ingest API. It is
**never in the request path** — trace export is asynchronous, so if the bridge
is down the gateway's data plane is unaffected.

## Data flow

```
                      (your traffic)
  clients ───────────────▶ Envoy AI Gateway ───────────▶ LLM providers
                                  │                        MCP servers
                                  │ extproc emits OTLP spans
                                  │ (async, out-of-band)
                                  ▼
                    ┌──────────────────────────────┐
                    │  cerberus-envoy-ai-gateway    │   ◀── this package
                    │  POST /v1/traces (OTLP/HTTP)  │
                    │                               │
                    │  decode → classify → map →    │
                    │  sanitize/hash → cap → queue  │
                    │            │                  │
                    │            ▼ batched flush     │
                    └────────────┼──────────────────┘
                                 │ POST /v1/ingest/batch (X-API-Key)
                                 ▼
        cerberus-int:  event_ingest ─▶ Kafka ─▶ event_process ─▶ PostgreSQL
                                                     │
                                                     ├─ processed_events
                                                     └─ mcp_*_discovery
```

## Why an OTLP trace bridge (design decision)

The gateway runs its AI logic in a controller-injected ext_proc sidecar that
third parties cannot replace or extend. So the integration had to attach to
one of its *observability* outlets. Three were viable; we chose OTLP traces:

| Mechanism | Verdict |
|---|---|
| **OTLP traces (chosen)** | The extproc's spans carry the full scope — LLM model/provider/token counts/status/latency and (optionally) content, **plus** MCP method/tool/backend. Async export ⇒ zero request-path risk. Standard OTel env vars point it at us; nothing is injected into the proxy. |
| ALS / access-log sink | `io.envoy.ai_gateway` dynamic metadata has LLM tokens/model/TTFT but **no MCP tool names** and no bodies — fails half the scope. Kept in mind as a future complementary tap for TTFT/ITL. |
| Extra ext_proc / Wasm filter via `EnvoyExtensionPolicy` | Body-capable, but filter-ordering vs. the AI Gateway's own injected ext_proc is unverifiable, and it adds request-path risk. Rejected. |

**Language: Python**, because it imports `cerberus-core` directly
(`sanitize_dict`, `hash_pii`, `normalize_ip`) instead of re-porting it. That
means **no parity-fixtures runner is needed** for this package (parity
fixtures exist to keep the *Rust* flex-gateway port in lockstep with the
Python source; an importer can't drift).

All span attribute keys were verified against the `envoyproxy/ai-gateway`
**v0.7.0** source — `internal/tracing/openinference/*` and
`internal/tracing/mcp.go`. When bumping the supported gateway version,
re-verify with `CERBERUS_DUMP_SPANS=true` in the playground (see Testing).

## Module map (`src/cerberus_envoy_ai_gateway/`)

| Module | Responsibility |
|---|---|
| `cli.py` | Console entrypoint → `uvicorn`. |
| `config.py` | `Config.from_env()` — all `CERBERUS_*` env vars + validation. |
| `app.py` | FastAPI app: `POST /v1/traces` (the OTLP receiver, 16 MB body cap), `GET /health` `/ready` `/stats`. Lifespan wires up the pipeline + sink and resolves the HMAC secret at startup. |
| `otlp.py` | Decode `ExportTraceServiceRequest` (protobuf **and** JSON), flatten span attributes, iterate spans, build the success response, and render spans for `CERBERUS_DUMP_SPANS`. |
| `classify.py` | `classify(attrs)` → `KIND_LLM` \| `KIND_MCP` \| `None`. Keys off attributes only the terminal AI span carries, so one call ⇒ one event. |
| `spanfields.py` | Shared extraction helpers: ISO timestamp, duration, error detection, first-non-empty-attr, first-hop client IP, JSON-string parsing. |
| `mapper_llm.py` | LLM span → `CoreData`-shaped dict. |
| `mapper_mcp.py` | MCP span → `MCPEventData`-shaped dict (+ a `mcp_schema_report` hook). |
| `pipeline.py` | The orchestrator: classify → map → sanitize/hash → size-cap → enqueue. **All privacy-affecting work lives here.** |
| `queue.py` | `BoundedQueue` — drop-on-full with a counter (never blocks, never evicts queued events). |
| `sink.py` | Background flush loop; batch-POSTs to `/v1/ingest/batch`; surfaces server-side accepted/skipped counts. |
| `secret.py` | Startup HMAC-key resolution (inline or fetched from the backend; graceful raw-PII fallback). |

## Request lifecycle

`app.receive_traces` streams the request body (rejecting >16 MB before
buffering, since the receiver is unauthenticated), decodes it, and hands the
export to `Pipeline.process_export`. For each span (`pipeline.py:66`):

1. **classify** (`classify.py`) — MCP if `mcp.method.name` is present; LLM if a
   model attr (`llm.model_name` / `llm.model` / `gen_ai.request.model`) is
   present or the OpenInference span-kind is `llm`; otherwise the span is
   counted in `spans_ignored` and skipped. (Envoy router/parent spans, MCP
   `initialize`/notifications, etc. all fall out here.)
2. **map** (`mapper_llm` / `mapper_mcp`) — produce a raw, pre-sanitization
   event dict. Mappers extract values only; they never hash or redact.
3. **finalize** (`pipeline._finalize`) — the privacy + safety stage, in order:
   - `remote_addr` → `normalize_ip` → `hash_pii` (HMAC-SHA256) when a secret is
     configured, else the normalized raw IP, else `"unknown"`.
   - `user_agent` / `user_id` / `custom_data.error` truncated to fixed caps —
     these are client-controlled header values, so without caps one oversized
     header could push every event from that client over the byte cap and
     silently drop its telemetry (an evasion vector).
   - MCP arguments / LLM body run through `cerberus_core.sanitize_dict`
     (key-name redaction of `SENSITIVE_KEYS`) and value truncation; MCP
     arguments are gated by `CERBERUS_CAPTURE_MCP_ARGUMENTS` (default on), LLM
     content by `CERBERUS_CAPTURE_LLM_CONTENT` (default off).
   - `_enforce_size` keeps each event under `CERBERUS_MAX_EVENT_BYTES`
     (default 56 KB, headroom under the server's 64 KB skip threshold): first
     it sheds captured content (`body=null`, `arguments={}`,
     `content_dropped_oversize=true`), then drops the event entirely as a last
     resort, counting `dropped_oversize`.
4. **enqueue** — `BoundedQueue.append`; full ⇒ drop + `dropped_full`.

`Sink` drains the queue every `CERBERUS_FLUSH_INTERVAL_MS` (≤20 batches per
tick, ≤`CERBERUS_BATCH_SIZE` events each) and POSTs `{"events": [...]}` with
the API key in `X-API-Key`. Delivery is **at-most-once**: a non-2xx or network
error drops the batch and increments `post_failures` (matches the flex-gateway
v1 posture; retry/backoff is a documented gap). The server's
`{accepted, skipped}` response is surfaced as `server_accepted` /
`server_skipped` in `/stats` so server-side filtering isn't invisible.

## Span → event mapping

Both mappers emit the shared event contract so the Cerberus backend needs
**zero** per-integration changes. The IP field is `remote_addr` (the backend's
name — the same rename cerberus-django / cerberus-mcp / flex-gateway apply at
the wire boundary). `token` is omitted; ingest stamps it from `X-API-Key`.

### LLM span → `CoreData` (`mapper_llm.py`)

| Event field | Source |
|---|---|
| `endpoint` | `llm://{provider}/{model}` (synthetic, low-cardinality) |
| `scheme` | `"llm"` |
| `method` | `llm_chat_completion` \| `llm_messages` \| `llm_embeddings` \| `llm_completion` \| `llm_call` (from `gen_ai.operation.name` / span name) |
| `timestamp` | span start → ISO 8601 +00:00 |
| `remote_addr` | client-IP attr (first XFF hop) → hashed in finalize |
| `user_id` / `user_agent` | from configured header-mapped attrs |
| `body` | only if `CERBERUS_CAPTURE_LLM_CONTENT` — `{input, output}` from `input.value`/`output.value`, sanitized + truncated |
| `custom_data` | `provider` (`llm.system`/`gen_ai.provider.name`), `model` (`llm.model_name`/`llm.model`), `response_model`, `tokens_{prompt,completion,total,cache_hit,reasoning}` (`llm.token_count.*`), `duration_ms`, `status`, `error`, `streaming`, `temperature`/`top_p`/`max_tokens`, `route_path`, `trace_id`, `span_id` |

### MCP span → `MCPEventData` (`mapper_mcp.py`)

| JSON-RPC method (`mcp.method.name`) | Event `method` | handler |
|---|---|---|
| `tools/call` | `mcp_tool_call` | `mcp.tool.name` |
| `resources/read` | `mcp_resource_read` | `mcp.resource.uri` |
| `prompts/get` | `mcp_prompt_get` | `mcp.prompt.name` |
| `tools/list` *(if response recorded)* | `mcp_schema_report` | — |
| anything else (`initialize`, notifications…) | skipped | — |

`endpoint` = `mcp://{backend}/{handler}` (backend from `mcp.backend.name`, else
`CERBERUS_MCP_SERVER_FALLBACK`); `scheme` = `"mcp"`. `custom_data` carries
exactly the keys `event_process`'s `MCPDiscoveryUpdater` consumes:
`mcp_server`, `handler_name`, `event_type`, `duration_ms`, `arguments`,
`error`, `result_summary`, `session_id`, `client_name`, `client_version`,
`request_id`, `mcp_transport`, `mcp_protocol_version`, `trace_id`.

> **Known limitation:** ai-gateway v0.7.0 does **not** record tool-call
> arguments in span attributes (only `CallToolParams.Name`), so MCP discovery
> lands at tool-name granularity with empty `arguments_observed`. The mapper
> probes candidate argument keys anyway, so capture lights up automatically if
> a future gateway version records them.

## Cross-repo contract (cerberus-int backend guards)

These events introduced two new vocabularies the backend hadn't seen — the
`llm://` / `mcp://` endpoint schemes and the `llm_*` / `mcp_*` method names.
Two guards in the `cerberus-int` backend make them land correctly; **the bridge
depends on them being deployed**:

1. **Health-filter exemption** — `event_ingest`'s `is_health_endpoint` exempts
   `mcp://` and `llm://` endpoints. Their last path segment is a tool/model
   *name*, so an MCP tool literally named `health` (common on infra MCP
   servers) is real traffic, not a probe to drop.
2. **Endpoint-discovery scheme guard** — `event_process` routes `mcp://` to MCP
   discovery and only sends scheme-less HTTP endpoints to endpoint discovery;
   `llm://` (and any future scheme) goes to neither. Without this, an
   `llm_chat_completion` method would overflow `endpoint_discovery.method
   VARCHAR(10)` and one poisoned UPSERT would wedge the whole discovery flush.
   The events still land in `processed_events`.

If you run the bridge against an older backend, watch `server_skipped` in
`/stats` and the discovery pipeline.

## Privacy & sanitization model

- Sanitization and pseudonymization happen **in the bridge, before anything is
  queued or logged** — via direct `cerberus-core` imports, so the contract is
  identical to the other integrations.
- Source IPs are HMAC-SHA256 pseudonymized; redaction is **key-name based**
  (`SENSITIVE_KEYS`), so secrets embedded in free-form prompt text are *not*
  scrubbed — LLM content capture is therefore off by default and double-gated
  (the bridge flag plus the gateway's `OPENINFERENCE_HIDE_*`).
- The `/v1/traces` receiver is unauthenticated (standard for in-cluster OTLP)
  and signs everything it forwards with the tenant API key, so deployments
  should restrict who can reach it (NetworkPolicy template in `deploy/`).

## Resilience & delivery semantics

Single replica, single event loop. Bounded in-memory queue with drop-on-full;
at-most-once delivery; a 16 MB request-body cap and per-event byte cap; a
best-effort final flush on `SIGTERM`. Everything that gets dropped is counted
and exposed at `/stats` (`dropped_queue_full`, `dropped_oversize`,
`post_failures`, `server_skipped`, `spans_ignored`). The receiver always
returns a full-success OTLP response — queue pressure and ingest failures are
absorbed here, never pushed back onto the gateway's exporter.

## Testing & re-verifying

- **Golden fixtures** — `tests/fixtures/spans/*.json` are OTLP payloads;
  `tests/fixtures/expected/*.yaml` are the mapped events. The mapper tests are
  pure functions over these.
- **Stub-ingest integration** — `tests/test_sink.py` runs against an in-process
  FastAPI stub mirroring `event_ingest`'s `/v1/ingest/batch` contract
  (401/403/413, health-skip, accepted/skipped).
- **Playground** — `playground/` boots the bridge + a stub ingest + mock LLM +
  mock MCP behind a standalone `aigw run`. To **re-verify span attribute keys**
  after a gateway upgrade, run with `CERBERUS_DUMP_SPANS=true` and diff the
  dumped attributes against the mapper's key lists / the golden fixtures.

## Future / extension points

See the README's *Known gaps* table. The notable internal hooks: the
`mcp_schema_report` path in `mapper_mcp.py` activates automatically if the
gateway ever records `tools/list` responses; an OTLP/gRPC listener and
retry/backoff in `sink.py` are the obvious next hardening steps; and the ALS
metadata tap is the route to TTFT/inter-token-latency if those become required.
