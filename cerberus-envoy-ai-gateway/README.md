# Cerberus Envoy AI Gateway Bridge

A drop-in [Envoy AI Gateway](https://aigateway.envoyproxy.io) integration
for Cerberus: a small OTLP trace bridge that converts the gateway's LLM and
MCP telemetry into Cerberus events.

> [!WARNING]
> **Experimental (v1).** This bridge is new and not yet production-hardened —
> expect rough edges and breaking changes. There is also **no published
> container image yet**: you build and push it yourself (see Deployment below).

The Envoy AI Gateway extproc already emits OpenTelemetry traces for every
LLM call (OpenInference conventions: model, provider, token counts, optional
request/response content) and every MCP call (JSON-RPC method, tool name,
backend). Point that exporter at this bridge and the traffic shows up in
Cerberus — no gateway forking, no filters injected, no app changes.

```
client ──▶ Envoy AI Gateway ──▶ LLM providers / MCP servers
                 │ extproc (async OTLP traces)
                 ▼
        cerberus-envoy-ai-gateway          ◀── this package
                 │ batch POST /v1/ingest/batch
                 ▼
          Cerberus backend
```

Because trace export is asynchronous, the bridge is **never in the request
path**: if it's down, gateway traffic is unaffected.

## Status: **experimental (v1 scaffold)**

Working end-to-end: span decode → classify → map → sanitize/hash → batch
POST. Events land in `processed_events`, and MCP tool calls feed the
`mcp_tool_discovery` pipeline.

### Known gaps in v1

| Gap | Why |
|---|---|
| MCP tool **arguments** are not recorded by the gateway (confirmed in ai-gateway v0.7.0 — spans carry only the tool name) | Discovery works at tool-name level: tool calls land in `mcp_tool_discovery` with counts/errors/durations, but `arguments_observed` stays empty. The mapper already probes candidate keys (`mcp.tool.arguments`, `mcp.request.arguments`, `mcp.request.argument.*`, `input.value`) so argument capture lights up if a future gateway version records them — re-check with `CERBERUS_DUMP_SPANS=true` after upgrades. Full argument observation requires `cerberus-mcp` on the MCP server itself. |
| `mcp_schema_report` / `input_schema` | Gateway spans don't carry `tools/list` response payloads (hook exists in `mapper_mcp.py` if that changes). Tool schemas come only from `cerberus-mcp`-instrumented servers. |
| `result_summary` for MCP calls | Tool results are not recorded in gateway spans. |
| Retry / backoff on ingest failures | At-most-once: failed batches are dropped and counted (matches flex-gateway v1). |
| Circuit breaker for sustained outages | Failures are logged + counted only. |
| OTLP/gRPC (port 4317) listener | v1 is OTLP/HTTP only — set `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf` on the gateway (the OTel default is gRPC and will otherwise export into the void). |
| TTFT / inter-token latency | Only available in Envoy dynamic metadata (`io.envoy.ai_gateway`), not spans. A future access-log (ALS) tap can add it. |
| MCP client name/version | Not in gateway spans (sent as `null`). |
| Prometheus metrics for the bridge itself | `/stats` JSON only. |
| Hosted container image | Build it yourself (`make image`) and push to your registry. |
| Multi-replica dedup | Run **1 replica**; N replicas would each receive a share of spans (fine), but the OTel exporter load-balances — never fan the same endpoint into multiple bridges via a mesh that duplicates. |
| OTLP receiver is unauthenticated | Standard for in-cluster collectors, but the bridge signs everything it receives with your API key — the NetworkPolicy in `deploy/kubernetes/bridge.yaml` ships **active** (preset to `envoy-gateway-system`) so only the gateway can reach `:4318`; change its `namespaceSelector` if your proxy pods run elsewhere. Request bodies are capped at 16MB. |
| Backend version requirement | MCP/LLM events need a Cerberus backend that includes the AI-scheme guards (event_ingest exempts `mcp://`/`llm://` from the health-endpoint filter; event_process keeps `llm://` out of HTTP endpoint discovery). On older backends, tools named `health`/`ready`/`live` are silently skipped at ingest, and `llm_*` methods break the endpoint-discovery flush. Watch `server_skipped` in `/stats`. |
| HMAC key not re-fetched after a startup failure | If `CERBERUS_BACKEND_URL` is set but the backend is unavailable at pod start, the key fetch fails once and source IPs ship **unhashed** for the process lifetime. Restart the bridge pod to retry. |

## Configuration (environment variables)

| Variable | Required | Default | Purpose |
|---|:---:|---|---|
| `CERBERUS_INGEST_SERVICE` | ✓ | — | Cerberus backend URL. The bridge POSTs to `{value}/v1/ingest/batch`. |
| `CERBERUS_TOKEN` (or `CERBERUS_TOKEN_FILE`) | ✓ | — | Cerberus API key, sent as `X-API-Key`. |
| `CERBERUS_SECRET_KEY` | | unset | HMAC-SHA256 key for PII hashing. Inline alternative to `CERBERUS_BACKEND_URL`. |
| `CERBERUS_BACKEND_URL` | | unset | Fetch the HMAC key from `{value}/api/secret-key` at startup (5s timeout; failure → one-time warning, IPs sent unhashed). |
| `CERBERUS_CLIENT_IP_ATTRIBUTE` | | `http.client_ip` | Span attribute holding the client IP. Populate it via `OTEL_AIGW_SPAN_REQUEST_HEADER_ATTRIBUTES` (see below). First hop before any comma is used. |
| `CERBERUS_USER_ID_ATTRIBUTE` | | unset | Span attribute holding end-user identity (map a header like `x-user-id`). Required for per-end-user analytics. |
| `CERBERUS_USER_AGENT_ATTRIBUTE` | | `http.user_agent` | Span attribute holding the client User-Agent. |
| `CERBERUS_CAPTURE_LLM_CONTENT` | | `false` | Ship LLM prompts/completions in the event body (key-based redaction only — secrets inside free-form prompt text are NOT scrubbed). Also requires the gateway to record content (don't set `OPENINFERENCE_HIDE_INPUTS/OUTPUTS=true`). |
| `CERBERUS_CAPTURE_MCP_ARGUMENTS` | | `true` | Ship sanitized MCP tool/prompt arguments (feeds `arguments_observed` in MCP discovery). |
| `CERBERUS_BATCH_SIZE` | | `50` | Events per POST (server cap 1000). |
| `CERBERUS_FLUSH_INTERVAL_MS` | | `2000` | Flush cadence (min 100). |
| `CERBERUS_QUEUE_CAPACITY` | | `10000` | Bounded queue; drop-on-full with counter. Memory ≈ capacity × ~2–10KB. |
| `CERBERUS_MAX_EVENT_BYTES` | | `57344` | Per-event cap (headroom under the server's 64KB skip threshold). Oversized events shed content, then drop. |
| `CERBERUS_MCP_SERVER_FALLBACK` | | `envoy-ai-gateway` | MCP server name when the backend attribute is absent from spans. |
| `CERBERUS_LISTEN_PORT` | | `4318` | OTLP/HTTP listen port. |
| `CERBERUS_LOG_LEVEL` | | `info` | `debug` / `info` / `warning` / `error`. |
| `CERBERUS_DUMP_SPANS` | | `false` | **Dev only.** Print every decoded span as JSON (may include prompt content — never enable in production). |

## Setup

```bash
make venv    # uv venv + editable install with dev extras
make test    # pytest (golden mapper tests, pipeline, sink-vs-stub-ingest)
make lint    # ruff + black --check
```

## Deployment (Kubernetes)

1. **Deploy the bridge** — in
   [`deploy/kubernetes/bridge.yaml`](./deploy/kubernetes/bridge.yaml), edit
   the Secret (API key) and the Deployment env + image (`CERBERUS_INGEST_SERVICE`,
   `CERBERUS_BACKEND_URL`, your pushed image) — four CHANGE-ME values. The file
   also ships an **active NetworkPolicy** preset to the standard
   `envoy-gateway-system` namespace; if your gateway proxy pods run elsewhere,
   update its `namespaceSelector` or the bridge will receive no spans. Then:

   ```bash
   kubectl apply -f deploy/kubernetes/bridge.yaml
   ```

2. **Point the gateway's extproc at it** — add the env vars from
   [`deploy/ai-gateway/extproc-env.yaml`](./deploy/ai-gateway/extproc-env.yaml)
   to the AI Gateway extproc:

   ```yaml
   - name: OTEL_EXPORTER_OTLP_ENDPOINT
     value: http://cerberus-bridge.cerberus.svc.cluster.local:4318
   - name: OTEL_EXPORTER_OTLP_PROTOCOL
     value: http/protobuf        # REQUIRED — OTel defaults to gRPC
   - name: OTEL_TRACES_EXPORTER
     value: otlp
   - name: OTEL_METRICS_EXPORTER
     value: none
   - name: OTEL_TRACES_SAMPLER
     value: always_on   # not parentbased_* — an unsampled upstream traceparent would drop the request
   - name: OTEL_AIGW_SPAN_REQUEST_HEADER_ATTRIBUTES
     value: "x-forwarded-for:http.client_ip,x-user-id:user.id,user-agent:http.user_agent"
   # Defense-in-depth while CERBERUS_CAPTURE_LLM_CONTENT=false:
   - name: OPENINFERENCE_HIDE_INPUTS
     value: "true"
   - name: OPENINFERENCE_HIDE_OUTPUTS
     value: "true"
   ```

   How to inject them depends on how you installed the gateway — in order
   of preference (verify against your chart version):
   - **Helm values** for `oci://docker.io/envoyproxy/ai-gateway-helm`
     (extproc env-var values, e.g. `extProc.extraEnvVars`);
   - the **`GatewayConfig`** CRD's extproc Kubernetes spec, when exposed;
   - escape hatch: `kubectl set env` on the extproc workload.

   > **Header mapping on Helm/Kubernetes:** `OTEL_AIGW_SPAN_REQUEST_HEADER_ATTRIBUTES`
   > only applies to standalone `aigw run`. For chart installs set the controller
   > value `controller.spanRequestHeaderAttributes` (older charts:
   > `controller.requestHeaderAttributes`) to the same mapping, or spans arrive
   > without `http.client_ip`/`user.id`/`http.user_agent` and events show
   > `remote_addr="unknown"`.

   If you already export gateway traces to your own collector, keep doing
   that — add an OTel Collector fan-out and point one exporter here.

3. **(Optional) per-end-user analytics** — make sure an upstream auth layer
   populates the user header you mapped (`x-user-id` above) and set
   `CERBERUS_USER_ID_ATTRIBUTE=user.id` on the bridge.

### Standalone mode (`aigw run`, no Kubernetes)

The gateway's CLI runs the full data plane locally and honors the same
OTel env vars as process environment. Useful for kicking the tires —
see [Playground](#playground-local-end-to-end).

## Playground (local end-to-end)

`playground/` boots the whole chain locally: a stub Cerberus ingest, a mock
OpenAI-compatible LLM, a mock MCP server, the bridge (docker compose), and —
if the `aigw` binary is installed (`go install
github.com/envoyproxy/ai-gateway/cmd/aigw@latest`) — a standalone Envoy AI
Gateway on `:1975` wired to all of them (`OPENAI_BASE_URL` → mock LLM,
`--mcp-config playground/mcp-servers.json` → mock MCP).

```bash
make run            # docker compose up + aigw run (see playground/run.sh)
playground/drive.sh # send one chat completion + one MCP tools/call
```

Success looks like the stub ingest printing one `llm_chat_completion` event
and one `mcp_tool_call` event with a 64-hex-char hashed `source_ip` and
`[REDACTED]` sensitive argument values.

Without `aigw`, `drive.sh --direct` POSTs pre-recorded OTLP payloads straight
to the bridge so you can still verify bridge → ingest behavior.

## Verification end-to-end

```bash
# Drive traffic through your gateway
curl -s http://<gateway>/v1/chat/completions \
     -H 'Content-Type: application/json' \
     -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}'

# Bridge accepted and shipped it?
curl -s http://<bridge>:4318/stats | jq
# {"queued": 0, "events_llm": 1, ..., "posted": 1, "post_failures": 0,
#  "server_accepted": 1, "server_skipped": 0}
```

Then check the Cerberus dashboard for your client: an `llm://...` endpoint
event, and for MCP traffic rows in MCP discovery. The event's `remote_addr`
should be a 64-char lowercase hex digest (HMAC-SHA256) when a secret key is
configured. A growing `server_skipped` means the ingest server is filtering
events (see known gaps).

`events_llm` / `events_mcp` count events **enqueued** for delivery, not raw
spans seen — under queue pressure they exclude `dropped_oversize` and
`dropped_queue_full`. Full accounting: `spans_ignored + spans_filtered +
dropped_oversize + dropped_queue_full + events_llm + events_mcp` = spans received.

## Privacy

- Source IPs are normalized (`normalize_ip`) and pseudonymized with
  HMAC-SHA256 (`hash_pii`) **in the bridge**, before anything is queued
  (shipped as `remote_addr`, the backend's field name).
- MCP arguments and (opt-in) LLM content pass through `cerberus_core.sanitize_dict`,
  redacting `SENSITIVE_KEYS` (passwords, tokens, api keys, …). **Redaction is
  key-based only**: secrets embedded in free-form prompt/completion text are
  NOT scrubbed — enable `CERBERUS_CAPTURE_LLM_CONTENT` only where that is
  acceptable.
- Client-controlled header fields (`user_agent`, `user_id`) and error strings
  are length-capped so an oversized header can't push events over the size
  limit (which would silently suppress that client's telemetry).
- LLM prompt/completion content is **off by default** twice over: the bridge
  doesn't ship it (`CERBERUS_CAPTURE_LLM_CONTENT=false`) and the recommended
  gateway env sets `OPENINFERENCE_HIDE_INPUTS/OUTPUTS=true` so it never even
  reaches the bridge.
- Events carry no credentials: the ingest server derives the client from the
  `X-API-Key` header.

## Parity note

Unlike `cerberus-flex-gateway` (a Rust **port** of the sanitization logic,
policed by `parity-fixtures/`), this package **imports** `cerberus-core`
directly — there is no second implementation to drift, so it needs no parity
runner. If you change `SENSITIVE_KEYS` in cerberus-core, this bridge picks
it up by version bump.

## Layout

```
cerberus-envoy-ai-gateway/
├── pyproject.toml
├── Makefile
├── Dockerfile
├── src/cerberus_envoy_ai_gateway/
│   ├── app.py            # FastAPI: POST /v1/traces, /health /ready /stats
│   ├── cli.py            # console entrypoint
│   ├── config.py         # CERBERUS_* env config
│   ├── otlp.py           # OTLP/HTTP decode (protobuf + JSON)
│   ├── classify.py       # span → LLM | MCP | ignore
│   ├── mapper_llm.py     # LLM span → CoreData event
│   ├── mapper_mcp.py     # MCP span → MCPEventData event (+schema-report hook)
│   ├── spanfields.py     # shared attribute/timestamp helpers
│   ├── pipeline.py       # sanitize (cerberus-core), hash PII, size caps
│   ├── queue.py          # bounded queue, drop-on-full
│   ├── sink.py           # batch POST /v1/ingest/batch
│   └── secret.py         # startup HMAC key fetch
├── deploy/
│   ├── kubernetes/bridge.yaml       # Secret + Deployment + Service
│   └── ai-gateway/extproc-env.yaml  # gateway-side env block
├── playground/           # local end-to-end harness (aigw standalone)
└── tests/                # golden OTLP fixtures + unit/integration tests
```

## Architecture references

- **Internal design / maintainer guide: [ARCHITECTURE.md](./ARCHITECTURE.md)** — data flow, why an OTLP bridge, module map, the span→event mapping spec, and the cross-repo backend contract.
- Envoy AI Gateway tracing: <https://aigateway.envoyproxy.io/docs/capabilities/observability/tracing>
- MCP gateway: <https://aigateway.envoyproxy.io/docs/capabilities/mcp/>
- Span attribute sources (gateway code): `internal/tracing/openinference/`,
  `internal/tracing/mcp.go` in <https://github.com/envoyproxy/ai-gateway>
