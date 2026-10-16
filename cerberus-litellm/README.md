# cerberus-litellm

LiteLLM proxy callback plugin that ships every LLM call, MCP tool call and MCP tools/list the
proxy serves to the Cerberus platform.

## What it is

`cerberus-litellm` is an observe-only LiteLLM `CustomLogger`. For each LLM call, MCP tool call
and MCP `tools/list` the proxy handles, it builds one Cerberus event and posts it, in batches, to
your Cerberus ingest endpoint.

- It implements the two terminal logging hooks (success and failure) and nothing on the request
  path. It never blocks, delays or alters a request or a response.
- Events go into a bounded in-memory queue and a background task posts batches. When the queue is
  full, new events are dropped and counted.
- Delivery is at-most-once: a failed batch is dropped and counted, not retried.
- A misconfigured plugin disables itself with a single `ERROR` log line instead of stopping the
  proxy.

## Install

Pick one:

1. **Wheel in the proxy image.** `playground/Dockerfile` is the template: it starts from the
   LiteLLM image and installs the wheel into the image's virtualenv. Pin the base image by digest.
2. **`pip install cerberus-litellm`** wherever the proxy runs.
3. **Source tree on `PYTHONPATH`** (for example mounted from a ConfigMap), together with
   `cerberus-core` and `httpx`.

Then register the callback in the proxy config:

```yaml
litellm_settings:
  callbacks: ["cerberus_litellm.handler"]
  request_correlation_in_logs: true
general_settings:
  use_x_forwarded_for: true   # only if the proxy sits behind a trusted LB
```

and set the two required environment variables:

```bash
export CERBERUS_INGEST_SERVICE=https://<your-ingest-host>
export CERBERUS_TOKEN=<your-api-key>      # or CERBERUS_TOKEN_FILE=/path/to/file
```

LiteLLM fails closed when a callback cannot be imported, so check the install before rolling out:
`python -c "import cerberus_litellm"`.

## Configuration

All configuration is by environment variable. Invalid values disable the plugin with an error
that names the variable.

| Variable | Default | Meaning |
|---|---|---|
| `CERBERUS_INGEST_SERVICE` | required | Base URL of the Cerberus ingest endpoint (`http://` or `https://`). |
| `CERBERUS_TOKEN` / `CERBERUS_TOKEN_FILE` | one required | Cerberus API key, or a file containing it. `CERBERUS_TOKEN` wins when both are set. |
| `CERBERUS_CAPTURE_LLM_CONTENT` | `true` | Send prompt and completion content. When `false`, LLM events carry metadata only. |
| `CERBERUS_CAPTURE_MCP_ARGUMENTS` | `true` | Send MCP tool-call arguments. |
| `CERBERUS_CAPTURE_MCP_RESULTS` | `true` | Send MCP tool results and tool-result error text. |
| `CERBERUS_MCP_RESULT_MAX_CHARS` | `2048` | Bound (64 to 8192) on result and error text per MCP event. |
| `CERBERUS_CAPTURE_HEADERS` | empty | Comma-separated request header names to forward (at most 20). Credential-bearing names are refused. |
| `CERBERUS_SESSION_HEADER` | `x-litellm-session-id` | Header that carries the session id. |
| `CERBERUS_TURN_HEADER` | `x-cerberus-turn-id` | Header that carries the turn id. |
| `CERBERUS_USER_ID_SOURCE` | `end_user,user_id,key_alias` | Ordered identity fields tried for `user_id`; allowed: `end_user`, `user_id`, `key_alias`, `team_alias`. |
| `CERBERUS_MCP_SERVER_FALLBACK` | `litellm` | Server name used for a tool whose name carries no server prefix. |
| `CERBERUS_BATCH_SIZE` | `50` | Events per POST (1 to 1000). |
| `CERBERUS_FLUSH_INTERVAL_MS` | `2000` | Flush period (100 to 60000). |
| `CERBERUS_QUEUE_CAPACITY` | `10000` | Queue bound (100 to 1000000); events beyond it are dropped. |
| `CERBERUS_MAX_EVENT_BYTES` | `57344` | Per-event size cap (1024 to 63488). |
| `CERBERUS_SAMPLE_RATE` | `1.0` | Fraction of calls to report (0.0 to 1.0). |
| `CERBERUS_SCHEMA_REPORT_INTERVAL_S` | `3600` | Minimum seconds (0 to 86400) between identical per-server tool catalogues; `0` reports every tools/list. |
| `CERBERUS_STATS_LOG_INTERVAL_S` | `300` | Period in seconds (0 to 86400) of the stats log line; `0` disables it. |
| `CERBERUS_LOG_LEVEL` | `info` | `debug`, `info`, `warning` or `error`. When the proxy attaches no log handler for the plugin, its lines go to stderr. |

## What is captured

Every event carries `integration: "litellm"` and the virtual-key identity fields listed under
"Identity, sessions and traces".

### LLM calls

Endpoint `llm://{provider}/{model}`, scheme `llm`. Method by LiteLLM call type:
`llm_chat_completion`, `llm_messages`, `llm_responses`, `llm_embeddings`, `llm_completion`, and
`llm_call` for anything else.

`custom_data` keys: `event_type`, `provider`, `model`, `litellm_model`, `model_group`, `model_id`,
`response_model`, `api_base_host` (host only), `duration_ms`, `ttft_ms`, `status`, `error`,
`error_class`, `error_code`, `error_normalized`, `llm_api_status`, `guardrail_status`,
`guardrails_applied`, `streaming`, `cache_hit`, `cost_usd`, `cost_input_usd`, `cost_output_usd`,
`tokens_prompt`, `tokens_completion`, `tokens_total`, `route_path`, `trace_id`, `litellm_trace_id`,
`litellm_call_id`, `request_tags`, `turn_id`, and, when set on the request, `temperature`,
`top_p`, `max_tokens`, `max_output_tokens`.

Body: `input.messages`, `input.tools` and `output` (the provider response, with streamed tool
calls assembled). Embeddings ship no output.

### MCP tool calls

Endpoint `mcp://{server}/{tool}`, scheme `mcp`, method `mcp_tool_call`. Body is the tool arguments.

`custom_data` keys: `mcp_server`, `handler_name`, `event_type`, `duration_ms`, `arguments`,
`error`, `result_summary`, `result_is_error`, `result_type`, `session_id`, `litellm_session_id`,
`client_name`, `client_version`, `request_id`, `namespaced_tool_name`, `mcp_server_host`,
`route_path`, `trace_id`, `litellm_trace_id`, `litellm_call_id`, `turn_id`.

### MCP tools/list

One `mcp_schema_report` event per server, endpoint `mcp://{server}/__schema__`. `custom_data`
holds `mcp_server`, `event_type`, `tools` (name, description, input schema), `resources`,
`prompts`, plus the correlation and identity fields. A server's report is sent again only when
its tool catalogue changes or `CERBERUS_SCHEMA_REPORT_INTERVAL_S` elapses.

Endpoint labels are normalised: surrounding whitespace and trailing slashes are trimmed, and a
label is occasionally suffixed with `_model` or `_tool`. `custom_data` keeps the original model or
tool name.

## Identity, sessions and traces

- **Identity:** `litellm_key_hash`, `litellm_key_alias`, `litellm_team_id`, `litellm_team_alias`,
  `litellm_org_id`, `litellm_user_id` and `litellm_end_user_id` come from the proxy's key and
  team records. The key hash is LiteLLM's own hash, never the key.
- **`user_id`:** the first non-empty field in `CERBERUS_USER_ID_SOURCE`.
- **`session_id`:** LiteLLM's session id, else the session header (default `x-litellm-session-id`, set by `CERBERUS_SESSION_HEADER`). It needs
  `request_correlation_in_logs: true` on the proxy. `litellm_trace_id` equals the session id by
  LiteLLM's design.
- **`turn_id`:** the turn header (default `x-cerberus-turn-id`, set by `CERBERUS_TURN_HEADER`), when the caller sends one.
- **`trace_id`:** the trace id from the caller's W3C `traceparent` header on LLM routes.

## Security

- **Content redaction is by key name.** Values under sensitive keys (for example `api_key`,
  `password`) are replaced with `[REDACTED]`. Secrets inside free text, such as a prompt, are not
  scrubbed. Where that matters, set `CERBERUS_CAPTURE_LLM_CONTENT=false`. Error and MCP result
  text is additionally masked for common credential shapes (bearer and basic credentials,
  provider-style API tokens, URL userinfo, `key=` style parameters).
- **The plugin reads only the logging payload.** It never reads or serialises the proxy's
  provider keys or the caller's virtual key. From the request headers it reads exactly one:
  `traceparent`.
- **Custom headers are an allowlist.** Only names in `CERBERUS_CAPTURE_HEADERS` are forwarded, and
  credential-bearing names (authorization, cookies, API-key headers) are refused at startup.
- **Source IPs are sent as-is** (normalised, not hashed).
- **Size cap.** Each event is bounded by `CERBERUS_MAX_EVENT_BYTES`. An oversized event first
  loses its captured content (marked `content_dropped_oversize`), and is dropped only if it is
  still too large.
- **Counters.** The periodic stats log line reports events by kind, skipped, deduplicated and
  sampled-out calls, queue drops, oversize and unserialisable drops, schema reports suppressed,
  and POST outcomes.

## Known gaps

- `requester_ip_address` is the TCP peer unless `use_x_forwarded_for` is on.
- MCP events carry no client name or version.
- The MCP route exposes no custom headers, so the turn id is unavailable there.
- No delivery retry; a failed batch is dropped.
- Events still queued at shutdown are lost.
- A callback import failure aborts proxy startup (LiteLLM behaviour); verify the install with
  `python -c "import cerberus_litellm"` before rolling out.

## Playground

`playground/` runs a LiteLLM proxy with the plugin installed, mock LLM and MCP servers, and a
stub ingest endpoint that prints and saves every event it receives.

```bash
make run                       # build the image and start everything (needs Docker)
cd playground && ./drive.sh    # send the scenarios and print what the stub received
docker compose down -v         # clean up before every re-run
```

Expect one event per call: chat, streamed chat with tool calls, messages, responses, embeddings,
two upstream errors, large completions and prompts, one `mcp_schema_report`, and seven
`mcp_tool_call` events. Events are saved under `playground/captures/`, and the proxy log shows
one "loaded" line and a periodic stats line.

## Development

```bash
make venv test lint typecheck
make fixtures CAPTURES=<dir>   # regenerate tests/fixtures/litellm from a capture directory
```

The fixtures are real payloads captured from a LiteLLM proxy; `tests/fixtures/trim_from_spike.py`
shows which captures feed which fixture.
