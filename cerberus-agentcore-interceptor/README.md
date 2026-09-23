# cerberus-agentcore-interceptor

A Lambda interceptor for [Amazon Bedrock AgentCore Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors.html).
It runs in your account, turns each call the gateway handles into a Cerberus
event, and returns the caller's request unchanged.

Everything the gateway fronts is covered: MCP targets, inference connectors and
generic providers, AgentCore Runtime targets and HTTP passthrough targets.

```
caller ──► AgentCore Gateway ──► target
               │ REQUEST interceptor
               ▼
      cerberus-agentcore-interceptor (your account)
               │
               ▼
      Firehose stream (your account) ──► Cerberus
```

The interceptor never talks to Cerberus directly and holds no Cerberus
credential: it writes to a Firehose delivery stream in your account, and the
stream's HTTP endpoint holds the ingest key.

## Read this before you attach it

**AgentCore Gateway fails closed on interceptor failure.** If the function
cannot answer, the caller gets an error and the target never runs. That is the
platform's behaviour, not a choice this package makes, and it is why the
handler treats availability as the first requirement: every step that builds a
capture runs under its own guard, so a capture that cannot be built is dropped
while the request goes through untouched.

The interceptor is therefore part of your gateway's availability. Alarm on the
function's `Errors` and `Throttles`, give it reserved concurrency, and move an
alias rather than editing the gateway role in place.

## What it captures

One event per intercepted request: method, path, the gateway host, the caller's
identity, an allowlisted set of headers, and the request body with sensitive
keys redacted (`cerberus-core`'s `SENSITIVE_KEYS`, plus any you name). Bodies
are bounded so a large one is trimmed toward a still-meaningful shape rather
than dropped outright.

Responses are not captured in this version.

### Identity

Follows the gateway's authorizer:

| Mode | Authorizer | What identifies the caller |
|---|---|---|
| `jwt` | `CUSTOM_JWT` | A claim from the caller's token, `sub` by default. The token itself is dropped. |
| `sigv4` | `AWS_IAM`, `AUTHENTICATE_ONLY` | The access key id from the signature. |
| `none` | `NONE` | Nothing; the gateway asserts no caller. |

`jwt` mode needs `passRequestHeaders: true` on the interceptor configuration,
and reads the token without verifying it — the gateway's authorizer has already
refused anything it does not trust before the interceptor runs.

### Headers

Captured by default: `User-Agent`, `Content-Type`, `X-Amzn-Trace-Id`,
`anthropic-version`, `anthropic-beta`, `OpenAI-Organization`, `OpenAI-Project`.

Credential-bearing headers are dropped whatever the allowlist says:
`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`,
`Proxy-Authorization`, `X-Amz-Security-Token` and `WWW-Authenticate`. So are the
gateway's own `x-amzn-vpce-*` and `x-amzn-tls-*` headers. Session ids travel in
the event's `session_id` field instead of the header map.

## A note on the `mcp` output shape

An interceptor on an MCP-protocol gateway must **echo the payload back**. An
output of `{"interceptorOutputVersion": "1.0", "mcp": {}}` is accepted and
answers HTTP 200, but it replaces the payload: at REQUEST the target never runs
and the caller gets a JSON-RPC parse error. `{"http": {}}` is a true
pass-through. This package's golden fixtures pin the echo form for exactly that
reason.

## Chaining

A gateway has one REQUEST interceptor slot. If yours is taken, point this
function at the one that is already there: it runs first on the raw input, its
answer is returned to the gateway unchanged, and our own failures can neither
skip it nor alter what it decided. If we cannot get its answer, the request is
refused rather than served without it.

Set `CERBERUS_CHAIN_REQUEST_ARN` to the qualified ARN, `CERBERUS_GATEWAY_IDS`
to the gateways this function serves, and `CERBERUS_CHAIN_READ_MS` to the
chained function's own timeout plus a cold-start allowance. A gateway that is
not on the list is refused, because it may have had an interceptor of its own
before this one. The execution role needs `lambda:InvokeFunction` on the ARN,
and the function's timeout has to cover `CERBERUS_CHAIN_READ_MS` plus the
throttle retries plus about a second for the capture.

What their interceptor did travels with the event: `passed`, `transformed`
(the transformed body is what gets captured, since it is what reaches the
target), `short_circuit` with its status code (a refused request is still a
captured attempt), `invalid_output`, or `error`.

## Configuration

| Variable | Default | |
|---|---|---|
| `CERBERUS_FIREHOSE_STREAM` | required | Delivery stream name, or a comma-separated list picked by gateway |
| `CERBERUS_IDENTITY` | `jwt` | `jwt`, `sigv4` or `none` |
| `CERBERUS_USER_ID_CLAIM` | `sub` | Which JWT claim identifies the caller |
| `CERBERUS_CAPTURE_HEADERS` | the list above | Comma-separated |
| `CERBERUS_CAPTURE_BODIES` | `true` | `false` captures metadata and identity only |
| `CERBERUS_SENSITIVE_KEYS` | empty | Extra body keys to redact |
| `CERBERUS_MAX_EVENT_BYTES` | `57344` | Ceiling 63488 |
| `CERBERUS_CHAIN_REQUEST_ARN` | unset | Qualified ARN of an interceptor to run first |
| `CERBERUS_GATEWAY_IDS` | unset | Required when chaining; any other gateway is refused |
| `CERBERUS_CHAIN_READ_MS` | unset | Required when chaining |
| `CERBERUS_FIREHOSE_CONNECT_MS` | `250` | |
| `CERBERUS_FIREHOSE_READ_MS` | `500` | |
| `CERBERUS_LOG_LEVEL` | `INFO` | Logs carry request ids and outcomes, never bodies or headers |

A malformed value fails at init, so a broken configuration shows up when the
function is deployed rather than as a gap in capture later. Lambda caps all
environment variables at 4 KB together.

## Deployment

`make zip` builds `dist/cerberus-agentcore-interceptor.zip` — this package and
`cerberus-core`, nothing else, since `boto3` comes from the runtime.

| | |
|---|---|
| Handler | `cerberus_agentcore_interceptor.handler.handler` |
| Runtime | `python3.13`, `arm64` |
| Memory | 512 MB to start; raise it from your own worst-case body sizes |
| Timeout | 3 s |
| Permissions | `firehose:PutRecord` on each stream, `lambda:InvokeFunction` on a chain target |

The gateway's role needs `lambda:InvokeFunction` on `function:<name>:*` — a
grant on the unqualified ARN does not cover an alias, and permission edits take
minutes to take effect in both directions, so publish a version and move an
alias rather than editing the role in place.

Leave `exceptionLevel` unset on the gateway. It keeps the interceptor's error
text away from MCP callers; inference callers still receive it, so nothing this
package raises says anything you would not show a customer's end user.

### Metrics

The handler emits CloudWatch embedded-metric lines in namespace
`Cerberus/AgentCoreInterceptor`: `Captured`, `CaptureDropped` (dimension
`Reason`: `throttle`, `timeout`, `oversize`, `sink_error`, `handler_error`),
`UnknownInputVersion`, `UnexpectedPhase` and `UnknownShape`.

Alarm on Lambda `Errors` first — each one is a blocked customer request — then
on `Throttles`, `CaptureDropped` by reason, and the stream's
`ThrottledRecords`.

## Development

```bash
make venv        # uv venv + editable install
make test
make lint
make typecheck
```

Python 3.13, arm64. `boto3` comes from the Lambda runtime and is a dev
dependency only.
