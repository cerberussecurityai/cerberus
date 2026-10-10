# cerberus-agentcore-interceptor

A Lambda interceptor for [Amazon Bedrock AgentCore Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors.html).
It runs in your account, turns each call the gateway handles into a Cerberus
event, and passes the caller's request through to its target.

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
function's `Errors` and on its `Throttles`: the gateway refuses a throttled
request, and a throttle does not show in `Errors`. Move an alias rather than
editing the gateway role in place.

Leave the function unreserved unless you size its reserved concurrency.
Reserved concurrency is a hard ceiling shared by every gateway on the function,
and Lambda also allows each reserved unit only 10 requests per second. Past
either limit the gateway refuses requests. To size it:

- need = max(peak RPS × p99 duration in seconds, peak RPS / 10)
- reserve at least 2 × need

## What it captures

One event per intercepted request: method, path, the gateway host, the caller's
identity, an allowlisted set of headers, and the request body with sensitive
keys redacted (`cerberus-core`'s `SENSITIVE_KEYS`, plus any you name). Bodies
are bounded so a large one is trimmed toward a still-meaningful shape rather
than dropped outright. Every event is portable JSON: U+0000 and unpaired
surrogates in captured text become U+FFFD, and NaN and infinite numbers become
the strings `"NaN"`, `"Infinity"` and `"-Infinity"`.

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

The echo changes one thing: an unpaired UTF-16 surrogate, which the Lambda
runtime cannot encode, comes back as U+FFFD.

## Chaining

A gateway has one REQUEST interceptor slot. If yours is taken, point this
function at the one that is already there: it runs first on the raw input, its
answer is returned to the gateway unchanged but for the surrogate replacement
above, and our own failures can neither skip it nor alter what it decided. If we cannot get its answer, the request is
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
| `CERBERUS_FIREHOSE_STREAM` | required | Delivery stream name or ARN, or a comma-separated list picked by gateway |
| `CERBERUS_IDENTITY` | `jwt` | `jwt`, `sigv4` or `none`, or the authorizer type from the table above |
| `CERBERUS_USER_ID_CLAIM` | `sub` | Which JWT claim identifies the caller |
| `CERBERUS_CAPTURE_HEADERS` | the list above | Comma-separated |
| `CERBERUS_CAPTURE_BODIES` | `true` | `false` captures metadata and identity only |
| `CERBERUS_SENSITIVE_KEYS` | empty | Extra body keys to redact |
| `CERBERUS_MAX_EVENT_BYTES` | `57344` | 1024 to 63488 |
| `CERBERUS_CHAIN_REQUEST_ARN` | unset | Qualified ARN of an interceptor to run first |
| `CERBERUS_GATEWAY_IDS` | unset | Required when chaining; any other gateway is refused |
| `CERBERUS_CHAIN_READ_MS` | unset | Required when chaining |
| `CERBERUS_FIREHOSE_CONNECT_MS` | `250` | At most 750; connect plus read is capped at 1500 |
| `CERBERUS_FIREHOSE_READ_MS` | `500` | Lowered when connect plus read exceeds 1500 |
| `CERBERUS_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN` or `WARNING`, `ERROR`. Logs carry request ids and outcomes, never bodies or headers |

A number out of range is clamped to the nearest bound, and an unknown log level
becomes `INFO`, each with a warning in the function's log. Any other value that
cannot be used turns capture off rather than failing the function: it logs an
`ERROR` naming the variable, passes every request through unchanged, and counts
`CaptureDropped` with reason `config_invalid`. A chaining setting that cannot be
used does fail the function at init, since no request may be served without the
chained interceptor. Lambda caps all environment variables at 4 KB together.

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
| Interception points | `["REQUEST"]` only |

Do not attach it at RESPONSE. It captures nothing there, and the attachment
makes the gateway buffer streamed responses whole, lowers its MCP request size
limit to about 2 MB, and adds a point that fails closed after the target has
run.

Capture gives up 500 ms before the function's timeout, and skips the Firehose
write when the time left cannot cover `CERBERUS_FIREHOSE_CONNECT_MS` plus
`CERBERUS_FIREHOSE_READ_MS`. Either way the request goes through unchanged and
`CaptureDropped` counts reason `deadline`. Those two timeouts add up to at most
1.5 s, so one write stays well inside the 3 s timeout. Do not go lower: with a
timeout under 500 ms plus the two, 1.25 s by default, every write is skipped.

The gateway's role needs `lambda:InvokeFunction` on `function:<name>:*` — a
grant on the unqualified ARN does not cover an alias, and permission edits take
minutes to take effect in both directions, so publish a version and move an
alias rather than editing the role in place.

Test-invoke each new version before you move the alias. Lambda runs a version's
init on the first request it receives, not when it is published, so this is
where a configuration problem first shows:

```bash
aws lambda invoke --function-name <name>:<version> \
  --cli-binary-format raw-in-base64-out --payload '{}' \
  --log-type Tail --query LogResult --output text out.json | base64 --decode
```

The invoke captures nothing and counts one `UnknownInputVersion`. An `ERROR`
line in its log means capture is off until the setting is fixed.

Leave `exceptionLevel` unset on the gateway. It keeps the interceptor's error
text away from MCP callers; inference callers still receive it, so nothing this
package raises says anything you would not show a customer's end user.

### Delivery stream

Give the stream an HTTP endpoint destination, with the endpoint URL and access
key Cerberus gives you, and these settings:

| | |
|---|---|
| Content encoding | `GZIP` |
| Buffer size | 2 MiB at most |
| Retry duration | 3600 s, so a short endpoint outage is retried rather than backed up |
| S3 backup | Failed data only |

The endpoint accepts deliveries up to 4 MiB uncompressed. Firehose
base64-encodes each record, so a delivery is about 4/3 the size of the buffer,
and 2 MiB leaves room for the request around it. A delivery over the limit is
refused on every retry and ends up in the backup bucket.

### Metrics

The handler emits CloudWatch embedded-metric lines in namespace
`Cerberus/AgentCoreInterceptor`: `Captured`, `CaptureDropped`,
`UnknownInputVersion`, `UnexpectedPhase` and `UnknownShape`. `CaptureDropped` is
published once without a dimension, summing every reason, and once by
`Reason`: `throttle`, `timeout`, `deadline`, `oversize`, `sink_error`,
`handler_error`, `config_invalid`.

`Captured` is logged at `INFO` and every other metric at `WARN`, so a Lambda
`ApplicationLogLevel` of `WARN` drops the per-request `Captured` line and keeps
the rest. `ERROR` or above hides them all.

Alarm on:

- Lambda `Errors`, first: each one is a blocked customer request
- Lambda `Throttles`
- `CaptureDropped` without a dimension; its `Reason` series say why
- `UnexpectedPhase` above 0: the function is attached at RESPONSE
- the stream's `ThrottledRecords`
- the stream's `DeliveryToHttpEndpoint.Success` below 1. A rejected access key
  or an endpoint outage shows there, not in the function's metrics

## Development

```bash
make venv        # uv venv + editable install
make test
make lint
make typecheck
```

Python 3.13, arm64. `boto3` comes from the Lambda runtime and is a dev
dependency only.
