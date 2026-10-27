# cerberus-agentcore-interceptor

A Lambda interceptor for [Amazon Bedrock AgentCore Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors.html).
It runs in your account, turns each call the gateway handles into a Cerberus
event, and passes the caller's request through to its target. With response
capture on, it does the same for the response on its way back.

Everything the gateway fronts is covered: MCP targets, inference connectors and
generic providers, AgentCore Runtime targets and HTTP passthrough targets.

```
caller ──► AgentCore Gateway ──► target
               │ REQUEST interceptor, and RESPONSE with response capture on
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
cannot answer, the caller gets an error. At REQUEST the target then never runs.
At RESPONSE it already has, so the caller gets an error for a call the target
executed. That is the platform's behaviour, not a choice this package makes,
and it is why the handler treats availability as the first requirement: every
step that builds a capture runs under its own guard, so a capture that cannot
be built is dropped while the call goes through untouched.

The interceptor is therefore part of your gateway's availability. Alarm on the
function's `Errors` and on its `Throttles`: the gateway refuses a throttled
request, and a throttle does not show in `Errors`. Move an alias rather than
editing the gateway role in place.

Attaching it also lowers the gateway's MCP request size limit. The REQUEST input
carries an MCP body twice, raw and parsed, and a synchronous Lambda invoke takes
at most 6 MB, so the gateway refuses an MCP request over about 3 MB with a 500
before the function runs.

Leave the function unreserved unless you size its reserved concurrency.
Reserved concurrency is a hard ceiling shared by every gateway on the function,
and Lambda also allows each reserved unit only 10 requests per second. Past
either limit the gateway refuses requests. To size it:

- need = max(peak RPS × p99 duration in seconds, peak RPS / 10)
- reserve at least 2 × need

With a chain, use this function's p99 duration, which includes the chained
call. While the chained function is throttled, each request holds this one for
up to 2 s more, so give one of the two reserved concurrency: that wait should
not draw on the pool the throttled function needs.

With response capture on, or a RESPONSE chain, each call is two invocations,
one at each point. Work out need for each point from its own p99 duration, the
RESPONSE one measured on your own responses, and size any provisioned or
reserved concurrency from the sum.

## What it captures

One event per intercepted request: method, path, the gateway host, the caller's
identity, an allowlisted set of headers, and the request body with sensitive
keys redacted (`cerberus-core`'s `SENSITIVE_KEYS`, plus any you name). Bodies
are bounded so a large one is trimmed toward a still-meaningful shape rather
than dropped outright. Every event is portable JSON: U+0000 and unpaired
surrogates in captured text become U+FFFD, and NaN and infinite numbers become
the strings `"NaN"`, `"Infinity"` and `"-Infinity"`.

Each request event's `custom_data.agentcore` carries `phase`, `"request"`, and
`response_expected`: true when this function also intercepts this call's
response.

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

### Responses

With response capture on, each RESPONSE invocation is an event of its own, with
`phase` `"response"` and the request's `event_id` followed by `#response`. Beside
the gateway host and source address it carries:

- `status_code`, when the gateway gives an integer one
- `response_body`, when the body is kept
- `custom_data.agentcore.response`, a note of what happened to the body: its
  `state`, a `reason` when it was not kept, and on `http` the response's
  `content_type`

An `mcp` response event also carries the request, which the gateway still hands
over at RESPONSE, handled as on a request event, unless this function chains a
REQUEST interceptor; see Chaining. An `http` response event has no request to
carry: no method, path, headers or caller identity.

JSON bodies are sanitized as request bodies are, JSON inside a tool result's
text included, and credential header names are redacted as keys too, since a
body can echo the request's headers. Event streams are sanitized event by event.
Redaction matches key names, so text that is not JSON is kept as sent: a secret
in plain-text tool output, or in an event-stream line that is not a JSON object
or array, reaches Cerberus as written. A gzip body is recorded as
`{"body_skipped_encoding": "gzip"}`. An `http` body with no content type is read
as JSON, or as an event stream when it is framed as one. A body that is absent,
empty or unreadable, or of another content type, is not kept, and the note's
`reason` says which. One that does not fit whole is reduced on `mcp` to
its JSON-RPC id, error and the result's names and clipped text, then cut to the
head and tail of its text, then shed. On `mcp` the request and the response
share one event's cap.

With `CERBERUS_CAPTURE_BODIES=false`, the response side is only the status code
and a `disabled` note.

## Response capture

Off by default. To turn it on, set `CERBERUS_RESPONSE_CAPTURE=true` and attach
this function at both points, in one interceptor configuration entry with
`["REQUEST", "RESPONSE"]`. Its request events then say a response event follows,
so set the variable only on a function attached at both points. Response
capture needs `enableResponseStreaming` off on the gateway.

A RESPONSE attachment changes how the gateway serves every call on it, whatever
this function does:

- The gateway holds each streamed response until it is complete and delivers it
  whole, so a streaming caller sees no output until the call has finished.
  Attach RESPONSE only on a gateway whose callers can take responses in one
  piece.
- The MCP request size limit falls to about 2.0 to 2.5 MB. An MCP interceptor's
  input holds the request twice, as sent and parsed, and at RESPONSE the
  response beside it, all within Lambda's 6 MB invoke limit. A request over the
  limit can pass REQUEST and then fail at RESPONSE, after the target has run.
  `payloadFilter` takes effect on `http` payloads only, so it does not shrink
  that input.
- Each call is two invocations and two Firehose records, and a RESPONSE
  invocation that fails or is throttled fails the call after the target has
  run.

If the gateway already has a REQUEST interceptor, chain it through this function
rather than leaving it as its own entry beside this one at RESPONSE only; see
Chaining. The RESPONSE input holds the caller's request as it was before your
interceptor ran, so in that setup no request event is sent and response events
carry what your interceptor removed.

Settings are read at init, and none of them can undo what the attachment does to
the gateway. To stop response capture quickly, detach the RESPONSE point, or the
function. Detaching it also detaches a RESPONSE interceptor this function
chains, so attach that one directly in its place. Then set
`CERBERUS_RESPONSE_CAPTURE` to false on a new version and move the alias, so
request events stop saying a response follows. `UpdateGateway` replaces the
gateway's whole configuration, so resend every field you are not changing.

## A note on the `mcp` output shape

An interceptor on an MCP-protocol gateway must **echo the payload back**. An
output of `{"interceptorOutputVersion": "1.0", "mcp": {}}` is accepted and
answers HTTP 200, but it replaces the payload: at REQUEST the target never runs
and the caller gets a JSON-RPC parse error, and at RESPONSE the caller gets
`{}`. `{"http": {}}` is a true pass-through, except at an `mcp` RESPONSE, where
the caller also gets `{}`. This package's golden fixtures pin the echo form for
exactly that reason.

The echo changes two things. An unpaired UTF-16 surrogate, which the Lambda
runtime cannot encode, comes back as U+FFFD. A number outside the double range,
such as `1e999`, comes back as the string `"Infinity"` or `"-Infinity"`, which
is what the gateway hands the target when no interceptor is attached.

At RESPONSE the echo carries the response body and status code back. A
response with no body has nothing to echo and is answered `{"mcp": {}}`, so
its caller gets `{}` where the target sent no body.

## Chaining

A gateway has one interceptor slot at each point. If yours is taken, point this
function at the one that is already there: it runs first on the gateway's
input, with numbers outside the double range written as strings as above. Its
answer is returned to the gateway unchanged but for the two replacements above,
and our own failures can neither skip it nor alter what it decided. If we
cannot get its answer, or the answer is not a JSON object, the call is refused
rather than served without it.

`CERBERUS_CHAIN_REQUEST_ARN` chains the REQUEST point and
`CERBERUS_CHAIN_RESPONSE_ARN` the RESPONSE point. If your interceptor is
attached at both in one configuration entry, set both ARNs to your function and
attach this one at both points in its place. An input this function cannot read
goes to the chained function, and is refused when the two chains differ, since
it could be for either.

At RESPONSE, yours runs first and its answer is what gets captured, since that
is what the caller receives: what it removed is never seen. With a REQUEST chain
set, an `mcp` response event carries no request side, as on `http`: the gateway
hands RESPONSE the caller's request as it was before your interceptor ran, so
only the request event records the request.

Set `CERBERUS_CHAIN_REQUEST_ARN` and `CERBERUS_CHAIN_RESPONSE_ARN` to qualified
ARNs, `CERBERUS_GATEWAY_IDS` to the ids or ARNs of the gateways this function
serves, and `CERBERUS_CHAIN_READ_MS` to the slower chained function's own
timeout plus a cold-start allowance; those two serve both chains. A gateway
that is not on the list is refused at either point, and its id logged, because
it may have had an interceptor of its own before this one. The execution role
needs `lambda:InvokeFunction` on each ARN.

A throttled invoke is retried twice, over about 1 to 2 s as the gateway itself
would, and no retry starts within 500 ms of the function's timeout. So at
REQUEST the function's timeout has to cover `CERBERUS_CHAIN_READ_MS` plus 2 s
for those retries plus 1.5 s for the capture. With a RESPONSE chain and response
capture on, add `CERBERUS_CHAIN_READ_MS` and 2 s to the RESPONSE timeout worked
out under Deployment, and about 0.2 s more to pass a multi-megabyte input on.

Set `CERBERUS_CHAIN_PASS_HEADERS` to the REQUEST interceptor's
`inputConfiguration.passRequestHeaders`, and
`CERBERUS_CHAIN_RESPONSE_PASS_HEADERS` to the RESPONSE one's; each is required
beside its ARN. This function's own slot passes request headers whenever
identity needs them, and with `false` they are taken out before the chained
function is invoked, so it never receives callers' credentials it was not
configured to see. The response's own headers reach a RESPONSE chain either
way, as the gateway passes them. With `true`, set `passRequestHeaders: true` on
this function's own interceptor entry as well, whatever the identity mode, or
the chained function receives no headers.

What their interceptor did travels with the event: `passed` (the body is
unchanged; headers are not compared), `transformed` (the transformed body is
what gets captured, since it is what reaches the target), `short_circuit` with
its status code (a refused request is still a captured attempt),
`invalid_output`, or `error`. At RESPONSE an answer is `passed` or
`transformed`, by its body alone, and a transformed response is captured with
the status code and content type the answer gives.

## Configuration

| Variable | Default | |
|---|---|---|
| `CERBERUS_FIREHOSE_STREAM` | required | Delivery stream name or ARN, or a comma-separated list picked by gateway |
| `CERBERUS_IDENTITY` | `jwt` | `jwt`, `sigv4` or `none`, or the authorizer type from the table above |
| `CERBERUS_USER_ID_CLAIM` | `sub` | Which JWT claim identifies the caller |
| `CERBERUS_CAPTURE_HEADERS` | the list above | Comma-separated |
| `CERBERUS_CAPTURE_BODIES` | `true` | `false` captures metadata and identity only |
| `CERBERUS_RESPONSE_CAPTURE` | `false` | `true` captures responses as well; see Response capture |
| `CERBERUS_SENSITIVE_KEYS` | empty | Extra body keys to redact |
| `CERBERUS_MAX_EVENT_BYTES` | `57344` | 1024 to 63488 |
| `CERBERUS_CHAIN_REQUEST_ARN` | unset | Qualified ARN of an interceptor to run first at REQUEST |
| `CERBERUS_CHAIN_RESPONSE_ARN` | unset | Qualified ARN of an interceptor to run first at RESPONSE |
| `CERBERUS_GATEWAY_IDS` | unset | Gateway ids or ARNs. Required when chaining; any other gateway is refused |
| `CERBERUS_CHAIN_READ_MS` | unset | Required when chaining; serves both chains |
| `CERBERUS_CHAIN_PASS_HEADERS` | unset | `true` or `false`. Required with `CERBERUS_CHAIN_REQUEST_ARN` |
| `CERBERUS_CHAIN_RESPONSE_PASS_HEADERS` | unset | `true` or `false`. Required with `CERBERUS_CHAIN_RESPONSE_ARN` |
| `CERBERUS_FIREHOSE_CONNECT_MS` | `250` | At most 750; connect plus read is capped at 1500 |
| `CERBERUS_FIREHOSE_READ_MS` | `500` | Lowered when connect plus read exceeds 1500 |
| `CERBERUS_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN` or `WARNING`, `ERROR`. Logs carry request ids and outcomes, never bodies or headers |

A number out of range is clamped to the nearest bound, and an unknown log level
becomes `INFO`, each with a warning in the function's log. Any other value that
cannot be used turns capture off rather than failing the function: it logs an
`ERROR` naming the variable, passes every request through unchanged, and counts
`CaptureDropped` with reason `config_invalid`. An unusable
`CERBERUS_RESPONSE_CAPTURE` is logged and turns off response capture alone;
request capture is unaffected. A chaining setting that cannot be
used does fail the function at init, since no call may be served without the
chained interceptor. So does a chaining setting set without the ARN it serves,
or a `CERBERUS_CHAIN_*` name the function does not know: either can mean an ARN
is missing or misspelled, and the function would otherwise hold the replaced
interceptor's slot without running it. The gateway refuses every call until the
setting is fixed. Lambda caps all environment variables at 4 KB together.

## Deployment

`make zip` builds `dist/cerberus-agentcore-interceptor.zip` — this package and
`cerberus-core`, nothing else, since `boto3` comes from the runtime.

| | |
|---|---|
| Handler | `cerberus_agentcore_interceptor.handler.handler` |
| Runtime | `python3.13`, `arm64` |
| Memory | 512 MB to start; 1769 MB with response capture on |
| Timeout | 3 s; 6 s with response capture on; longer with a chain, see Chaining |
| Permissions | `firehose:PutRecord` on each stream, `lambda:InvokeFunction` on each chain target |
| Interception points | `["REQUEST"]`, or `["REQUEST", "RESPONSE"]` with response capture on or a RESPONSE chain |

Capture gives up 500 ms before the function's timeout, and skips the Firehose
write when the time left cannot cover `CERBERUS_FIREHOSE_CONNECT_MS` plus
`CERBERUS_FIREHOSE_READ_MS`. Either way the call goes through unchanged and
`CaptureDropped` counts reason `deadline`. Those two timeouts add up to at most
1.5 s, so one write stays well inside the 3 s timeout. Do not go lower: with a
timeout under 500 ms plus the two, 1.25 s by default, every write is skipped.

The same holds at RESPONSE, where the 500 ms left also covers echoing the
response back. Lambda gives a function CPU in proportion to its memory, and
response capture needs 1769 MB, a full vCPU, to read a large response in time
and room to hold it.

Of the 6 s timeout, 500 ms is that margin and 750 ms the two Firehose timeouts
by default; the rest is for reading the response. Raise the timeout by as much
as you raise those two. A response that cannot be read in time has its capture
dropped, the call goes through unchanged, and `CaptureDropped` counts reason
`deadline`. If those drops appear, raise the timeout.

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
line in its log means capture is off until the setting is fixed; a line naming
`CERBERUS_RESPONSE_CAPTURE` means only response capture is. With a chain
set, the invoke is refused instead, as from an unlisted gateway, and its log
names gateway `''`. That line is expected; the test invoke never reaches the
chained function.

Leave `exceptionLevel` unset on the gateway. It keeps the interceptor's error
text away from MCP callers. Inference callers still receive a refusal as
Lambda's error payload: the message, the `InterceptorError` type, the Lambda
request id and a stack trace through this package's files. The message is fixed
text and the trace shows only this package's code, so neither carries request
content or settings. Lambda's own errors reach inference callers too: while the
function is throttled, the caller's error names its ARN, account id included.

### Delivery stream

Create the stream in the function's own account and region. The function writes
by stream name: an ARN in `CERBERUS_FIREHOSE_STREAM` is reduced to its name, and
its region and account are ignored.

Give the stream an HTTP endpoint destination, with the endpoint URL and access
key Cerberus gives you, and these settings:

| | |
|---|---|
| Content encoding | `GZIP` |
| Buffer size | 2 MiB at most |
| Retry duration | 3600 s, so a short endpoint outage is retried rather than backed up |
| S3 backup | Failed data only |

The endpoint accepts deliveries up to 4 MiB uncompressed. Firehose keeps a
delivery's uncompressed body, its base64-encoded records included, within the
buffer size, but treats that size as a hint, so 2 MiB leaves room under the
limit. A delivery over the limit is refused on every retry and ends up in the
backup bucket. With response capture on, each call writes two records.

### Metrics

The handler emits CloudWatch embedded-metric lines in namespace
`Cerberus/AgentCoreInterceptor`: `Captured`, `CaptureDropped`,
`UnknownInputVersion`, `UnexpectedPhase` and `UnknownShape`. `CaptureDropped` is
published once without a dimension, summing every reason, and once by
`Reason`: `throttle`, `timeout`, `deadline`, `oversize`, `sink_error`,
`handler_error`, `config_invalid`. A throttled stream can answer slower than the
read timeout instead of refusing, so throttling shows as `timeout` as well as
`throttle`.

`Captured` and `CaptureDropped` are also published by `Phase`, `request` or
`response`, since Lambda's own `Errors`, `Throttles` and `Duration` cannot tell
the two points apart. A drop counted before the phase is known, such as an input
that cannot be read, has no `Phase`.

Metric lines are printed to stdout, which Lambda's `ApplicationLogLevel` does
not filter, so they count at every level. The function's other log lines are
filtered: `ERROR` hides the `capture dropped` warnings but not their metric
lines. `botocore` and `urllib3` stay at `WARNING` whatever the level, since at
`DEBUG` botocore logs each request with its payload.

Alarm on:

- Lambda `Errors`, first: each one is a blocked customer request
- Lambda `Throttles`
- `CaptureDropped` without a dimension; its `Reason` series say why. An alarm
  on response capture reads the `Phase` `response` series
- `UnexpectedPhase` above 0: the function is attached at RESPONSE while
  response capture is off and no RESPONSE chain is set
- the stream's `ThrottledRecords`
- the stream's `DeliveryToHttpEndpoint.DataFreshness` (Maximum) above the buffer
  interval plus 300 s. A rejected access key or an endpoint outage shows there,
  not in the function's metrics. `DeliveryToHttpEndpoint.Success` cannot
  replace it: while every attempt fails it reports no datapoints at all
- a canary call through the gateway, or a drop in the gateway's `Invocations`
  with missing data treated as breaching. A lost invoke grant refuses calls
  without invoking the function, and no other Lambda or gateway metric counts
  them

## Development

```bash
make venv        # uv venv + editable install
make test
make lint
make typecheck
```

Python 3.13, arm64. `boto3` comes from the Lambda runtime and is a dev
dependency only.
