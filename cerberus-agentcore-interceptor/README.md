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

**AgentCore Gateway fails closed on interceptor failure.** If the Lambda
raises, times out, is throttled, loses its invoke permission or is deleted, the
caller gets an error and the target never runs. That is the platform's
behaviour, not a choice this package makes, and it is why the handler treats
availability as the first requirement: every step that builds a capture runs
under its own guard, and a capture that cannot be built is dropped while the
request goes through untouched.

Two boundaries, opposite policies:

| Boundary | On failure |
|---|---|
| Gateway → this Lambda | Fails **closed**. The caller's request is blocked. |
| This Lambda → Cerberus | Fails **open**. Capture is lost, traffic keeps flowing. |

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

## Development

```bash
make venv        # uv venv + editable install
make test
make lint
make typecheck
```

Python 3.13, arm64. `boto3` comes from the Lambda runtime and is a dev
dependency only.
