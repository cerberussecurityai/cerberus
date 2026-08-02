# Securing MCP servers: what to instrument, and why

The Model Context Protocol gives a model the ability to take actions. That is
the point of it, and it is also what changes your attack surface: the thing
deciding which action to take is a model whose instructions arrive as
untrusted text.

This page covers the failure modes that matter at the MCP tool boundary, why
network-layer controls miss most of them, and what to record if you want to
detect them. It ends with what [`cerberus-mcp`](../cerberus-mcp/README.md)
does, but the first three sections apply whatever you instrument with.

## The failure modes

### Tool poisoning

Manipulation of a tool's metadata, its name, description, or parameter hints,
so that a model invokes it toward a purpose the user never asked for. The
agent behaves correctly given what it was told the tool does.

The deception lives in the tool definition rather than in the request, so
nothing in the traffic is malformed. Payload inspection does not catch it.
The signal is the mismatch between what the agent set out to do and what it
actually called.

Tool definitions can also change after a user has approved them, sometimes
called a rug pull: the server presents a benign tool at registration and a
different one later. Validating schemas once, at install time, does not
address this.

### Prompt injection that becomes a tool call

Injected instructions only matter to the extent that they can reach
something. An injection that changes a summary is a nuisance. An injection
that reaches `fs.read` and then `http.post` is an incident.

The useful boundary to watch is therefore not the prompt but the call graph.
A plan that says "summarize quarterly invoices" followed by a read of
`/etc/secrets/*.pem` is off-plan regardless of how the model was persuaded.

### Excessive agency

An agent holding credentials broader than its task needs. Most MCP
deployments start here, because scoping per-agent credentials is more work
than reusing an existing service account. Excessive agency is what turns a
successful injection into a large blast radius, and it is the reason the
first two failure modes are worth detecting at all.

### Confused deputy

An agent tricked into using its own privileges on an attacker's behalf. The
request is authentic, the credentials are legitimate, and the authorization
check passes. Only intent is wrong. This is why an authorization decision
made by the same model that may have been injected is not a control.

### Exfiltration by chaining

No single call is anomalous. A read is a read; an outbound POST is an
outbound POST. The chain is the anomaly. Detection has to operate over the
sequence, not over individual calls, which is a different data model from
most request logging.

### Unbounded consumption

An agent looping, retrying, or being driven to burn tokens against a metered
provider. OWASP tracks this as LLM10:2025 Unbounded Consumption, and it has
picked up the informal name "token torching" for the deliberate case. It is a
cost and availability problem rather than a confidentiality one, which is why
it is often noticed by finance before security.

## Why network controls miss this

A WAF or API gateway sees the transport. For MCP over stdio there is no
network hop to see at all. For MCP over HTTP the calls are well-formed
JSON-RPC to an endpoint the agent is allowed to reach, made with credentials
it is allowed to hold.

Every one of the failure modes above is legitimate traffic used wrongly. That
is not a gap in WAF quality; it is a category the layer cannot see, because
the distinguishing information (what the agent was asked to do, what it did
instead, what it did next) does not exist in any single request.

## What to record

If you want to detect the above, these are the fields that carry signal.
Nothing here is specific to a vendor.

| Record | Because |
|---|---|
| Tool name, per call, with timing and errors | The baseline. Without it there is no call graph. |
| Declared inventory at startup | Comparing declared tools against called tools is how you find drift, undeclared tools, and definitions that changed after approval. |
| Arguments, sanitized | The difference between "read a file" and "read the private key". Redact by key name before the data leaves the process. |
| Session and client identity | A call graph is only a graph if you can group calls by who made them. |
| Sequence and timing within a session | Chaining is a sequence property. Per-call records alone cannot express it. |
| Error and result shape | Repeated failures against the same tool are how enumeration looks. |

Two notes on doing this safely. Sanitize before transmission, not after
storage, so sensitive values never leave the process that saw them. And
pseudonymize identifiers you need for correlation but not in the clear: an
HMAC digest of a source IP still joins across events without storing the
address.

## Mapping to OWASP

| Failure mode | OWASP |
|---|---|
| Tool poisoning, prompt injection to action | ASI01 Agent Goal Hijacking, [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/) |
| Excessive agency | LLM06:2025 Excessive Agency |
| Confused deputy | ASI01, with LLM06 as the amplifier |
| Unbounded consumption, token torching | LLM10:2025 Unbounded Consumption |

The agentic list is newer and less settled than the LLM Top 10. Treat it as a
shared vocabulary rather than a checklist, and expect the numbering to move.

## What cerberus-mcp does

[`cerberus-mcp`](../cerberus-mcp/README.md) is a drop-in subclass of
`FastMCP`. Changing the class instruments every tool, resource, and prompt
handler on the server:

```python
from cerberus_mcp import CerberusMCP

mcp = CerberusMCP("my-server", cerberus_config={
    "token": "...",
    "client_id": "...",
    "ws_url": "wss://...",
})
```

It records the fields in the table above: per-call timing, arguments, errors
and results, session and client identity, plus a one-time schema report of
the declared tool, resource and prompt inventory so that declared and
observed can be compared. Arguments and headers are sanitized by key name
through [`cerberus-core`](../cerberus-core/README.md) before anything is
sent, and source IPs are HMAC-SHA256 pseudonymized.

Worth being clear about the limits:

- It observes an MCP **server**. It sees what that server was asked to do,
  not what the model was thinking.
- Instrumenting at a gateway instead
  ([`cerberus-envoy-ai-gateway`](../cerberus-envoy-ai-gateway/README.md))
  gives you coverage without touching each server, but gateway spans
  currently carry tool names without arguments. Server-side instrumentation
  is the only way to observe the arguments a tool actually received.
- Detection is downstream. This package is the sensor, not the analysis.

## Frequently asked

**Can I detect tool poisoning without access to the model's reasoning?**

Yes, and it is the more robust place to look. Reasoning is not reliably
available, is not always faithful to what the model then does, and can be
influenced by the same injection. The call graph is content-blind: it
compares declared intent against observed calls, which holds whether the
divergence came from a poisoned tool, an injection, or a bug.

**Does instrumenting every tool call slow the server down?**

The instrumentation is on the handler and the transmission is asynchronous on
a bounded queue, so the handler does not wait for the network. Under sustained
overload the queue drops rather than blocking the server, which is a
deliberate trade: an observability path that can stall a tool call is worse
than one that loses events.

**Do I need this if my MCP server only exposes read-only tools?**

Read-only is the first half of an exfiltration chain, not a reason to skip
recording. It is also worth verifying that "read-only" is true of the
credentials rather than only of the tool descriptions.

**What about MCP servers I do not control?**

Instrument the client side or the gateway. You lose observed arguments but
keep the call graph, which is what most of the detection above depends on.

## See also

- [`cerberus-mcp`](../cerberus-mcp/README.md), installation and configuration
- [`cerberus-envoy-ai-gateway`](../cerberus-envoy-ai-gateway/README.md), gateway-side coverage for LLM and MCP traffic
- [Model Context Protocol specification](https://modelcontextprotocol.io)
- [OWASP GenAI Security Project](https://genai.owasp.org/)
