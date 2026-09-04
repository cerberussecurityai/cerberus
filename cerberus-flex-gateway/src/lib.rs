// Cerberus Flex Gateway custom policy.
//
// Architectural overview:
//
//   Request → request_filter:
//     - early-exit on health endpoints and capturePaths/excludePaths misses
//     - sampling decision (sampleRate + sampleBy): deterministic keyed
//       session-consistent verdicts by default, independent per-request
//       coin in request mode; unsampled requests do no capture work.
//       MCP-handshake-shaped requests are captured speculatively and
//       resolved in response_filter on the minted session id
//     - extract method, scheme, endpoint, query params (sanitized)
//     - extract headers (captureHeaders allowlist if configured, then
//       sanitized; Authorization HMAC'd if secret available)
//     - resolve source IP from clientIpHeader (XFF first hop) or stream
//     - if captureRequestBody && content-type matches application/json:
//       buffer body, parse, recursively sanitize; bodies detected as
//       LLM/AI prompt content are withheld unless captureAiContent is
//       set (MCP/JSON-RPC bodies are never treated as AI content —
//       see ai_content.rs)
//     - stash partial Event in RequestData; pass through
//
//   Response → response_filter:
//     - record status_code + latency_ms (wall-clock since request)
//     - capture captureResponseHeaders-allowlisted response headers
//       (sanitized like request headers; opt-in, default mcp-session-id)
//     - if captureResponseBody && content-type is JSON or SSE: observe
//       the body stream (pass-through, never buffered or delayed) into
//       a head+tail accumulator; in-budget bodies ship whole (JSON
//       sanitized / SSE sanitized per data frame), oversized bodies ship
//       head/tail slices with explicit truncation markers, compressed
//       bodies ship a body_skipped_encoding marker (see
//       response_capture.rs). LLM/AI response bodies respect
//       captureAiContent exactly like request prompts.
//     - push onto bounded queue (drop-on-full counter)
//
//   on_tick (every flushIntervalMs):
//     - drain up to batchSize events into a batch envelope with
//       {events: [...]}
//     - POST to ingestService/v1/ingest/batch with X-API-Key header
//     - on failure: drop the batch (at-most-once)
//
// Implementation references for PDK shapes used here:
//   - metrics/         (on_tick + outbound POST batching)
//   - certs/           (StreamProperties read_property)
//   - jwt-validation/  (header iteration + body access)
//   - simple-oauth-2-validation/ (init-time outbound HTTP via HttpClient)
//
// See README.md for the operator-facing config and deployment guide.
// Search for "TODO(v1.1)" in the source for scoped-out-of-v1 items.

mod ai_content;
mod config;
mod event;
mod hash;
mod path_filter;
mod pii_rules;
mod queue;
mod response_capture;
mod sampler;
mod sanitize;
mod secret;
mod sink;
mod source_ip;

#[cfg(test)]
mod pipeline_tests;

// Toolchain-generated module. Produced by `cargo anypoint config-gen`
// from definition/gcl.yaml. We don't use the generated `Config` struct
// (we use our hand-written typed wrapper in `mod config` instead, which
// applies serde defaults), but the module must be compiled in because
// it contains a `#[pdk::hl::entrypoint_flex] fn init(...)` hook the
// PDK runtime relies on.
#[allow(dead_code)]
mod generated;

/// Re-exports for the cross-impl parity test runner at
/// tests/parity_runner.rs. Marked `#[doc(hidden)]` so it doesn't
/// show up in operator-facing rustdoc; the internal modules are
/// otherwise private.
#[doc(hidden)]
pub mod __test_exports {
    pub use crate::hash::{hash_pii, normalize_ip};
    pub use crate::path_filter::PathFilter;
    pub use crate::pii_rules::{CompiledPiiRules, PiiPatternConfig};
    pub use crate::sampler::keyed_decision;
    pub use crate::sanitize::{is_sensitive_header_lower, sanitize_value, sanitize_value_with};
    pub use super::content_type_is_json;
}

use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::join;
use pdk::authentication::{Authentication, AuthenticationHandler};
use pdk::hl::timer::{Clock, Timer};
use pdk::hl::*;
use pdk::logger;
use serde_json::Value;

use crate::config::Config;
use crate::event::CerberusEvent;
use crate::path_filter::PathFilter;
use crate::pii_rules::CompiledPiiRules;
use crate::queue::EventQueue;
use crate::sampler::{
    Coin, KeyedSampler, DOMAIN_AUTHORIZATION, DOMAIN_PRINCIPAL, DOMAIN_SESSION, DOMAIN_USER,
    EPOCH_SECONDS,
};
use crate::sanitize::{is_sensitive_header_lower, sanitize_value_with, REDACTED};

const HEALTH_ENDPOINTS: [&str; 3] = ["/health", "/health_check", "/ready"];

/// Upper bound for responseHeadBytes / responseTailBytes — mirrors the
/// `maximum` declared in definition/gcl.yaml; enforced at runtime because
/// only Connected mode validates the schema.
const MAX_RESPONSE_SLICE_BYTES: u32 = 49_152;

/// `sample_key` provenance values (wire contract — see event.rs).
const KIND_SESSION_REQUEST: &str = "session_request";
const KIND_SESSION_RESPONSE: &str = "session_response";
const KIND_SESSION_HEADER: &str = "session_header";
const KIND_PRINCIPAL: &str = "principal";
const KIND_USER_ID: &str = "user_id";
const KIND_AUTHORIZATION: &str = "authorization";
const KIND_REQUEST: &str = "request";

/// MCP Streamable HTTP session header (2025-03-26 → 2025-11-25 spec
/// revisions): a response header on the initialize reply, a request
/// header on every later call. The 2026-07-28 revision removes sessions
/// entirely — servers on it never mint one, and their traffic simply
/// falls down the key ladder.
const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";
/// Sent on every non-initialize MCP request (and never on a legacy-era
/// initialize), which makes its absence a handshake discriminator in
/// `sampling_decision`.
const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

/// Per-policy state shared across request, response, and flush handlers.
/// All members are immutable except the queue and the sampler's PRNG
/// state (interior mutability via RefCell, safe because proxy-wasm
/// workers are single-threaded — no task can hold a mutable borrow
/// across an await point).
struct PolicyContext {
    config: Config,
    secret_key: Option<String>,
    path_filter: PathFilter,
    /// Lowercased captureHeaders allowlist. None = capture all headers.
    header_allowlist: Option<std::collections::HashSet<String>>,
    /// Lowercased captureResponseHeaders allowlist. Pure opt-in, unlike
    /// the request-side allowlist: empty = capture no response headers.
    response_header_allowlist: std::collections::HashSet<String>,
    /// Compiled customSensitiveKeys + customPiiPatterns. Empty when the
    /// operator configured neither — sanitization then follows the
    /// fixed built-in contract exactly.
    pii_rules: CompiledPiiRules,
    queue: EventQueue,
    /// Independent per-request draw: sampleBy: request, and the
    /// terminal rung of the session-mode key ladder.
    coin: Coin,
    /// Deterministic keyed-threshold sampler for sampleBy: session.
    keyed: KeyedSampler,
    sample_mode: SampleMode,
    /// Lowercased sessionKeyHeader entries, in configured order.
    session_key_headers: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum SampleMode {
    Session,
    Request,
}

impl SampleMode {
    fn as_str(self) -> &'static str {
        match self {
            SampleMode::Session => "session",
            SampleMode::Request => "request",
        }
    }
}

impl PolicyContext {
    fn new(config: Config, secret_key: Option<String>, sampler_seed: u64) -> Result<Self> {
        // Clamp out-of-range / non-finite sampleRate instead of failing
        // policy load — a bad numeric knob must not take capture down
        // entirely. NaN → 1.0 (capture all). (Type-level mistakes, e.g.
        // a quoted "0.5" in Local-mode YAML, still fail config
        // deserialization upstream like any other numeric field.)
        // gcl.yaml declares minimum/maximum so API Manager validates the
        // form input; the clamp is defense for Local-mode YAML.
        let configured_rate = config.sample_rate;
        let clamped_rate = if configured_rate.is_nan() {
            1.0
        } else {
            configured_rate.clamp(0.0, 1.0)
        };
        if clamped_rate != configured_rate {
            logger::warn!(
                "cerberus-flex-gateway: sampleRate {} out of range; clamped to {}",
                configured_rate,
                clamped_rate
            );
        }
        // Store the effective value back so anything reading config
        // sees what the sampler actually uses.
        let mut config = config;
        config.sample_rate = clamped_rate;
        // Same defense for the response-capture budgets: gcl.yaml declares
        // maximum 49152 for each, but only API Manager enforces the schema
        // — Local-mode YAML can carry any u32, and the README's memory and
        // event-size guarantees lean on the bound. Clamp + warn, as above.
        for (name, value) in [
            ("responseHeadBytes", &mut config.response_head_bytes),
            ("responseTailBytes", &mut config.response_tail_bytes),
        ] {
            if *value > MAX_RESPONSE_SLICE_BYTES {
                logger::warn!(
                    "cerberus-flex-gateway: {} {} exceeds the maximum; clamped to {}",
                    name,
                    *value,
                    MAX_RESPONSE_SLICE_BYTES
                );
                *value = MAX_RESPONSE_SLICE_BYTES;
            }
        }

        let path_filter = PathFilter::compile(
            config.capture_paths.as_deref().unwrap_or(&[]),
            config.exclude_paths.as_deref().unwrap_or(&[]),
        )?;
        // Trim + lowercase entries defensively (header matching is
        // case-insensitive); blank entries are dropped. If nothing
        // survives (unset, `[]`, or all-blank) the allowlist is None —
        // capture all headers, mirroring capturePaths' empty semantics.
        let header_allowlist = config
            .capture_headers
            .as_deref()
            .map(|names| {
                names
                    .iter()
                    .map(|n| n.trim().to_lowercase())
                    .filter(|n| !n.is_empty())
                    .collect::<std::collections::HashSet<_>>()
            })
            .filter(|set| !set.is_empty());
        // Response-header allowlist: trim + lowercase like the request
        // side, but empty means "capture none" (opt-in semantics), so a
        // blank-entries list needs no fail-open warning.
        let response_header_allowlist = config
            .capture_response_headers
            .iter()
            .map(|n| n.trim().to_lowercase())
            .filter(|n| !n.is_empty())
            .collect::<std::collections::HashSet<_>>();
        // A configured-but-all-blank allowlist fails open to capture-all
        // (more data leaves the gateway than the operator intended) —
        // surface that in policy logs rather than collapsing silently.
        if header_allowlist.is_none()
            && config
                .capture_headers
                .as_deref()
                .is_some_and(|names| !names.is_empty())
        {
            logger::warn!(
                "cerberus-flex-gateway: captureHeaders entries are all blank; capturing ALL headers"
            );
        }
        // Customer PII rules — compiled once here; a rule that fails to
        // compile fails policy load (mirroring PathFilter): silently
        // skipping a scrub rule the operator wrote is a PII leak.
        let (pii_rules, pii_warnings) = CompiledPiiRules::compile(
            config.custom_sensitive_keys.as_deref().unwrap_or(&[]),
            config.custom_pii_patterns.as_deref().unwrap_or(&[]),
        )
        .map_err(|err| anyhow!("invalid custom PII scrubbing config: {err:#}"))?;
        for warning in &pii_warnings {
            logger::warn!("cerberus-flex-gateway: {}", warning);
        }
        if !pii_rules.is_empty() {
            // Confirmable from pod logs, like sampling — custom scrub
            // rules changing event content should be visible at startup.
            logger::info!(
                "cerberus-flex-gateway: custom PII scrubbing active: {} extra sensitive keys, {} patterns",
                pii_rules.extra_keys.len(),
                pii_rules.patterns.len()
            );
        }
        if pii_rules.has_hash_action() && secret_key.is_none() {
            logger::warn!(
                "cerberus-flex-gateway: customPiiPatterns uses action: hash but no HMAC secret is available; matches will be redacted instead"
            );
        }
        // sampleBy — warn-and-default on unknown values, same philosophy
        // as the sampleRate clamp: a typo'd sampling knob must not take
        // capture down.
        let sample_mode = match config.sample_by.trim().to_ascii_lowercase().as_str() {
            "session" => SampleMode::Session,
            "request" => SampleMode::Request,
            other => {
                logger::warn!(
                    "cerberus-flex-gateway: unknown sampleBy {:?}; defaulting to \"session\"",
                    other
                );
                SampleMode::Session
            }
        };
        // sessionKeyHeader — trim + lowercase (header matching is
        // case-insensitive); blank entries are dropped with a warning.
        let configured_session_headers = config.session_key_header.as_deref().unwrap_or(&[]);
        let session_key_headers: Vec<String> = configured_session_headers
            .iter()
            .map(|n| n.trim().to_lowercase())
            .filter(|n| !n.is_empty())
            .collect();
        if session_key_headers.len() != configured_session_headers.len() {
            logger::warn!(
                "cerberus-flex-gateway: sessionKeyHeader contains blank entries; ignored"
            );
        }
        if clamped_rate < 1.0
            && sample_mode == SampleMode::Session
            && !response_header_allowlist.contains(MCP_SESSION_ID_HEADER)
        {
            // The decision itself still works — the sampler reads the
            // raw response header regardless of capture settings — but
            // without the captured header the backend loses one of its
            // session correlators. (Sampled events still carry the
            // top-level session_id field.)
            logger::warn!(
                "cerberus-flex-gateway: sampleBy: session with captureResponseHeaders not listing mcp-session-id — session sampling still applies, but events won't carry the response header copy of the session id"
            );
        }
        let queue = EventQueue::new(config.queue_capacity as usize);
        let coin = Coin::new(clamped_rate, sampler_seed);
        // Sampling key material: the resolved HMAC secret when one is
        // available, else the token — deployment-level values either
        // way, so replicas agree on every keyed decision.
        let keyed = KeyedSampler::new(
            clamped_rate,
            secret_key.as_deref().unwrap_or(&config.token),
        );
        Ok(Self {
            config,
            secret_key,
            path_filter,
            header_allowlist,
            response_header_allowlist,
            pii_rules,
            queue,
            coin,
            keyed,
            sample_mode,
            session_key_headers,
        })
    }

    /// HMAC-hash a value if a secret is configured; otherwise return
    /// the raw value. Used for fields where pseudoanonymization is
    /// useful but raw passthrough is acceptable when no secret is set
    /// (e.g. source IP).
    fn maybe_hash(&self, value: &str) -> String {
        pseudonymize_or_passthrough(self.secret_key.as_deref(), value)
    }

    /// Like `maybe_hash` but redacts when no secret is configured.
    /// Used for high-sensitivity fields (e.g. Authorization header)
    /// that must never ship raw.
    fn hash_or_redact(&self, value: &str) -> String {
        pseudonymize_or_redact(self.secret_key.as_deref(), value)
    }
}

/// HMAC-hash with the secret if present, otherwise pass the value
/// through raw. Backs `PolicyContext::maybe_hash`; a free function so
/// the secret-present/absent policy is unit-testable without a full
/// `Config`.
fn pseudonymize_or_passthrough(secret_key: Option<&str>, value: &str) -> String {
    match secret_key {
        Some(key) => crate::hash::hash_pii(value, key),
        None => value.to_string(),
    }
}

/// HMAC-hash with the secret if present, otherwise redact entirely.
/// Backs `PolicyContext::hash_or_redact`.
fn pseudonymize_or_redact(secret_key: Option<&str>, value: &str) -> String {
    match secret_key {
        Some(key) => crate::hash::hash_pii(value, key),
        None => REDACTED.to_string(),
    }
}

/// Carried from request_filter to response_filter via PDK's RequestData.
/// We build most of the event in request_filter (including timestamp so
/// it reflects the request arrival, not the response) and only push to
/// the queue once the response has been seen.
#[derive(Debug)]
enum RequestSlot {
    /// Event was suppressed early (health endpoint / path filter miss /
    /// sampling miss). Response filter is a no-op. Note: a non-matching
    /// content-type does NOT suppress the event — it only skips body
    /// capture; the bodyless event still ships.
    Skip,
    /// Event is partially built; response filter will push it onto the
    /// queue. `start_epoch_micros` is the request-arrival instant (same
    /// hostcall read as the event timestamp) for latency_ms.
    /// `ai_content_withheld` records that the request body was withheld
    /// as LLM/AI prompt content (captureAiContent off + prompt-shaped
    /// body on a custom path) so the response side can withhold the
    /// model output too — the response filter cannot re-derive that
    /// decision from the path alone.
    Capture {
        event: CerberusEvent,
        start_epoch_micros: u64,
        ai_content_withheld: bool,
    },
    /// MCP-handshake-shaped request captured speculatively under
    /// sampleBy: session — no session key existed at header time, so
    /// the keep/drop verdict is deferred to response_filter, keyed on
    /// the session id the server mints in its response (or resolved by
    /// the stashed fallback verdict when none appears: stateless
    /// server, 401 discovery round trip, Envoy local reply). The
    /// capture work spent before the verdict is bounded to roughly one
    /// small request per session.
    PendingHandshake {
        event: CerberusEvent,
        start_epoch_micros: u64,
        ai_content_withheld: bool,
        fallback_keep: bool,
        fallback_kind: &'static str,
    },
}

/// Outcome of the header-time sampling decision for one request.
enum SampleDecision {
    /// sampleRate 1.0 (the default): capture and stamp no sampling
    /// fields, so the pre-0.5.0 wire shape is untouched.
    CaptureAll,
    /// Sampled in: capture; stamp sample_key (plus session_id when the
    /// key was an MCP session id).
    Keep {
        kind: &'static str,
        session_id: Option<String>,
    },
    /// Sampled out: skip all capture work.
    Drop,
    /// MCP-handshake-shaped (session mode only): capture speculatively,
    /// resolve in response_filter.
    PendingHandshake {
        fallback_keep: bool,
        fallback_kind: &'static str,
    },
}

fn keep_or_drop(keep: bool, kind: &'static str, session_id: Option<String>) -> SampleDecision {
    if keep {
        SampleDecision::Keep { kind, session_id }
    } else {
        SampleDecision::Drop
    }
}

/// Trim a header/key value; empty → None, so a present-but-blank header
/// can never become a degenerate sampling key.
fn nonempty(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Legacy HTTP+SSE MCP transport (2024-11-05): the session id rides the
/// query string of every POST. Param name is SDK convention, not spec —
/// `sessionId` (TypeScript), `session_id` (Python).
fn legacy_mcp_session_query(query_string: Option<&str>) -> Option<String> {
    let qs = query_string?;
    url::form_urlencoded::parse(qs.as_bytes())
        .find(|(k, v)| (k.as_ref() == "sessionId" || k.as_ref() == "session_id") && !v.trim().is_empty())
        .map(|(_, v)| v.trim().to_string())
}

/// Both session-era MCP spec revisions REQUIRE POSTs to advertise
/// Accept listing application/json AND text/event-stream — a sharp
/// handshake discriminator: LLM SDKs send only the former, plain SSE
/// streamers only the latter.
fn accept_lists_json_and_sse(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return false;
    };
    let accept = accept.to_ascii_lowercase();
    accept.contains("application/json") && accept.contains("text/event-stream")
}

/// Header-time sampling decision. Reads raw headers via `read_header` —
/// never the sanitized/allowlisted event maps, so captureHeaders /
/// captureResponseHeaders settings can never change a decision. Every
/// key is used in memory only; nothing read here ships except the MCP
/// session id (which the backend indexes).
///
/// Body-derived session keys (A2A contextId, OpenAI Responses
/// conversation ids, /threads/{id} path handles) are deliberately not
/// consulted: they would require buffering the body before the
/// decision. That traffic falls to the identity ladder — whole-per-user,
/// the coarser but safe outcome — until an opt-in body/path tier
/// exists (see DEVELOPMENT.md "Planned improvements").
fn sampling_decision(
    ctx: &PolicyContext,
    read_header: impl Fn(&str) -> Option<String>,
    auth: &Authentication,
    endpoint: &str,
    method: &str,
    query_string: Option<&str>,
) -> SampleDecision {
    let rate = ctx.config.sample_rate;
    if rate >= 1.0 {
        return SampleDecision::CaptureAll;
    }
    if rate <= 0.0 {
        return SampleDecision::Drop;
    }
    if ctx.sample_mode == SampleMode::Request {
        return keep_or_drop(ctx.coin.flip(), KIND_REQUEST, None);
    }

    // sampleBy: session — walk the key ladder. Tiers are never mixed
    // within one session: the ladder is ordered so that a session
    // either always or never has each key (a session observed across
    // two tiers would survive whole only with probability p²).

    // 1. MCP session id echoed on the request (every call after
    //    initialize). Same hash domain as the response-minted id in
    //    response_filter — one session, one verdict.
    if let Some(session_id) = nonempty(read_header(MCP_SESSION_ID_HEADER)) {
        let keep = ctx.keyed.keep(DOMAIN_SESSION, &session_id, None);
        return keep_or_drop(keep, KIND_SESSION_REQUEST, Some(session_id));
    }
    if let Some(session_id) = legacy_mcp_session_query(query_string) {
        let keep = ctx.keyed.keep(DOMAIN_SESSION, &session_id, None);
        return keep_or_drop(keep, KIND_SESSION_REQUEST, Some(session_id));
    }

    // 2. Operator-named session key headers (traceparent, a
    //    conversation-id header, a framework session header). First
    //    configured header present on the request wins. The raw value
    //    may be sensitive (a cookie, a bearer-adjacent id), so it is
    //    hashed in memory and never stamped on the event — only the
    //    kind ships. The header NAME is bound into the hash domain so
    //    two headers with colliding values can't share a decision.
    for name in &ctx.session_key_headers {
        if let Some(value) = nonempty(read_header(name)) {
            let domain = format!("header:{name}");
            let keep = ctx.keyed.keep(&domain, &value, None);
            return keep_or_drop(keep, KIND_SESSION_HEADER, None);
        }
    }

    // 3. Chat-shaped LLM traffic is sampled per-request even in session
    //    mode — deliberately, not as a fallback. Chat completion APIs
    //    (OpenAI Chat Completions, Anthropic Messages, Gemini
    //    generateContent, Bedrock Converse, ...) are stateless on the
    //    server: every turn re-sends the full conversation so far
    //    (earlier prompts, model outputs, tool results), so any single
    //    sampled request already contains the whole session up to that
    //    point. Whole-session capture here would multiply bytes — an
    //    n-turn chat ships ~n²/2 messages for n distinct ones — while
    //    adding only cross-turn ordering, and the request-body cap
    //    truncates late turns anyway. Detection is header-time by path
    //    only; a prompt-shaped body on a custom path can't be known
    //    before the decision and falls down the identity ladder below
    //    (whole-per-user — coarser but safe). A per-user knob for chat
    //    is deliberately deferred; see DEVELOPMENT.md.
    //
    //    Ordered BELOW the explicit session keys (tiers 1–2) on
    //    purpose: a configured sessionKeyHeader such as traceparent is
    //    an explicit operator opt-in to whole-run capture, and an
    //    agent run's LLM calls belong to the run it keys — putting
    //    them on a coin would shred exactly the cross-protocol
    //    LLM-then-tool-call story that knob exists to keep whole. The
    //    carve-out governs chat traffic with NO explicit session key,
    //    which would otherwise land on the identity tiers.
    if ai_content::is_llm_path(endpoint) {
        return keep_or_drop(ctx.coin.flip(), KIND_REQUEST, None);
    }

    // 4. Fallback identity ladder — computed for all remaining traffic:
    //    it is either the verdict itself, or the stashed verdict for a
    //    handshake whose response mints no session id.
    //
    //    Principal sits above Authorization because OAuth refresh
    //    rotates the bearer token mid-session while the principal —
    //    recomputed per request by the upstream MuleSoft auth policy —
    //    survives rotation. The principal tier only exists when that
    //    policy is ordered before this one (API Manager policy order);
    //    the per-event sample_key makes its absence visible after the
    //    fact.
    //
    //    The principal and user tiers mix in a weekly epoch: a fixed
    //    identity key would otherwise be permanently in or out of the
    //    sample. Session-id tiers never rotate (each session is a fresh
    //    draw). Authorization doesn't either: OAuth bearer values churn
    //    on their own, and a static API key that only ever appears here
    //    stays a permanent stratum — accepted for v1.
    let epoch = Some(now_epoch_micros() / 1_000_000 / EPOCH_SECONDS);
    let (fallback_keep, fallback_kind) = if let Some(principal) = auth
        .authentication()
        .and_then(|a| a.principal.or(a.client_id))
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
    {
        (
            ctx.keyed.keep(DOMAIN_PRINCIPAL, &principal, epoch),
            KIND_PRINCIPAL,
        )
    } else if let Some(user) = ctx
        .config
        .user_id_header
        .as_deref()
        .and_then(|name| nonempty(read_header(name)))
    {
        (ctx.keyed.keep(DOMAIN_USER, &user, epoch), KIND_USER_ID)
    } else if let Some(authz) = nonempty(read_header("authorization")) {
        (
            ctx.keyed.keep(DOMAIN_AUTHORIZATION, &authz, None),
            KIND_AUTHORIZATION,
        )
    } else {
        // True terminal: an independent coin. (Deliberately not the
        // client IP: it is spoofable per request, NAT collapses many
        // users onto one decision, and behind an L7 balancer with no
        // client-IP header the connection source is the balancer
        // itself — one key deciding ALL otherwise-keyless traffic
        // all-or-nothing.)
        (ctx.coin.flip(), KIND_REQUEST)
    };

    // 5. MCP-handshake-shaped? Header-only pre-gate, sharper than it
    //    looks (see accept_lists_json_and_sse); legacy-era clients
    //    never send MCP-Protocol-Version on initialize but do on every
    //    later request, so requiring its absence confines speculative
    //    capture to genuine handshakes (plus 2025-03-26-era clients
    //    talking to stateless servers, which resolve to the fallback
    //    verdict in response_filter).
    if method == "POST"
        && content_type_is_json(read_header("content-type").as_deref())
        && accept_lists_json_and_sse(read_header("accept").as_deref())
        && read_header(MCP_PROTOCOL_VERSION_HEADER).is_none()
    {
        return SampleDecision::PendingHandshake {
            fallback_keep,
            fallback_kind,
        };
    }

    keep_or_drop(fallback_keep, fallback_kind, None)
}

async fn request_filter(
    state: RequestState,
    stream: StreamProperties,
    auth: Authentication,
    ctx: &PolicyContext,
) -> Flow<RequestSlot> {
    let headers_state = state.into_headers_state().await;

    // Envoy's :path includes the query string; split once.
    let raw_path = headers_state.path();
    let (endpoint, query_string) = match raw_path.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (raw_path.clone(), None),
    };

    if HEALTH_ENDPOINTS.contains(&endpoint.as_str()) {
        return Flow::Continue(RequestSlot::Skip);
    }

    if !ctx.path_filter.should_capture(&endpoint) {
        return Flow::Continue(RequestSlot::Skip);
    }

    // Sampling comes after the (cheaper) health/path checks and before
    // any extraction or body work, so sampleRate reads as "fraction of
    // otherwise-captured traffic" and unsampled requests skip all
    // capture work (the decision itself costs a few raw header reads
    // and at most two HMAC-SHA256 computations — see sampler.rs).
    let method = headers_state.method().to_uppercase();
    let decision = sampling_decision(
        ctx,
        |name| headers_state.handler().header(name),
        &auth,
        &endpoint,
        &method,
        query_string.as_deref(),
    );
    let (sample_key, session_id, pending_fallback) = match decision {
        SampleDecision::Drop => return Flow::Continue(RequestSlot::Skip),
        SampleDecision::CaptureAll => (None, None, None),
        SampleDecision::Keep { kind, session_id } => (Some(kind), session_id, None),
        SampleDecision::PendingHandshake {
            fallback_keep,
            fallback_kind,
        } => (None, None, Some((fallback_keep, fallback_kind))),
    };
    // PDK exposes `:scheme` ("http" / "https"). The CoreData contract is
    // a boolean: scheme == "https".
    let scheme_https = headers_state.scheme().eq_ignore_ascii_case("https");
    let user_agent = headers_state.handler().header("user-agent");

    let headers = extract_headers(headers_state.handler().headers(), ctx);

    // Query params — sanitized for SENSITIVE_KEYS + customer PII rules.
    let query_params = query_string.as_deref().and_then(parse_query_string);
    let query_params = query_params
        .map(|q| sanitize_value_with(Value::Object(q), &ctx.pii_rules, ctx.secret_key.as_deref()))
        .map(|v| match v {
            Value::Object(map) => map,
            _ => unreachable!("sanitize preserves object → object"),
        });

    // Source IP — first try clientIpHeader, then connection source.
    let source_ip_raw = source_ip::resolve(
        headers_state.handler().header(&ctx.config.client_ip_header),
        &stream,
    );
    let source_ip = source_ip_raw.as_deref().map(|raw| {
        let normalized = crate::hash::normalize_ip(raw);
        ctx.maybe_hash(&normalized)
    });

    // user_id — passed through verbatim if header is configured and present.
    let user_id = ctx
        .config
        .user_id_header
        .as_deref()
        .and_then(|h| headers_state.handler().header(h));

    // Body — only buffer for write-mutating methods + JSON content-type.
    // With captureAiContent off, a well-known LLM API path skips body
    // buffering entirely: prompts are the largest bodies the gateway sees,
    // and the body would be withheld anyway. Tradeoff: an MCP server
    // mounted on an LLM-looking path would lose body capture — acceptable,
    // since real MCP mounts don't collide with provider API path shapes,
    // and the body-shape carve-out below still protects every normal MCP
    // mount.
    let mut body_value: Option<Value> = None;
    let mut ai_content_withheld = false;
    let should_capture_body = ctx.config.capture_request_body
        && matches!(method.as_str(), "POST" | "PUT" | "PATCH")
        && content_type_is_json(headers_state.handler().header("content-type").as_deref())
        && (ctx.config.capture_ai_content || !ai_content::is_llm_path(&endpoint));

    // One hostcall read serves both the event timestamp and the
    // latency_ms baseline carried to the response filter.
    let start_epoch_micros = now_epoch_micros();
    let timestamp = format_epoch_micros(start_epoch_micros);
    let endpoint_for_event = endpoint.clone();

    if should_capture_body {
        let body_state = headers_state.into_body_state().await;
        let body_bytes = body_state.handler().body();
        if !body_bytes.is_empty() {
            // Parse and sanitize. Bare-primitive JSON (string, number, bool,
            // null) → None — only objects and arrays are captured.
            if let Ok(parsed) = serde_json::from_slice::<Value>(&body_bytes) {
                body_value = match parsed {
                    Value::Object(_) | Value::Array(_) => {
                        if !ctx.config.capture_ai_content
                            && ai_content::should_suppress_body(&endpoint, &parsed)
                        {
                            // AI prompt content — withheld from the event (the event
                            // itself still ships for endpoint discovery). Remembered
                            // so the response filter withholds the output as well.
                            ai_content_withheld = true;
                            None
                        } else {
                            Some(sanitize_value_with(
                                parsed,
                                &ctx.pii_rules,
                                ctx.secret_key.as_deref(),
                            ))
                        }
                    }
                    _ => None,
                };
            }
        }
    }

    let event = CerberusEvent {
        remote_addr: source_ip,
        endpoint: endpoint_for_event,
        scheme: scheme_https,
        method,
        timestamp,
        headers,
        query_params,
        body: body_value,
        user_agent,
        user_id,
        status_code: None,
        latency_ms: None,
        response_headers: None,
        response_body: None,
        session_id,
        // Stamped whenever sampling is active, including on speculative
        // handshakes (their sample_key arrives in response_filter).
        sample_rate: (ctx.config.sample_rate < 1.0).then_some(ctx.config.sample_rate),
        sample_key,
    };

    match pending_fallback {
        None => Flow::Continue(RequestSlot::Capture {
            event,
            start_epoch_micros,
            ai_content_withheld,
        }),
        Some((fallback_keep, fallback_kind)) => Flow::Continue(RequestSlot::PendingHandshake {
            event,
            start_epoch_micros,
            ai_content_withheld,
            fallback_keep,
            fallback_kind,
        }),
    }
}

/// Containment invariant: once this filter holds a Capture event, every
/// path ends in `ctx.queue.push(event)` — response-capture failure must
/// never lose the request event. PendingHandshake is the one deliberate
/// exception: its event is speculative until the decide-late sampling
/// verdict resolves, and an unsampled verdict discards it here — that
/// IS the sampling decision, not a loss.
async fn response_filter(state: ResponseState, data: RequestData<RequestSlot>, ctx: &PolicyContext) {
    let (mut event, start_epoch_micros, ai_content_withheld, pending_fallback) = match data {
        RequestData::Continue(RequestSlot::Capture {
            event,
            start_epoch_micros,
            ai_content_withheld,
        }) => (event, start_epoch_micros, ai_content_withheld, None),
        RequestData::Continue(RequestSlot::PendingHandshake {
            event,
            start_epoch_micros,
            ai_content_withheld,
            fallback_keep,
            fallback_kind,
        }) => (
            event,
            start_epoch_micros,
            ai_content_withheld,
            Some((fallback_keep, fallback_kind)),
        ),
        // Skip / Break / Cancel — nothing to ship.
        _ => return,
    };
    // Response headers already arrived when the filter runs — this is a
    // Ready future, not a suspension point.
    let headers = state.into_headers_state().await;
    // Decide-late resolution for MCP-handshake-shaped requests. The
    // minted session id is read raw (captureResponseHeaders settings
    // never change the decision) and hashed in the same domain as
    // request-side session ids — the whole point is that a session's
    // initialize and its later requests reach one verdict. Conforming
    // servers can't split a session across the two legs: both reference
    // SDKs refuse to mint a different id for a request that already
    // carries one. No minted id (stateless server, 401 discovery round
    // trip, Envoy local reply) resolves to the deterministic fallback
    // verdict stashed at request time — one decision, not a second
    // coin.
    if let Some((fallback_keep, fallback_kind)) = pending_fallback {
        match nonempty(headers.handler().header(MCP_SESSION_ID_HEADER)) {
            Some(session_id) => {
                if !ctx.keyed.keep(DOMAIN_SESSION, &session_id, None) {
                    return;
                }
                event.sample_key = Some(KIND_SESSION_RESPONSE);
                event.session_id = Some(session_id);
            }
            None => {
                if !fallback_keep {
                    return;
                }
                event.sample_key = Some(fallback_kind);
            }
        }
    }
    let status = headers.status_code();
    // status_code() returns 0 for an absent/unparseable :status — omit
    // the field rather than shipping a bogus 0.
    event.status_code = (status != 0).then_some(status);
    event.response_headers = extract_response_headers(&headers, ctx);
    event.response_body =
        capture_response_body(headers, &event.endpoint, ai_content_withheld, ctx).await;
    // Measured after body capture completes so it covers the full
    // response, not just headers. Wall-clock (proxy-wasm exposes no
    // monotonic clock); skew saturates to 0.
    event.latency_ms = Some(elapsed_ms(start_epoch_micros));
    if let Err(()) = ctx.queue.push(event) {
        // Queue full — already counted by EventQueue::push.
        // TODO(v1.1): emit a Prometheus / Envoy stat here.
    }
}

/// Observe (never mutate) the response body per the gate order below.
/// Returns the event's `response_body` value, or None when nothing is
/// captured. With the knob off the body stream is never opened — zero
/// new per-request cost.
async fn capture_response_body(
    headers: ResponseHeadersState,
    endpoint: &str,
    ai_content_withheld: bool,
    ctx: &PolicyContext,
) -> Option<Value> {
    // 1. Knob off → current (0.3.0) behavior exactly.
    if !ctx.config.capture_response_body {
        return None;
    }
    // 2. Only JSON and SSE content-types are observed.
    let kind =
        response_capture::classify_content_type(headers.handler().header("content-type").as_deref())?;
    // 3. captureAiContent off: skip all body work before touching the
    //    stream when the request was AI traffic — a well-known LLM path
    //    (mirrors the request-side short-circuit) OR a request whose body
    //    was already withheld as prompt-shaped on a custom path. The
    //    latter is what makes SSE model output on custom paths respect
    //    the flag: an SSE body never reaches the parsed-shape check in
    //    finalize, so the request-side decision has to carry over.
    if !ctx.config.capture_ai_content
        && (ai_content_withheld || ai_content::is_llm_path(endpoint))
    {
        return None;
    }
    // 4. No body (204 / 304 / HEAD — headers arrived with end_of_stream):
    //    nothing to capture, whatever other headers say. Checked BEFORE
    //    the encoding gate: a 304 may legitimately carry Content-Encoding
    //    (RFC 7232 lets it refresh representation metadata) and HEAD
    //    mirrors GET's headers, and neither must ship a marker.
    if !headers.contains_body() {
        return None;
    }
    // 5. Compressed bodies are never sliced — a byte slice of a
    //    gzip/br stream is undecodable. Ship the marker; don't open
    //    the stream.
    if let Some(enc) = headers.handler().header("content-encoding") {
        let enc = enc.trim().to_ascii_lowercase();
        if !enc.is_empty() && enc != "identity" {
            return Some(response_capture::skipped_encoding_marker(&enc));
        }
    }
    // 6. Stream pass-through: every chunk flows to the client as it
    //    arrives; we only accumulate the capped head + tail. A stream
    //    that ends early (upstream reset) just ends — finalize works
    //    over whatever arrived.
    let body_state = headers.into_body_stream_state().await;
    let mut accumulator = response_capture::HeadTailAccumulator::new(
        ctx.config.response_head_bytes as usize,
        ctx.config.response_tail_bytes as usize,
    );
    let mut stream = body_state.stream();
    while let Some(chunk) = stream.next().await {
        accumulator.push(chunk.bytes());
    }
    response_capture::finalize_response_body(
        accumulator.finalize(),
        kind,
        endpoint,
        ctx.config.capture_ai_content,
        &ctx.pii_rules,
        ctx.secret_key.as_deref(),
    )
}

/// Periodic flush. Drains up to batchSize events and POSTs to
/// ingestService/v1/ingest/batch.
async fn flush_loop(timer: &Timer, client: &HttpClient, ctx: &PolicyContext) {
    while timer.next_tick().await {
        let drained = ctx.queue.drain(ctx.config.batch_size as usize);
        let dropped = ctx.queue.take_dropped();
        if drained.is_empty() && dropped == 0 {
            continue;
        }

        if dropped > 0 {
            // Surface the drop count in policy logs for now.
            // TODO(v1.1) emit as a proper metric or include it as a
            // synthetic health event in the next batch payload.
            logger::warn!(
                "cerberus-flex-gateway: dropped {} events (queue full)",
                dropped
            );
        }

        if let Err(err) = sink::post_batch(client, &ctx.config.ingest_service, &ctx.config, &drained).await {
            // At-most-once. We log and move on — the next tick will try
            // a fresh batch with whatever has accumulated.
            //
            // TODO(v1.1): retry policy + circuit breaker. Currently a
            // long backend outage means every flush hits the same
            // failure mode and we silently lose every batch.
            logger::warn!(
                "cerberus-flex-gateway: failed to post batch: {}",
                err
            );
        }
    }
}

/// Extract and sanitize request headers (captureHeaders allowlist;
/// None = capture all).
fn extract_headers(
    pairs: Vec<(String, String)>,
    ctx: &PolicyContext,
) -> Option<std::collections::BTreeMap<String, String>> {
    collect_headers(pairs, ctx.header_allowlist.as_ref(), ctx)
}

/// Extract and sanitize response headers per the captureResponseHeaders
/// allowlist. Pure opt-in: an empty allowlist captures nothing (the
/// header iteration is skipped entirely).
fn extract_response_headers(
    headers: &ResponseHeadersState,
    ctx: &PolicyContext,
) -> Option<std::collections::BTreeMap<String, String>> {
    if ctx.response_header_allowlist.is_empty() {
        return None;
    }
    collect_headers(
        headers.handler().headers(),
        Some(&ctx.response_header_allowlist),
        ctx,
    )
}

/// Shared header collection + sanitization — one implementation for both
/// directions (request headers via `captureHeaders`, response headers via
/// `captureResponseHeaders`); only the allowlist differs. Nothing below is
/// direction-specific: the Authorization branch fires for a response
/// `Authorization` header too, should one ever be allowlisted, and gets
/// the same HMAC/redact treatment.
///
/// Rules:
///   * Allowlist (if given): non-listed headers are omitted entirely —
///     absent, not redacted. Matched on the lowercased name. The gate
///     runs before sensitivity handling, so the allowlist controls
///     presence and sanitization controls value.
///   * Iterate (name, value) pairs as Envoy presents them.
///   * Lowercase the name once for allowlist + sensitivity matching.
///   * Authorization → HMAC-SHA256(secret, value) if secret is configured;
///     else REDACTED.
///   * Other SENSITIVE_HEADERS → REDACTED.
///   * Otherwise → pass through.
///
/// Multi-valued headers (e.g. comma-folded X-Forwarded-For, repeated
/// Set-Cookie): Envoy may surface these as multiple (name, value) tuples
/// with the same name. We collapse with `, ` separator after sanitization.
/// Documented in README "Header semantics".
fn collect_headers(
    pairs: Vec<(String, String)>,
    allowlist: Option<&std::collections::HashSet<String>>,
    ctx: &PolicyContext,
) -> Option<std::collections::BTreeMap<String, String>> {
    if pairs.is_empty() {
        return None;
    }

    use std::collections::BTreeMap;
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (name, value) in pairs {
        // Skip Envoy pseudo-headers (`:method`, `:path`, `:scheme`,
        // `:authority`, `:status`). The metadata they carry is captured
        // in dedicated event fields.
        if name.starts_with(':') {
            continue;
        }

        let name_lower = name.to_lowercase();

        // Allowlist gate — before the sensitivity branch, so non-listed
        // sensitive headers are absent rather than redacted-but-present.
        if let Some(allow) = allowlist {
            if !allow.contains(&name_lower) {
                continue;
            }
        }

        let entry_value: String = if name_lower == "authorization" {
            ctx.hash_or_redact(&value)
        } else if is_sensitive_header_lower(&name_lower) {
            REDACTED.to_string()
        } else {
            value
        };

        // Title-case canonical form ("User-Agent", "Authorization")
        // rather than the lowercase HTTP/2-native form Envoy provides.
        let canonical = title_case_header(&name);
        out.entry(canonical).or_default().push(entry_value);
    }

    if out.is_empty() {
        return None;
    }
    Some(
        out.into_iter()
            .map(|(k, vs)| (k, vs.join(", ")))
            .collect(),
    )
}

/// Title-case an HTTP header name (`x-api-key` → `X-Api-Key`,
/// `user-agent` → `User-Agent`).
fn title_case_header(name: &str) -> String {
    name.split('-')
        .map(|seg| {
            let mut chars = seg.chars();
            match chars.next() {
                Some(first) => {
                    let mut s = String::with_capacity(seg.len());
                    s.push(first.to_ascii_uppercase());
                    for c in chars {
                        s.push(c.to_ascii_lowercase());
                    }
                    s
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse a query string into a sanitized object map. SENSITIVE_KEYS
/// values get redacted; single-valued keys serialize as strings,
/// multi-valued as arrays.
fn parse_query_string(qs: &str) -> Option<serde_json::Map<String, Value>> {
    let pairs = url::form_urlencoded::parse(qs.as_bytes());
    let mut grouped: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for (k, v) in pairs {
        grouped.entry(k.into_owned()).or_default().push(v.into_owned());
    }
    if grouped.is_empty() {
        return None;
    }
    let mut out = serde_json::Map::with_capacity(grouped.len());
    for (k, mut values) in grouped {
        let v = if values.len() == 1 {
            Value::String(values.pop().unwrap())
        } else {
            Value::Array(values.into_iter().map(Value::String).collect())
        };
        out.insert(k, v);
    }
    Some(out)
}

/// Substring check for `application/json` in the Content-Type header.
/// Case-insensitive — pinned by parity-fixtures/content_type.yaml.
pub fn content_type_is_json(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else {
        return false;
    };
    ct.to_ascii_lowercase().contains("application/json")
}

/// Microseconds since UNIX_EPOCH from the host clock.
///
/// We previously tried Envoy's `request.time` stream property, but it
/// isn't reliably exposed via PDK 1.8's `read_property` bridge — the
/// official examples capture wall-clock time inside the filter instead.
/// We use proxy-wasm's `get_current_time` hostcall, which returns a
/// `SystemTime` from the host (Envoy) clock and works from WASM where a
/// syscall-based `SystemTime::now()` would not. This is the same
/// hostcall the PDK's own `Clock::now()` uses; we call it directly
/// because `request_filter` has no `Clock` handle (the single `Clock`
/// is consumed building the flush timer).
fn now_epoch_micros() -> u64 {
    use pdk::classy::proxy_wasm::hostcalls;
    use std::time::UNIX_EPOCH;

    let t = hostcalls::get_current_time().unwrap_or(UNIX_EPOCH);
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_micros() as u64
}

/// Wall-clock milliseconds elapsed since `start_epoch_micros`,
/// saturating to 0 (the host clock is not monotonic).
fn elapsed_ms(start_epoch_micros: u64) -> u64 {
    now_epoch_micros().saturating_sub(start_epoch_micros) / 1_000
}

/// Format an epoch-microseconds instant as ISO 8601 UTC with a literal
/// `+00:00` suffix (e.g. `2026-05-02T23:14:05.123456+00:00`).
fn format_epoch_micros(epoch_micros: u64) -> String {
    format_epoch(
        (epoch_micros / 1_000_000) as i64,
        (epoch_micros % 1_000_000) as u32,
    )
}

/// Seed for the per-worker sampling PRNG: microseconds since UNIX_EPOCH
/// from the host clock, XOR'd with the SplitMix64 gamma so a degenerate
/// zero clock still yields a non-trivial seed. Workers configure at
/// slightly different instants, so they walk different decision
/// sequences.
fn sampler_seed_from_clock() -> u64 {
    now_epoch_micros() ^ 0x9E37_79B9_7F4A_7C15
}

/// Format `(seconds-since-epoch, microseconds)` as ISO 8601 UTC with a
/// literal `+00:00` suffix.
fn format_epoch(secs: i64, micros: u32) -> String {
    chrono::DateTime::from_timestamp(secs, micros * 1_000)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S%.6f+00:00")
        .to_string()
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    clock: Clock,
    client: HttpClient,
) -> Result<()> {
    // A rejected config is logged at Error level by the runtime, so the
    // parse error must never echo the config (it carries token /
    // secretKey). `config::parse` also scrubs those values from serde's
    // own message.
    let config = config::parse(&bytes)?;

    // Token normalization — trim whitespace defensively. A pasted token
    // with a trailing newline silently 403s every batch otherwise.
    let trimmed_token = config.token.trim().to_string();
    if trimmed_token.len() != config.token.len() {
        logger::warn!(
            "cerberus-flex-gateway: token contained surrounding whitespace; trimmed"
        );
    }
    logger::info!(
        "cerberus-flex-gateway: configured with token_len={}",
        trimmed_token.len()
    );

    if config.user_id_header.is_none() {
        logger::warn!(
            "cerberus-flex-gateway: userIdHeader unset; events will not carry end-user identity"
        );
    }

    // Capturing AI/LLM prompt bodies is the default (sanitized, but
    // free-form text is not scrubbable by key-matching). Surface the
    // opt-out in pod logs instead: an operator who sets
    // captureAiContent: false has chosen to withhold detected LLM/AI
    // request bodies (endpoint/method and sanitized metadata still ship).
    if !config.capture_ai_content {
        logger::info!(
            "cerberus-flex-gateway: captureAiContent disabled; LLM/AI request and response bodies will be withheld from events"
        );
    }


    let mut config = config;
    config.token = trimmed_token;

    // Init-time secret fetch (best-effort, 5s timeout).
    let secret_key = secret::resolve_secret(&config, &client).await;
    if secret_key.is_none() {
        logger::warn!(
            "cerberus-flex-gateway: no secret configured and backend fetch failed; PII will be emitted raw"
        );
    }

    let ctx = PolicyContext::new(config, secret_key, sampler_seed_from_clock())?;
    // Confirmable from pod logs, mirroring the captureAiContent log —
    // response capture changing event content/size should be visible at
    // startup. Logged AFTER PolicyContext::new so the budgets shown are
    // the clamped values actually enforced, not the raw config.
    if ctx.config.capture_response_body {
        logger::info!(
            "cerberus-flex-gateway: captureResponseBody enabled (head {} bytes, tail {} bytes)",
            ctx.config.response_head_bytes,
            ctx.config.response_tail_bytes
        );
    }
    if ctx.config.sample_rate < 1.0 {
        // Confirmable from pod logs — sampling silently suppressing
        // events is otherwise indistinguishable from a broken pipeline.
        logger::info!(
            "cerberus-flex-gateway: sampling active; effective sampleRate={} sampleBy={}",
            ctx.config.sample_rate,
            ctx.sample_mode.as_str()
        );
    }

    // Periodic flush.
    let timer = clock.period(Duration::from_millis(ctx.config.flush_interval_ms as u64));
    let flush = flush_loop(&timer, &client, &ctx);

    // Request handling.
    let launched = launcher.launch(
        on_request(|rs, sp, auth| request_filter(rs, sp, auth, &ctx))
            .on_response(|rs, rd| response_filter(rs, rd, &ctx)),
    );

    // Run forever — proxy-wasm guarantees these alternate cooperatively
    // at await points; there is no parallelism within a worker.
    let joined = join!(launched, flush);
    joined.0?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn title_case_header_basic() {
        assert_eq!(title_case_header("user-agent"), "User-Agent");
        assert_eq!(title_case_header("x-api-key"), "X-Api-Key");
        assert_eq!(title_case_header("authorization"), "Authorization");
    }

    #[test]
    fn content_type_substring_match_positive() {
        assert!(content_type_is_json(Some("application/json")));
        assert!(content_type_is_json(Some("application/json; charset=utf-8")));
        // Case-insensitive: mixed-case must match.
        assert!(content_type_is_json(Some("Application/JSON")));
    }

    #[test]
    fn content_type_substring_match_negative() {
        assert!(!content_type_is_json(Some("application/vnd.api+json")));
        assert!(!content_type_is_json(Some("text/plain")));
        assert!(!content_type_is_json(None));
        assert!(!content_type_is_json(Some("")));
    }

    #[test]
    fn format_epoch_known_values() {
        // Unix epoch.
        assert_eq!(format_epoch(0, 0), "1970-01-01T00:00:00.000000+00:00");
        // 2024-02-29 leap day, 12:34:56.789012 UTC. Day count cross-
        // checked via `date -j -f '%Y-%m-%d' '2024-02-29' +%s` → 1709164800.
        assert_eq!(
            format_epoch(1_709_164_800 + 12 * 3600 + 34 * 60 + 56, 789_012),
            "2024-02-29T12:34:56.789012+00:00"
        );
        // 2000-01-01 00:00:00 (century leap year).
        assert_eq!(
            format_epoch(946_684_800, 0),
            "2000-01-01T00:00:00.000000+00:00"
        );
    }

    #[test]
    fn hash_or_redact_redacts_when_no_secret() {
        // Security-critical: Authorization must never ship raw. With no
        // secret configured, the value is redacted, not passed through.
        assert_eq!(pseudonymize_or_redact(None, "Bearer sk-live-abc"), REDACTED);
    }

    #[test]
    fn hash_or_redact_hashes_when_secret_present() {
        let out = pseudonymize_or_redact(Some("topsecret"), "Bearer sk-live-abc");
        assert_ne!(out, "Bearer sk-live-abc");
        assert_ne!(out, REDACTED);
        assert_eq!(out, crate::hash::hash_pii("Bearer sk-live-abc", "topsecret"));
    }

    #[test]
    fn maybe_hash_passes_through_when_no_secret() {
        // Source IP is allowed to ship raw when no secret is set
        // (parity with cerberus-django) — verify the passthrough branch.
        assert_eq!(pseudonymize_or_passthrough(None, "1.2.3.4"), "1.2.3.4");
        assert_eq!(
            pseudonymize_or_passthrough(Some("topsecret"), "1.2.3.4"),
            crate::hash::hash_pii("1.2.3.4", "topsecret")
        );
    }

    #[test]
    fn legacy_mcp_session_query_both_sdk_conventions() {
        assert_eq!(
            legacy_mcp_session_query(Some("sessionId=abc")),
            Some("abc".to_string())
        );
        assert_eq!(
            legacy_mcp_session_query(Some("a=1&session_id=xyz")),
            Some("xyz".to_string())
        );
        assert_eq!(legacy_mcp_session_query(Some("session=nope")), None);
        assert_eq!(legacy_mcp_session_query(Some("sessionId=")), None);
        assert_eq!(legacy_mcp_session_query(Some("sessionId=%20%20")), None);
        assert_eq!(legacy_mcp_session_query(None), None);
    }

    #[test]
    fn accept_gate_requires_both_media_types() {
        // MCP POSTs must advertise both; LLM SDKs send only JSON and
        // plain SSE streamers only the event-stream type.
        assert!(accept_lists_json_and_sse(Some(
            "application/json, text/event-stream"
        )));
        assert!(accept_lists_json_and_sse(Some(
            "Text/Event-Stream;q=0.9, Application/JSON"
        )));
        assert!(!accept_lists_json_and_sse(Some("application/json")));
        assert!(!accept_lists_json_and_sse(Some("text/event-stream")));
        assert!(!accept_lists_json_and_sse(Some("*/*")));
        assert!(!accept_lists_json_and_sse(None));
    }

    #[test]
    fn nonempty_trims_and_rejects_blank() {
        assert_eq!(nonempty(Some("  x  ".into())), Some("x".to_string()));
        assert_eq!(nonempty(Some("   ".into())), None);
        assert_eq!(nonempty(None), None);
    }

    #[test]
    fn parse_query_string_sanitizes_via_caller() {
        // parse_query_string itself doesn't sanitize — sanitize_value
        // is applied by the caller. Verifies the parse side only.
        let map = parse_query_string("a=1&b=2&a=3").unwrap();
        assert_eq!(map["b"], json!("2"));
        let a_values = match &map["a"] {
            Value::Array(arr) => arr.clone(),
            other => panic!("expected array, got {:?}", other),
        };
        assert_eq!(a_values.len(), 2);
    }
}
