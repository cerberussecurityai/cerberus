// Cerberus Flex Gateway custom policy.
//
// Architectural overview:
//
//   Request → request_filter:
//     - early-exit on health endpoints and capturePaths/excludePaths misses
//     - extract method, scheme, endpoint, query params (sanitized)
//     - extract headers (sanitized; Authorization HMAC'd if secret available)
//     - resolve source IP from clientIpHeader (XFF first hop) or stream
//     - if captureRequestBody && content-type matches application/json:
//       buffer body, parse, recursively sanitize
//     - stash partial Event in RequestData; pass through
//
//   Response → response_filter:
//     - finalize Event (timestamp set in request_filter)
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

mod config;
mod event;
mod hash;
mod path_filter;
mod queue;
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
    pub use crate::sanitize::{is_sensitive_header_lower, sanitize_value};
    pub use super::content_type_is_json;
}

use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::join;
use pdk::hl::timer::{Clock, Timer};
use pdk::hl::*;
use pdk::logger;
use serde_json::Value;

use crate::config::Config;
use crate::event::CerberusEvent;
use crate::path_filter::PathFilter;
use crate::queue::EventQueue;
use crate::sanitize::{is_sensitive_header_lower, sanitize_value, REDACTED};

const HEALTH_ENDPOINTS: [&str; 3] = ["/health", "/health_check", "/ready"];

/// Per-policy state shared across request, response, and flush handlers.
/// All members are immutable except the queue (interior mutability via
/// RefCell, safe because proxy-wasm workers are single-threaded — no
/// task can hold a mutable borrow across an await point).
struct PolicyContext {
    config: Config,
    secret_key: Option<String>,
    path_filter: PathFilter,
    queue: EventQueue,
}

impl PolicyContext {
    fn new(config: Config, secret_key: Option<String>) -> Result<Self> {
        let path_filter = PathFilter::compile(
            config.capture_paths.as_deref().unwrap_or(&[]),
            config.exclude_paths.as_deref().unwrap_or(&[]),
        )?;
        let queue = EventQueue::new(config.queue_capacity as usize);
        Ok(Self {
            config,
            secret_key,
            path_filter,
            queue,
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
    /// non-matching content-type). Response filter is a no-op.
    Skip,
    /// Event is partially built; response filter will push it onto the queue.
    Capture(CerberusEvent),
}

async fn request_filter(
    state: RequestState,
    stream: StreamProperties,
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

    let method = headers_state.method().to_uppercase();
    // PDK exposes `:scheme` ("http" / "https"). The CoreData contract is
    // a boolean: scheme == "https".
    let scheme_https = headers_state.scheme().eq_ignore_ascii_case("https");
    let user_agent = headers_state.handler().header("user-agent");

    let headers = extract_headers(headers_state.handler().headers(), ctx);

    // Query params — sanitized for SENSITIVE_KEYS.
    let query_params = query_string.as_deref().and_then(parse_query_string);
    let query_params = query_params.map(|q| sanitize_value(Value::Object(q)))
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
    let mut body_value: Option<Value> = None;
    let should_capture_body = ctx.config.capture_request_body
        && matches!(method.as_str(), "POST" | "PUT" | "PATCH")
        && content_type_is_json(headers_state.handler().header("content-type").as_deref());

    let timestamp = current_timestamp_iso8601();
    let endpoint_for_event = endpoint.clone();

    if should_capture_body {
        let body_state = headers_state.into_body_state().await;
        let body_bytes = body_state.handler().body();
        if !body_bytes.is_empty() {
            // Parse and sanitize. Bare-primitive JSON (string, number, bool,
            // null) → None — only objects and arrays are captured.
            if let Ok(parsed) = serde_json::from_slice::<Value>(&body_bytes) {
                body_value = match parsed {
                    Value::Object(_) | Value::Array(_) => Some(sanitize_value(parsed)),
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
    };

    Flow::Continue(RequestSlot::Capture(event))
}

async fn response_filter(_state: ResponseState, data: RequestData<RequestSlot>, ctx: &PolicyContext) {
    let event = match data {
        RequestData::Continue(RequestSlot::Capture(ev)) => ev,
        _ => return,
    };
    // TODO(v1.1): capture status_code and latency_ms here.
    if let Err(()) = ctx.queue.push(event) {
        // Queue full — already counted by EventQueue::push.
        // TODO(v1.1): emit a Prometheus / Envoy stat here.
    }
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

/// Extract and sanitize request headers.
///
/// Rules:
///   * Iterate (name, value) pairs as Envoy presents them.
///   * Lowercase the name once for sensitivity matching.
///   * Authorization → HMAC-SHA256(secret, value) if secret is configured;
///     else REDACTED.
///   * Other SENSITIVE_HEADERS → REDACTED.
///   * Otherwise → pass through.
///
/// Multi-valued headers (e.g. comma-folded X-Forwarded-For, repeated
/// Set-Cookie): Envoy may surface these as multiple (name, value) tuples
/// with the same name. We collapse with `, ` separator after sanitization.
/// Documented in README "Header semantics".
fn extract_headers(
    pairs: Vec<(String, String)>,
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

/// Build an ISO 8601 UTC timestamp for the current moment.
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
///
/// The returned string follows RFC 3339 / ISO 8601 with microsecond
/// precision and a literal `+00:00` suffix
/// (e.g. `2026-05-02T23:14:05.123456+00:00`).
fn current_timestamp_iso8601() -> String {
    use pdk::classy::proxy_wasm::hostcalls;
    use std::time::UNIX_EPOCH;

    let t = hostcalls::get_current_time().unwrap_or(UNIX_EPOCH);
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    format_epoch(dur.as_secs() as i64, dur.subsec_micros())
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
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "cerberus-flex-gateway: failed to parse config '{}': {}",
            String::from_utf8_lossy(&bytes),
            err
        )
    })?;

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

    let mut config = config;
    config.token = trimmed_token;

    // Init-time secret fetch (best-effort, 5s timeout).
    let secret_key = secret::resolve_secret(&config, &client).await;
    if secret_key.is_none() {
        logger::warn!(
            "cerberus-flex-gateway: no secret configured and backend fetch failed; PII will be emitted raw"
        );
    }

    let ctx = PolicyContext::new(config, secret_key)?;

    // Periodic flush.
    let timer = clock.period(Duration::from_millis(ctx.config.flush_interval_ms as u64));
    let flush = flush_loop(&timer, &client, &ctx);

    // Request handling.
    let launched = launcher.launch(
        on_request(|rs, sp| request_filter(rs, sp, &ctx))
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
