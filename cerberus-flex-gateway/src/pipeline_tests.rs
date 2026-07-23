// End-to-end pipeline tests driven by PDK's in-process unit-test harness
// (`pdk-unit`). These exercise the parts that the pure-function parity
// runner can't reach: header extraction/collapse, pseudo-header skipping,
// query-param + body sanitization, and the full request → queue → flush →
// outbound-batch path.
//
// They live in-crate (not under tests/) because `configure` is private to
// the crate and the harness needs the entrypoint directly.

use std::rc::Rc;
use std::sync::Mutex;
use std::time::Duration;

use pdk_unit::{TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder};
use serde_json::Value;

const INGEST_AUTHORITY: &str = "ingest.cerberus.test";

// The pdk-unit harness installs its proxy-wasm host stub *thread-locally*
// (see `pdk-proxy-wasm-stub`), and the policy's async tasks log/read-the-clock
// through that stub. Under `cargo test`'s default parallelism a hostcall can
// land on a thread whose stub is still the default `UnimplementedHost` — every
// method of which panics — which double-panics during unwind and aborts the
// entire test binary, taking unrelated tests down with it. The suite is
// therefore run single-threaded via `RUST_TEST_THREADS=1` in
// `.cargo/config.toml` (a per-test lock can't fix this — the stray hostcall
// races against whatever *other* test happens to be running).
//
// NOTE: with that config in place this lock is currently redundant — all tests
// are already serialized. It is kept as a safeguard: if the thread count is
// ever raised it still serializes the two harness-driven tests against each
// other. Poison is ignored — a panicking test has already reported its own
// failure.
static HARNESS_LOCK: Mutex<()> = Mutex::new(());

// No secretKey / backendUrl → secret resolves to None, so Authorization
// must redact (not hash) and source IP ships raw.
fn config() -> String {
    format!(r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key"}}"#)
}

// Drive `request`, then advance past one flush interval (default 2000ms)
// so the flush loop drains the queue and POSTs the batch to the ingest
// upstream, where the TraceBackend captures it. Returns the parsed
// `{"events":[...]}` array, or None if no batch was sent.
fn capture_events(req: UnitHttpRequest) -> Option<Vec<Value>> {
    capture_events_with_config(req, config())
}

// Same as `capture_events` but with an explicit policy config, for tests that
// exercise config-gated behavior.
fn capture_events_with_config(req: UnitHttpRequest, config: String) -> Option<Vec<Value>> {
    let _guard = HARNESS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let trace = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
    let mut tester = UnitTestBuilder::default()
        .with_config(config)
        .with_http_upstream_from_authority(INGEST_AUTHORITY, Rc::clone(&trace))
        .with_entrypoint(crate::configure);

    let _ = tester.request(req);
    tester.sleep(Duration::from_millis(2500));

    let batch = trace.next()?;
    assert_eq!(
        batch.header("x-api-key"),
        Some("test-api-key"),
        "batch must carry the API key header"
    );
    let body: Value = serde_json::from_slice(batch.body()).expect("batch body is JSON");
    Some(
        body["events"]
            .as_array()
            .expect("batch envelope has an events array")
            .clone(),
    )
}

#[test]
fn post_request_produces_sanitized_event() {
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/api/orders?token=secret123&page=2")
        .with_header("authorization", "Bearer abc")
        .with_header("cookie", "sid=1")
        .with_header("user-agent", "testagent")
        .with_header("x-custom", "keep")
        // Multi-valued header → collapsed with ", ".
        .with_header("x-multi", "a")
        .with_header("x-multi", "b")
        .with_header("content-type", "application/json")
        .with_body(r#"{"password":"hunter2","name":"alice"}"#);

    let events = capture_events(req).expect("expected a flushed batch");
    assert_eq!(events.len(), 1, "one request → one event");
    let e = &events[0];

    // Top-level request metadata.
    assert_eq!(e["method"], "POST");
    assert_eq!(e["scheme"], true, "scheme maps to https == true");
    assert_eq!(e["endpoint"], "/api/orders", "query stripped from endpoint");

    // Query params: sensitive key redacted, ordinary key preserved.
    assert_eq!(e["query_params"]["token"], "[REDACTED]");
    assert_eq!(e["query_params"]["page"], "2");

    // Headers.
    let headers = e["headers"].as_object().expect("headers object");
    assert_eq!(headers["Authorization"], "[REDACTED]", "no secret → redact");
    assert_eq!(headers["Cookie"], "[REDACTED]");
    assert_eq!(headers["X-Custom"], "keep");
    assert_eq!(headers["X-Multi"], "a, b", "multi-value collapse");
    assert_eq!(headers["User-Agent"], "testagent");
    assert_eq!(headers["Content-Type"], "application/json");
    // Pseudo-headers (:method, :path, :scheme, ...) must be skipped.
    assert!(
        headers.keys().all(|k| !k.contains(':')),
        "no pseudo-headers should leak into the event: {:?}",
        headers.keys().collect::<Vec<_>>()
    );
    assert!(headers.get("Scheme").is_none() && headers.get("Path").is_none());

    // Body: sensitive key redacted, ordinary key preserved.
    assert_eq!(e["body"]["password"], "[REDACTED]");
    assert_eq!(e["body"]["name"], "alice");

    // user_agent is captured into its own field too.
    assert_eq!(e["user_agent"], "testagent");

    // Timestamp is present and ISO 8601 UTC.
    let ts = e["timestamp"].as_str().expect("timestamp string");
    assert!(ts.ends_with("+00:00"), "expected UTC offset suffix: {ts}");
}

// Mixed-case allowlist entries prove matching is case-insensitive
// (Envoy presents header names lowercased).
fn allowlist_config() -> String {
    format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureHeaders":["content-type","X-CUSTOM","Authorization","cookie"]}}"#
    )
}

#[test]
fn header_allowlist_filters_headers_map() {
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/api/orders")
        .with_header("authorization", "Bearer abc")
        .with_header("cookie", "sid=1")
        // Sensitive AND non-allowlisted: must be absent entirely, not
        // redacted-but-present (the allowlist gate runs before the
        // sensitivity branch). Covered by the exact-key-set assert below.
        .with_header("proxy-authorization", "Basic xyz")
        .with_header("user-agent", "testagent")
        .with_header("x-custom", "keep")
        .with_header("x-other", "drop")
        .with_header("content-type", "application/json")
        .with_body(r#"{"name":"alice"}"#);

    let events = capture_events_with_config(req, allowlist_config())
        .expect("expected a flushed batch");
    assert_eq!(events.len(), 1);
    let e = &events[0];

    // Exactly the allowlisted headers survive — nothing else.
    let headers = e["headers"].as_object().expect("headers object");
    let mut keys: Vec<&str> = headers.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["Authorization", "Content-Type", "Cookie", "X-Custom"],
        "headers map must contain exactly the allowlisted headers"
    );

    // Allowlisting controls presence; sanitization still controls value.
    assert_eq!(e["headers"]["Authorization"], "[REDACTED]", "no secret → redact");
    assert_eq!(e["headers"]["Cookie"], "[REDACTED]", "allowlisted-but-sensitive stays redacted");
    assert_eq!(e["headers"]["X-Custom"], "keep");
    assert_eq!(e["headers"]["Content-Type"], "application/json");

    // The dedicated user_agent field is unaffected by the allowlist even
    // though User-Agent is filtered out of the headers map.
    assert_eq!(e["user_agent"], "testagent");
}

#[test]
fn header_allowlist_empty_array_captures_all() {
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureHeaders":[]}}"#
    );
    let req = UnitHttpRequest::get()
        .with_header(":scheme", "https")
        .with_path("/api/orders")
        .with_header("user-agent", "testagent")
        .with_header("x-custom", "keep")
        .with_header("x-other", "also-kept");

    let events = capture_events_with_config(req, config).expect("expected a flushed batch");
    let headers = events[0]["headers"].as_object().expect("headers object");
    // Empty allowlist = unset = capture everything.
    assert_eq!(headers["X-Custom"], "keep");
    assert_eq!(headers["X-Other"], "also-kept");
    assert_eq!(headers["User-Agent"], "testagent");
}

#[test]
fn header_allowlist_blank_entries_capture_all() {
    // Non-empty array whose entries are all blank (e.g. a config-templating
    // bug or an empty row in the Anypoint UI array editor) collapses to
    // capture-all — the documented fail-open, surfaced by a startup warning.
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureHeaders":["  ", ""]}}"#
    );
    let req = UnitHttpRequest::get()
        .with_header(":scheme", "https")
        .with_path("/api/orders")
        .with_header("x-custom", "keep")
        .with_header("x-other", "also-kept");

    let events = capture_events_with_config(req, config).expect("expected a flushed batch");
    let headers = events[0]["headers"].as_object().expect("headers object");
    assert_eq!(headers["X-Custom"], "keep");
    assert_eq!(headers["X-Other"], "also-kept");
}

#[test]
fn header_allowlist_no_survivors_omits_headers_field() {
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureHeaders":["x-never-sent"]}}"#
    );
    let req = UnitHttpRequest::get()
        .with_header(":scheme", "https")
        .with_path("/api/orders")
        .with_header("user-agent", "testagent")
        .with_header("x-custom", "drop");

    let events = capture_events_with_config(req, config).expect("expected a flushed batch");
    let e = &events[0];
    // Every header was filtered out → the headers field is absent
    // (None serializes as omitted), not an empty object.
    assert!(
        e.get("headers").is_none(),
        "headers field should be absent when the allowlist admits nothing: {e}"
    );
}

#[test]
fn custom_pii_rules_scrub_params_and_body() {
    // customSensitiveKeys + customPiiPatterns end-to-end: the camelCase
    // config fields must deserialize, compile, and scrub both query
    // params and JSON bodies. secretKey present → the hash-action rule
    // must produce a digest, not a redaction.
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","secretKey":"test-hmac-secret","customSensitiveKeys":["member_number"],"customPiiPatterns":[{{"pattern":"\\b\\d{{3}}-\\d{{2}}-\\d{{4}}\\b","label":"ssn"}},{{"pattern":"^ACC-\\d+$","label":"account","action":"hash"}}]}}"#
    );
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/api/claims?member_number=M-1&status=open")
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"note":"ssn 123-45-6789 on file","account":"ACC-42","password":"hunter2","ok":"keep"}"#,
        );

    let events = capture_events_with_config(req, config).expect("expected a flushed batch");
    assert_eq!(events.len(), 1);
    let e = &events[0];

    // Query params: custom key redacted, ordinary param preserved.
    assert_eq!(e["query_params"]["member_number"], "[REDACTED]");
    assert_eq!(e["query_params"]["status"], "open");

    // Body: value pattern scrubs inside free text, hash rule digests,
    // built-in floor unaffected, untouched fields pass through.
    assert_eq!(e["body"]["note"], "ssn [REDACTED] on file");
    let account = e["body"]["account"].as_str().expect("account is a string");
    assert_eq!(account.len(), 64, "hash action → SHA-256 hex digest");
    assert_ne!(account, "ACC-42");
    assert_eq!(e["body"]["password"], "[REDACTED]");
    assert_eq!(e["body"]["ok"], "keep");
}

#[test]
fn invalid_custom_pii_pattern_fails_policy_load() {
    // A rule that fails to compile must fail policy load (no events, no
    // silent not-scrubbing) — mirrors PathFilter's bad-glob behavior.
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","customPiiPatterns":[{{"pattern":"([unclosed"}}]}}"#
    );
    assert!(
        capture_events_with_config(minimal_post(), config).is_none(),
        "policy with an invalid scrub pattern must not capture events"
    );
}

#[test]
fn health_endpoint_is_skipped() {
    let req = UnitHttpRequest::get()
        .with_header(":scheme", "https")
        .with_path("/health");

    assert!(
        capture_events(req).is_none(),
        "health-check requests must not generate events"
    );
}

// Minimal capturable request for the sampling tests — a POST to a
// non-health path that survives the default (empty) path filters.
fn minimal_post() -> UnitHttpRequest {
    UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/api/orders")
}

// Baseline config plus a raw sampleRate JSON value (number, out-of-range,
// etc. — passed through verbatim so tests can exercise the clamp).
fn config_with_sample_rate(rate: &str) -> String {
    format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","sampleRate":{rate}}}"#
    )
}

#[test]
fn sample_rate_zero_suppresses_all_events() {
    assert!(
        capture_events_with_config(minimal_post(), config_with_sample_rate("0")).is_none(),
        "sampleRate 0 must capture nothing"
    );
}

#[test]
fn sample_rate_one_captures() {
    let events = capture_events_with_config(minimal_post(), config_with_sample_rate("1"))
        .expect("sampleRate 1 must capture every request");
    assert_eq!(events.len(), 1, "one request → one event");
    let e = &events[0];
    assert_eq!(e["method"], "POST");
    assert_eq!(e["endpoint"], "/api/orders");
}

#[test]
fn sample_rate_out_of_range_clamps() {
    // Above range clamps to 1 → still captures.
    let events = capture_events_with_config(minimal_post(), config_with_sample_rate("7.5"))
        .expect("sampleRate 7.5 clamps to 1 and captures");
    assert_eq!(events.len(), 1);

    // Below range clamps to 0 → captures nothing.
    assert!(
        capture_events_with_config(minimal_post(), config_with_sample_rate("-3")).is_none(),
        "sampleRate -3 clamps to 0 and captures nothing"
    );
}

#[test]
fn ai_prompt_body_captured_by_default() {
    // captureAiContent defaults to true — a well-known LLM path buffers
    // and captures the body, SENSITIVE_KEYS-sanitized like any JSON body.
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/v1/chat/completions")
        .with_header("user-agent", "openai-python")
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"model":"gpt-4o","api_key":"sk-123","messages":[{"role":"user","content":"hi"}]}"#,
        );

    let events = capture_events(req).expect("expected a flushed batch");
    assert_eq!(events.len(), 1);
    let e = &events[0];

    assert_eq!(e["endpoint"], "/v1/chat/completions");
    assert_eq!(e["method"], "POST");
    let headers = e["headers"].as_object().expect("headers object");
    assert_eq!(headers["User-Agent"], "openai-python");
    // Body captured by default; key-matching sanitization still runs, so
    // the free-form prompt content ships while sensitive keys redact.
    assert_eq!(e["body"]["model"], "gpt-4o");
    assert_eq!(e["body"]["messages"][0]["content"], "hi");
    assert_eq!(e["body"]["api_key"], "[REDACTED]");
}

#[test]
fn ai_prompt_body_withheld_when_disabled() {
    // captureAiContent: false → the well-known LLM path short-circuits
    // body buffering and the event ships without a body.
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/v1/chat/completions")
        .with_header("user-agent", "openai-python")
        .with_header("content-type", "application/json")
        .with_body(r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#);

    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureAiContent":false}}"#
    );
    let events = capture_events_with_config(req, config).expect("expected a flushed batch");
    assert_eq!(events.len(), 1);
    let e = &events[0];

    // Everything except the body still ships — AI endpoint discovery
    // and traffic analytics keep working.
    assert_eq!(e["endpoint"], "/v1/chat/completions");
    assert_eq!(e["method"], "POST");
    let headers = e["headers"].as_object().expect("headers object");
    assert_eq!(headers["User-Agent"], "openai-python");
    assert!(
        e.get("body").is_none(),
        "AI prompt body must be withheld when captureAiContent is disabled: {e}"
    );
}

#[test]
fn ai_prompt_shaped_body_on_custom_path_withheld_when_disabled() {
    // captureAiContent: false, non-LLM path → the body is buffered, so the
    // post-parse body-shape heuristic must still withhold it.
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/internal/ai/ask")
        .with_header("content-type", "application/json")
        .with_body(r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#);

    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureAiContent":false}}"#
    );
    let events = capture_events_with_config(req, config).expect("expected a flushed batch");
    assert_eq!(events.len(), 1);
    let e = &events[0];

    assert_eq!(e["endpoint"], "/internal/ai/ask");
    assert!(
        e.get("body").is_none(),
        "prompt-shaped body must be withheld even off well-known LLM paths: {e}"
    );
}

#[test]
fn mcp_jsonrpc_body_still_captured() {
    // MCP carve-out: JSON-RPC bodies always ship (discovery depends on
    // the arguments), with standard sanitization applied.
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/mcp")
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"query":"x","api_key":"sk-123"}}}"#,
        );

    let events = capture_events(req).expect("expected a flushed batch");
    assert_eq!(events.len(), 1);
    let e = &events[0];

    assert_eq!(e["body"]["jsonrpc"], "2.0");
    assert_eq!(e["body"]["method"], "tools/call");
    assert_eq!(e["body"]["params"]["arguments"]["query"], "x");
    assert_eq!(e["body"]["params"]["arguments"]["api_key"], "[REDACTED]");
}
