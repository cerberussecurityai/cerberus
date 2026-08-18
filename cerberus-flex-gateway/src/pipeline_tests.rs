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
    run_pipeline(req, config, UnitHttpResponse::new(200)).0
}

// Full driver: sends `req` through the policy with `upstream` as the
// backend response, then flushes. Returns the flushed events AND the
// client-visible response, so response-capture tests can assert the
// observe-only invariant: what the client receives is byte-identical to
// what the backend sent (pdk-unit reassembles the Continue'd chunks
// into the client-visible response).
fn run_pipeline(
    req: UnitHttpRequest,
    config: String,
    upstream: UnitHttpResponse,
) -> (Option<Vec<Value>>, UnitHttpResponse) {
    let _guard = HARNESS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let trace = Rc::new(TraceBackend::new(UnitHttpResponse::new(200)));
    let mut tester = UnitTestBuilder::default()
        .with_config(config)
        .with_backend(upstream)
        .with_http_upstream_from_authority(INGEST_AUTHORITY, Rc::clone(&trace))
        .with_entrypoint(crate::configure);

    let response = tester.request(req);
    tester.sleep(Duration::from_millis(2500));

    let events = trace.next().map(|batch| {
        assert_eq!(
            batch.header("x-api-key"),
            Some("test-api-key"),
            "batch must carry the API key header"
        );
        let body: Value = serde_json::from_slice(batch.body()).expect("batch body is JSON");
        body["events"]
            .as_array()
            .expect("batch envelope has an events array")
            .clone()
    });
    (events, response)
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

// ---------------------------------------------------------------------
// Response-body capture (captureResponseBody).
//
// Every test here asserts the observe-only invariant via `assert_pass_through`:
// the client-visible response is byte-identical to what the backend sent.
// The harness delivers response bodies to the policy in 3-byte chunks, so
// multi-chunk accumulation is exercised for free.
// ---------------------------------------------------------------------

fn response_capture_config() -> String {
    format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureResponseBody":true}}"#
    )
}

fn assert_pass_through(client: &UnitHttpResponse, expected: &UnitHttpResponse) {
    assert_eq!(
        client.status_code(),
        expected.status_code(),
        "client-visible status must be unmodified"
    );
    assert_eq!(
        client.body(),
        expected.body(),
        "client-visible body must be byte-identical — the tap must never mutate"
    );
}

#[test]
fn response_whole_json_captured_and_sanitized() {
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"password":"hunter2","item":"widget"}"#);
    let (events, client) =
        run_pipeline(minimal_post(), response_capture_config(), upstream.clone());
    assert_pass_through(&client, &upstream);

    let events = events.expect("expected a flushed batch");
    let e = &events[0];
    // Sensitive keys in the response body sanitize like request bodies.
    assert_eq!(e["response_body"]["password"], "[REDACTED]");
    assert_eq!(e["response_body"]["item"], "widget");
    assert_eq!(e["status_code"], 200);
    assert!(
        e["latency_ms"].is_u64(),
        "latency_ms must be present: {e}"
    );
}

#[test]
fn response_capture_off_by_default_status_latency_still_ship() {
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"item":"widget"}"#);
    let (events, client) = run_pipeline(minimal_post(), config(), upstream.clone());
    assert_pass_through(&client, &upstream);

    let events = events.expect("expected a flushed batch");
    let e = &events[0];
    assert!(
        e.get("response_body").is_none(),
        "default config must not capture response bodies: {e}"
    );
    // status_code / latency_ms ship unconditionally.
    assert_eq!(e["status_code"], 200);
    assert!(e["latency_ms"].is_u64());
}

#[test]
fn response_non_json_non_sse_content_type_skipped() {
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "text/html")
        .with_body("<html><body>hi</body></html>");
    let (events, client) =
        run_pipeline(minimal_post(), response_capture_config(), upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    assert!(
        e.get("response_body").is_none(),
        "text/html must not be captured: {e}"
    );
    assert_eq!(e["status_code"], 200);
}

#[test]
fn response_compressed_body_ships_encoding_marker() {
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_header("content-encoding", "gzip")
        // Not real gzip — the policy must not read the stream at all.
        .with_body(b"\x1f\x8b compressed bytes".to_vec());
    let (events, client) =
        run_pipeline(minimal_post(), response_capture_config(), upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    assert_eq!(
        e["response_body"],
        serde_json::json!({"body_skipped_encoding": "gzip"}),
        "compressed bodies ship exactly the encoding marker: {e}"
    );
}

#[test]
fn response_sse_within_budget_ships_raw_string() {
    let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"result\":{\"ok\":true}}\n\n";
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse);
    let (events, client) =
        run_pipeline(minimal_post(), response_capture_config(), upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    assert_eq!(
        e["response_body"], sse,
        "in-budget SSE ships whole as a raw string: {e}"
    );
}

#[test]
fn response_sse_truncated_with_tiny_budgets() {
    let sse = "data: 0123456789abcdefghijklmnopqrstuvwxyz\n\n"; // 44 bytes
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureResponseBody":true,"responseHeadBytes":10,"responseTailBytes":8}}"#
    );
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse);
    let (events, client) = run_pipeline(minimal_post(), config, upstream.clone());
    // The client stream must be intact even though the capture truncated.
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    let marker = e["response_body"]
        .as_object()
        .expect("truncation marker object");
    assert_eq!(marker["body_truncated"], true);
    assert_eq!(marker["body_bytes_total"], 44);
    assert_eq!(marker["body_bytes_dropped"], 44 - 10 - 8);
    assert_eq!(marker["head"], &sse[..10], "head is the exact prefix");
    assert_eq!(marker["tail"], &sse[44 - 8..], "tail is the exact suffix");
}

#[test]
fn response_oversized_json_document_truncates_too() {
    // JSON documents go through the same head+tail path as SSE — an
    // over-budget JSON body yields the marker, not a parse attempt.
    let big = format!(r#"{{"data":"{}"}}"#, "x".repeat(100));
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureResponseBody":true,"responseHeadBytes":16,"responseTailBytes":8}}"#
    );
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_body(big.clone());
    let (events, client) = run_pipeline(minimal_post(), config, upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    let marker = e["response_body"]
        .as_object()
        .expect("truncation marker object");
    assert_eq!(marker["body_truncated"], true);
    assert_eq!(marker["body_bytes_total"], big.len() as u64);
    assert_eq!(
        marker["head"],
        &big[..16],
        "head is a parseable prefix for content sniffing"
    );
}

#[test]
fn response_llm_path_withheld_when_ai_capture_disabled() {
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureResponseBody":true,"captureAiContent":false}}"#
    );
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/v1/chat/completions")
        .with_header("content-type", "application/json")
        .with_body(r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#);
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"choices":[{"message":{"role":"assistant","content":"hello"}}]}"#);
    let (events, client) = run_pipeline(req, config, upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    assert!(
        e.get("response_body").is_none(),
        "LLM response body must be withheld when captureAiContent is off: {e}"
    );
    // Metadata still ships.
    assert_eq!(e["status_code"], 200);
    assert!(e["latency_ms"].is_u64());
}

#[test]
fn response_sse_on_custom_path_withheld_when_request_was_ai_suppressed() {
    // captureAiContent: false, custom (non-LLM) path, prompt-shaped
    // request body → the request body is withheld by the parsed-shape
    // check. The response is SSE, which never reaches a parsed-shape
    // check, so the request-side decision must carry over: model output
    // is withheld too.
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureResponseBody":true,"captureAiContent":false}}"#
    );
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/internal/ai/ask")
        .with_header("content-type", "application/json")
        .with_body(r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#);
    let sse = "data: {\"choices\":[{\"delta\":{\"content\":\"hello there\"}}]}\n\ndata: [DONE]\n\n";
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse);
    let (events, client) = run_pipeline(req, config, upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    assert!(e.get("body").is_none(), "prompt body must be withheld: {e}");
    assert!(
        e.get("response_body").is_none(),
        "SSE model output on a custom path must be withheld when the request was AI-suppressed: {e}"
    );
    assert_eq!(e["status_code"], 200);
}

#[test]
fn response_completion_json_on_custom_path_withheld_without_prompt_shaped_request() {
    // The case neither the path list nor the request-side carry-over can
    // catch: custom path, a request body that is NOT prompt-shaped (an
    // internal wrapper API), and a whole-JSON response that is a real
    // OpenAI-shaped completion. captureAiContent: false must still withhold
    // it — the response-shape check is what does that.
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureResponseBody":true,"captureAiContent":false}}"#
    );
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/internal/assistant/answer")
        .with_header("content-type", "application/json")
        .with_body(r#"{"question":"what is our refund policy?","ticket":"T-1"}"#);
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Refunds within 30 days."},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":6}}"#);
    let (events, client) = run_pipeline(req, config, upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    // The request was not AI-shaped, so its body ships as usual...
    assert_eq!(e["body"]["ticket"], "T-1");
    // ...but the completion-shaped response is model output → withheld.
    assert!(
        e.get("response_body").is_none(),
        "completion-shaped JSON on a custom path must be withheld: {e}"
    );
    assert_eq!(e["status_code"], 200);
}

#[test]
fn response_sse_on_custom_path_captured_when_ai_capture_on() {
    // Positive control for the test above: same traffic with the default
    // captureAiContent (true) captures the SSE output.
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/internal/ai/ask")
        .with_header("content-type", "application/json")
        .with_body(r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#);
    let sse = "data: {\"choices\":[{\"delta\":{\"content\":\"hello there\"}}]}\n\n";
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse);
    let (events, client) = run_pipeline(req, response_capture_config(), upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    assert!(e["body"].is_object(), "prompt body captured by default: {e}");
    assert!(
        e["response_body"].is_string(),
        "SSE output captured when captureAiContent is on: {e}"
    );
}

#[test]
fn response_mcp_tools_list_result_captured_whole() {
    // The schema-report enabler: a captured tools/list JSON-RPC result.
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/mcp")
        .with_header("content-type", "application/json")
        .with_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
    let result = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","description":"find things","inputSchema":{"type":"object"}}]}}"#;
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_body(result);
    let (events, client) =
        run_pipeline(req, response_capture_config(), upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    assert_eq!(e["response_body"]["result"]["tools"][0]["name"], "search");
    assert_eq!(
        e["response_body"]["result"]["tools"][0]["inputSchema"]["type"],
        "object"
    );
}

#[test]
fn response_mcp_sse_result_key_sanitized_client_untouched() {
    // Structured PII inside an SSE-transported MCP tool result is key-
    // redacted on the retained copy — while the client still receives the
    // original bytes (the tap never mutates the wire).
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/mcp")
        .with_header("content-type", "application/json")
        .with_body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup","arguments":{"q":"x"}}}"#);
    let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}],\"structuredContent\":{\"api_key\":\"sk-live-1\",\"user\":\"alice\"}}}\n\n";
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "text/event-stream")
        .with_body(sse);
    let (events, client) = run_pipeline(req, response_capture_config(), upstream.clone());
    assert_pass_through(&client, &upstream);
    assert!(
        std::str::from_utf8(client.body()).unwrap().contains("sk-live-1"),
        "client must receive the original bytes"
    );

    let e = &events.expect("expected a flushed batch")[0];
    let captured = e["response_body"].as_str().expect("SSE ships as a string");
    assert!(!captured.contains("sk-live-1"), "secret must not ship: {captured}");
    assert!(captured.contains("\"api_key\":\"[REDACTED]\""), "{captured}");
    assert!(captured.contains("\"user\":\"alice\""), "{captured}");
    assert!(captured.starts_with("event: message\ndata: "), "framing preserved: {captured}");
}

#[test]
fn response_budgets_clamp_to_schema_maximum() {
    // gcl.yaml declares maximum 49152 for both budgets, but that is only
    // enforced by API Manager's form — Local-mode YAML can carry anything.
    // Out-of-range values clamp (with a startup warning) instead of driving
    // an unbounded accumulator: a 60 KB body under a "1 MB" head budget
    // must still truncate at 49152.
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureResponseBody":true,"responseHeadBytes":1048576,"responseTailBytes":0}}"#
    );
    let big = "x".repeat(60_000);
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "text/event-stream")
        .with_body(big.clone());
    let (events, client) = run_pipeline(minimal_post(), config, upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    let marker = e["response_body"].as_object().expect("truncation marker");
    assert_eq!(marker["body_truncated"], true);
    assert_eq!(marker["head"].as_str().unwrap().len(), 49_152);
    assert_eq!(marker["body_bytes_dropped"], 60_000 - 49_152);
}

#[test]
fn response_truncated_completion_on_custom_path_withheld_when_ai_capture_off() {
    // Over budget + captureAiContent: false + custom path + non-prompt-
    // shaped request: the pre-stream gate can't see the shape, so the
    // finalizer's head sniff must withhold the truncated model output.
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureResponseBody":true,"captureAiContent":false,"responseHeadBytes":256,"responseTailBytes":128}}"#
    );
    let req = UnitHttpRequest::post()
        .with_header(":scheme", "https")
        .with_path("/internal/assistant/answer")
        .with_header("content-type", "application/json")
        .with_body(r#"{"question":"tell me a long story","ticket":"T-2"}"#);
    let long = "Once upon a time ".repeat(200);
    let body = format!(
        r#"{{"id":"chatcmpl-2","object":"chat.completion","model":"gpt-4o","choices":[{{"index":0,"message":{{"role":"assistant","content":"{long}"}},"finish_reason":"stop"}}]}}"#
    );
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_body(body);
    let (events, client) = run_pipeline(req, config, upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    assert!(
        e.get("response_body").is_none(),
        "truncated completion must be withheld: {e}"
    );
    assert_eq!(e["status_code"], 200);
}

#[test]
fn response_bodyless_with_content_encoding_ships_nothing() {
    // A 304 (or HEAD) may carry Content-Encoding with no body; the
    // body-presence gate must win over the compression marker.
    let upstream = UnitHttpResponse::new(304)
        .with_header("content-type", "application/json")
        .with_header("content-encoding", "gzip");
    let (events, client) =
        run_pipeline(minimal_post(), response_capture_config(), upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    assert!(
        e.get("response_body").is_none(),
        "body-less response must not ship an encoding marker: {e}"
    );
    assert_eq!(e["status_code"], 304);
}

#[test]
fn response_header_allowlist_captures_default_mcp_session_id() {
    // Default config: captureResponseHeaders defaults to
    // ["mcp-session-id"], independent of captureResponseBody.
    let upstream = UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_header("mcp-session-id", "4bbd920a-sess")
        .with_header("x-internal-shard", "not-listed")
        .with_body(r#"{"ok":true}"#);
    let (events, client) = run_pipeline(minimal_post(), config(), upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    let rh = e["response_headers"].as_object().expect("response_headers");
    assert_eq!(rh["Mcp-Session-Id"], "4bbd920a-sess");
    assert_eq!(
        rh.len(),
        1,
        "only allowlisted response headers may ship: {rh:?}"
    );
}

#[test]
fn response_header_allowlist_empty_captures_none() {
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureResponseHeaders":[]}}"#
    );
    let upstream = UnitHttpResponse::new(200)
        .with_header("mcp-session-id", "4bbd920a-sess")
        .with_body("ok");
    let (events, client) = run_pipeline(minimal_post(), config, upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    assert!(
        e.get("response_headers").is_none(),
        "empty captureResponseHeaders must capture nothing: {e}"
    );
}

#[test]
fn response_header_allowlist_sensitive_header_still_redacts() {
    // Listing a sensitive response header controls presence, not value —
    // same contract as the request-side allowlist.
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureResponseHeaders":["Set-Cookie","X-Trace-Id"]}}"#
    );
    let upstream = UnitHttpResponse::new(200)
        .with_header("set-cookie", "sid=supersecret")
        .with_header("x-trace-id", "trace-1")
        .with_body("ok");
    let (events, client) = run_pipeline(minimal_post(), config, upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    let rh = e["response_headers"].as_object().expect("response_headers");
    assert_eq!(rh["Set-Cookie"], "[REDACTED]");
    assert_eq!(rh["X-Trace-Id"], "trace-1");
}

#[test]
fn response_header_allowlist_multi_value_collapses_after_sanitization() {
    // Repeated response headers (Set-Cookie is the canonical case) collapse
    // with ", " AFTER per-value sanitization — same contract as request
    // headers, exercised here in the direction where Set-Cookie lives.
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureResponseHeaders":["set-cookie","x-shard"]}}"#
    );
    let upstream = UnitHttpResponse::new(200)
        .with_header("set-cookie", "sid=one")
        .with_header("set-cookie", "csrf=two")
        .with_header("x-shard", "a")
        .with_header("x-shard", "b")
        .with_body("ok");
    let (events, client) = run_pipeline(minimal_post(), config, upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    let rh = e["response_headers"].as_object().expect("response_headers");
    assert_eq!(rh["Set-Cookie"], "[REDACTED], [REDACTED]");
    assert_eq!(rh["X-Shard"], "a, b");
}

#[test]
fn response_header_allowlist_absent_header_omits_field_or_key() {
    // Allowlisted-but-absent headers simply don't appear: no key when others
    // are present, and no response_headers field at all when none matched.
    let config = format!(
        r#"{{"ingestService":"http://{INGEST_AUTHORITY}","token":"test-api-key","captureResponseHeaders":["mcp-session-id","x-trace-id"]}}"#
    );
    let upstream = UnitHttpResponse::new(200)
        .with_header("x-trace-id", "t-1")
        .with_body("ok");
    let (events, client) = run_pipeline(minimal_post(), config.clone(), upstream.clone());
    assert_pass_through(&client, &upstream);
    let e = &events.expect("expected a flushed batch")[0];
    let rh = e["response_headers"].as_object().expect("response_headers");
    assert_eq!(rh.len(), 1);
    assert_eq!(rh["X-Trace-Id"], "t-1");
    assert!(rh.get("Mcp-Session-Id").is_none());

    let upstream = UnitHttpResponse::new(200).with_body("ok");
    let (events, client) = run_pipeline(minimal_post(), config, upstream.clone());
    assert_pass_through(&client, &upstream);
    let e = &events.expect("expected a flushed batch")[0];
    assert!(
        e.get("response_headers").is_none(),
        "no allowlisted header present → field omitted: {e}"
    );
}

#[test]
fn response_bodyless_204_no_response_body() {
    let upstream = UnitHttpResponse::new(204).with_header("content-type", "application/json");
    let (events, client) =
        run_pipeline(minimal_post(), response_capture_config(), upstream.clone());
    assert_pass_through(&client, &upstream);

    let e = &events.expect("expected a flushed batch")[0];
    assert!(
        e.get("response_body").is_none(),
        "body-less response must not produce a response_body: {e}"
    );
    assert_eq!(e["status_code"], 204);
    assert!(e["latency_ms"].is_u64());
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
