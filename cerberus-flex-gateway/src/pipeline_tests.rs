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
