// CerberusEvent — payload shape sent to the Cerberus backend. The
// api_key is NOT serialized here — it rides as the X-API-Key header
// on the batch POST (see sink.rs).
//
// `custom_data` is intentionally absent for now. See DEVELOPMENT.md
// "Planned improvements" — the response-body mutation needed to extract
// `_cerberus_metrics` is out of scope.

use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct CerberusEvent {
    /// Hashed client IP (HMAC-SHA256 hex), or raw IP if no secret is
    /// configured. None when no IP could be resolved.
    pub remote_addr: Option<String>,

    /// Request path without query string.
    pub endpoint: String,

    /// True for HTTPS, false for HTTP.
    pub scheme: bool,

    /// Uppercased HTTP method.
    pub method: String,

    /// ISO 8601 UTC timestamp captured at request_filter entry.
    pub timestamp: String,

    /// Sanitized headers (Authorization HMAC'd / SENSITIVE_HEADERS
    /// REDACTED). BTreeMap so serialization order is stable across
    /// runs — matters for deterministic golden-fixture comparisons.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, String>>,

    /// Sanitized query parameters. Single-valued keys serialize as
    /// strings, multi-valued as arrays.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_params: Option<serde_json::Map<String, serde_json::Value>>,

    /// Sanitized JSON body for write-mutating methods + JSON content
    /// type. None for everything else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,

    /// User-Agent header, raw.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// Application-supplied user identity (read from userIdHeader).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// Upstream HTTP status code. None when the response's `:status`
    /// pseudo-header was absent or unparseable (never 0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u32>,

    /// Wall-clock milliseconds between request arrival and response
    /// headers + captured body completion. Saturates to 0 on clock skew.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,

    /// Response headers captured via the captureResponseHeaders
    /// allowlist, sanitized like request headers. Absent when the
    /// allowlist is empty or none of the listed headers appeared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<BTreeMap<String, String>>,

    /// Captured response body (captureResponseBody): a sanitized JSON
    /// value, a frame-sanitized SSE string, or one of the explicit
    /// marker objects (`body_skipped_encoding` / `body_truncated` —
    /// see response_capture.rs). Absent ⇒ omitted ⇒ the pre-0.4.0
    /// event shape is unchanged on the wire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<serde_json::Value>,

    /// Session correlator behind the sampling decision: the MCP session
    /// id from the request (header or legacy query param) or — for a
    /// decide-late handshake — the id the server minted in its
    /// response. Present only when session sampling keyed on a session
    /// id (the backend indexes this field); operator `sessionKeyHeader`
    /// values and fallback-tier keys (principal, user id,
    /// Authorization) never ship, in this field or any other.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Effective sampleRate at decision time, so the backend can
    /// re-inflate counts by 1/sample_rate. Present only when sampling
    /// is active (rate < 1.0); omitted at rate 1.0 so the pre-0.5.0
    /// wire shape is untouched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_rate: Option<f64>,

    /// Which key decided this event's sampling — the estimator stratum
    /// and a misconfiguration signal (e.g. everything `request` means
    /// no usable keys reach the policy). One of: session_request |
    /// session_response | session_header | principal | user_id |
    /// authorization | request. Present only when sampling is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_key: Option<&'static str>,
}
