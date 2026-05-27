// CerberusEvent — payload shape sent to the Cerberus backend. The
// api_key is NOT serialized here — it rides as the X-API-Key header
// on the batch POST (see sink.rs).
//
// `custom_data` is intentionally absent in v1. See README "Known gaps
// in v1" — the response-body mutation needed to extract
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
}
