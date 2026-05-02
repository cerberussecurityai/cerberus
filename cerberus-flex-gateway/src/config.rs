// Typed Config wrapper for the policy.
//
// `cargo anypoint config-gen` (invoked via `make build-asset-files`)
// produces a sibling `src/generated/config.rs` with the same field set
// derived from `definition/gcl.yaml` — but every non-required field is
// `Option<T>` and gcl.yaml `default:` values are not propagated to the
// Rust struct. This module duplicates the field set with proper types
// and serde defaults so the rest of the policy can use ergonomic typed
// values (e.g. `config.batch_size: u32` rather than `Option<i64>`).
// The generated module is still compiled in via `mod generated;` in
// lib.rs because it provides the `#[pdk::hl::entrypoint_flex]` init
// hook the PDK runtime depends on.
//
// Field names are camelCase in YAML and snake_case here; serde maps via
// `rename_all = "camelCase"`.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    /// Cerberus backend URL. Declared as `format: service` in
    /// `definition/gcl.yaml` — Flex Gateway registers an Envoy cluster
    /// for this URL at policy load and the PDK hands us a `Service`
    /// handle bound to it. Required for outbound dispatch from the
    /// WASM filter (proxy-wasm `dispatch_http_call` only accepts
    /// registered cluster names).
    #[serde(deserialize_with = "pdk::serde::deserialize_service")]
    pub ingest_service: pdk::hl::Service,

    /// Cerberus API key. Sent as the X-API-Key header on outbound
    /// requests; the server resolves client_id from the key.
    pub token: String,

    /// Optional. HMAC-SHA256 key for PII hashing.
    pub secret_key: Option<String>,

    /// Optional. Base URL to fetch the HMAC key from at startup.
    pub backend_url: Option<String>,

    /// Header to read client IP from. Default: X-Forwarded-For.
    #[serde(default = "default_client_ip_header")]
    pub client_ip_header: String,

    /// Optional. Header to read end-user identity from.
    pub user_id_header: Option<String>,

    /// Optional glob allowlist.
    pub capture_paths: Option<Vec<String>>,

    /// Optional glob denylist.
    pub exclude_paths: Option<Vec<String>>,

    /// Buffer + sanitize JSON request bodies. Default: true.
    #[serde(default = "default_capture_request_body")]
    pub capture_request_body: bool,

    /// Max events per outbound batch. Default: 50.
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,

    /// Flush interval in milliseconds. Default: 2000.
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u32,

    /// Per-worker queue capacity. Default: 10000.
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: u32,

    /// Log verbosity. Default: info.
    /// TODO(v1.1): wire this through to PDK's logger. As of PDK 1.8.0
    /// there is no public API to set per-policy log verbosity at
    /// runtime — the gateway pod's global LOG_LEVEL env var dominates.
    /// We accept the field anyway so config remains forward-compatible.
    #[serde(default = "default_log_level")]
    #[allow(dead_code)]
    pub log_level: String,
}

fn default_client_ip_header() -> String {
    "X-Forwarded-For".to_string()
}
fn default_capture_request_body() -> bool {
    true
}
fn default_batch_size() -> u32 {
    50
}
fn default_flush_interval_ms() -> u32 {
    2000
}
fn default_queue_capacity() -> u32 {
    10_000
}
fn default_log_level() -> String {
    "info".to_string()
}
