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

use crate::pii_rules::PiiPatternConfig;
use crate::sanitize::REDACTED;

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

    /// Optional. Cerberus backend to fetch the HMAC key from at startup.
    /// Declared as `format: service` in `definition/gcl.yaml` so Flex
    /// Gateway registers an Envoy cluster for it at policy load and hands
    /// us a `Service` handle — required for the init-time outbound GET,
    /// since proxy-wasm `dispatch_http_call` only accepts registered
    /// cluster names (a runtime-manufactured `Service` is never wired up).
    #[serde(default, deserialize_with = "pdk::serde::deserialize_service_opt")]
    pub backend_url: Option<pdk::hl::Service>,

    /// Header to read client IP from. Default: X-Forwarded-For.
    #[serde(default = "default_client_ip_header")]
    pub client_ip_header: String,

    /// Optional. Header to read end-user identity from.
    pub user_id_header: Option<String>,

    /// Optional. Allowlist of request header names to capture
    /// (case-insensitive). Empty/unset = capture all headers.
    pub capture_headers: Option<Vec<String>>,

    /// Optional. Extra key names (case-insensitive) whose values are
    /// redacted in query params and JSON bodies — additive to the
    /// built-in SENSITIVE_KEYS floor.
    pub custom_sensitive_keys: Option<Vec<String>>,

    /// Optional. Customer regex scrubbing rules applied to query params
    /// and JSON bodies. Compiled once at policy load; invalid rules
    /// fail policy load. See pii_rules.rs.
    pub custom_pii_patterns: Option<Vec<PiiPatternConfig>>,

    /// Optional glob allowlist.
    pub capture_paths: Option<Vec<String>>,

    /// Optional glob denylist.
    pub exclude_paths: Option<Vec<String>>,

    /// Fraction of capturable traffic to sample. Default: 1.0 (all).
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,

    /// Sampling unit when sampleRate < 1: "session" (default —
    /// deterministic keyed decision per session/identity, identical on
    /// every replica; see sampler.rs) or "request" (independent
    /// per-request coin, the pre-0.5.0 behavior). Unknown values warn
    /// and fall back to "session" in PolicyContext::new — a typo in
    /// this knob must not take capture down.
    #[serde(default = "default_sample_by")]
    pub sample_by: String,

    /// Optional. Extra request headers to use as the session sampling
    /// key when no MCP session id is present (e.g. traceparent,
    /// X-Conversation-Id). Checked in order; first present header
    /// wins. The value is used in memory only — never shipped.
    pub session_key_header: Option<Vec<String>>,

    /// Buffer + sanitize JSON request bodies. Default: true.
    #[serde(default = "default_capture_request_body")]
    pub capture_request_body: bool,

    /// Capture request bodies detected as LLM/AI prompt content.
    /// Default: true — AI/LLM request bodies are captured and sanitized
    /// like any other JSON body (customPiiPatterns value rules reach
    /// inside prompt text). Set to false to withhold prompt content
    /// entirely (detected LLM/AI traffic then ships its event without
    /// the body). MCP (JSON-RPC) bodies are never treated as AI content.
    #[serde(default = "default_capture_ai_content")]
    pub capture_ai_content: bool,

    /// Observe response bodies (application/json + text/event-stream).
    /// Default: false — opt-in first; the response stream is never even
    /// opened when off. Read-only tap: the response the client receives
    /// is never modified, buffered, or delayed.
    #[serde(default)]
    pub capture_response_body: bool,

    /// Allowlist of RESPONSE header names to capture (case-insensitive)
    /// into the event's `response_headers` map. Unlike captureHeaders,
    /// this is a pure opt-in: empty = capture no response headers.
    /// Default: ["mcp-session-id"] — the session correlator stateful
    /// APIs (e.g. MCP) assign in a response and clients echo on
    /// subsequent requests. Sanitization applies as for request headers.
    #[serde(default = "default_capture_response_headers")]
    pub capture_response_headers: Vec<String>,

    /// First N bytes of a response body retained. Default: 24576.
    #[serde(default = "default_response_head_bytes")]
    pub response_head_bytes: u32,

    /// Rolling last N bytes of a response body retained. Default: 16384.
    /// The tail is where SSE terminal events / usage live, hence
    /// generous relative to typical response tails.
    #[serde(default = "default_response_tail_bytes")]
    pub response_tail_bytes: u32,

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
fn default_sample_rate() -> f64 {
    1.0
}
fn default_sample_by() -> String {
    "session".to_string()
}
fn default_capture_request_body() -> bool {
    true
}
fn default_capture_ai_content() -> bool {
    true
}
fn default_capture_response_headers() -> Vec<String> {
    vec!["mcp-session-id".to_string()]
}
fn default_response_head_bytes() -> u32 {
    24_576
}
fn default_response_tail_bytes() -> u32 {
    16_384
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

// ---------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------

/// Top-level config properties whose values must never reach a log
/// line, as named on the wire (camelCase). Both are declared
/// `security:sensitive` in definition/gcl.yaml.
const SENSITIVE_CONFIG_KEYS: [&str; 2] = ["token", "secretKey"];

/// Parse the policy configuration handed to us at init.
///
/// The error for a rejected config names the problem — unknown or
/// missing field, type mismatch, JSON syntax error, each with serde's
/// line/column — but never includes the configuration itself: it
/// carries `token` and `secretKey`, and the PDK runtime writes a failed
/// configure to the gateway log at Error level. See
/// [`redact_parse_error`] for the value scrubbing on top of that.
pub fn parse(bytes: &[u8]) -> anyhow::Result<Config> {
    serde_json::from_slice::<Config>(bytes).map_err(|err| {
        anyhow::anyhow!(
            "cerberus-flex-gateway: failed to parse config: {}",
            redact_parse_error(bytes, &err)
        )
    })
}

/// Render a config deserialization error for logging.
///
/// serde's type-mismatch messages quote the offending value
/// (``invalid type: integer `1234`, expected a string``), so a
/// wrongly-typed `token` or `secretKey` would otherwise land in the
/// log verbatim. The values of the sensitive top-level properties are
/// therefore replaced with the redaction sentinel wherever they occur
/// in the message, both as serde renders strings (Debug-escaped and
/// quoted) and raw. JSON syntax errors carry only positions, never
/// content, so there is nothing to scrub when the config isn't
/// parseable at all.
///
/// Also used by the toolchain-generated init hook in
/// `src/generated/config.rs` (patched in by
/// `scripts/redact_generated_config.sh` during `make build-asset-files`).
pub fn redact_parse_error(bytes: &[u8], err: &serde_json::Error) -> String {
    let mut message = err.to_string();
    for value in sensitive_config_values(bytes) {
        // Quoted/escaped form first so the raw form doesn't leave a
        // stray pair of quotes behind.
        for needle in [format!("{value:?}"), value] {
            message = message.replace(&needle, REDACTED);
        }
    }
    message
}

/// String renderings of the sensitive top-level properties present in
/// `bytes`, if it parses as a JSON object at all. Non-string values
/// (the type-mismatch case) render as their JSON text, which is how
/// serde quotes them.
fn sensitive_config_values(bytes: &[u8]) -> Vec<String> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(bytes)
    else {
        return Vec::new();
    };
    SENSITIVE_CONFIG_KEYS
        .iter()
        .filter_map(|key| map.get(*key))
        .map(|value| match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Stand-ins for the sensitive fields so the scrubbing can be
    // exercised without a Service-bearing Config (whose URL fields
    // deserialize through the PDK host). `parse` itself is covered end
    // to end by
    // pipeline_tests::config_parse_failure_does_not_log_sensitive_values.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Probe {
        token: String,
        #[serde(rename = "secretKey")]
        secret_key: Option<String>,
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct NumericProbe {
        token: u32,
    }

    fn redacted<T: serde::de::DeserializeOwned>(json: &str) -> String {
        let err = match serde_json::from_str::<T>(json) {
            Ok(_) => panic!("probe config must be rejected"),
            Err(err) => err,
        };
        redact_parse_error(json.as_bytes(), &err)
    }

    #[test]
    fn unknown_field_names_the_field_not_the_values() {
        let msg = redacted::<Probe>(r#"{"token":"tok-4f9a","secretKey":"sk-77c1","tokn":"x"}"#);
        assert!(msg.contains("unknown field `tokn`"), "{msg}");
        assert!(
            !msg.contains("tok-4f9a") && !msg.contains("sk-77c1"),
            "{msg}"
        );
    }

    #[test]
    fn wrongly_typed_token_is_scrubbed() {
        // A digits-only token in Local-mode YAML arrives as a JSON
        // number; serde's message quotes it.
        let msg = redacted::<Probe>(r#"{"token":81234567}"#);
        assert!(msg.contains("invalid type"), "{msg}");
        assert!(!msg.contains("81234567"), "{msg}");
        assert!(msg.contains(REDACTED), "{msg}");
    }

    #[test]
    fn wrongly_typed_secret_key_is_scrubbed() {
        let msg = redacted::<Probe>(r#"{"token":"tok-4f9a","secretKey":true}"#);
        assert!(msg.contains("invalid type"), "{msg}");
        assert!(!msg.contains("true") && !msg.contains("tok-4f9a"), "{msg}");
    }

    #[test]
    fn string_quoted_by_serde_is_scrubbed_including_escapes() {
        // serde renders strings Debug-escaped: a token containing a
        // quote or backslash must still be found and replaced.
        let msg = redacted::<NumericProbe>(r#"{"token":"tok\"q\\z"}"#);
        assert!(msg.contains("invalid type"), "{msg}");
        assert!(!msg.contains("tok"), "{msg}");
        assert!(msg.contains(&format!("string {REDACTED}")), "{msg}");
    }

    #[test]
    fn syntax_error_carries_no_config_content() {
        let msg = redacted::<Probe>(r#"{"token":"tok-4f9a","secretKey":"#);
        assert!(!msg.contains("tok-4f9a"), "{msg}");
    }

    /// `make build-asset-files` regenerates src/generated/config.rs and
    /// then runs scripts/redact_generated_config.sh over it. Guard
    /// against a regeneration (or toolchain bump) that skips the script
    /// and brings the config echo back.
    #[test]
    fn generated_init_hook_does_not_echo_config() {
        let generated = include_str!("generated/config.rs");
        assert!(
            !generated.contains("from_utf8_lossy"),
            "generated init hook echoes the configuration; run scripts/redact_generated_config.sh"
        );
        assert!(
            generated.contains("crate::config::redact_parse_error"),
            "generated init hook must report parse errors through config::redact_parse_error"
        );
    }
}
