// Rust port of cerberus-core's sanitization primitives. Constants are
// duplicated here on purpose — sharing a Rust crate with cerberus-core
// would force us to translate Python types and add a build-time
// dependency the WASM target doesn't need. Drift between the two is
// caught by the parity test runner (tests/parity/) which consumes the
// shared YAML fixtures at parity-fixtures/.
//
// See cerberus-core/src/cerberus_core/sanitization.py:14-117 for the
// canonical Python implementation.

use serde_json::{Map, Value};

pub const REDACTED: &str = "[REDACTED]";

/// Lowercase forms of header names that always need redaction. The
/// caller is expected to lowercase the incoming header name before
/// calling `is_sensitive_header_lower`. This avoids re-lowercasing
/// per check.
///
/// Authorization is sensitive but special-cased upstream — it's
/// HMAC-hashed when a secret is available so cross-request user
/// tracking still works. The other entries are always REDACTED.
pub const SENSITIVE_HEADERS_LOWER: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
];

/// Keys (case-insensitive) whose values get redacted in JSON bodies,
/// query params, and any other dict-like structure we sanitize.
/// Mirrors cerberus_core.sanitization.SENSITIVE_KEYS exactly.
pub const SENSITIVE_KEYS_LOWER: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api_secret",
    "access_token",
    "refresh_token",
    "authorization",
    "auth",
    "credential",
    "credentials",
    "private_key",
    "ssh_key",
    "session_id",
    "session_token",
    "cookie",
    "credit_card",
    "card_number",
    "cvv",
    "ssn",
];

const MAX_DEPTH: usize = 20;

pub fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_KEYS_LOWER.iter().any(|k| *k == lower)
}

pub fn is_sensitive_header_lower(header_lower: &str) -> bool {
    SENSITIVE_HEADERS_LOWER.iter().any(|h| *h == header_lower)
}

/// Recursive sanitize for a serde_json::Value tree. Mirrors
/// cerberus_core.sanitize_dict including:
///   - case-insensitive key matching against SENSITIVE_KEYS
///   - REDACTED replacement happens at the value level (the entire
///     subtree under a sensitive key is replaced, not recursed into)
///   - depth-capped at MAX_DEPTH; deeper subtrees become REDACTED
///     wholesale. Matches Python's `_max_depth=20` default.
///   - non-string keys get passed through (Python ignores them with
///     `if isinstance(key, str)`); JSON has no non-string keys so
///     this is moot — included for shape parity only.
pub fn sanitize_value(value: Value) -> Value {
    sanitize_inner(value, 0)
}

fn sanitize_inner(value: Value, depth: usize) -> Value {
    if depth > MAX_DEPTH {
        return Value::String(REDACTED.to_string());
    }
    match value {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                if is_sensitive_key(&k) {
                    out.insert(k, Value::String(REDACTED.to_string()));
                } else if matches!(v, Value::Object(_) | Value::Array(_)) {
                    out.insert(k, sanitize_inner(v, depth + 1));
                } else {
                    out.insert(k, v);
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .map(|v| {
                    if matches!(v, Value::Object(_) | Value::Array(_)) {
                        sanitize_inner(v, depth + 1)
                    } else {
                        v
                    }
                })
                .collect(),
        ),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sensitive_key_lookup_case_insensitive() {
        assert!(is_sensitive_key("password"));
        assert!(is_sensitive_key("Password"));
        assert!(is_sensitive_key("API_KEY"));
        assert!(!is_sensitive_key("username"));
    }

    #[test]
    fn sensitive_header_lookup_lowercase_only() {
        // Caller must lowercase first.
        assert!(is_sensitive_header_lower("authorization"));
        assert!(is_sensitive_header_lower("cookie"));
        assert!(!is_sensitive_header_lower("user-agent"));
    }

    #[test]
    fn redacts_top_level_sensitive_value() {
        let input = json!({"username": "alice", "password": "hunter2"});
        let expected = json!({"username": "alice", "password": "[REDACTED]"});
        assert_eq!(sanitize_value(input), expected);
    }

    #[test]
    fn redacts_entire_subtree_when_key_is_sensitive() {
        let input = json!({"credentials": {"token": "abc", "role": "admin"}});
        let expected = json!({"credentials": "[REDACTED]"});
        assert_eq!(sanitize_value(input), expected);
    }

    #[test]
    fn list_of_dicts_each_sanitized() {
        let input = json!([
            {"username": "alice", "password": "x"},
            {"username": "bob", "password": "y"}
        ]);
        let expected = json!([
            {"username": "alice", "password": "[REDACTED]"},
            {"username": "bob", "password": "[REDACTED]"}
        ]);
        assert_eq!(sanitize_value(input), expected);
    }

    #[test]
    fn deep_nesting_caps_at_max_depth() {
        let mut v = json!({"value": "leaf"});
        for _ in 0..25 {
            v = json!({"level": v});
        }
        let result = sanitize_value(v);
        // Walk to depth 21 — should hit REDACTED there.
        let mut node = &result;
        for _ in 0..21 {
            node = &node["level"];
        }
        assert_eq!(node, &Value::String("[REDACTED]".to_string()));
    }
}
