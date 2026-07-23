// Sanitization primitives. Constants are duplicated from cerberus-core
// on purpose — a shared Rust crate would force translating Python
// types and add a build-time dependency the WASM target doesn't need.
// Drift between implementations is caught by the parity test runner
// (tests/parity_runner.rs) which consumes the shared YAML fixtures at
// parity-fixtures/.

use std::collections::HashSet;
use std::sync::OnceLock;

use serde_json::{Map, Value};

use crate::pii_rules::{CompiledPiiRules, PiiAction};

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

// Lazily-built lookup sets. Each OnceLock is initialized exactly once on
// first access and then lives for the rest of the program — the slices
// above are the source of truth; these are just O(1)-lookup views.
static SENSITIVE_KEYS_SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
static SENSITIVE_HEADERS_SET: OnceLock<HashSet<&'static str>> = OnceLock::new();

fn sensitive_keys_set() -> &'static HashSet<&'static str> {
    SENSITIVE_KEYS_SET.get_or_init(|| SENSITIVE_KEYS_LOWER.iter().copied().collect())
}

fn sensitive_headers_set() -> &'static HashSet<&'static str> {
    SENSITIVE_HEADERS_SET.get_or_init(|| SENSITIVE_HEADERS_LOWER.iter().copied().collect())
}

pub fn is_sensitive_header_lower(header_lower: &str) -> bool {
    sensitive_headers_set().contains(header_lower)
}

/// Recursive sanitize for a serde_json::Value tree with the fixed
/// built-in contract only (no customer rules). Kept as the base-parity
/// entry point (parity-fixtures/sanitize_dict.yaml pins it).
pub fn sanitize_value(value: Value) -> Value {
    sanitize_value_with(value, &CompiledPiiRules::default(), None)
}

/// Recursive sanitize with customer PII rules layered on top of the
/// built-in contract:
///   - case-insensitive key matching against SENSITIVE_KEYS *plus*
///     customSensitiveKeys — the built-in set is the floor, customer
///     keys only ever add
///   - REDACTED replacement happens at the value level (the entire
///     subtree under a sensitive key is replaced, not recursed into)
///   - key-scope pattern rules replace the whole value when the key
///     name matches (hash action: string values HMAC'd; non-string
///     subtrees redact — there is no cross-language-stable subtree
///     serialization to hash)
///   - value-scope pattern rules rewrite matched substrings inside
///     string leaves, in rule declaration order (each rule scans the
///     previous rule's output); hash replaces each match with its
///     HMAC-SHA256 hex digest
///   - `action: hash` without an available secret falls back to
///     REDACTED — matched PII never ships raw
///   - non-string leaves (numbers, bools, null) are never pattern-
///     matched
///   - depth-capped at MAX_DEPTH; deeper subtrees become REDACTED
///     wholesale.
///
/// Pinned by parity-fixtures/custom_pii_rules.yaml.
pub fn sanitize_value_with(
    value: Value,
    rules: &CompiledPiiRules,
    secret: Option<&str>,
) -> Value {
    sanitize_inner(value, 0, rules, secret)
}

fn sanitize_inner(
    value: Value,
    depth: usize,
    rules: &CompiledPiiRules,
    secret: Option<&str>,
) -> Value {
    if depth > MAX_DEPTH {
        return Value::String(REDACTED.to_string());
    }
    match value {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                let key_lower = k.to_lowercase();
                if sensitive_keys_set().contains(key_lower.as_str())
                    || rules.extra_keys.contains(&key_lower)
                {
                    out.insert(k, Value::String(REDACTED.to_string()));
                } else if let Some(replacement) = key_rule_replacement(&k, &v, rules, secret) {
                    out.insert(k, replacement);
                } else if matches!(v, Value::Object(_) | Value::Array(_)) {
                    out.insert(k, sanitize_inner(v, depth + 1, rules, secret));
                } else {
                    out.insert(k, scrub_leaf(v, rules, secret));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .map(|v| {
                    if matches!(v, Value::Object(_) | Value::Array(_)) {
                        sanitize_inner(v, depth + 1, rules, secret)
                    } else {
                        scrub_leaf(v, rules, secret)
                    }
                })
                .collect(),
        ),
        other => scrub_leaf(other, rules, secret),
    }
}

/// First key-scope rule (declaration order) whose regex matches the key
/// name decides the whole value's replacement, mirroring sensitive-key
/// handling. Returns None when no key-scope rule matches.
fn key_rule_replacement(
    key: &str,
    value: &Value,
    rules: &CompiledPiiRules,
    secret: Option<&str>,
) -> Option<Value> {
    for rule in rules.patterns.iter().filter(|r| r.match_keys) {
        if !rule.regex.is_match(key) {
            continue;
        }
        let replacement = match (rule.action, value, secret) {
            (PiiAction::Hash, Value::String(s), Some(sec)) => crate::hash::hash_pii(s, sec),
            // Hash of a non-string subtree, or hash without a secret:
            // redact. Never ship raw on a matched rule.
            _ => REDACTED.to_string(),
        };
        return Some(Value::String(replacement));
    }
    None
}

/// Apply value-scope pattern rules to a string leaf. Non-string leaves
/// pass through untouched — pattern matching is defined on text only
/// (an SSN stored as a JSON *number* will not match; see README).
fn scrub_leaf(value: Value, rules: &CompiledPiiRules, secret: Option<&str>) -> Value {
    let Value::String(mut current) = value else {
        return value;
    };
    for rule in rules.patterns.iter().filter(|r| r.match_values) {
        if !rule.regex.is_match(&current) {
            continue;
        }
        current = match (rule.action, secret) {
            (PiiAction::Hash, Some(sec)) => rule
                .regex
                .replace_all(&current, |caps: &regex_lite::Captures| {
                    crate::hash::hash_pii(&caps[0], sec)
                })
                .into_owned(),
            // Redact — also the hash-without-secret fallback. REDACTED
            // contains no `$`, so plain-string replacement is safe from
            // capture-group expansion.
            _ => rule.regex.replace_all(&current, REDACTED).into_owned(),
        };
    }
    Value::String(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sensitive_key_lookup_case_insensitive() {
        let input = json!({"Password": "x", "API_KEY": "y", "username": "z"});
        let expected =
            json!({"Password": "[REDACTED]", "API_KEY": "[REDACTED]", "username": "z"});
        assert_eq!(sanitize_value(input), expected);
    }

    #[test]
    fn sensitive_header_lookup_lowercase_only() {
        // Caller must lowercase first.
        assert!(is_sensitive_header_lower("authorization"));
        assert!(is_sensitive_header_lower("cookie"));
        assert!(!is_sensitive_header_lower("user-agent"));
    }

    #[test]
    fn sensitive_header_wrong_casing_not_matched() {
        // The contract is that the caller lowercases before calling
        // is_sensitive_header_lower; non-lowercase inputs must NOT be
        // treated as sensitive (otherwise it'd hide caller bugs).
        assert!(!is_sensitive_header_lower("Authorization"));
        assert!(!is_sensitive_header_lower("AUTHORIZATION"));
        assert!(!is_sensitive_header_lower("Cookie"));
        assert!(!is_sensitive_header_lower("Set-Cookie"));
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

    // ------------------------------------------------------------------
    // Customer rules (sanitize_value_with). Cross-checked against
    // parity-fixtures/custom_pii_rules.yaml by tests/parity_runner.rs;
    // these in-crate tests cover the semantics compactly.
    // ------------------------------------------------------------------

    use crate::pii_rules::{CompiledPiiRules, PiiPatternConfig};

    fn rules(extra_keys: &[&str], patterns: &[(&str, &str, &str)]) -> CompiledPiiRules {
        let keys: Vec<String> = extra_keys.iter().map(|s| s.to_string()).collect();
        let pats: Vec<PiiPatternConfig> = patterns
            .iter()
            .map(|(pattern, action, scope)| PiiPatternConfig {
                pattern: pattern.to_string(),
                label: None,
                action: Some(action.to_string()),
                scope: Some(scope.to_string()),
            })
            .collect();
        CompiledPiiRules::compile(&keys, &pats).expect("test rules compile").0
    }

    #[test]
    fn custom_key_redacts_like_builtin() {
        let r = rules(&["member_number"], &[]);
        let input = json!({"Member_Number": "M-123", "name": "alice"});
        let expected = json!({"Member_Number": "[REDACTED]", "name": "alice"});
        assert_eq!(sanitize_value_with(input, &r, None), expected);
    }

    #[test]
    fn builtin_keys_still_redact_with_custom_rules_present() {
        let r = rules(&["member_number"], &[]);
        let input = json!({"password": "hunter2"});
        let expected = json!({"password": "[REDACTED]"});
        assert_eq!(sanitize_value_with(input, &r, None), expected);
    }

    #[test]
    fn value_pattern_redacts_substring_in_free_text() {
        let r = rules(&[], &[(r"\b\d{3}-\d{2}-\d{4}\b", "redact", "values")]);
        let input = json!({"note": "ssn is 123-45-6789, call me"});
        let expected = json!({"note": "ssn is [REDACTED], call me"});
        assert_eq!(sanitize_value_with(input, &r, None), expected);
    }

    #[test]
    fn value_pattern_reaches_nested_arrays() {
        let r = rules(&[], &[(r"\b\d{3}-\d{2}-\d{4}\b", "redact", "values")]);
        let input = json!({"messages": [{"content": "my ssn: 123-45-6789"}, "078-05-1120"]});
        let expected =
            json!({"messages": [{"content": "my ssn: [REDACTED]"}, "[REDACTED]"]});
        assert_eq!(sanitize_value_with(input, &r, None), expected);
    }

    #[test]
    fn value_pattern_hash_replaces_each_match_with_digest() {
        let r = rules(&[], &[(r"\b\d{3}-\d{2}-\d{4}\b", "hash", "values")]);
        let input = json!({"note": "id 123-45-6789 end"});
        let out = sanitize_value_with(input, &r, Some("s3cret"));
        let expected_digest = crate::hash::hash_pii("123-45-6789", "s3cret");
        assert_eq!(out["note"], format!("id {expected_digest} end"));
    }

    #[test]
    fn hash_without_secret_falls_back_to_redact() {
        let r = rules(&[], &[(r"\d{3}-\d{2}-\d{4}", "hash", "values")]);
        let input = json!({"note": "123-45-6789"});
        let expected = json!({"note": "[REDACTED]"});
        assert_eq!(sanitize_value_with(input, &r, None), expected);
    }

    #[test]
    fn key_scope_replaces_whole_value_not_substrings() {
        let r = rules(&[], &[("internal_id", "redact", "keys")]);
        let input = json!({"x_internal_id": "abc-123", "note": "internal_id mentioned"});
        // Key match → whole value replaced; value text untouched by a
        // keys-scope rule.
        let expected =
            json!({"x_internal_id": "[REDACTED]", "note": "internal_id mentioned"});
        assert_eq!(sanitize_value_with(input, &r, None), expected);
    }

    #[test]
    fn key_scope_hash_hashes_string_value_redacts_subtree() {
        let r = rules(&[], &[("^account_ref$", "hash", "keys")]);
        let input = json!({"account_ref": "AR-9", "nested": {"account_ref": {"a": 1}}});
        let out = sanitize_value_with(input, &r, Some("s3cret"));
        assert_eq!(out["account_ref"], crate::hash::hash_pii("AR-9", "s3cret"));
        // Non-string value under a hash rule: redact (no stable
        // cross-language subtree serialization to hash).
        assert_eq!(out["nested"]["account_ref"], "[REDACTED]");
    }

    #[test]
    fn both_scope_matches_keys_and_values() {
        let r = rules(&[], &[("secretish", "redact", "both")]);
        let input = json!({"secretish_field": "v", "note": "very secretish text"});
        let expected = json!({"secretish_field": "[REDACTED]", "note": "very [REDACTED] text"});
        assert_eq!(sanitize_value_with(input, &r, None), expected);
    }

    #[test]
    fn non_string_leaves_never_pattern_matched() {
        let r = rules(&[], &[(r"\d+", "redact", "values")]);
        let input = json!({"count": 123456789, "flag": true, "nil": null});
        // Numbers/bools/null pass through — patterns are text-only.
        assert_eq!(sanitize_value_with(input.clone(), &r, None), input);
    }

    #[test]
    fn builtin_key_redaction_wins_over_pattern_rules() {
        // A sensitive key's value is replaced wholesale before any
        // pattern rule sees it — customer rules layer on top of the
        // floor, never interleave with it.
        let r = rules(&[], &[(r"hunter\d", "hash", "values")]);
        let input = json!({"password": "hunter2"});
        let expected = json!({"password": "[REDACTED]"});
        assert_eq!(sanitize_value_with(input, &r, Some("s3cret")), expected);
    }

    #[test]
    fn rules_apply_to_query_param_shaped_maps() {
        // Query params sanitize through the same path as bodies —
        // single-valued params are strings, multi-valued are arrays.
        let r = rules(&["customer_ref"], &[(r"\b\d{3}-\d{2}-\d{4}\b", "redact", "values")]);
        let input = json!({"customer_ref": "c-1", "q": "ssn:123-45-6789", "multi": ["078-05-1120", "ok"]});
        let expected = json!({"customer_ref": "[REDACTED]", "q": "ssn:[REDACTED]", "multi": ["[REDACTED]", "ok"]});
        assert_eq!(sanitize_value_with(input, &r, None), expected);
    }
}
