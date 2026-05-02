// Cross-implementation parity test runner.
//
// Reads YAML fixtures from ../parity-fixtures/ (sibling to this crate
// at the repo root) and asserts that this crate's sanitization
// primitives produce the same outputs as the other Cerberus
// implementations.
//
// `make sync-fixtures` creates `tests/fixtures -> ../../parity-fixtures`,
// which lets this file reference the fixtures via a stable relative path
// even when `cargo test` is run from a workspace root.
//
// These tests detect drift between the various Cerberus implementations
// of the shared sanitization contract.
//
// See parity-fixtures/README.md for the fixture format.

use std::path::PathBuf;

use serde::Deserialize;

use cerberus_flex_gateway::__test_exports::{
    content_type_is_json, hash_pii, is_sensitive_header_lower, normalize_ip, sanitize_value,
    PathFilter,
};

fn fixtures_dir() -> PathBuf {
    // Prefer the symlink populated by `make sync-fixtures`; fall back
    // to walking up from CARGO_MANIFEST_DIR for direct `cargo test` runs
    // outside the Makefile's lifecycle.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let symlinked = manifest.join("tests").join("fixtures");
    if symlinked.exists() {
        return symlinked;
    }
    manifest.parent().unwrap().join("parity-fixtures")
}

fn load<T: for<'de> Deserialize<'de>>(filename: &str) -> Vec<T> {
    let path = fixtures_dir().join(filename);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing fixture {}: {}", path.display(), e));
    let doc: FixtureDoc<T> = serde_yaml::from_str(&text)
        .unwrap_or_else(|e| panic!("malformed fixture {}: {}", path.display(), e));
    doc.cases
}

#[derive(Deserialize)]
struct FixtureDoc<T> {
    cases: Vec<T>,
}

// ============================================================================
// sanitize_dict
// ============================================================================

#[derive(Deserialize)]
struct SanitizeCase {
    name: String,
    input: serde_json::Value,
    expected: serde_json::Value,
}

#[test]
fn parity_sanitize_dict() {
    let cases: Vec<SanitizeCase> = load("sanitize_dict.yaml");
    for case in cases {
        let actual = sanitize_value(case.input.clone());
        assert_eq!(
            actual, case.expected,
            "case {:?}: got {:?}, expected {:?}",
            case.name, actual, case.expected
        );
    }
}

// ============================================================================
// normalize_ip
// ============================================================================

#[derive(Deserialize)]
struct NormalizeIpCase {
    name: String,
    input: Option<String>,
    expected: Option<String>,
}

#[test]
fn parity_normalize_ip() {
    let cases: Vec<NormalizeIpCase> = load("normalize_ip.yaml");
    for case in cases {
        // Python's normalize_ip(None) → None. Rust port deals in &str
        // so the None case is handled at the call site (lib.rs); for
        // the parity runner we treat null as "skip — not applicable".
        let Some(input) = case.input.as_deref() else {
            assert!(
                case.expected.is_none(),
                "case {:?}: null input must have null expected",
                case.name
            );
            continue;
        };
        let actual = normalize_ip(input);
        let expected = case.expected.clone().unwrap_or_default();
        assert_eq!(
            actual, expected,
            "case {:?}: got {:?}, expected {:?}",
            case.name, actual, expected
        );
    }
}

// ============================================================================
// hash_pii
// ============================================================================

#[derive(Deserialize)]
struct HashPiiInput {
    value: Option<String>,
    secret_key: String,
}

#[derive(Deserialize)]
struct HashPiiCase {
    name: String,
    input: HashPiiInput,
    expected: Option<String>,
}

#[test]
fn parity_hash_pii() {
    let cases: Vec<HashPiiCase> = load("hash_pii.yaml");
    for case in cases {
        match (&case.input.value, &case.expected) {
            (None, None) => {
                // The Rust port doesn't expose a None input — the call
                // site short-circuits. Nothing to assert here; skip.
            }
            (Some(value), Some(expected)) => {
                let actual = hash_pii(value, &case.input.secret_key);
                assert_eq!(
                    &actual, expected,
                    "case {:?}: got {:?}, expected {:?}",
                    case.name, actual, expected
                );
            }
            _ => panic!(
                "case {:?}: malformed fixture (input/expected null mismatch)",
                case.name
            ),
        }
    }
}

// ============================================================================
// content_type
// ============================================================================

#[derive(Deserialize)]
struct ContentTypeCase {
    name: String,
    content_type: String,
    expected_capture: bool,
}

#[test]
fn parity_content_type() {
    let cases: Vec<ContentTypeCase> = load("content_type.yaml");
    for case in cases {
        let actual = content_type_is_json(Some(&case.content_type));
        assert_eq!(
            actual, case.expected_capture,
            "case {:?}: matches={}, expected={}",
            case.name, actual, case.expected_capture
        );
    }
}

// ============================================================================
// sensitive_headers
// ============================================================================

#[derive(Deserialize)]
struct SensitiveHeaderCase {
    name: String,
    header: String,
    expected_sensitive: bool,
}

/// Translate Python's WSGI key form (`HTTP_X_API_KEY`) to the wire-form
/// the Rust sanitizer sees from Envoy (`x-api-key`). Returns None for
/// inputs that aren't in canonical Python WSGI form — those test
/// Python-specific encoding quirks and don't translate to Rust.
fn python_wsgi_to_wire_name(s: &str) -> Option<String> {
    let rest = s.strip_prefix("HTTP_")?;
    if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
        return None;
    }
    Some(rest.to_ascii_lowercase().replace('_', "-"))
}

#[test]
fn parity_sensitive_headers() {
    let cases: Vec<SensitiveHeaderCase> = load("sensitive_headers.yaml");
    let mut covered = 0;
    for case in cases {
        // Skip cases that exercise Python's WSGI-encoding casing quirks
        // (e.g. lowercase `http_authorization`, bare `AUTHORIZATION`).
        // The shared contract is "is this header name in the sensitive
        // set"; the encoding layer is per-implementation.
        let Some(rust_form) = python_wsgi_to_wire_name(&case.header) else {
            continue;
        };
        let actual = is_sensitive_header_lower(&rust_form);
        assert_eq!(
            actual, case.expected_sensitive,
            "case {:?}: header={:?} (rust form {:?}) sensitive={}, expected={}",
            case.name, case.header, rust_form, actual, case.expected_sensitive
        );
        covered += 1;
    }
    // Sanity check: don't silently turn into a no-op if all cases get
    // skipped by the translator.
    assert!(covered > 0, "no sensitive_headers cases survived translation");
}

// ============================================================================
// path_filter (Rust-only — no Python equivalent)
// ============================================================================

#[derive(Deserialize)]
struct PathFilterCase {
    name: String,
    endpoint: String,
    capture_paths: Vec<String>,
    exclude_paths: Vec<String>,
    expected: bool,
}

#[test]
fn parity_path_filter() {
    let cases: Vec<PathFilterCase> = load("path_filter.yaml");
    for case in cases {
        let pf = PathFilter::compile(&case.capture_paths, &case.exclude_paths)
            .unwrap_or_else(|e| panic!("case {:?}: glob compile failed: {}", case.name, e));
        let actual = pf.should_capture(&case.endpoint);
        assert_eq!(
            actual, case.expected,
            "case {:?}: got {}, expected {}",
            case.name, actual, case.expected
        );
    }
}

// Header iteration / multi-value handling and full event JSON round-trips
// are not covered by parity-fixtures/ — they require harness state that
// only PDK's UnitTestBuilder provides. Add them under
// tests/integration/*.rs alongside other PDK integration tests once
// `make build` produces a usable .wasm.
