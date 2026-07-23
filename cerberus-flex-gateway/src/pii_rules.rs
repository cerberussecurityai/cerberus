// Customer-configurable PII scrubbing rules.
//
// Two config surfaces (definition/gcl.yaml):
//   * customSensitiveKeys — extra key names (case-insensitive) redacted
//     everywhere sanitization runs. Additive to the built-in
//     SENSITIVE_KEYS floor; customer rules can never *remove* a
//     built-in redaction.
//   * customPiiPatterns — regex rules applied to query params and JSON
//     bodies. `scope: values` rules rewrite matched substrings inside
//     string leaves (an SSN inside a free-text note); `scope: keys`
//     rules match key *names* and replace the entire value, like a
//     sensitive key. `action: hash` HMAC-SHA256s instead of redacting
//     so stable identifiers keep analytics value.
//
// Rules are compiled exactly once at policy load (`configure` →
// `PolicyContext::new`). Compilation is strict: an invalid pattern,
// action, or scope fails policy load with a descriptive error rather
// than silently not scrubbing — a typo'd rule that "loads anyway"
// is a PII leak the operator explicitly tried to prevent.
//
// Patterns compile case-insensitively by default (a PII net that
// misses `SSN` because the rule said `ssn` fails the fail-safe test);
// authors can opt out per-pattern with an inline `(?-i)`.

use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use regex_lite::{Regex, RegexBuilder};
use serde::Deserialize;

/// Compiled-pattern memory bound. regex-lite guarantees linear-time
/// matching, so the remaining resource risk is a pathological pattern
/// compiling to a huge program — cap it well below the crate default.
const PATTERN_SIZE_LIMIT: usize = 1 << 20; // 1 MiB

/// One `customPiiPatterns` entry as deserialized from policy config.
/// `action` / `scope` stay raw strings here and are validated in
/// `CompiledPiiRules::compile` — serde enums would reject an empty
/// string (which UI form fields may submit for "unset") and produce
/// worse error messages than the explicit match below.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PiiPatternConfig {
    /// Regex (regex-lite flavor: linear-time, ASCII-only `\d`/`\w`/`\s`).
    pub pattern: String,
    /// Optional human-readable name, used in startup logs and error
    /// messages only — never in event output.
    #[serde(default)]
    pub label: Option<String>,
    /// "redact" (default) or "hash".
    #[serde(default)]
    pub action: Option<String>,
    /// "values" (default), "keys", or "both".
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiAction {
    Redact,
    Hash,
}

#[derive(Debug)]
pub struct CompiledPattern {
    pub regex: Regex,
    pub action: PiiAction,
    pub match_keys: bool,
    pub match_values: bool,
    /// Retained for startup logging.
    #[allow(dead_code)]
    pub label: Option<String>,
}

/// The compiled rule set threaded through sanitization. `Default` is
/// the empty set — behavior identical to the fixed built-in contract.
#[derive(Debug, Default)]
pub struct CompiledPiiRules {
    /// Lowercased extra sensitive key names.
    pub extra_keys: HashSet<String>,
    /// In declaration order — value-scope rules apply sequentially,
    /// each scanning the previous rule's output.
    pub patterns: Vec<CompiledPattern>,
}

impl CompiledPiiRules {
    /// Compile config into the runtime rule set. Returns the rules plus
    /// non-fatal warnings for the caller to log (this module stays free
    /// of the pdk logger so it's testable outside the proxy-wasm host).
    pub fn compile(
        extra_keys: &[String],
        patterns: &[PiiPatternConfig],
    ) -> Result<(Self, Vec<String>)> {
        let mut warnings = Vec::new();

        let mut keys = HashSet::with_capacity(extra_keys.len());
        let mut blank_keys = 0usize;
        for key in extra_keys {
            let trimmed = key.trim();
            if trimmed.is_empty() {
                blank_keys += 1;
                continue;
            }
            keys.insert(trimmed.to_lowercase());
        }
        if blank_keys > 0 {
            // Unlike captureHeaders (where blank-collapse fails open),
            // a dropped blank key just means one less redaction — but
            // it still signals a templating bug worth surfacing.
            warnings.push(format!(
                "customSensitiveKeys: ignored {blank_keys} blank entr{}",
                if blank_keys == 1 { "y" } else { "ies" }
            ));
        }

        let mut compiled = Vec::with_capacity(patterns.len());
        for (i, p) in patterns.iter().enumerate() {
            // Identify the rule in errors by label when given, else by
            // 1-based position — matching the config the operator wrote.
            let display = match p.label.as_deref().map(str::trim) {
                Some(label) if !label.is_empty() => format!("\"{label}\""),
                _ => format!("#{}", i + 1),
            };

            if p.pattern.trim().is_empty() {
                bail!("customPiiPatterns rule {display}: pattern is empty");
            }
            let regex = RegexBuilder::new(&p.pattern)
                .case_insensitive(true)
                .size_limit(PATTERN_SIZE_LIMIT)
                .build()
                .with_context(|| {
                    format!("customPiiPatterns rule {display}: invalid pattern")
                })?;

            let action = match p.action.as_deref().map(str::trim) {
                None | Some("") => PiiAction::Redact,
                Some(s) if s.eq_ignore_ascii_case("redact") => PiiAction::Redact,
                Some(s) if s.eq_ignore_ascii_case("hash") => PiiAction::Hash,
                Some(other) => bail!(
                    "customPiiPatterns rule {display}: unknown action {other:?} (expected \"redact\" or \"hash\")"
                ),
            };
            let (match_keys, match_values) = match p.scope.as_deref().map(str::trim) {
                None | Some("") => (false, true),
                Some(s) if s.eq_ignore_ascii_case("values") => (false, true),
                Some(s) if s.eq_ignore_ascii_case("keys") => (true, false),
                Some(s) if s.eq_ignore_ascii_case("both") => (true, true),
                Some(other) => bail!(
                    "customPiiPatterns rule {display}: unknown scope {other:?} (expected \"keys\", \"values\", or \"both\")"
                ),
            };

            compiled.push(CompiledPattern {
                regex,
                action,
                match_keys,
                match_values,
                label: p.label.clone(),
            });
        }

        Ok((
            Self {
                extra_keys: keys,
                patterns: compiled,
            },
            warnings,
        ))
    }

    pub fn is_empty(&self) -> bool {
        self.extra_keys.is_empty() && self.patterns.is_empty()
    }

    /// Whether any rule wants HMAC hashing — used at startup to warn
    /// when no secret is available (hash falls back to redact).
    pub fn has_hash_action(&self) -> bool {
        self.patterns.iter().any(|p| p.action == PiiAction::Hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(p: &str, action: Option<&str>, scope: Option<&str>) -> PiiPatternConfig {
        PiiPatternConfig {
            pattern: p.to_string(),
            label: None,
            action: action.map(String::from),
            scope: scope.map(String::from),
        }
    }

    #[test]
    fn empty_config_compiles_to_empty_rules() {
        let (rules, warnings) = CompiledPiiRules::compile(&[], &[]).unwrap();
        assert!(rules.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn extra_keys_trimmed_lowercased_blanks_warned() {
        let keys = vec![
            "  Member_Number ".to_string(),
            "".to_string(),
            "   ".to_string(),
        ];
        let (rules, warnings) = CompiledPiiRules::compile(&keys, &[]).unwrap();
        assert!(rules.extra_keys.contains("member_number"));
        assert_eq!(rules.extra_keys.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("2 blank entries"), "{}", warnings[0]);
    }

    #[test]
    fn defaults_are_redact_values() {
        let (rules, _) =
            CompiledPiiRules::compile(&[], &[pattern(r"\d{3}", None, None)]).unwrap();
        let p = &rules.patterns[0];
        assert_eq!(p.action, PiiAction::Redact);
        assert!(p.match_values && !p.match_keys);
    }

    #[test]
    fn action_and_scope_parse_case_insensitively() {
        let (rules, _) = CompiledPiiRules::compile(
            &[],
            &[pattern(r"x", Some("HASH"), Some("Both"))],
        )
        .unwrap();
        let p = &rules.patterns[0];
        assert_eq!(p.action, PiiAction::Hash);
        assert!(p.match_values && p.match_keys);
    }

    #[test]
    fn empty_action_and_scope_fall_back_to_defaults() {
        // UI form fields may submit "" for unset — must not fail load.
        let (rules, _) =
            CompiledPiiRules::compile(&[], &[pattern(r"x", Some(""), Some(" "))]).unwrap();
        let p = &rules.patterns[0];
        assert_eq!(p.action, PiiAction::Redact);
        assert!(p.match_values && !p.match_keys);
    }

    #[test]
    fn invalid_regex_fails_compile() {
        let err = CompiledPiiRules::compile(&[], &[pattern(r"([unclosed", None, None)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("rule #1"), "{err}");
    }

    #[test]
    fn unknown_action_fails_compile_with_label() {
        let mut p = pattern(r"x", Some("redakt"), None);
        p.label = Some("ssn".to_string());
        let err = CompiledPiiRules::compile(&[], &[p]).unwrap_err().to_string();
        assert!(err.contains("\"ssn\""), "{err}");
        assert!(err.contains("redakt"), "{err}");
    }

    #[test]
    fn unknown_scope_fails_compile() {
        let err = CompiledPiiRules::compile(&[], &[pattern(r"x", None, Some("value"))])
            .unwrap_err()
            .to_string();
        assert!(err.contains("scope"), "{err}");
    }

    #[test]
    fn empty_pattern_fails_compile() {
        let err = CompiledPiiRules::compile(&[], &[pattern("  ", None, None)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("pattern is empty"), "{err}");
    }

    #[test]
    fn patterns_match_case_insensitively_by_default() {
        let (rules, _) = CompiledPiiRules::compile(&[], &[pattern("ssn", None, None)]).unwrap();
        assert!(rules.patterns[0].regex.is_match("my SSN is here"));
    }

    #[test]
    fn inline_flag_opts_out_of_case_insensitivity() {
        let (rules, _) =
            CompiledPiiRules::compile(&[], &[pattern("(?-i)ssn", None, None)]).unwrap();
        assert!(rules.patterns[0].regex.is_match("ssn"));
        assert!(!rules.patterns[0].regex.is_match("SSN"));
    }

    #[test]
    fn has_hash_action_detects_hash_rules() {
        let (rules, _) = CompiledPiiRules::compile(
            &[],
            &[
                pattern(r"a", None, None),
                pattern(r"b", Some("hash"), None),
            ],
        )
        .unwrap();
        assert!(rules.has_hash_action());
        let (rules, _) =
            CompiledPiiRules::compile(&[], &[pattern(r"a", None, None)]).unwrap();
        assert!(!rules.has_hash_action());
    }
}
