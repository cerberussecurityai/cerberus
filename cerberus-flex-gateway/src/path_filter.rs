// Glob-based capturePaths / excludePaths filter.
//
// Compiled once in lib.rs::configure (per-worker), then queried per-
// request — designed to be the cheapest possible early-exit so policies
// can scope themselves to business-relevant endpoints in high-RPS
// deployments without buffering or sanitizing the bypassed traffic.
//
// Rules (per flex_gateway_plan.md §0 row 13 + §2.3):
//   1. Empty capture_paths → match anything.
//   2. Non-empty capture_paths → only matches generate events.
//   3. Non-empty exclude_paths → matches are skipped.
//   4. exclude_paths wins over capture_paths on overlap.
//
// Health endpoints (/health, /health_check, /ready) are filtered
// OUTSIDE this struct in lib.rs::request_filter; not this module's
// concern.

use anyhow::Result;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

pub struct PathFilter {
    capture: Option<GlobSet>,
    exclude: Option<GlobSet>,
}

impl PathFilter {
    pub fn compile(capture_paths: &[String], exclude_paths: &[String]) -> Result<Self> {
        let capture = build_globset(capture_paths)?;
        let exclude = build_globset(exclude_paths)?;
        Ok(Self { capture, exclude })
    }

    pub fn should_capture(&self, endpoint: &str) -> bool {
        if let Some(set) = &self.exclude {
            if set.is_match(endpoint) {
                return false;
            }
        }
        match &self.capture {
            Some(set) => set.is_match(endpoint),
            None => true,
        }
    }
}

fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        // literal_separator(true) makes `*` match a single segment only.
        // Without it, `/users/*` matches `/users/alice/profile`, which
        // breaks the path-scoping semantics documented in
        // parity-fixtures/path_filter.yaml. `**` still matches across
        // segments — that's the standard globset behavior either way.
        let glob = GlobBuilder::new(p).literal_separator(true).build()?;
        builder.add(glob);
    }
    Ok(Some(builder.build()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pf(capture: &[&str], exclude: &[&str]) -> PathFilter {
        let cap: Vec<String> = capture.iter().map(|s| s.to_string()).collect();
        let exc: Vec<String> = exclude.iter().map(|s| s.to_string()).collect();
        PathFilter::compile(&cap, &exc).unwrap()
    }

    #[test]
    fn empty_filters_capture_everything() {
        let f = pf(&[], &[]);
        assert!(f.should_capture("/anything"));
        assert!(f.should_capture("/api/v1/users/42"));
    }

    #[test]
    fn allowlist_match() {
        let f = pf(&["/api/**"], &[]);
        assert!(f.should_capture("/api/v1/users"));
        assert!(!f.should_capture("/admin/dashboard"));
    }

    #[test]
    fn denylist_match() {
        let f = pf(&[], &["/internal/**"]);
        assert!(f.should_capture("/api/v1/users"));
        assert!(!f.should_capture("/internal/debug"));
    }

    #[test]
    fn exclude_wins_over_capture() {
        let f = pf(&["/api/**"], &["/api/internal/**"]);
        assert!(f.should_capture("/api/v1/users"));
        assert!(!f.should_capture("/api/internal/secret"));
    }
}
