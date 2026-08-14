// Response-body capture: head+tail byte accumulation and event-shape
// finalization.
//
// The gateway never parses SSE framing or provider JSON on the response
// path — it counts bytes. A response body streams through the policy
// chunk by chunk (pass-through, never buffered or delayed); this module
// retains the first `responseHeadBytes` of the stream plus a rolling
// ring of the last `responseTailBytes`. At end-of-stream, a body that
// fit entirely within head + tail is reconstructed exactly and shipped
// whole (JSON parsed + sanitized like a request body; SSE as a
// pattern-scrubbed string). A larger body ships as head/tail slices
// with explicit truncation markers so truncation is never silent.
//
// Everything here is pure and unit-tested in-module; the stream plumbing
// lives in lib.rs (`capture_response_body`).

use serde_json::Value;

use crate::pii_rules::CompiledPiiRules;
use crate::sanitize::sanitize_value_with;

// Marker key names are wire contract — the ingest consumer matches these
// strings exactly, and they mirror the cerberus-django agent's response
// capture. Do not rename.
pub const KEY_SKIPPED_ENCODING: &str = "body_skipped_encoding";
pub const KEY_TRUNCATED: &str = "body_truncated";
pub const KEY_BYTES_TOTAL: &str = "body_bytes_total";
pub const KEY_BYTES_DROPPED: &str = "body_bytes_dropped";
pub const KEY_HEAD: &str = "head";
pub const KEY_TAIL: &str = "tail";

/// Response content types the policy observes. Anything else is skipped
/// before the body stream is even opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseContentKind {
    Json,
    Sse,
}

/// Classify a response Content-Type header. `Json` reuses the request
/// side's substring test (`application/json`, case-insensitive —
/// `application/vnd.api+json` stays excluded, pinned by
/// parity-fixtures/content_type.yaml). `Sse` is a case-insensitive
/// `text/event-stream` substring match.
pub fn classify_content_type(content_type: Option<&str>) -> Option<ResponseContentKind> {
    if crate::content_type_is_json(content_type) {
        return Some(ResponseContentKind::Json);
    }
    let ct = content_type?;
    if ct.to_ascii_lowercase().contains("text/event-stream") {
        return Some(ResponseContentKind::Sse);
    }
    None
}

/// The compression-gate marker: `{"body_skipped_encoding": "<enc>"}`.
/// Slices of a compressed stream are undecodable at any layer, so
/// compressed bodies are never sliced (the caller skips the body stream
/// entirely).
pub fn skipped_encoding_marker(encoding_lower: &str) -> Value {
    let mut m = serde_json::Map::with_capacity(1);
    m.insert(
        KEY_SKIPPED_ENCODING.to_string(),
        Value::String(encoding_lower.to_string()),
    );
    Value::Object(m)
}

/// Rolling ring of the last `cap` bytes pushed.
struct TailRing {
    buf: Vec<u8>,
    cap: usize,
    /// Next write index — only meaningful once `buf.len() == cap`; it
    /// then also marks the oldest byte.
    write: usize,
}

impl TailRing {
    fn new(cap: usize) -> Self {
        Self {
            // Lazily grown to `cap` — empty bodies never allocate.
            buf: Vec::new(),
            cap,
            write: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        if self.cap == 0 || bytes.is_empty() {
            return;
        }
        // Only the last `cap` bytes of the input can survive.
        let src = if bytes.len() >= self.cap {
            &bytes[bytes.len() - self.cap..]
        } else {
            bytes
        };
        if self.buf.len() < self.cap {
            let take = (self.cap - self.buf.len()).min(src.len());
            self.buf.extend_from_slice(&src[..take]);
            let rest = &src[take..];
            if rest.is_empty() {
                return;
            }
            // Ring just filled; remaining bytes wrap to the start.
            self.write = 0;
            self.copy_wrapping(rest);
        } else {
            self.copy_wrapping(src);
        }
    }

    /// Overwrite starting at `write`, wrapping once. `buf.len() == cap`
    /// and `src.len() <= cap` hold here.
    fn copy_wrapping(&mut self, src: &[u8]) {
        let first = (self.cap - self.write).min(src.len());
        self.buf[self.write..self.write + first].copy_from_slice(&src[..first]);
        let rest = &src[first..];
        if rest.is_empty() {
            self.write = (self.write + first) % self.cap;
        } else {
            self.buf[..rest.len()].copy_from_slice(rest);
            self.write = rest.len();
        }
    }

    /// Retained bytes in arrival order.
    fn into_vec(self) -> Vec<u8> {
        if self.buf.len() < self.cap {
            return self.buf;
        }
        let mut out = Vec::with_capacity(self.cap);
        out.extend_from_slice(&self.buf[self.write..]);
        out.extend_from_slice(&self.buf[..self.write]);
        out
    }
}

/// Head buffer + tail ring + total byte counter. Memory is capped at
/// `head_cap + tail_cap` regardless of body size.
pub struct HeadTailAccumulator {
    head: Vec<u8>,
    head_cap: usize,
    tail: TailRing,
    total: u64,
}

/// Outcome of accumulating a full body stream.
pub enum AccumulatedBody {
    /// No bytes arrived.
    Empty,
    /// `total <= head_cap + tail_cap`: head ++ tail reconstructs the
    /// original bytes exactly.
    Complete(Vec<u8>),
    /// Body exceeded the budget; the middle was discarded as it streamed.
    Truncated {
        total: u64,
        head: Vec<u8>,
        tail: Vec<u8>,
    },
}

impl HeadTailAccumulator {
    pub fn new(head_cap: usize, tail_cap: usize) -> Self {
        Self {
            head: Vec::new(),
            head_cap,
            tail: TailRing::new(tail_cap),
            total: 0,
        }
    }

    /// O(chunk). Empty chunks are no-ops.
    pub fn push(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        self.total += chunk.len() as u64;
        let take = (self.head_cap - self.head.len()).min(chunk.len());
        self.head.extend_from_slice(&chunk[..take]);
        self.tail.push(&chunk[take..]);
    }

    pub fn finalize(self) -> AccumulatedBody {
        if self.total == 0 {
            return AccumulatedBody::Empty;
        }
        let mut head = self.head;
        let tail = self.tail.into_vec();
        if self.total == (head.len() + tail.len()) as u64 {
            head.extend_from_slice(&tail);
            AccumulatedBody::Complete(head)
        } else {
            AccumulatedBody::Truncated {
                total: self.total,
                head,
                tail,
            }
        }
    }
}

/// Run customer `customPiiPatterns` value rules over a raw text slice.
/// A root-level string falls through `sanitize_value_with` to the
/// scrub-leaf path, so value-scope rules apply with no dedicated scrub
/// code. Key-based redaction cannot apply to unparsed text — the
/// documented sanitize asymmetry for truncated slices and raw SSE.
fn scrub_text(text: String, rules: &CompiledPiiRules, secret: Option<&str>) -> String {
    match sanitize_value_with(Value::String(text), rules, secret) {
        Value::String(out) => out,
        // sanitize preserves string → string at the root.
        other => other.to_string(),
    }
}

fn scrub_lossy(bytes: &[u8], rules: &CompiledPiiRules, secret: Option<&str>) -> String {
    scrub_text(String::from_utf8_lossy(bytes).into_owned(), rules, secret)
}

/// Turn an accumulated body into the event's `response_body` value.
///
/// - `Empty` → `None`.
/// - `Complete` + parses as a JSON object/array → AI-shape suppression
///   check first (prompt-echoing responses on custom paths), else full
///   sanitize — identical treatment to the request side.
/// - `Complete` + parse failure or bare primitive → SSE ships as one
///   pattern-scrubbed string; JSON kinds are discarded (mirrors the
///   Django agent).
/// - `Truncated` → explicit marker with lossy-decoded, pattern-scrubbed
///   head/tail slices.
pub fn finalize_response_body(
    outcome: AccumulatedBody,
    kind: ResponseContentKind,
    endpoint: &str,
    capture_ai_content: bool,
    rules: &CompiledPiiRules,
    secret: Option<&str>,
) -> Option<Value> {
    match outcome {
        AccumulatedBody::Empty => None,
        AccumulatedBody::Complete(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(parsed @ (Value::Object(_) | Value::Array(_))) => {
                if !capture_ai_content
                    && crate::ai_content::should_suppress_body(endpoint, &parsed)
                {
                    None
                } else {
                    Some(sanitize_value_with(parsed, rules, secret))
                }
            }
            _ => match kind {
                ResponseContentKind::Sse => {
                    Some(Value::String(scrub_lossy(&bytes, rules, secret)))
                }
                ResponseContentKind::Json => None,
            },
        },
        AccumulatedBody::Truncated { total, head, tail } => {
            let dropped = total - (head.len() + tail.len()) as u64;
            let mut m = serde_json::Map::with_capacity(5);
            m.insert(KEY_TRUNCATED.to_string(), Value::Bool(true));
            m.insert(KEY_BYTES_TOTAL.to_string(), Value::from(total));
            m.insert(KEY_BYTES_DROPPED.to_string(), Value::from(dropped));
            m.insert(
                KEY_HEAD.to_string(),
                Value::String(scrub_lossy(&head, rules, secret)),
            );
            m.insert(
                KEY_TAIL.to_string(),
                Value::String(scrub_lossy(&tail, rules, secret)),
            );
            Some(Value::Object(m))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pii_rules::{CompiledPiiRules, PiiPatternConfig};
    use serde_json::json;

    fn no_rules() -> CompiledPiiRules {
        CompiledPiiRules::default()
    }

    fn accumulate(head_cap: usize, tail_cap: usize, chunks: &[&[u8]]) -> AccumulatedBody {
        let mut acc = HeadTailAccumulator::new(head_cap, tail_cap);
        for c in chunks {
            acc.push(c);
        }
        acc.finalize()
    }

    fn expect_truncated(outcome: AccumulatedBody) -> (u64, Vec<u8>, Vec<u8>) {
        match outcome {
            AccumulatedBody::Truncated { total, head, tail } => (total, head, tail),
            AccumulatedBody::Complete(_) => panic!("expected Truncated, got Complete"),
            AccumulatedBody::Empty => panic!("expected Truncated, got Empty"),
        }
    }

    // ---------------- accumulator ----------------

    #[test]
    fn empty_input_finalizes_empty() {
        assert!(matches!(accumulate(4, 4, &[]), AccumulatedBody::Empty));
        // Empty chunks are no-ops, not bytes.
        assert!(matches!(
            accumulate(4, 4, &[b"", b"", b""]),
            AccumulatedBody::Empty
        ));
    }

    #[test]
    fn exact_fit_boundary_is_complete() {
        // total == head_cap + tail_cap → Complete, exact reconstruction.
        let out = accumulate(4, 4, &[b"abcd", b"efgh"]);
        match out {
            AccumulatedBody::Complete(bytes) => assert_eq!(bytes, b"abcdefgh"),
            _ => panic!("expected Complete at the exact-fit boundary"),
        }
    }

    #[test]
    fn one_over_budget_truncates_with_one_dropped() {
        let (total, head, tail) = expect_truncated(accumulate(4, 4, &[b"abcdefghi"]));
        assert_eq!(total, 9);
        assert_eq!(head, b"abcd");
        assert_eq!(tail, b"fghi");
        assert_eq!(total - (head.len() + tail.len()) as u64, 1);
    }

    #[test]
    fn tail_ring_wraparound_many_small_pushes() {
        // 1–3-byte pushes force the ring through several wraparounds.
        let data = b"0123456789abcdefghij"; // 20 bytes
        let mut acc = HeadTailAccumulator::new(3, 5);
        let mut i = 0;
        let mut step = 1;
        while i < data.len() {
            let end = (i + step).min(data.len());
            acc.push(&data[i..end]);
            i = end;
            step = step % 3 + 1;
        }
        let (total, head, tail) = expect_truncated(acc.finalize());
        assert_eq!(total, 20);
        assert_eq!(head, b"012");
        assert_eq!(tail, b"fghij");
    }

    #[test]
    fn single_chunk_larger_than_both_caps() {
        let (total, head, tail) =
            expect_truncated(accumulate(2, 3, &[b"the quick brown fox"]));
        assert_eq!(total, 19);
        assert_eq!(head, b"th");
        assert_eq!(tail, b"fox");
    }

    #[test]
    fn complete_reconstruction_across_chunk_sizes() {
        // Whatever the chunking, an in-budget body reconstructs exactly.
        let data = b"abcdefghijklmno"; // 15 bytes, budget 8+8
        for chunk_size in 1..=15 {
            let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
            match accumulate(8, 8, &chunks) {
                AccumulatedBody::Complete(bytes) => assert_eq!(bytes, data),
                _ => panic!("chunk_size {chunk_size}: expected Complete"),
            }
        }
    }

    #[test]
    fn zero_budgets_yield_empty_slices_marker() {
        // "Response size telemetry" mode: nothing retained, counts kept.
        let (total, head, tail) = expect_truncated(accumulate(0, 0, &[b"hello"]));
        assert_eq!(total, 5);
        assert!(head.is_empty());
        assert!(tail.is_empty());
    }

    #[test]
    fn zero_tail_budget_keeps_head_only() {
        let (total, head, tail) = expect_truncated(accumulate(4, 0, &[b"abcdef"]));
        assert_eq!(total, 6);
        assert_eq!(head, b"abcd");
        assert!(tail.is_empty());
    }

    #[test]
    fn zero_head_budget_keeps_tail_only() {
        let (total, head, tail) = expect_truncated(accumulate(0, 4, &[b"abcdef"]));
        assert_eq!(total, 6);
        assert!(head.is_empty());
        assert_eq!(tail, b"cdef");
    }

    #[test]
    fn byte_counts_track_totals_not_retention() {
        let mut acc = HeadTailAccumulator::new(1, 1);
        for _ in 0..1000 {
            acc.push(b"xy");
        }
        let (total, head, tail) = expect_truncated(acc.finalize());
        assert_eq!(total, 2000);
        assert_eq!(head, b"x");
        assert_eq!(tail, b"y");
    }

    // ---------------- content-type classification ----------------

    #[test]
    fn classify_json_and_sse() {
        assert_eq!(
            classify_content_type(Some("application/json")),
            Some(ResponseContentKind::Json)
        );
        assert_eq!(
            classify_content_type(Some("Application/JSON; charset=utf-8")),
            Some(ResponseContentKind::Json)
        );
        assert_eq!(
            classify_content_type(Some("text/event-stream")),
            Some(ResponseContentKind::Sse)
        );
        assert_eq!(
            classify_content_type(Some("Text/Event-Stream; charset=utf-8")),
            Some(ResponseContentKind::Sse)
        );
        // The request side's vnd.api+json exclusion carries over.
        assert_eq!(classify_content_type(Some("application/vnd.api+json")), None);
        assert_eq!(classify_content_type(Some("text/html")), None);
        assert_eq!(classify_content_type(None), None);
        assert_eq!(classify_content_type(Some("")), None);
    }

    // ---------------- finalize matrix ----------------

    fn finalize_complete(
        bytes: &[u8],
        kind: ResponseContentKind,
        capture_ai: bool,
    ) -> Option<Value> {
        finalize_response_body(
            AccumulatedBody::Complete(bytes.to_vec()),
            kind,
            "/api/data",
            capture_ai,
            &no_rules(),
            None,
        )
    }

    #[test]
    fn whole_json_object_sanitized() {
        let out = finalize_complete(
            br#"{"password":"hunter2","item":"widget"}"#,
            ResponseContentKind::Json,
            true,
        )
        .expect("captured");
        assert_eq!(out, json!({"password":"[REDACTED]","item":"widget"}));
    }

    #[test]
    fn whole_json_parse_failure_discarded() {
        assert!(finalize_complete(b"not json at all", ResponseContentKind::Json, true).is_none());
        // Bare primitives mirror the request side: not captured.
        assert!(finalize_complete(b"\"just a string\"", ResponseContentKind::Json, true).is_none());
        assert!(finalize_complete(b"42", ResponseContentKind::Json, true).is_none());
    }

    #[test]
    fn whole_sse_ships_as_string() {
        let sse = b"event: message\ndata: {\"ok\":true}\n\n";
        let out = finalize_complete(sse, ResponseContentKind::Sse, true).expect("captured");
        assert_eq!(out, Value::String(String::from_utf8_lossy(sse).into_owned()));
    }

    #[test]
    fn ai_shaped_response_suppressed_when_ai_capture_off() {
        // A prompt-echoing response body on a custom path: the parsed-
        // shape check withholds it when captureAiContent is off.
        let body = br#"{"model":"gpt-4o","messages":[{"role":"assistant","content":"hi"}]}"#;
        assert!(finalize_complete(body, ResponseContentKind::Json, false).is_none());
        // Same body ships (sanitized) when AI capture is on.
        assert!(finalize_complete(body, ResponseContentKind::Json, true).is_some());
        // Non-AI-shaped bodies are unaffected by the flag.
        assert!(
            finalize_complete(br#"{"ok":true}"#, ResponseContentKind::Json, false).is_some()
        );
    }

    #[test]
    fn truncation_marker_fields_and_math() {
        let out = finalize_response_body(
            AccumulatedBody::Truncated {
                total: 100,
                head: b"HEAD".to_vec(),
                tail: b"TAIL!".to_vec(),
            },
            ResponseContentKind::Sse,
            "/api/data",
            true,
            &no_rules(),
            None,
        )
        .expect("marker");
        assert_eq!(
            out,
            json!({
                "body_truncated": true,
                "body_bytes_total": 100,
                "body_bytes_dropped": 91,
                "head": "HEAD",
                "tail": "TAIL!",
            })
        );
    }

    #[test]
    fn empty_outcome_is_none() {
        assert!(finalize_response_body(
            AccumulatedBody::Empty,
            ResponseContentKind::Json,
            "/api/data",
            true,
            &no_rules(),
            None,
        )
        .is_none());
    }

    // ---------------- UTF-8 handling at slice cuts ----------------

    #[test]
    fn multibyte_utf8_split_at_head_and_tail_cuts() {
        // "é" is 0xC3 0xA9. Cut the head budget mid-character and split
        // a character across a chunk boundary feeding the tail.
        let (_, head, tail) = expect_truncated(accumulate(
            3,
            3,
            &[b"ab\xC3", b"\xA9cdef\xC3", b"\xA9gh"],
        ));
        // Lossy decode replaces the orphaned continuation bytes.
        let head_str = String::from_utf8_lossy(&head).into_owned();
        let tail_str = String::from_utf8_lossy(&tail).into_owned();
        assert_eq!(head_str, "ab\u{FFFD}");
        assert_eq!(tail_str, "\u{FFFD}gh");
    }

    // ---------------- customer scrub rules on raw text ----------------

    fn ssn_rule() -> CompiledPiiRules {
        CompiledPiiRules::compile(
            &[],
            &[PiiPatternConfig {
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
                label: Some("ssn".to_string()),
                action: None,
                scope: None,
            }],
        )
        .expect("rule compiles")
        .0
    }

    #[test]
    fn value_rules_scrub_raw_sse_text() {
        let sse = b"data: {\"note\":\"ssn 123-45-6789\"}\n\n";
        let out = finalize_response_body(
            AccumulatedBody::Complete(sse.to_vec()),
            ResponseContentKind::Sse,
            "/api/data",
            true,
            &ssn_rule(),
            None,
        )
        .expect("captured");
        assert_eq!(
            out,
            Value::String("data: {\"note\":\"ssn [REDACTED]\"}\n\n".to_string())
        );
    }

    #[test]
    fn value_rules_scrub_truncated_slices() {
        let out = finalize_response_body(
            AccumulatedBody::Truncated {
                total: 64,
                head: b"head 123-45-6789 text".to_vec(),
                tail: b"tail 078-05-1120 text".to_vec(),
            },
            ResponseContentKind::Sse,
            "/api/data",
            true,
            &ssn_rule(),
            None,
        )
        .expect("marker");
        assert_eq!(out["head"], "head [REDACTED] text");
        assert_eq!(out["tail"], "tail [REDACTED] text");
    }
}
