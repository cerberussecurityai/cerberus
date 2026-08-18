// Response-body capture: head+tail byte accumulation and event-shape
// finalization.
//
// The gateway does no semantic work on the response path — no usage
// mining, no provider schemas, no SSE resync; it counts bytes and the
// backend does the rest. A response body streams through the policy
// chunk by chunk (pass-through, never buffered or delayed); this module
// retains the first `responseHeadBytes` of the stream plus a rolling
// ring of the last `responseTailBytes`. At end-of-stream, a body that
// fit entirely within head + tail is reconstructed exactly and shipped
// whole (JSON parsed + sanitized like a request body; SSE as text). A
// larger body ships as head/tail slices with explicit truncation
// markers so truncation is never silent.
//
// The one syntactic concession, for PII's sake: SSE text is sanitized
// per `data:` line. A data line whose payload is a complete JSON
// object/array is parsed, key-sanitized exactly like a JSON body, and
// re-serialized in place; every other line (event/id/comment lines,
// non-JSON data such as `[DONE]`, and the partial frames at a
// truncation cut) falls back to `customPiiPatterns` value rules. This
// is what keeps structured PII in SSE-transported JSON — MCP tool
// results over streamable-http, for one — from bypassing key-based
// redaction just because it rode a stream. Line splitting + a JSON
// parse is not provider knowledge, so schema drift still never
// requires a gateway change.
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

/// Sanitize SSE text line by line, preserving framing byte-for-byte
/// where it matters (line terminators, field prefixes, blank-line event
/// boundaries) so downstream SSE parsing is unaffected.
///
/// - `data:` line whose payload parses as a JSON object/array → the
///   payload is key-sanitized like a JSON body (`SENSITIVE_KEYS`,
///   `customSensitiveKeys`, `customPiiPatterns` key + value scope) and
///   re-serialized (compact form; whitespace inside JSON is not
///   significant to any consumer).
/// - Any other line — `event:` / `id:` / `retry:` / comments, non-JSON
///   data (`[DONE]`), a bare primitive, or a data line cut mid-payload
///   at a truncation boundary — → `customPiiPatterns` value rules only.
///   A parse failure can never make a line *less* scrubbed than before.
pub fn sanitize_sse_text(text: &str, rules: &CompiledPiiRules, secret: Option<&str>) -> String {
    let mut out = String::with_capacity(text.len());
    for piece in text.split_inclusive('\n') {
        let (content, terminator) = match piece.strip_suffix("\r\n") {
            Some(c) => (c, "\r\n"),
            None => match piece.strip_suffix('\n') {
                Some(c) => (c, "\n"),
                None => (piece, ""),
            },
        };
        out.push_str(&sanitize_sse_line(content, rules, secret));
        out.push_str(terminator);
    }
    out
}

fn sanitize_sse_line(line: &str, rules: &CompiledPiiRules, secret: Option<&str>) -> String {
    if let Some(payload) = line.strip_prefix("data:") {
        // SSE strips exactly one leading space after the colon; we
        // strip any run, since the parser side does the same.
        let payload = payload.trim_start_matches(' ');
        if let Ok(parsed @ (Value::Object(_) | Value::Array(_))) =
            serde_json::from_str::<Value>(payload)
        {
            let sanitized = sanitize_value_with(parsed, rules, secret);
            return format!("data: {}", sanitized);
        }
    }
    scrub_text(line.to_string(), rules, secret)
}


/// Turn an accumulated body into the event's `response_body` value.
///
/// - `Empty` → `None`.
/// - `Complete` + parses as a JSON object/array → AI-shape suppression
///   check first (completion-shaped model output, or a prompt-echoing
///   wrapper, on custom paths), else full sanitize — identical treatment
///   to the request side.
/// - `Complete` + parse failure or bare primitive → SSE ships as one
///   string, sanitized per data frame (`sanitize_sse_text`) — unless
///   `captureAiContent` is off and the text carries a model-output
///   signature; JSON kinds are discarded (mirrors the Django agent).
/// - `Truncated` → the same textual AI-shape check on the head first
///   (an over-budget completion is still a completion), then an explicit
///   marker with lossy-decoded head/tail slices: SSE slices sanitized per
///   data frame (partial frames at the cuts fall back to value rules),
///   JSON-document slices value-scrubbed.
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
                    && crate::ai_content::should_suppress_response(endpoint, &parsed)
                {
                    None
                } else {
                    Some(sanitize_value_with(parsed, rules, secret))
                }
            }
            _ => match kind {
                ResponseContentKind::Sse => {
                    let text = String::from_utf8_lossy(&bytes);
                    // Unparseable text gets the textual AI-shape check —
                    // the same suppression the parsed branch applies.
                    if !capture_ai_content
                        && crate::ai_content::should_suppress_response_text(endpoint, &text)
                    {
                        return None;
                    }
                    Some(Value::String(sanitize_sse_text(&text, rules, secret)))
                }
                ResponseContentKind::Json => None,
            },
        },
        AccumulatedBody::Truncated { total, head, tail } => {
            // Byte counts are raw wire counts, taken before any decoding or
            // sanitization (diagnostics only — the consumer never gates on
            // them).
            let dropped = total - (head.len() + tail.len()) as u64;
            // Decode each slice once; the AI check and the sanitizer share it.
            let head_text = String::from_utf8_lossy(&head);
            let tail_text = String::from_utf8_lossy(&tail);
            // The pre-stream gate cannot know a body's shape; an over-budget
            // completion must not slip out just because it was big. Judge
            // from both slices — provider signatures sit at the top of a
            // document / first frame AND in the terminal frames / usage
            // block, and either slice may be empty by configuration — and
            // withhold like the Complete arm would. (JSON-RPC openers win:
            // MCP is never AI content.)
            if !capture_ai_content
                && crate::ai_content::should_suppress_truncated_response(
                    endpoint, &head_text, &tail_text,
                )
            {
                return None;
            }
            let slice = |text: &str| match kind {
                ResponseContentKind::Sse => sanitize_sse_text(text, rules, secret),
                ResponseContentKind::Json => scrub_text(text.to_string(), rules, secret),
            };
            let mut m = serde_json::Map::with_capacity(5);
            m.insert(KEY_TRUNCATED.to_string(), Value::Bool(true));
            m.insert(KEY_BYTES_TOTAL.to_string(), Value::from(total));
            m.insert(KEY_BYTES_DROPPED.to_string(), Value::from(dropped));
            m.insert(KEY_HEAD.to_string(), Value::String(slice(&head_text)));
            m.insert(KEY_TAIL.to_string(), Value::String(slice(&tail_text)));
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
        // Real completion bodies on a custom path — the shapes providers
        // actually return, not request-shaped stand-ins — are withheld when
        // captureAiContent is off, and ship (sanitized) when it is on.
        let bodies: [&[u8]; 4] = [
            br#"{"id":"chatcmpl-1","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}"#,
            br#"{"type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn"}"#,
            br#"{"candidates":[{"content":{"parts":[{"text":"hi"}]},"finishReason":"STOP"}]}"#,
            // A prompt-echoing wrapper.
            br#"{"model":"gpt-4o","messages":[{"role":"assistant","content":"hi"}]}"#,
        ];
        for body in bodies {
            assert!(
                finalize_complete(body, ResponseContentKind::Json, false).is_none(),
                "must be withheld: {}",
                String::from_utf8_lossy(body)
            );
            assert!(finalize_complete(body, ResponseContentKind::Json, true).is_some());
        }
        // Non-AI-shaped bodies are unaffected by the flag.
        assert!(
            finalize_complete(br#"{"ok":true}"#, ResponseContentKind::Json, false).is_some()
        );
        // MCP results are never AI content, whatever the flag.
        assert!(finalize_complete(
            br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hi"}]}}"#,
            ResponseContentKind::Json,
            false
        )
        .is_some());
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
    fn truncated_completion_withheld_when_ai_capture_off() {
        // Over-budget model output on a custom path: the head sniff
        // withholds it exactly like a whole body would be.
        let head = br#"{"id":"chatcmpl-1","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"Once upon a time"#.to_vec();
        let tail = br#" the end."},"finish_reason":"stop"}],"usage":{"total_tokens":9000}}"#.to_vec();
        let truncated = |capture_ai| {
            finalize_response_body(
                AccumulatedBody::Truncated { total: 60_000, head: head.clone(), tail: tail.clone() },
                ResponseContentKind::Json,
                "/internal/assistant/answer",
                capture_ai,
                &no_rules(),
                None,
            )
        };
        assert!(truncated(false).is_none(), "truncated completion must be withheld");
        assert!(truncated(true).is_some(), "ships when AI capture is on");

        // Over-budget SSE completion: same rule.
        let sse_head = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n".to_vec();
        let out = finalize_response_body(
            AccumulatedBody::Truncated { total: 60_000, head: sse_head, tail: b"data: [DONE]\n\n".to_vec() },
            ResponseContentKind::Sse,
            "/internal/assistant/stream",
            false,
            &no_rules(),
            None,
        );
        assert!(out.is_none());

        // Over-budget MCP result over SSE: never AI content, ships.
        let mcp_head = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"".to_vec();
        let out = finalize_response_body(
            AccumulatedBody::Truncated { total: 60_000, head: mcp_head, tail: b"\"}]}}\n\n".to_vec() },
            ResponseContentKind::Sse,
            "/mcp",
            false,
            &no_rules(),
            None,
        );
        assert!(out.is_some());
        // Over-budget business JSON: no signature, ships as a marker.
        let out = finalize_response_body(
            AccumulatedBody::Truncated {
                total: 60_000,
                head: br#"{"orders":[{"id":1,"item":"widget"},"#.to_vec(),
                tail: br#"{"id":999,"item":"gadget"}]}"#.to_vec(),
            },
            ResponseContentKind::Json,
            "/api/orders",
            false,
            &no_rules(),
            None,
        );
        assert!(out.is_some());
    }

    #[test]
    fn whole_sse_completion_withheld_when_ai_capture_off() {
        // In-budget SSE model output on a custom path (request not
        // shape-detected) — the text sniff closes what used to be the one
        // uncovered combination.
        let sse = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n";
        assert!(finalize_complete(sse, ResponseContentKind::Sse, false).is_none());
        assert!(finalize_complete(sse, ResponseContentKind::Sse, true).is_some());
        // Non-AI SSE is unaffected by the flag.
        let ticks = b"data: {\"tick\":1}\n\ndata: {\"tick\":2}\n\n";
        assert!(finalize_complete(ticks, ResponseContentKind::Sse, false).is_some());
    }

    /// Cross-arm parity: the same payload must get the same
    /// captureAiContent decision whether it arrives whole, over budget, or
    /// as SSE — the structural check (parsed JSON) and the textual sniff
    /// (unparseable slices/streams) are different mechanisms and this pins
    /// them to one answer.
    #[test]
    fn ai_suppression_is_consistent_across_arms() {
        let completions: [&str; 5] = [
            r#"{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Once upon a time there was a very long story indeed."},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":12}}"#,
            r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4","content":[{"type":"text","text":"Once upon a time there was a very long story indeed."}],"stop_reason":"end_turn","usage":{"input_tokens":9,"output_tokens":12}}"#,
            r#"{"candidates":[{"content":{"parts":[{"text":"Once upon a time there was a very long story indeed."}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":9}}"#,
            r#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":3}}"#,
            r#"[{"generated_text":"Once upon a time there was a very long story indeed."}]"#,
        ];
        let non_ai: [&str; 3] = [
            r#"{"orders":[{"id":1,"item":"widget","qty":2},{"id":2,"item":"gadget","qty":1}],"total":2}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"choices\":[{\"message\":{\"content\":\"model text inside a tool result\"}}]}"}]}}"#,
            r#"[{"id":1,"name":"widget"},{"id":2,"name":"gadget"}]"#,
        ];
        let arms = |body: &str| -> [bool; 4] {
            let bytes = body.as_bytes().to_vec();
            let mid = bytes.len() / 2;
            let sse = format!("event: message\ndata: {body}\n\n").into_bytes();
            let sse_mid = sse.len() / 2;
            let run = |outcome, kind| {
                finalize_response_body(outcome, kind, "/internal/api", false, &no_rules(), None)
                    .is_none()
            };
            [
                run(AccumulatedBody::Complete(bytes.clone()), ResponseContentKind::Json),
                run(
                    AccumulatedBody::Truncated {
                        total: bytes.len() as u64 + 1,
                        head: bytes[..mid].to_vec(),
                        tail: bytes[mid..].to_vec(),
                    },
                    ResponseContentKind::Json,
                ),
                run(AccumulatedBody::Complete(sse.clone()), ResponseContentKind::Sse),
                run(
                    AccumulatedBody::Truncated {
                        total: sse.len() as u64 + 1,
                        head: sse[..sse_mid].to_vec(),
                        tail: sse[sse_mid..].to_vec(),
                    },
                    ResponseContentKind::Sse,
                ),
            ]
        };
        for body in completions {
            assert_eq!(arms(body), [true; 4], "all arms must withhold: {body}");
        }
        for body in non_ai {
            assert_eq!(arms(body), [false; 4], "no arm may withhold: {body}");
        }
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

    // ---------------- SSE frame-level sanitization ----------------

    #[test]
    fn sse_data_frame_key_sanitized_framing_preserved() {
        // JSON data payloads are key-sanitized like a body; event lines,
        // CRLF terminators and the blank-line boundary survive intact.
        let sse = "event: message\r\ndata: {\"result\":{\"api_key\":\"sk-1\",\"name\":\"x\"}}\r\n\r\n";
        let out = sanitize_sse_text(sse, &no_rules(), None);
        assert_eq!(
            out,
            "event: message\r\ndata: {\"result\":{\"api_key\":\"[REDACTED]\",\"name\":\"x\"}}\r\n\r\n"
        );
    }

    #[test]
    fn sse_partial_frame_at_cut_falls_back_to_value_rules() {
        // A data line cut mid-payload (truncation boundary) is not JSON:
        // it cannot be key-redacted, but value rules still run — never
        // less scrubbed than the plain-text path.
        let cut = "data: {\"note\":\"ssn 123-45-6789\",\"pass";
        let out = sanitize_sse_text(cut, &ssn_rule(), None);
        assert_eq!(out, "data: {\"note\":\"ssn [REDACTED]\",\"pass");
    }

    #[test]
    fn sse_non_json_lines_untouched() {
        let sse = ": keep-alive\nid: 7\nretry: 3000\ndata: [DONE]\ndata: 42\n\n";
        assert_eq!(sanitize_sse_text(sse, &no_rules(), None), sse);
    }

    #[test]
    fn sse_multi_frame_nested_secret_redacted() {
        // MCP tool result over streamable-http: structured PII inside a
        // frame is caught by key redaction, not left to regex luck.
        let sse = concat!(
            "event: message\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"structuredContent\":{\"user\":\"alice\",\"password\":\"hunter2\"}}}\n",
            "\n",
            "event: message\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"ok\":true}}\n",
            "\n",
        );
        let out = sanitize_sse_text(sse, &no_rules(), None);
        assert!(!out.contains("hunter2"), "secret must not survive: {out}");
        assert!(out.contains("\"password\":\"[REDACTED]\""), "{out}");
        assert!(out.contains("\"user\":\"alice\""), "{out}");
        assert!(out.contains("\"ok\":true"), "{out}");
        assert_eq!(out.matches("event: message\n").count(), 2, "framing intact: {out}");
    }

    #[test]
    fn sse_value_rules_still_apply_inside_frames_and_comments() {
        let sse = ": trace 078-05-1120\ndata: {\"text\":\"call 123-45-6789\"}\n\n";
        let out = sanitize_sse_text(sse, &ssn_rule(), None);
        assert_eq!(
            out,
            ": trace [REDACTED]\ndata: {\"text\":\"call [REDACTED]\"}\n\n"
        );
    }

    #[test]
    fn truncated_sse_slices_sanitized_per_frame_json_slices_not() {
        let head = b"data: {\"token\":\"t-1\",\"a\":1}\n\ndata: {\"secret\":\"cut-he".to_vec();
        let tail = b"re\"}\n\ndata: {\"api_key\":\"k-9\"}\n\n".to_vec();
        let out = finalize_response_body(
            AccumulatedBody::Truncated { total: 500, head: head.clone(), tail: tail.clone() },
            ResponseContentKind::Sse,
            "/mcp",
            true,
            &no_rules(),
            None,
        )
        .expect("marker");
        let h = out["head"].as_str().unwrap();
        let t = out["tail"].as_str().unwrap();
        // Complete frames key-redacted; the frame split by the cut is not
        // JSON on either side and passes through (value rules only).
        assert!(h.starts_with("data: {\"a\":1,\"token\":\"[REDACTED]\"}\n\n"), "{h}");
        assert!(h.ends_with("data: {\"secret\":\"cut-he"), "{h}");
        assert!(t.starts_with("re\"}\n\n"), "{t}");
        assert!(t.ends_with("data: {\"api_key\":\"[REDACTED]\"}\n\n"), "{t}");
        // Byte counts stay raw-wire counts regardless of sanitization.
        assert_eq!(out["body_bytes_total"], 500);
        assert_eq!(out["body_bytes_dropped"], 500 - (head.len() + tail.len()) as u64);

        // JSON-document kind: slices are not line-framed → value rules only,
        // even when a slice happens to start with "data:".
        let out = finalize_response_body(
            AccumulatedBody::Truncated {
                total: 100,
                head: b"data: {\"token\":\"t-1\"}".to_vec(),
                tail: b"}".to_vec(),
            },
            ResponseContentKind::Json,
            "/api",
            true,
            &no_rules(),
            None,
        )
        .expect("marker");
        assert_eq!(out["head"], "data: {\"token\":\"t-1\"}");
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
