// LLM/AI prompt-content detection for the captureAiContent gate.
//
// Stopgap heuristic pending proper AI-content handling in the backend
// (future work): free-form prompt text has high PII potential and
// SENSITIVE_KEYS matching cannot reach inside it. captureAiContent
// defaults to true (bodies captured + sanitized like any JSON body);
// when an operator sets it false, requests detected here as LLM/AI
// traffic ship their event WITHOUT the body.
//
// The heuristics are biased toward recall — when withholding is enabled,
// a false positive only costs body capture for one event, while a false
// negative ships prompt text.
//
// MCP carve-out: JSON-RPC bodies (an object with a "jsonrpc" key) are
// never treated as AI content, even on an AI-ish path. MCP bodies are
// well-structured (method names + typed params) so standard
// SENSITIVE_KEYS sanitization handles them — and MCP discovery depends
// on the captured arguments.

use std::sync::OnceLock;

use regex_lite::Regex;
use serde_json::Value;

/// True if the request path looks like a well-known LLM API route.
/// Matched against the lowercased, query-stripped path.
pub fn is_llm_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    // /v1/completions, /chat/completions, Azure OpenAI
    // /openai/deployments/{d}/chat/completions
    p.ends_with("/completions")
        // Embedding inputs are content too.
        || p.ends_with("/embeddings")
        // Anthropic Messages API + subroutes.
        || p.contains("/v1/messages")
        // Gemini :generateContent / :streamGenerateContent.
        || p.contains("generatecontent")
        // Bedrock Converse.
        || p.ends_with("/converse")
        || p.ends_with("/converse-stream")
        // Bedrock InvokeModel; the /model/ guard keeps generic /invoke
        // RPC routes out.
        || (p.contains("/model/")
            && (p.ends_with("/invoke") || p.ends_with("/invoke-with-response-stream")))
        // OpenAI Responses API.
        || p.contains("/v1/responses")
        // Vertex AI custom methods (:predict / :rawPredict /
        // :streamRawPredict) — the colon keeps ordinary /predict
        // business routes out. Non-generative Vertex models match too;
        // their feature-vector payloads carry the same PII concerns.
        || p.contains(":predict")
        || p.contains(":rawpredict")
        || p.contains(":streamrawpredict")
}

/// True if a parsed JSON body is MCP / JSON-RPC shaped. Such bodies are
/// never treated as AI content — see module docs. (Note: the buffering
/// short-circuit in lib.rs runs before body inspection, so this
/// carve-out only reaches bodies that were buffered.)
pub fn is_jsonrpc_shaped(body: &Value) -> bool {
    matches!(body, Value::Object(o) if o.contains_key("jsonrpc"))
}

/// True if a parsed JSON body looks like an LLM prompt payload.
pub fn is_prompt_shaped(body: &Value) -> bool {
    match body {
        Value::Object(o) => {
            // OpenAI/Anthropic chat shape: messages array whose elements
            // carry a role.
            if o.get("messages").and_then(Value::as_array).is_some_and(|msgs| {
                msgs.iter()
                    .any(|m| m.as_object().is_some_and(|m| m.contains_key("role")))
            }) {
                return true;
            }
            // Chat/completion/embedding request with routing field.
            // message/chat_history/texts are Cohere v1 chat/embed
            // shapes; requiring the model companion keeps ordinary
            // business payloads with a bare "message" field out.
            if o.contains_key("model")
                && [
                    "prompt",
                    "input",
                    "messages",
                    "contents",
                    "message",
                    "chat_history",
                    "texts",
                ]
                .iter()
                .any(|k| o.contains_key(*k))
            {
                return true;
            }
            // Gemini: contents array whose elements carry parts.
            if o.get("contents").and_then(Value::as_array).is_some_and(|cs| {
                cs.iter()
                    .any(|c| c.as_object().is_some_and(|c| c.contains_key("parts")))
            }) {
                return true;
            }
            // Legacy completion shapes: prompt + generation params.
            if o.contains_key("prompt")
                && ["max_tokens", "max_tokens_to_sample", "temperature", "top_p"]
                    .iter()
                    .any(|k| o.contains_key(*k))
            {
                return true;
            }
            // Bedrock-Anthropic invoke bodies.
            if o.contains_key("anthropic_version") {
                return true;
            }
            // Bedrock Titan.
            o.contains_key("inputText") && o.contains_key("textGenerationConfig")
        }
        // Bare message-list POSTs.
        Value::Array(arr) => arr
            .first()
            .and_then(Value::as_object)
            .is_some_and(|first| first.contains_key("role") && first.contains_key("content")),
        _ => false,
    }
}

/// True if a parsed JSON body looks like an LLM *response* payload — a
/// completion, chat message, embedding, or generation result. Response
/// shapes differ from request shapes (no top-level `messages`/`prompt`),
/// so `is_prompt_shaped` cannot recognise them; this is the response-side
/// twin, biased toward recall the same way.
pub fn is_completion_shaped(body: &Value) -> bool {
    let Value::Object(o) = body else {
        return false;
    };
    // OpenAI chat/completions: choices[] whose elements carry a message /
    // delta / text / finish_reason.
    if o.get("choices").and_then(Value::as_array).is_some_and(|cs| {
        cs.iter().any(|c| {
            c.as_object().is_some_and(|c| {
                ["message", "delta", "text", "finish_reason"]
                    .iter()
                    .any(|k| c.contains_key(*k))
            })
        })
    }) {
        return true;
    }
    // OpenAI Responses API: {"object":"response","output":[...]} — or the
    // output array alongside a model.
    if o.get("output").and_then(Value::as_array).is_some()
        && (o.get("object").and_then(Value::as_str) == Some("response") || o.contains_key("model"))
    {
        return true;
    }
    // Anthropic Messages: {"type":"message","role":"assistant","content":[...]}
    // — or a stop_reason beside content (Bedrock-Anthropic invoke too).
    if o.contains_key("content")
        && (o.get("type").and_then(Value::as_str) == Some("message")
            || o.contains_key("stop_reason"))
    {
        return true;
    }
    // Gemini: candidates[] whose elements carry content.
    if o.get("candidates").and_then(Value::as_array).is_some_and(|cs| {
        cs.iter()
            .any(|c| c.as_object().is_some_and(|c| c.contains_key("content")))
    }) {
        return true;
    }
    // Embeddings: data[] whose elements carry an embedding vector.
    if o.get("data").and_then(Value::as_array).is_some_and(|ds| {
        ds.iter()
            .any(|d| d.as_object().is_some_and(|d| d.contains_key("embedding")))
    }) {
        return true;
    }
    // Bedrock Converse: {"output":{"message":...},"stopReason":...}.
    if o.contains_key("stopReason") && o.contains_key("output") {
        return true;
    }
    // Bedrock Titan: results[] whose elements carry outputText.
    if o.get("results").and_then(Value::as_array).is_some_and(|rs| {
        rs.iter()
            .any(|r| r.as_object().is_some_and(|r| r.contains_key("outputText")))
    }) {
        return true;
    }
    // Cohere chat/generate: a finish_reason beside a message or text.
    o.contains_key("finish_reason") && (o.contains_key("message") || o.contains_key("text"))
}

/// Decision used by the request filter: suppress the body iff the request
/// looks like LLM traffic and is not MCP/JSON-RPC.
pub fn should_suppress_body(path: &str, body: &Value) -> bool {
    !is_jsonrpc_shaped(body) && (is_llm_path(path) || is_prompt_shaped(body))
}

/// How much of a raw response text the signature sniff inspects. Every
/// provider's discriminating keys (`choices`, `candidates`, `type`,
/// `object`, `stop_reason`, ...) sit at the top of the document or in
/// the first SSE frame, so a short window is enough and keeps the sniff
/// O(1) on large slices.
const AI_SNIFF_WINDOW: usize = 2048;

/// Signature keys/values that mark raw response text as model output —
/// the textual twin of `is_completion_shaped` (+ the prompt-echo shapes),
/// for text that cannot be parsed: a truncated JSON document's head, or an
/// SSE stream (whole or sliced). Whitespace-tolerant around the colon.
/// Recall-biased on purpose: a false positive costs one event's response
/// body, a false negative ships model output.
static AI_RESPONSE_SIGNATURE: OnceLock<Regex> = OnceLock::new();
/// A JSON-RPC envelope opener at the start of the text (optionally behind
/// an SSE `data:` prefix): MCP, never AI content — mirrors the parsed
/// carve-out in `is_jsonrpc_shaped`.
static JSONRPC_OPENER: OnceLock<Regex> = OnceLock::new();

fn ai_response_signature() -> &'static Regex {
    AI_RESPONSE_SIGNATURE.get_or_init(|| {
        Regex::new(concat!(
            r#""(?:choices|candidates|stop_reason|stopReason|finish_reason|outputText|"#,
            r#"embedding|delta|generation_id|messages)"\s*:"#,
            r#"|"object"\s*:\s*"(?:chat\.completion|text_completion|response|list)"#,
            r#"|"type"\s*:\s*"(?:message|content_block|response\.)"#,
        ))
        .expect("static regex")
    })
}

fn jsonrpc_opener() -> &'static Regex {
    JSONRPC_OPENER
        .get_or_init(|| Regex::new(r#"^\s*(?:data:\s*)?\{\s*"jsonrpc""#).expect("static regex"))
}

/// True if raw response text looks like model output. Inspects the first
/// `AI_SNIFF_WINDOW` bytes; a JSON-RPC opener wins over any signature (MCP
/// results may legitimately carry a completion inside a tool result).
pub fn looks_like_ai_response_text(text: &str) -> bool {
    let end = text
        .char_indices()
        .map(|(i, _)| i)
        .find(|&i| i >= AI_SNIFF_WINDOW)
        .unwrap_or(text.len());
    let window = &text[..end];
    if jsonrpc_opener().is_match(window) {
        return false;
    }
    ai_response_signature().is_match(window)
}

/// Decision used by the response filter for response text it cannot parse
/// (SSE, truncated slices): suppress iff the request hit an LLM path or the
/// text carries a model-output signature.
pub fn should_suppress_response_text(path: &str, text: &str) -> bool {
    is_llm_path(path) || looks_like_ai_response_text(text)
}

/// Decision used by the response filter for a whole JSON response body:
/// suppress iff the response looks like model output — a completion-shaped
/// body, or a prompt-shaped one (an echoing wrapper) — on any path, and is
/// not MCP/JSON-RPC. (Well-known LLM paths never reach this check: the
/// response filter skips the stream for them before any body work.)
pub fn should_suppress_response(path: &str, body: &Value) -> bool {
    !is_jsonrpc_shaped(body)
        && (is_llm_path(path) || is_completion_shaped(body) || is_prompt_shaped(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn llm_paths_positive() {
        let paths = [
            "/v1/chat/completions",
            "/openai/deployments/gpt-4o/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "/v1/messages",
            "/v1/messages/batches",
            "/v1beta/models/gemini-2.0-flash:generateContent",
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
            "/model/anthropic.claude-3-sonnet/invoke",
            "/model/meta.llama3/converse",
            "/model/x/invoke-with-response-stream",
            "/v1/responses",
            // Vertex AI custom methods.
            "/v1/projects/p/locations/us-central1/publishers/google/models/text-bison:predict",
            "/v1/projects/p/locations/us-central1/endpoints/123:rawPredict",
            "/v1/projects/p/locations/us-central1/endpoints/123:streamRawPredict",
            // Case-insensitivity.
            "/V1/CHAT/COMPLETIONS",
        ];
        for path in paths {
            assert!(is_llm_path(path), "expected LLM path match: {path}");
        }
    }

    #[test]
    fn llm_paths_negative() {
        let paths = [
            "/api/orders",
            "/api/v2/messages",
            // No /model/ guard → generic RPC route stays out.
            "/rpc/invoke",
            // Suffix must not match mid-word (ends_with handles this).
            "/api/users/converserdata",
            // No colon → ordinary predict/ML business routes stay out.
            "/api/predict",
            "/predictions/model-a",
            "/health",
        ];
        for path in paths {
            assert!(!is_llm_path(path), "expected non-LLM path: {path}");
        }
    }

    #[test]
    fn prompt_bodies_positive() {
        let bodies = [
            // OpenAI chat.
            json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}),
            // Bare messages array with role elements.
            json!({"messages":[{"role":"user","content":"hi"}]}),
            // Anthropic.
            json!({"model":"claude-sonnet-4","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}),
            // Legacy completion with model.
            json!({"model":"gpt-3.5","prompt":"complete this"}),
            // Gemini.
            json!({"contents":[{"parts":[{"text":"hi"}]}]}),
            // Embeddings.
            json!({"model":"text-embedding-3-small","input":"chunk"}),
            // Bedrock-Anthropic.
            json!({"anthropic_version":"bedrock-2023-05-31","messages":[{"role":"user","content":"hi"}]}),
            // Bedrock Titan.
            json!({"inputText":"summarize","textGenerationConfig":{}}),
            // Legacy completion without model.
            json!({"prompt":"complete this","max_tokens":100}),
            // Cohere v1 chat.
            json!({"model":"command-r","message":"hi","chat_history":[]}),
            // Cohere v1 embed.
            json!({"model":"embed-english-v3.0","texts":["chunk one","chunk two"]}),
            // Top-level array of {role, content} messages.
            json!([{"role":"user","content":"hi"}]),
        ];
        for body in bodies {
            assert!(is_prompt_shaped(&body), "expected prompt-shaped: {body}");
        }
    }

    #[test]
    fn prompt_bodies_negative() {
        let bodies = [
            // message without model (ordinary business payload).
            json!({"message":"hello"}),
            // input without model.
            json!({"input":"abc"}),
            // texts without model.
            json!({"texts":["a","b"]}),
            // model without a companion payload field.
            json!({"model":"tesla-model-3"}),
            json!({"model":"SM-G991B","serial":"R58M"}),
            // prompt without generation params.
            json!({"prompt":"pick a username"}),
            json!({"username":"alice","password":"x"}),
            // messages elements without role.
            json!({"messages":["plain","strings"]}),
            // contents elements without parts.
            json!({"contents":["a","b"]}),
        ];
        for body in bodies {
            assert!(!is_prompt_shaped(&body), "expected non-prompt body: {body}");
        }
    }

    #[test]
    fn completion_bodies_positive() {
        let bodies = [
            // OpenAI chat completion.
            json!({"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o",
                   "choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],
                   "usage":{"prompt_tokens":1,"completion_tokens":1}}),
            // OpenAI streaming-style chunk (delta) delivered as JSON.
            json!({"choices":[{"delta":{"content":"hi"}}]}),
            // Legacy completion.
            json!({"choices":[{"text":"hi","index":0}]}),
            // OpenAI Responses API.
            json!({"object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"hi"}]}]}),
            // Anthropic Messages.
            json!({"type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn"}),
            // Bedrock-Anthropic (stop_reason beside content, no type).
            json!({"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn"}),
            // Gemini.
            json!({"candidates":[{"content":{"parts":[{"text":"hi"}]},"finishReason":"STOP"}]}),
            // Embeddings.
            json!({"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2],"index":0}]}),
            // Bedrock Converse.
            json!({"output":{"message":{"role":"assistant","content":[{"text":"hi"}]}},"stopReason":"end_turn"}),
            // Bedrock Titan.
            json!({"results":[{"outputText":"hi","completionReason":"FINISH"}]}),
            // Cohere.
            json!({"text":"hi","finish_reason":"COMPLETE","generation_id":"g"}),
        ];
        for body in bodies {
            assert!(is_completion_shaped(&body), "expected completion-shaped: {body}");
        }
    }

    #[test]
    fn completion_bodies_negative() {
        let bodies = [
            // Ordinary business payloads that share a key name.
            json!({"choices":["red","green"]}),
            json!({"data":[{"id":1,"name":"widget"}]}),
            json!({"content":"plain string, no message type or stop reason"}),
            json!({"output":"done"}),
            json!({"results":[{"id":1}]}),
            json!({"candidates":[{"name":"alice"}]}),
            json!({"message":"created","id":7}),
            // MCP result envelope: never AI content.
            json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hi"}]}}),
        ];
        for body in bodies {
            assert!(!is_completion_shaped(&body), "expected non-completion body: {body}");
        }
    }

    #[test]
    fn ai_response_text_sniff_positive() {
        let texts = [
            // Truncated OpenAI completion document (a JSON prefix).
            r#"{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Once upon"#,
            // Truncated Anthropic message.
            r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4","content":[{"type":"text","text":"Once"#,
            // Truncated Gemini.
            r#"{"candidates":[{"content":{"parts":[{"text":"Once"#,
            // Truncated embeddings response.
            r#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.0123,-0.0456,"#,
            // OpenAI SSE stream.
            "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            // Anthropic SSE stream.
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            // Responses API SSE stream.
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n",
            // Gemini SSE.
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}]}}]}\n\n",
            // Pretty-printed wrapper echoing messages.
            "{\n  \"model\": \"gpt-4o\",\n  \"messages\" : [\n    {\"role\": \"assistant\"",
        ];
        for t in texts {
            assert!(looks_like_ai_response_text(t), "expected AI signature: {t}");
        }
    }

    #[test]
    fn ai_response_text_sniff_negative() {
        let texts = [
            // Business JSON prefix.
            r#"{"orders":[{"id":1,"item":"widget","qty":2},{"id":2,"item":"gadget","#,
            // Plain SSE with non-AI JSON.
            "data: {\"tick\":1,\"price\":42.5}\n\ndata: {\"tick\":2,\"price\":42.6}\n\n",
            // MCP JSON-RPC result — even one that carries a completion
            // inside a tool result: MCP is never AI content.
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"choices\":[]}"}]}}"#,
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"structuredContent\":{\"choices\":[\"a\"]}}}\n\n",
            // Keep-alive comments only.
            ": keep-alive\n\n",
        ];
        for t in texts {
            assert!(!looks_like_ai_response_text(t), "expected no AI signature: {t}");
        }
    }

    #[test]
    fn ai_response_text_sniff_only_inspects_the_head_window() {
        // A signature buried past the window is not seen — the sniff is a
        // bounded prefix check, not a whole-body scan.
        let mut t = String::from(r#"{"data":""#);
        t.push_str(&"x".repeat(AI_SNIFF_WINDOW + 10));
        t.push_str(r#"","choices":[]}"#);
        assert!(!looks_like_ai_response_text(&t));
        // Multi-byte chars right at the window edge must not panic.
        let mut t = "é".repeat(AI_SNIFF_WINDOW);
        t.push_str(r#""choices":"#);
        let _ = looks_like_ai_response_text(&t);
    }

    #[test]
    fn should_suppress_response_decision() {
        // Real completion on a custom path → suppressed.
        assert!(should_suppress_response(
            "/internal/ai/ask",
            &json!({"choices":[{"message":{"role":"assistant","content":"hi"}}]})
        ));
        // Prompt-echoing wrapper on a custom path → suppressed.
        assert!(should_suppress_response(
            "/internal/ai/ask",
            &json!({"model":"gpt-4o","messages":[{"role":"assistant","content":"hi"}]})
        ));
        // MCP JSON-RPC result → never suppressed, even on an LLM-looking path.
        assert!(!should_suppress_response(
            "/v1/chat/completions",
            &json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hi"}]}})
        ));
        // Ordinary business response on a custom path → captured.
        assert!(!should_suppress_response("/api/orders", &json!({"item":"widget","qty":2})));
    }

    #[test]
    fn mcp_jsonrpc_carve_out() {
        let mcp = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "search", "arguments": {"query": "x"}}
        });
        assert!(is_jsonrpc_shaped(&mcp));
        // The body gate never suppresses JSON-RPC, even on an LLM-looking
        // path. (Policy-level: path-matched requests skip buffering before
        // this gate runs — see the tradeoff comment in lib.rs.)
        assert!(!should_suppress_body("/v1/chat/completions", &mcp));

        // An MCP body whose params carry a nested messages/role structure
        // is still not suppressed — the jsonrpc key wins.
        let mcp_nested = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"arguments": {"messages": [{"role": "user", "content": "hi"}]}}
        });
        assert!(!should_suppress_body("/v1/chat/completions", &mcp_nested));
    }

    #[test]
    fn should_suppress_body_decision() {
        // LLM path alone suffices, even with a non-prompt body.
        assert!(should_suppress_body(
            "/v1/chat/completions",
            &json!({"unrelated":"field"})
        ));
        // Prompt-shaped body alone suffices on a non-LLM path.
        assert!(should_suppress_body(
            "/internal/ai/ask",
            &json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]})
        ));
        // Non-LLM path + normal body → capture as usual.
        assert!(!should_suppress_body(
            "/api/orders",
            &json!({"item":"widget","qty":2})
        ));
    }
}
