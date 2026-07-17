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

/// Decision used by the request filter: suppress the body iff the request
/// looks like LLM traffic and is not MCP/JSON-RPC.
pub fn should_suppress_body(path: &str, body: &Value) -> bool {
    !is_jsonrpc_shaped(body) && (is_llm_path(path) || is_prompt_shaped(body))
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
