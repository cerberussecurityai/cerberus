"""Mock OpenAI-compatible LLM backend: /v1/chat/completions with a usage block."""

import time

import uvicorn
from fastapi import FastAPI

app = FastAPI(title="mock-llm")


@app.post("/v1/chat/completions")
async def chat_completions(payload: dict) -> dict:
    model = payload.get("model", "mock-gpt")
    last_message = (payload.get("messages") or [{}])[-1].get("content", "")
    return {
        "id": "chatcmpl-mock-1",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": f"echo: {last_message}"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 17, "completion_tokens": 5, "total_tokens": 22},
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9081, log_level="warning")
