"""Mock OpenAI-compatible upstream for the LiteLLM capture comparison.

Richer than the Envoy playground mock on purpose: the spike has to observe how
LiteLLM assembles *streamed* tool-call arguments, how it reports upstream
errors, and whether large bodies survive, so this mock can produce all three.

Routes (all under /v1):
- POST /chat/completions   stream or not; emits tool_calls when the request
                           carries `tools` (arguments are streamed in several
                           deltas so assembly is actually exercised); a
                           trailing usage chunk is sent when stream_options
                           asks for it (and always as the final SSE chunk).
- POST /embeddings         fixed small vector + usage.
- Model switches:
    mock-error  -> HTTP 500 with an OpenAI-style error body
    mock-429    -> HTTP 429
    mock-big    -> ~48 KB completion text (byte-cap scenario)
"""

import json
import time

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

app = FastAPI(title="spike-mock-llm")

TOOL_ARGS = {"city": "Reykjavik", "unit": "celsius", "api_key": "should-be-redacted"}


def _chunk(model: str, delta: dict, finish: str | None = None, usage: dict | None = None) -> str:
    body = {
        "id": "chatcmpl-mock-stream-1",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    }
    if usage is not None:
        body["usage"] = usage
    return f"data: {json.dumps(body)}\n\n"


def _usage(prompt_chars: int, completion_chars: int) -> dict:
    return {
        "prompt_tokens": max(1, prompt_chars // 4),
        "completion_tokens": max(1, completion_chars // 4),
        "total_tokens": max(2, prompt_chars // 4 + completion_chars // 4),
    }


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    payload = await request.json()
    model = payload.get("model", "mock-gpt")
    messages = payload.get("messages") or [{}]
    prompt_chars = len(json.dumps(messages))
    last = messages[-1].get("content", "")
    if isinstance(last, list):  # content blocks
        last = " ".join(b.get("text", "") for b in last if isinstance(b, dict))

    if model == "mock-error":
        return JSONResponse(
            status_code=500,
            content={"error": {"message": "mock upstream exploded", "type": "server_error", "code": "mock_500"}},
        )
    if model == "mock-429":
        return JSONResponse(
            status_code=429,
            content={"error": {"message": "mock rate limit", "type": "rate_limit_error", "code": "mock_429"}},
            headers={"retry-after": "1"},
        )

    want_tool = bool(payload.get("tools"))
    text = f"echo: {last}"
    if model == "mock-big":
        text = ("lorem ipsum dolor sit amet " * 1800)[:48_000]

    if payload.get("stream"):

        async def gen():
            yield _chunk(model, {"role": "assistant", "content": ""})
            completion_chars = 0
            if want_tool:
                tool_name = payload["tools"][0]["function"]["name"]
                yield _chunk(
                    model,
                    {"tool_calls": [{"index": 0, "id": "call_mock_1", "type": "function", "function": {"name": tool_name, "arguments": ""}}]},
                )
                args = json.dumps(TOOL_ARGS)
                # Split the argument JSON across several deltas on purpose.
                for i in range(0, len(args), 7):
                    piece = args[i : i + 7]
                    completion_chars += len(piece)
                    yield _chunk(model, {"tool_calls": [{"index": 0, "function": {"arguments": piece}}]})
                yield _chunk(model, {}, finish="tool_calls")
            else:
                for i in range(0, len(text), 64):
                    piece = text[i : i + 64]
                    completion_chars += len(piece)
                    yield _chunk(model, {"content": piece})
                yield _chunk(model, {}, finish="stop")
            yield _chunk(model, {}, usage=_usage(prompt_chars, completion_chars))
            yield "data: [DONE]\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    if want_tool:
        tool_name = payload["tools"][0]["function"]["name"]
        message = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "call_mock_1", "type": "function", "function": {"name": tool_name, "arguments": json.dumps(TOOL_ARGS)}}
            ],
        }
        finish = "tool_calls"
        completion_chars = len(json.dumps(TOOL_ARGS))
    else:
        message = {"role": "assistant", "content": text}
        finish = "stop"
        completion_chars = len(text)
    return {
        "id": "chatcmpl-mock-1",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": _usage(prompt_chars, completion_chars),
    }


def _resp_envelope(model: str, output: list, usage: dict | None, status: str = "completed") -> dict:
    return {
        "id": "resp_mock_1",
        "object": "response",
        "created_at": int(time.time()),
        "status": status,
        "model": model,
        "output": output,
        "usage": usage,
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "text": {"format": {"type": "text"}},
        "truncation": "disabled",
        "temperature": 1.0,
        "top_p": 1.0,
        "reasoning": {"effort": None, "summary": None},
        "store": False,
        "metadata": {},
        "incomplete_details": None,
        "instructions": None,
        "max_output_tokens": None,
        "previous_response_id": None,
        "user": None,
        "error": None,
    }


def _resp_usage(prompt_chars: int, completion_chars: int) -> dict:
    return {
        "input_tokens": max(1, prompt_chars // 4),
        "output_tokens": max(1, completion_chars // 4),
        "total_tokens": max(2, prompt_chars // 4 + completion_chars // 4),
        "input_tokens_details": {"cached_tokens": 0},
        "output_tokens_details": {"reasoning_tokens": 0},
    }


@app.post("/v1/responses")
async def responses(request: Request):
    """Minimal OpenAI Responses API. LiteLLM bridges /v1/messages for openai/*
    models onto this route, so it serves S3 and S4."""
    payload = await request.json()
    model = payload.get("model", "mock-gpt")
    inp = payload.get("input")
    prompt_chars = len(json.dumps(inp))
    if isinstance(inp, str):
        last = inp
    else:
        last = ""
        for item in inp or []:
            content = item.get("content") if isinstance(item, dict) else None
            if isinstance(content, str):
                last = content
            elif isinstance(content, list):
                last = " ".join(b.get("text", "") for b in content if isinstance(b, dict))
    want_tool = bool(payload.get("tools"))
    text = f"echo: {last}"
    if want_tool:
        tool_name = payload["tools"][0].get("name") or payload["tools"][0].get("function", {}).get("name", "tool")
        args = json.dumps(TOOL_ARGS)
        item = {"type": "function_call", "id": "fc_mock_1", "call_id": "call_mock_1", "name": tool_name, "arguments": args, "status": "completed"}
        completion_chars = len(args)
    else:
        item = {"type": "message", "id": "msg_mock_1", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": text, "annotations": []}]}
        completion_chars = len(text)
    usage = _resp_usage(prompt_chars, completion_chars)

    if not payload.get("stream"):
        return _resp_envelope(model, [item], usage)

    async def gen():
        seq = 0

        def ev(kind: str, **fields):
            nonlocal seq
            seq += 1
            return f"event: {kind}\ndata: {json.dumps({'type': kind, 'sequence_number': seq, **fields})}\n\n"

        yield ev("response.created", response=_resp_envelope(model, [], None, status="in_progress"))
        yield ev("response.in_progress", response=_resp_envelope(model, [], None, status="in_progress"))
        if want_tool:
            start = dict(item, arguments="", status="in_progress")
            yield ev("response.output_item.added", output_index=0, item=start)
            for i in range(0, len(args), 7):
                yield ev("response.function_call_arguments.delta", item_id=item["id"], output_index=0, delta=args[i : i + 7])
            yield ev("response.function_call_arguments.done", item_id=item["id"], output_index=0, arguments=args)
            yield ev("response.output_item.done", output_index=0, item=item)
        else:
            start = dict(item, status="in_progress", content=[])
            yield ev("response.output_item.added", output_index=0, item=start)
            yield ev("response.content_part.added", item_id=item["id"], output_index=0, content_index=0, part={"type": "output_text", "text": "", "annotations": []})
            for i in range(0, len(text), 64):
                yield ev("response.output_text.delta", item_id=item["id"], output_index=0, content_index=0, delta=text[i : i + 64])
            yield ev("response.output_text.done", item_id=item["id"], output_index=0, content_index=0, text=text)
            yield ev("response.content_part.done", item_id=item["id"], output_index=0, content_index=0, part={"type": "output_text", "text": text, "annotations": []})
            yield ev("response.output_item.done", output_index=0, item=item)
        yield ev("response.completed", response=_resp_envelope(model, [item], usage))

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.post("/v1/embeddings")
async def embeddings(payload: dict) -> dict:
    inputs = payload.get("input")
    if isinstance(inputs, str):
        inputs = [inputs]
    return {
        "object": "list",
        "data": [{"object": "embedding", "index": i, "embedding": [0.1, 0.2, 0.3, 0.4]} for i, _ in enumerate(inputs or [])],
        "model": payload.get("model", "mock-embed"),
        "usage": {"prompt_tokens": 8, "total_tokens": 8},
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(path: str, request: Request):
    body = (await request.body())[:300]
    print(f"[mock-llm] UNHANDLED {request.method} /{path} body={body!r}", flush=True)
    return JSONResponse(status_code=404, content={"error": {"message": f"mock has no route /{path}", "type": "not_found"}})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9081, log_level="warning")
