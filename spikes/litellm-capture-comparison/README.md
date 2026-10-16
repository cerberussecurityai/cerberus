# LiteLLM capture comparison

A local harness that sends the same traffic through a pinned LiteLLM proxy
(`ghcr.io/berriai/litellm:v1.105.1`) and records what two observation points see.
It is throwaway test code and is not intended to merge. It runs against local mocks
only and is for local use only: the compose file uses a known throwaway master key
and debug dumping, and binds every port to `127.0.0.1`.

```
client --> litellm:4000 --+--> dump_logger.py  (CustomLogger, in-process)  --> captures/plugin/
                          +--> OTel export     --> otlp_tee:4319            --> captures/otel/
                                                   \--> cerberus-envoy-ai-gateway --> stub ingest --> captures/events/
```

- `mocks/mock_llm.py` is an OpenAI-compatible upstream (chat, Responses API, embeddings,
  streaming, error injection, large completions).
- `mocks/mock_mcp.py` is a streamable-HTTP MCP server with a few test tools.
- `dump_logger.py` writes each LiteLLM hook payload to disk, with provider keys stripped.
- `otlp_tee.py` records each OTLP/HTTP export and forwards it unchanged.
- `stub_ingest.py` records whatever the forwarded spans produce.
- `drive.sh` runs the scenarios below.

```bash
docker compose down -v && docker compose up -d --build && ./drive.sh
```

`captures/` holds the output of one run. Pre-call dumps and raw `.pb` files are
git-ignored, and `drive.sh` redacts the throwaway virtual key and fails if it remains.
The upstream `api_key` seen in some dumps is the literal string `dummy-upstream-key`.

## Scenarios

| # | Call |
| -- | -- |
| S1 | chat, non-stream, `user` set |
| S2 | chat, stream, tool call |
| S3 | `/v1/messages`, stream, tool use |
| S4 | `/v1/responses` |
| S5 | embeddings |
| S6 | upstream 500, upstream 429 |
| S7 | large completion (stream and non-stream), large prompt |
| S8 | `/mcp`: initialize, tools/list, three tools/call |
| S9 | `/mcp/<server>` and `/<server>/mcp` routes |
| S10 | second chat in the same session |

Every request carries session and turn headers, W3C `traceparent` and `baggage`,
`x-forwarded-for`, a custom header, and a virtual key with team, alias and user set.

Results are recorded internally.
