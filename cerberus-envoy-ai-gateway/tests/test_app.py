"""End-to-end in-process tests: OTLP request in → queued Cerberus event."""

import json
from dataclasses import replace

from fastapi.testclient import TestClient
from helpers import load_export

from cerberus_envoy_ai_gateway.app import create_app


def make_test_config(config, **overrides):
    return replace(
        config,
        # Unreachable ingest + max flush interval: nothing leaves the queue
        # during a test; the shutdown flush fails fast on connection refused.
        ingest_service="http://127.0.0.1:9",
        secret_key="test-secret",
        flush_interval_ms=60000,
        **overrides,
    )


def test_traces_protobuf_to_stats(config):
    app = create_app(make_test_config(config))
    with TestClient(app) as client:
        body = load_export("llm_openai_chat").SerializeToString()
        response = client.post(
            "/v1/traces", content=body, headers={"Content-Type": "application/x-protobuf"}
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/x-protobuf"

        body = load_export("mcp_tool_call").SerializeToString()
        assert (
            client.post(
                "/v1/traces", content=body, headers={"Content-Type": "application/x-protobuf"}
            ).status_code
            == 200
        )

        stats = client.get("/stats").json()
        assert stats["events_llm"] == 1
        assert stats["events_mcp"] == 1
        assert stats["queued"] == 2
        assert stats["posted"] == 0


def test_oversized_body_is_413(config):
    from cerberus_envoy_ai_gateway import app as app_module

    app = create_app(make_test_config(config))
    with TestClient(app) as client:
        response = client.post(
            "/v1/traces",
            content=b"x" * (app_module.MAX_OTLP_BODY_BYTES + 1),
            headers={"Content-Type": "application/x-protobuf"},
        )
        assert response.status_code == 413


def test_undecodable_body_is_400(config):
    app = create_app(make_test_config(config))
    with TestClient(app) as client:
        response = client.post(
            "/v1/traces",
            content=b"\xff\xfegarbage\x00" * 5,
            headers={"Content-Type": "application/x-protobuf"},
        )
        assert response.status_code == 400
        # CodeQL: the decode-error detail must not be echoed to the caller —
        # the response body is a fixed generic message.
        assert response.text == "invalid OTLP request"


def test_health_and_ready(config):
    app = create_app(make_test_config(config))
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        ready = client.get("/ready")
        assert ready.status_code == 200
        assert ready.json() == {"status": "ready"}


def test_dump_spans_prints_decoded_spans(config, capsys):
    app = create_app(make_test_config(config, dump_spans=True))
    with TestClient(app) as client:
        body = load_export("mcp_tool_call").SerializeToString()
        client.post("/v1/traces", content=body, headers={"Content-Type": "application/x-protobuf"})
    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    dumped = [json.loads(line) for line in lines]
    assert any(d["attributes"].get("mcp.tool.name") == "get_weather" for d in dumped)
