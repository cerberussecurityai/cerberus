"""Tests for cerberus_django middleware extraction and sanitization helpers."""

import json
import logging
import queue as thread_queue
from unittest.mock import MagicMock, patch

import pytest
from django.test import RequestFactory

from cerberus_core import REDACTED
from cerberus_django.middleware import (
    CerberusMiddleware,
    _extract_body,
    _extract_headers,
    _extract_query_params,
    _extract_response_body,
    event_queue,
)


@pytest.fixture
def rf():
    return RequestFactory()


class TestExtractHeaders:
    """Tests for _extract_headers."""

    def test_extracts_standard_http_headers(self, rf):
        request = rf.get("/", HTTP_ACCEPT="text/html", HTTP_HOST="example.com")
        headers = _extract_headers(request)
        assert headers["Accept"] == "text/html"
        assert headers["Host"] == "example.com"

    def test_includes_content_type_and_length(self, rf):
        request = rf.post(
            "/",
            data=b"{}",
            content_type="application/json",
        )
        headers = _extract_headers(request)
        assert headers["Content-Type"] == "application/json"

    def test_redacts_cookie_header(self, rf):
        request = rf.get("/", HTTP_COOKIE="session=abc123")
        headers = _extract_headers(request)
        assert headers["Cookie"] == REDACTED

    def test_redacts_x_api_key_header(self, rf):
        request = rf.get("/", HTTP_X_API_KEY="sk-secret")
        headers = _extract_headers(request)
        assert headers["X-Api-Key"] == REDACTED

    def test_hashes_authorization_with_secret_key(self, rf):
        request = rf.get("/", HTTP_AUTHORIZATION="Bearer token123")
        headers = _extract_headers(request, secret_key="test-key")
        assert headers["Authorization"] != "Bearer token123"
        assert headers["Authorization"] != REDACTED
        assert len(headers["Authorization"]) == 64  # SHA-256 hex

    def test_redacts_authorization_without_secret_key(self, rf):
        request = rf.get("/", HTTP_AUTHORIZATION="Bearer token123")
        headers = _extract_headers(request, secret_key=None)
        assert headers["Authorization"] == REDACTED

    def test_returns_none_for_no_headers(self):
        request = MagicMock()
        request.META = {}
        headers = _extract_headers(request)
        assert headers is None

    def test_consistent_authorization_hash(self, rf):
        """Same Authorization value + same key = same hash."""
        request = rf.get("/", HTTP_AUTHORIZATION="Bearer abc")
        h1 = _extract_headers(request, secret_key="key")
        h2 = _extract_headers(request, secret_key="key")
        assert h1["Authorization"] == h2["Authorization"]


class TestExtractQueryParams:
    """Tests for _extract_query_params."""

    def test_extracts_simple_params(self, rf):
        request = rf.get("/?page=1&sort=name")
        params = _extract_query_params(request)
        assert params["page"] == "1"
        assert params["sort"] == "name"

    def test_redacts_sensitive_params(self, rf):
        request = rf.get("/?api_key=secret&token=xyz&page=1")
        params = _extract_query_params(request)
        assert params["api_key"] == REDACTED
        assert params["token"] == REDACTED
        assert params["page"] == "1"

    def test_redacts_password_param(self, rf):
        request = rf.get("/?password=hunter2")
        params = _extract_query_params(request)
        assert params["password"] == REDACTED

    def test_returns_none_for_no_params(self, rf):
        request = rf.get("/")
        params = _extract_query_params(request)
        assert params is None

    def test_multi_value_params(self, rf):
        request = rf.get("/?tag=a&tag=b&tag=c")
        params = _extract_query_params(request)
        assert params["tag"] == ["a", "b", "c"]

    def test_single_value_not_wrapped_in_list(self, rf):
        request = rf.get("/?name=alice")
        params = _extract_query_params(request)
        assert params["name"] == "alice"
        assert not isinstance(params["name"], list)


class TestExtractBody:
    """Tests for _extract_body."""

    def test_extracts_json_body(self, rf):
        data = {"username": "alice", "role": "admin"}
        request = rf.post("/", data=json.dumps(data), content_type="application/json")
        body = _extract_body(request)
        assert body["username"] == "alice"
        assert body["role"] == "admin"

    def test_sanitizes_sensitive_keys_in_body(self, rf):
        data = {"username": "alice", "password": "hunter2", "api_key": "sk-123"}
        request = rf.post("/", data=json.dumps(data), content_type="application/json")
        body = _extract_body(request)
        assert body["username"] == "alice"
        assert body["password"] == REDACTED
        assert body["api_key"] == REDACTED

    def test_sanitizes_nested_body(self, rf):
        data = {"user": {"name": "alice", "token": "abc"}}
        request = rf.post("/", data=json.dumps(data), content_type="application/json")
        body = _extract_body(request)
        assert body["user"]["name"] == "alice"
        assert body["user"]["token"] == REDACTED

    def test_returns_none_for_get_request(self, rf):
        request = rf.get("/")
        body = _extract_body(request)
        assert body is None

    def test_returns_none_for_non_json_content(self, rf):
        request = rf.post("/", data="form=data", content_type="application/x-www-form-urlencoded")
        body = _extract_body(request)
        assert body is None

    def test_returns_none_for_invalid_json(self, rf):
        request = rf.post("/", data=b"not json{{{", content_type="application/json")
        body = _extract_body(request)
        assert body is None

    def test_returns_none_for_bare_json_string(self, rf):
        request = rf.post("/", data=json.dumps("just a string"), content_type="application/json")
        body = _extract_body(request)
        assert body is None

    def test_returns_none_for_bare_json_number(self, rf):
        request = rf.post("/", data=json.dumps(42), content_type="application/json")
        body = _extract_body(request)
        assert body is None

    def test_handles_json_list_body(self, rf):
        data = [{"password": "secret"}, {"name": "alice"}]
        request = rf.post("/", data=json.dumps(data), content_type="application/json")
        body = _extract_body(request)
        assert isinstance(body, list)
        assert body[0]["password"] == REDACTED
        assert body[1]["name"] == "alice"

    def test_handles_empty_body(self, rf):
        request = rf.post("/", data=b"", content_type="application/json")
        body = _extract_body(request)
        assert body is None

    def test_handles_raw_post_data_exception(self, rf):
        """Broad except should catch RawPostDataException without crashing."""
        request = rf.post("/", data=b"{}", content_type="application/json")
        # Simulate RawPostDataException by making body access raise
        # Use a mock to avoid mutating the class-level descriptor
        request = MagicMock()
        request.method = "POST"
        request.content_type = "application/json"
        type(request).body = property(lambda self: (_ for _ in ()).throw(Exception("body already read")))
        body = _extract_body(request)
        assert body is None
        # Clean up the property we set on MagicMock
        del type(request).body

    def test_put_method(self, rf):
        data = {"field": "value"}
        request = rf.put("/", data=json.dumps(data), content_type="application/json")
        body = _extract_body(request)
        assert body is not None
        assert body["field"] == "value"

    def test_patch_method(self, rf):
        data = {"field": "value"}
        request = rf.patch("/", data=json.dumps(data), content_type="application/json")
        body = _extract_body(request)
        assert body is not None
        assert body["field"] == "value"

    def test_delete_method_returns_none(self, rf):
        request = rf.delete("/")
        body = _extract_body(request)
        assert body is None


class TestExtractResponseBody:
    """Tests for _extract_response_body."""

    def _json_response(self, data, **kwargs):
        from django.http import HttpResponse

        return HttpResponse(
            json.dumps(data), content_type="application/json", **kwargs
        )

    def test_extracts_and_sanitizes_json_response(self):
        response = self._json_response({"answer": "hello", "api_key": "sk-123"})
        body = _extract_response_body(response)
        assert body["answer"] == "hello"
        assert body["api_key"] == REDACTED

    def test_handles_json_list_response(self):
        response = self._json_response([{"password": "secret"}, {"name": "alice"}])
        body = _extract_response_body(response)
        assert isinstance(body, list)
        assert body[0]["password"] == REDACTED
        assert body[1]["name"] == "alice"

    def test_returns_none_for_non_json_content_type(self):
        from django.http import HttpResponse

        response = HttpResponse("<html></html>", content_type="text/html")
        assert _extract_response_body(response) is None

    def test_returns_none_for_invalid_json(self):
        from django.http import HttpResponse

        response = HttpResponse(b"not json{{{", content_type="application/json")
        assert _extract_response_body(response) is None

    def test_returns_none_for_bare_json_primitive(self):
        response = self._json_response("just a string")
        assert _extract_response_body(response) is None

    def test_returns_none_for_empty_body(self):
        from django.http import HttpResponse

        response = HttpResponse(b"", content_type="application/json")
        assert _extract_response_body(response) is None

    def test_returns_none_for_streaming_response(self):
        from django.http import StreamingHttpResponse

        response = StreamingHttpResponse(
            iter([b'{"a":', b" 1}"]), content_type="application/json"
        )
        assert _extract_response_body(response) is None
        # The stream must not have been consumed by the capture attempt
        assert b"".join(response.streaming_content) == b'{"a": 1}'

    def test_returns_none_for_file_response(self, tmp_path):
        from django.http import FileResponse

        f = tmp_path / "data.json"
        f.write_bytes(b'{"a": 1}')
        response = FileResponse(open(f, "rb"), content_type="application/json")
        assert _extract_response_body(response) is None

    def test_skips_compressed_response_with_marker(self):
        response = self._json_response({"a": 1})
        response["Content-Encoding"] = "gzip"
        body = _extract_response_body(response)
        assert body == {"body_skipped_encoding": "gzip"}

    def test_identity_encoding_still_captured(self):
        response = self._json_response({"a": 1})
        response["Content-Encoding"] = "identity"
        body = _extract_response_body(response)
        assert body == {"a": 1}

    def test_body_within_budget_ships_whole_without_markers(self):
        data = {"content": "x" * 100}
        response = self._json_response(data)
        body = _extract_response_body(response, head_bytes=1024, tail_bytes=1024)
        assert body == data
        assert "body_truncated" not in body

    def test_oversized_body_ships_head_tail_with_markers(self):
        data = {"content": "x" * 1000}
        response = self._json_response(data)
        body = _extract_response_body(response, head_bytes=64, tail_bytes=32)
        serialized = json.dumps(data)  # sanitization is a no-op for this data
        assert body["body_truncated"] is True
        assert body["body_bytes_total"] == len(serialized)
        assert body["body_bytes_dropped"] == len(serialized) - 64 - 32
        assert body["head"] == serialized[:64]
        assert body["tail"] == serialized[-32:]

    def test_truncation_applies_to_sanitized_form(self):
        """Sensitive values must be redacted BEFORE slicing — the head/tail
        slices must never leak a secret that fits inside them."""
        data = {"api_key": "sk-verysecret", "content": "x" * 1000}
        response = self._json_response(data)
        body = _extract_response_body(response, head_bytes=64, tail_bytes=32)
        assert body["body_truncated"] is True
        assert "sk-verysecret" not in body["head"]
        assert REDACTED in body["head"]

    def test_zero_tail_bytes_does_not_ship_whole_body(self):
        """Guard against the b[-0:] == whole-string slicing pitfall."""
        data = {"content": "x" * 1000}
        response = self._json_response(data)
        body = _extract_response_body(response, head_bytes=64, tail_bytes=0)
        assert body["body_truncated"] is True
        assert body["tail"] == ""
        assert len(body["head"]) == 64

    def test_unreadable_content_returns_none(self):
        """An unrendered TemplateResponse-style .content error must not raise."""
        response = MagicMock()
        response.streaming = False
        response.get = lambda header: {
            "Content-Type": "application/json"
        }.get(header)
        type(response).content = property(
            lambda self: (_ for _ in ()).throw(Exception("not rendered"))
        )
        assert _extract_response_body(response) is None
        del type(response).content

    def test_deeply_nested_json_returns_none_without_raising(self):
        """json.loads raises RecursionError on attacker-controllable nesting
        depth — capture must degrade to None, never break the response path
        with a 500. Depth 100_000 raises on every supported interpreter
        (3.12+ parses far deeper than 3.11 before raising)."""
        from django.http import HttpResponse

        response = HttpResponse(
            b"[" * 100_000 + b"]" * 100_000, content_type="application/json"
        )
        assert _extract_response_body(response) is None


class TestResponseBodyCapture:
    """Middleware-level tests for opt-in response body capture."""

    def _drain_queue(self):
        while not event_queue.empty():
            try:
                event_queue.get_nowait()
            except thread_queue.Empty:
                break

    @patch("cerberus_django.middleware.ensure_background_thread")
    def test_response_body_captured_when_enabled(self, mock_bg, rf):
        from django.http import JsonResponse

        with patch.dict("django.conf.settings.__dict__", {"CERBERUS_CONFIG": {
            "token": "tok", "client_id": "cid", "ws_url": "wss://b:8765",
            "secret_key": "test-key", "capture_response_body": True,
        }}):
            mw = CerberusMiddleware(
                lambda req: JsonResponse({"answer": "ok", "token": "sk-1"})
            )
            self._drain_queue()
            mw(rf.get("/test"))
            event = event_queue.get_nowait()
            assert event.response_body == {"answer": "ok", "token": REDACTED}

    @patch("cerberus_django.middleware.ensure_background_thread")
    def test_response_body_not_captured_by_default(self, mock_bg, rf):
        from django.http import JsonResponse

        with patch.dict("django.conf.settings.__dict__", {"CERBERUS_CONFIG": {
            "token": "tok", "client_id": "cid", "ws_url": "wss://b:8765",
            "secret_key": "test-key",
        }}):
            mw = CerberusMiddleware(lambda req: JsonResponse({"answer": "ok"}))
            self._drain_queue()
            mw(rf.get("/test"))
            event = event_queue.get_nowait()
            assert event.response_body is None

    @patch("cerberus_django.middleware.ensure_background_thread")
    def test_malformed_sizing_knob_falls_back_to_default(self, mock_bg, rf):
        from cerberus_django.middleware import RESPONSE_HEAD_BYTES_DEFAULT

        with patch.dict("django.conf.settings.__dict__", {"CERBERUS_CONFIG": {
            "token": "tok", "client_id": "cid", "ws_url": "wss://b:8765",
            "secret_key": "test-key", "capture_response_body": True,
            "response_head_bytes": "lots",
        }}):
            mw = CerberusMiddleware(lambda req: MagicMock(data={}))
            assert mw.response_head_bytes == RESPONSE_HEAD_BYTES_DEFAULT

    @patch("cerberus_django.middleware.ensure_background_thread")
    def test_valid_sizing_knobs_are_honored_end_to_end(self, mock_bg, rf):
        """A configured cap must flow from CERBERUS_CONFIG through __call__ to
        the extractor — catches a typo'd config key or a dropped call-site
        argument, which the defaults would otherwise mask."""
        from django.http import HttpResponse

        big = json.dumps({"content": "x" * 1000})
        with patch.dict("django.conf.settings.__dict__", {"CERBERUS_CONFIG": {
            "token": "tok", "client_id": "cid", "ws_url": "wss://b:8765",
            "secret_key": "test-key", "capture_response_body": True,
            "response_head_bytes": 64, "response_tail_bytes": 32,
        }}):
            mw = CerberusMiddleware(
                lambda req: HttpResponse(big, content_type="application/json")
            )
            self._drain_queue()
            mw(rf.get("/test"))
            event = event_queue.get_nowait()
            assert event.response_body["body_truncated"] is True
            assert event.response_body["head"] == big[:64]
            assert event.response_body["tail"] == big[-32:]

    def test_ws_payload_includes_response_body(self):
        """The transport payload must carry response_body under that exact key
        — the middleware-level tests stop at event_queue, one hop before
        serialization."""
        import asyncio

        from cerberus_django.middleware import AsyncWebSocketClient
        from cerberus_django.structs import CoreData

        sent = []

        class FakeWebSocket:
            async def send(self, data):
                sent.append(data)

            async def recv(self):
                return "ack"

        client = AsyncWebSocketClient("wss://b:8765", "key", "cid")
        client.websocket = FakeWebSocket()
        event = CoreData(
            token="tok", source_ip="ip", endpoint="/e", scheme=True,
            method="GET", timestamp="ts", response_body={"answer": "ok"},
        )
        asyncio.run(client.send(event))
        payload = json.loads(sent[0])
        assert payload["response_body"] == {"answer": "ok"}


class TestSourceIpHandling:
    """Tests for source IP hashing and plaintext warning."""

    def _drain_queue(self):
        while not event_queue.empty():
            try:
                event_queue.get_nowait()
            except thread_queue.Empty:
                break

    @patch("cerberus_django.middleware.ensure_background_thread")
    def test_source_ip_hashed_with_secret_key(self, mock_bg, rf):
        with patch.dict("django.conf.settings.__dict__", {"CERBERUS_CONFIG": {
            "token": "tok", "client_id": "cid", "ws_url": "wss://b:8765",
            "secret_key": "test-key",
        }}):
            mw = CerberusMiddleware(lambda req: MagicMock(data={}))
            self._drain_queue()
            request = rf.get("/test")
            mw(request)
            event = event_queue.get_nowait()
            # Should be a 64-char hex hash, not the raw IP
            assert event.source_ip != request.META.get("REMOTE_ADDR")
            assert len(event.source_ip) == 64

    @patch("cerberus_django.middleware.ensure_background_thread")
    def test_source_ip_raw_without_secret_key_warns(self, mock_bg, rf, caplog):
        with patch.dict("django.conf.settings.__dict__", {"CERBERUS_CONFIG": {
            "token": "tok", "client_id": "cid", "ws_url": "wss://b:8765",
        }}):
            mw = CerberusMiddleware(lambda req: MagicMock(data={}))
            self._drain_queue()
            request = rf.get("/test")
            with caplog.at_level(logging.WARNING, logger="cerberus_django.middleware"):
                mw(request)
            event = event_queue.get_nowait()
            # IP should be the raw value (127.0.0.1 from RequestFactory)
            assert event.source_ip == "127.0.0.1"
            assert "plaintext" in caplog.text

    @patch("cerberus_django.middleware.ensure_background_thread")
    def test_source_ip_warning_only_once(self, mock_bg, rf, caplog):
        with patch.dict("django.conf.settings.__dict__", {"CERBERUS_CONFIG": {
            "token": "tok", "client_id": "cid", "ws_url": "wss://b:8765",
        }}):
            mw = CerberusMiddleware(lambda req: MagicMock(data={}))
            self._drain_queue()
            with caplog.at_level(logging.WARNING, logger="cerberus_django.middleware"):
                mw(rf.get("/one"))
                mw(rf.get("/two"))
            assert caplog.text.count("plaintext") == 1
