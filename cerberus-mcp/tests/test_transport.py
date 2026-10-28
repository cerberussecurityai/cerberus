"""Tests for cerberus_mcp transport layer."""

import logging
import queue as thread_queue
from unittest.mock import MagicMock, patch

from cerberus_mcp.transport import queue_event, init_client, _shutdown, event_queue


class TestQueueEvent:
    """Tests for event queuing behavior."""

    def setup_method(self):
        """Clear the queue before each test."""
        while not event_queue.empty():
            try:
                event_queue.get_nowait()
            except thread_queue.Empty:
                break

    def test_queues_event_data(self):
        event = MagicMock()
        event.method = "mcp_tool_call"
        event.endpoint = "/test"
        queue_event(event)
        assert not event_queue.empty()
        assert event_queue.get_nowait() is event

    def test_drops_event_when_queue_full(self, caplog):
        """Full queue should log warning, not raise."""
        small_queue = thread_queue.Queue(maxsize=1)
        small_queue.put_nowait("filler")
        with patch("cerberus_mcp.transport.event_queue", small_queue):
            event = MagicMock()
            event.method = "mcp_tool_call"
            event.endpoint = "/test"
            with caplog.at_level(logging.WARNING, logger="cerberus_mcp.transport"):
                queue_event(event)
        assert "Event queue full, dropping event" in caplog.text
        assert small_queue.qsize() == 1
        assert small_queue.get_nowait() == "filler"


class TestInitClient:
    """Tests for init_client behavior."""

    @patch("cerberus_mcp.transport._ensure_background_thread")
    def test_warns_on_overwrite(self, mock_bg, caplog):
        """Second init_client call should warn about overwriting."""
        import cerberus_mcp.transport as transport_mod
        old = transport_mod._ws_client
        try:
            transport_mod._ws_client = None
            init_client("wss://first:8765", "key1", "cid1")
            with caplog.at_level(logging.WARNING, logger="cerberus_mcp.transport"):
                init_client("wss://second:8765", "key2", "cid2")
            assert "Overwriting" in caplog.text
            assert "wss://second:8765" in caplog.text
        finally:
            transport_mod._ws_client = old

    @patch("cerberus_mcp.transport._ensure_background_thread")
    def test_no_warn_on_first_init(self, mock_bg, caplog):
        """First init_client call should not warn."""
        with patch("cerberus_mcp.transport._ws_client", None):
            with caplog.at_level(logging.WARNING, logger="cerberus_mcp.transport"):
                init_client("wss://backend:8765", "key", "cid")
        assert "Overwriting" not in caplog.text


class TestShutdown:
    """Tests for graceful shutdown behavior."""

    def test_shutdown_sends_sentinel_when_thread_alive(self):
        """Shutdown should put None sentinel and join the thread."""
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        sentinel_queue = thread_queue.Queue()
        with patch("cerberus_mcp.transport._background_thread", mock_thread), \
                patch("cerberus_mcp.transport.event_queue", sentinel_queue):
            _shutdown()
        assert sentinel_queue.get_nowait() is None
        mock_thread.join.assert_called_once_with(timeout=2.0)

    def test_shutdown_noop_when_no_thread(self):
        """Shutdown should be safe when background thread is None."""
        with patch("cerberus_mcp.transport._background_thread", None):
            _shutdown()  # Should not raise

    def test_shutdown_noop_when_thread_dead(self):
        """Shutdown should be safe when background thread is not alive."""
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = False
        with patch("cerberus_mcp.transport._background_thread", mock_thread):
            _shutdown()
        mock_thread.join.assert_not_called()
