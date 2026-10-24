"""Fixture loading, the shared mapping call behind the golden cases, and test doubles."""

from __future__ import annotations

import json
import socket
import struct
import threading
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cerberus_agentcore_interceptor import __version__
from cerberus_agentcore_interceptor import envelope as envelope_mod
from cerberus_agentcore_interceptor.mapper import MapperOptions, source_event
from cerberus_agentcore_interceptor.sink import FirehoseSink

FIXTURES = Path(__file__).parent / "fixtures"

# Fixed so the goldens are byte-stable.
TIMESTAMP = datetime(2026, 9, 20, 6, 24, 30, 123456, tzinfo=UTC)


class ClientContext:
    """Stands in for the Lambda client context."""

    def __init__(self, custom: dict[str, Any]):
        self.custom = custom


class LambdaContext:
    """Stands in for the Lambda context object."""

    def __init__(self, custom: dict[str, Any]):
        self.client_context = ClientContext(custom)


class TimedContext(LambdaContext):
    """A Lambda context that reports a fixed remaining time."""

    def __init__(self, custom: dict[str, Any], remaining_ms: int):
        super().__init__(custom)
        self.remaining_ms = remaining_ms

    def get_remaining_time_in_millis(self) -> int:
        return self.remaining_ms


class RecordingSink(FirehoseSink):
    """A sink that records instead of writing, and can fail on demand."""

    def __init__(self, reason: str = "", raises: Exception | None = None):
        super().__init__(("stream",), 250, 500, client=object())
        self.events: list[dict] = []
        self.keys: list[str] = []
        self.deadlines: list[float | None] = []
        self._reason = reason
        self._raises = raises

    def put(self, event, key, deadline=None):
        if self._raises is not None:
            raise self._raises
        self.events.append(event)
        self.keys.append(key)
        self.deadlines.append(deadline)
        return self._reason


def boom(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("boom")


def case_names() -> list[str]:
    return sorted(path.name[: -len(".input.json")] for path in FIXTURES.glob("*.input.json"))


def load_case(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.input.json").read_text())


def load_expected(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.event.json").read_text())


def runtime_encode(value: Any) -> bytes:
    """What the python3.13 Lambda runtime does with a handler's answer."""
    return json.dumps(value, ensure_ascii=False, allow_nan=True).encode("utf-8")


def options(case: dict[str, Any], **overrides: Any) -> MapperOptions:
    base = MapperOptions(
        identity_mode=case.get("options", {}).get("identity_mode", "jwt"),
        version=__version__,
    )
    return replace(base, **overrides) if overrides else base


def map_loaded_case(
    case: dict[str, Any], deadline: float | None = None, **overrides: Any
) -> dict[str, Any] | None:
    """Map a loaded, possibly edited, fixture through the parser and mapper."""
    return source_event(
        envelope_mod.parse(case["input"]),
        envelope_mod.gateway_context(LambdaContext(case["client_context"])),
        options(case, **overrides),
        TIMESTAMP,
        deadline=deadline,
    )


def map_case(name: str, **overrides: Any) -> dict[str, Any] | None:
    """Map a fixture through the parser and mapper, as the handler would."""
    return map_loaded_case(load_case(name), **overrides)


def invoke(name: str = "mcp-tools-call-lambda") -> Any:
    """Run a fixture through the handler."""
    # Imported here: the handler reads its configuration at import, and
    # regenerate.py has none.
    from cerberus_agentcore_interceptor import handler as handler_mod

    case = load_case(name)
    return handler_mod.handler(case["input"], LambdaContext(case["client_context"]))


def invoke_with(name: str, remaining_ms: int) -> tuple[dict[str, Any], Any]:
    """Run a fixture through the handler with remaining_ms left; returns the case too."""
    from cerberus_agentcore_interceptor import handler as handler_mod

    case = load_case(name)
    context = TimedContext(case["client_context"], remaining_ms)
    return case, handler_mod.handler(case["input"], context)


class ForgetfulEndpoint:
    """A local AWS endpoint that, once told to forget, resets older connections."""

    def __init__(self, answer: bytes, content_type: str):
        self.answer = answer
        self.content_type = content_type
        self.forget = threading.Event()
        self.connections = 0
        self.requests = 0
        self.sock = socket.create_server(("127.0.0.1", 0))
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.sock.getsockname()[1]}"

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        opened_before = not self.forget.is_set()
        reader = conn.makefile("rb")
        while _read_request(reader):
            if opened_before and self.forget.is_set():
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                break
            self.requests += 1
            head = f"HTTP/1.1 200 OK\r\nContent-Length: {len(self.answer)}\r\n"
            tail = f"Content-Type: {self.content_type}\r\n\r\n"
            conn.sendall(head.encode() + tail.encode() + self.answer)
        reader.close()
        conn.close()


def _read_request(reader: Any) -> bool:
    line = reader.readline()
    length = 0
    while line not in (b"\r\n", b""):
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value)
        line = reader.readline()
    return bool(line) and len(reader.read(length)) == length


def use_local_endpoint(
    monkeypatch: Any, tmp_path: Path, service: str, url: str, region: str
) -> None:
    """Point boto3's client for service at url, with throwaway credentials and no profile."""
    env = {
        f"AWS_ENDPOINT_URL_{service}": url,
        "AWS_DEFAULT_REGION": region,
        "AWS_ACCESS_KEY_ID": "AKIDEXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "example",
        "AWS_CONFIG_FILE": str(tmp_path / "none"),
        "AWS_SHARED_CREDENTIALS_FILE": str(tmp_path / "none"),
        "AWS_EC2_METADATA_DISABLED": "true",
        "NO_PROXY": "127.0.0.1",
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    for name in ("AWS_PROFILE", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)
