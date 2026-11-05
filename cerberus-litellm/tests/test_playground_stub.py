"""The playground stub ingest writes captures; it must never write outside its dir."""

import importlib.util
import sys
from pathlib import Path

import httpx
import pytest

STUB = Path(__file__).resolve().parent.parent / "playground" / "stub_ingest.py"
KEY = "sk_test_playground"


@pytest.fixture
def stub(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("playground_stub_ingest", STUB)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "playground_stub_ingest", module)
    spec.loader.exec_module(module)
    capture_dir = tmp_path / "captures"
    monkeypatch.setattr(module, "CAPTURE_DIR", str(capture_dir))
    return module, capture_dir


async def _post(module, events):
    transport = httpx.ASGITransport(app=module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://stub") as client:
        return await client.post(
            "/v1/ingest/batch", json={"events": events}, headers={"X-API-Key": KEY}
        )


async def test_hostile_method_cannot_escape_the_capture_dir(stub, tmp_path):
    module, capture_dir = stub
    response = await _post(
        module, [{"endpoint": "llm://openai/x", "method": "../../escape", "timestamp": "t"}]
    )
    assert response.status_code == 200
    written = list(capture_dir.iterdir())
    assert len(written) == 1
    assert written[0].resolve().parent == capture_dir.resolve()
    assert "/" not in written[0].name
    assert not (tmp_path / "escape.json").exists()
    assert not list(tmp_path.glob("*escape*"))  # nothing beside the capture dir


async def test_symlinked_capture_name_is_refused(stub, tmp_path):
    module, capture_dir = stub
    capture_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    # Pre-plant a symlink where the next capture would be written.
    (capture_dir / "001_llm_chat_completion.json").symlink_to(outside / "pwned.json")
    response = await _post(
        module, [{"endpoint": "llm://openai/x", "method": "llm_chat_completion"}]
    )
    assert response.status_code == 400
    assert not (outside / "pwned.json").exists()


async def test_ordinary_event_is_captured_and_printed(stub, capsys):
    module, capture_dir = stub
    await _post(module, [{"endpoint": "llm://openai/x", "method": "llm_chat_completion"}])
    assert [p.name for p in capture_dir.iterdir()][0].endswith("_llm_chat_completion.json")
    assert "[stub_ingest]" in capsys.readouterr().out
