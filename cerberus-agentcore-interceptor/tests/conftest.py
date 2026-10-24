import importlib
import os

import pytest

from cerberus_agentcore_interceptor import metrics

# The handler reads its configuration at import, so this has to be set before
# any test module imports it.
os.environ.setdefault("CERBERUS_FIREHOSE_STREAM", "cerberus-capture-test")


@pytest.fixture
def counted(monkeypatch):
    """Every metric counted during the test, as (name, reason)."""
    counts: list[tuple[str, str]] = []
    monkeypatch.setattr(
        metrics, "count", lambda name, reason="", **fields: counts.append((name, reason))
    )
    return counts


@pytest.fixture
def reload_handler(monkeypatch):
    """Re-import the handler under the test's environment; the original is restored after."""
    # Imported here so the environment above is set first.
    from cerberus_agentcore_interceptor import handler as handler_mod

    yield lambda: importlib.reload(handler_mod)
    monkeypatch.undo()
    importlib.reload(handler_mod)
