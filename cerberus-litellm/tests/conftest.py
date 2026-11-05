import pytest

from cerberus_litellm.config import Config


@pytest.fixture(autouse=True)
def exit_hooks(monkeypatch) -> list:
    """Capture atexit registrations so tests never leave real exit hooks behind."""
    registered: list = []

    def fake_register(func, *args, **kwargs):
        registered.append(func)
        return func

    monkeypatch.setattr("cerberus_litellm.plugin.atexit.register", fake_register)
    return registered


@pytest.fixture
def config() -> Config:
    """Baseline test config; tests override fields with dataclasses.replace."""
    # Token matches VALID_KEY in the sink tests copied from the bridge.
    return Config(ingest_service="http://ingest.test", token="sk_test_0123456789")
