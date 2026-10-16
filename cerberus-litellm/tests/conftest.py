import pytest

from cerberus_litellm.config import Config


@pytest.fixture
def config() -> Config:
    """Baseline test config; tests override fields with dataclasses.replace."""
    # Token matches VALID_KEY in the sink tests copied from the bridge (Task 6).
    return Config(ingest_service="http://ingest.test", token="sk_test_0123456789")
