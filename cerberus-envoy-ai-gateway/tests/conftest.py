import pytest

from cerberus_envoy_ai_gateway.config import Config


@pytest.fixture
def config() -> Config:
    """Baseline test config; tests override fields as needed."""
    return Config(
        ingest_service="http://ingest.test",
        token="sk_test_0123456789",
        user_id_attribute="user.id",
    )
