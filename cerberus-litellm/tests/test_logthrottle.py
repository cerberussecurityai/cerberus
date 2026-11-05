import logging

from cerberus_litellm.logthrottle import LogThrottle


def test_one_warning_per_interval_and_suppressed_count_is_reported(caplog):
    caplog.set_level(logging.WARNING, logger="throttle-test")
    now = [100.0]
    throttle = LogThrottle(interval=60.0, clock=lambda: now[0])
    log = logging.getLogger("throttle-test")

    assert throttle.warn(log, "first %s", "a") is True
    now[0] += 10
    assert throttle.warn(log, "second") is False
    assert throttle.warn(log, "third") is False
    assert throttle.suppressed == 2

    now[0] += 60
    assert throttle.warn(log, "fourth") is True
    assert throttle.suppressed == 0
    messages = [r.getMessage() for r in caplog.records]
    assert messages == ["first a", "fourth (2 similar warnings suppressed)"]
