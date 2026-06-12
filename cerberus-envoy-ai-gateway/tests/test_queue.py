from cerberus_envoy_ai_gateway.queue import BoundedQueue


def test_append_and_drain_fifo():
    queue = BoundedQueue(10)
    for i in range(5):
        assert queue.append({"i": i})
    assert len(queue) == 5
    assert [e["i"] for e in queue.drain(3)] == [0, 1, 2]
    assert [e["i"] for e in queue.drain(10)] == [3, 4]
    assert len(queue) == 0


def test_drop_on_full():
    queue = BoundedQueue(2)
    assert queue.append({"i": 0})
    assert queue.append({"i": 1})
    assert not queue.append({"i": 2})
    assert queue.dropped_full == 1
    # Existing events are never evicted.
    assert [e["i"] for e in queue.drain(10)] == [0, 1]
