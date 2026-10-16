from cerberus_litellm.queue import BoundedQueue


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


def test_byte_budget_drops_new_events_and_counts_them():
    queue = BoundedQueue(100, max_bytes=1000)
    assert queue.append({"i": 0}, 600)
    assert not queue.append({"i": 1}, 500)  # would take the queue to 1100
    assert queue.dropped_bytes == 1
    assert queue.dropped_full == 0
    assert queue.queued_bytes == 600
    assert queue.append({"i": 2}, 400)  # exactly at the budget is fine
    assert queue.queued_bytes == 1000
    assert [e["i"] for e in queue.drain(10)] == [0, 2]  # nothing evicted


def test_drain_releases_bytes_so_the_budget_frees_up():
    queue = BoundedQueue(100, max_bytes=1000)
    queue.append({"i": 0}, 900)
    queue.drain(1)
    assert queue.queued_bytes == 0
    assert queue.append({"i": 1}, 900)


def test_count_bound_is_unchanged_by_the_byte_budget():
    queue = BoundedQueue(2, max_bytes=10_000)
    assert queue.append({"i": 0}, 1)
    assert queue.append({"i": 1}, 1)
    assert not queue.append({"i": 2}, 1)
    assert queue.dropped_full == 1
    assert queue.dropped_bytes == 0


def test_no_byte_budget_means_count_bound_only():
    queue = BoundedQueue(3)
    assert queue.append({"i": 0}, 10**9)
    assert queue.dropped_bytes == 0
