from dataclasses import replace

from helpers import load_capture

from cerberus_litellm.schema_reporter import SchemaReporter


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _events(reporter, slo, tools):
    """Emit and mark every report as queued, as the plugin does after queue.append."""
    out = reporter.events(slo, tools)
    for event in out:
        reporter.commit(event)
    return out


def test_a_report_that_was_never_committed_does_not_suppress_the_next_one(config):
    reporter = SchemaReporter(config, clock=Clock())
    slo, tools = _capture()
    assert len(reporter.events(slo, tools)) == 1  # e.g. dropped by finalize or a full queue
    assert len(reporter.events(slo, tools)) == 1  # so the same catalogue is offered again
    assert reporter.suppressed == 0


def _capture():
    c = load_capture("mcp_list_tools")
    return c["standard_logging_object"], c["response_obj"]


def test_first_list_emits_then_identical_list_is_suppressed(config):
    clock = Clock()
    reporter = SchemaReporter(config, clock=clock)
    slo, tools = _capture()
    assert len(_events(reporter, slo, tools)) == 1
    assert _events(reporter, slo, tools) == []
    assert reporter.suppressed == 1


def test_changed_catalogue_emits_again(config):
    reporter = SchemaReporter(config, clock=Clock())
    slo, tools = _capture()
    _events(reporter, slo, tools)
    changed = tools + [{"name": "mockmcp-new", "description": "", "input_schema": {}}]
    assert len(_events(reporter, slo, changed)) == 1


def test_interval_elapsed_emits_again(config):
    clock = Clock()
    reporter = SchemaReporter(replace(config, schema_report_interval_s=60), clock=clock)
    slo, tools = _capture()
    _events(reporter, slo, tools)
    clock.now += 59
    assert _events(reporter, slo, tools) == []
    clock.now += 2
    assert len(_events(reporter, slo, tools)) == 1


def test_interval_zero_always_emits(config):
    reporter = SchemaReporter(replace(config, schema_report_interval_s=0), clock=Clock())
    slo, tools = _capture()
    assert len(_events(reporter, slo, tools)) == 1
    assert len(_events(reporter, slo, tools)) == 1


def test_bounded_memory(config):
    reporter = SchemaReporter(config, clock=Clock())
    slo, _ = _capture()
    for i in range(1500):
        _events(reporter, slo, [{"name": f"s{i}-t", "description": "", "input_schema": {}}])
    assert len(reporter._last) <= 1024
