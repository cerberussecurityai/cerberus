from dataclasses import replace

from helpers import load_capture

from cerberus_litellm.schema_reporter import SchemaReporter


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _capture():
    c = load_capture("mcp_list_tools")
    return c["standard_logging_object"], c["response_obj"]


def test_first_list_emits_then_identical_list_is_suppressed(config):
    clock = Clock()
    reporter = SchemaReporter(config, clock=clock)
    slo, tools = _capture()
    assert len(reporter.events(slo, tools)) == 1
    assert reporter.events(slo, tools) == []
    assert reporter.suppressed == 1


def test_changed_catalogue_emits_again(config):
    reporter = SchemaReporter(config, clock=Clock())
    slo, tools = _capture()
    reporter.events(slo, tools)
    changed = tools + [{"name": "mockmcp-new", "description": "", "input_schema": {}}]
    assert len(reporter.events(slo, changed)) == 1


def test_interval_elapsed_emits_again(config):
    clock = Clock()
    reporter = SchemaReporter(replace(config, schema_report_interval_s=60), clock=clock)
    slo, tools = _capture()
    reporter.events(slo, tools)
    clock.now += 59
    assert reporter.events(slo, tools) == []
    clock.now += 2
    assert len(reporter.events(slo, tools)) == 1


def test_interval_zero_always_emits(config):
    reporter = SchemaReporter(replace(config, schema_report_interval_s=0), clock=Clock())
    slo, tools = _capture()
    assert len(reporter.events(slo, tools)) == 1
    assert len(reporter.events(slo, tools)) == 1


def test_bounded_memory(config):
    reporter = SchemaReporter(config, clock=Clock())
    slo, _ = _capture()
    for i in range(1500):
        reporter.events(slo, [{"name": f"s{i}-t", "description": "", "input_schema": {}}])
    assert len(reporter._last) <= 1024
