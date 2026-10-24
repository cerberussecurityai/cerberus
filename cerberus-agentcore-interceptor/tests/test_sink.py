import json
import logging
import re
from datetime import datetime
from time import monotonic

import pytest
from botocore import exceptions as botocore_errors
from helpers import ForgetfulEndpoint, boom, use_local_endpoint

from cerberus_agentcore_interceptor import metrics
from cerberus_agentcore_interceptor import sink as sink_mod
from cerberus_agentcore_interceptor.sink import MAX_RECORD_BYTES, FirehoseSink

ENDPOINT = "https://firehose.us-east-1.amazonaws.com"
OK = json.dumps({"RecordId": "r-1", "Encrypted": False}).encode()


class FakeFirehose:
    def __init__(self, raises=None):
        self.calls = []
        self._raises = raises

    def put_record(self, **kwargs):
        self.calls.append(kwargs)
        if self._raises is not None:
            raise self._raises
        return {"RecordId": "r-1"}


class FlakyFirehose(FakeFirehose):
    """Raises each error in turn, then succeeds."""

    def __init__(self, *errors):
        super().__init__()
        self._errors = list(errors)

    def put_record(self, **kwargs):
        self.calls.append(kwargs)
        if self._errors:
            raise self._errors.pop(0)
        return {"RecordId": "r-1"}


@pytest.fixture
def forgetful(monkeypatch, tmp_path):
    endpoint = ForgetfulEndpoint(OK, "application/x-amz-json-1.1")
    use_local_endpoint(monkeypatch, tmp_path, "FIREHOSE", endpoint.url, "us-east-1")
    yield endpoint
    endpoint.sock.close()


def closed():
    return botocore_errors.ConnectionClosedError(endpoint_url=ENDPOINT)


class ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class ReadTimeoutError(Exception):
    pass


def sink(streams=("stream-a",), client=None):
    return FirehoseSink(streams, 250, 500, client=client or FakeFirehose())


def test_a_record_is_one_newline_terminated_json_line():
    client = FakeFirehose()
    assert sink(client=client).put({"event_id": "e-1"}, "key") == ""

    data = client.calls[0]["Record"]["Data"]
    assert client.calls[0]["DeliveryStreamName"] == "stream-a"
    assert data.endswith(b"\n")
    assert json.loads(data) == {"event_id": "e-1"}


def test_one_attempt_per_interception():
    client = FakeFirehose(raises=ClientError("ServiceUnavailableException"))
    assert sink(client=client).put({"event_id": "e"}, "key") == metrics.REASON_THROTTLE
    assert len(client.calls) == 1


def test_failures_map_to_reasons():
    assert sink(client=FakeFirehose(raises=ReadTimeoutError())).put({}, "k") == (
        metrics.REASON_TIMEOUT
    )
    assert sink(client=FakeFirehose(raises=ClientError("AccessDeniedException"))).put({}, "k") == (
        metrics.REASON_SINK
    )
    assert sink(client=FakeFirehose(raises=RuntimeError("boom"))).put({}, "k") == (
        metrics.REASON_SINK
    )


def test_a_put_that_could_outlast_the_deadline_is_skipped():
    client = FakeFirehose()
    assert sink(client=client).put({"event_id": "e"}, "k", monotonic() + 0.7) == (
        metrics.REASON_DEADLINE
    )
    assert client.calls == []

    assert sink(client=client).put({"event_id": "e"}, "k", monotonic() + 1) == ""
    assert len(client.calls) == 1


def test_a_connection_closed_under_the_request_is_resent_once():
    client = FlakyFirehose(closed())
    assert sink(client=client).put({"event_id": "e"}, "k") == ""
    assert len(client.calls) == 2
    assert client.calls[0] == client.calls[1]


def test_a_second_closed_connection_drops_the_record():
    client = FlakyFirehose(closed(), closed())
    assert sink(client=client).put({"event_id": "e"}, "k") == metrics.REASON_SINK
    assert len(client.calls) == 2


@pytest.mark.parametrize(
    "error",
    [
        botocore_errors.ReadTimeoutError(endpoint_url=ENDPOINT),
        botocore_errors.ConnectTimeoutError(endpoint_url=ENDPOINT),
        botocore_errors.EndpointConnectionError(endpoint_url=ENDPOINT),
        botocore_errors.ClientError({"Error": {"Code": "ThrottlingException"}}, "PutRecord"),
    ],
)
def test_other_failures_are_not_resent(error):
    client = FlakyFirehose(error)
    assert sink(client=client).put({"event_id": "e"}, "k") != ""
    assert len(client.calls) == 1


def test_a_closed_connection_is_not_resent_past_the_deadline(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(sink_mod, "monotonic", lambda: now[0])

    class Slow(FlakyFirehose):
        def put_record(self, **kwargs):
            now[0] += 0.5
            return super().put_record(**kwargs)

    client = Slow(closed())
    assert sink(client=client).put({"event_id": "e"}, "k", 101.0) == metrics.REASON_SINK
    assert len(client.calls) == 1


def test_a_connection_reset_after_an_idle_gap_is_resent_on_a_new_one(forgetful):
    shipped = FirehoseSink(("stream-a",), 250, 500)
    assert shipped.put({"event_id": "e-1"}, "k") == ""
    forgetful.forget.set()

    assert shipped.put({"event_id": "e-2"}, "k") == ""
    assert forgetful.connections == 2
    assert forgetful.requests == 2


def test_an_oversized_record_never_reaches_firehose():
    client = FakeFirehose()
    event = {"body": {"blob": "x" * (MAX_RECORD_BYTES + 10)}}
    assert sink(client=client).put(event, "key") == metrics.REASON_OVERSIZE
    assert client.calls == []


def test_several_streams_are_picked_stably_by_key():
    streams = ("a", "b", "c")
    chosen = sink(streams=streams)
    first = chosen.stream_for("arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/gw-1")
    again = chosen.stream_for("arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/gw-1")
    assert first == again
    assert first in streams


@pytest.mark.parametrize(
    ("gateway", "stream"),
    [("gw-1", "b"), ("gw-2", "c"), ("gw-4", "a")],
)
def test_a_key_picks_the_same_stream_in_every_release(gateway, stream):
    key = f"arn:aws:bedrock-agentcore:us-west-2:123456789012:gateway/{gateway}"
    assert sink(streams=("a", "b", "c")).stream_for(key) == stream


def test_one_stream_needs_no_hashing():
    assert sink().stream_for("anything") == "stream-a"


def test_keys_spread_across_streams():
    chosen = sink(streams=("a", "b", "c"))
    picked = {chosen.stream_for(f"gateway-{index}") for index in range(50)}
    assert len(picked) > 1


def test_prepare_does_not_raise_without_credentials(monkeypatch, caplog):
    broken = FirehoseSink(("s",), 250, 500)
    monkeypatch.setattr(broken, "_firehose", boom)
    with caplog.at_level(logging.WARNING, logger="cerberus_agentcore_interceptor"):
        broken.prepare()

    assert "firehose client not ready: RuntimeError" in caplog.text
    assert "boom" not in caplog.text


def test_metrics_emit_one_embedded_metric_line(capsys):
    metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_THROTTLE, request_id="r-1")
    record = json.loads(capsys.readouterr().out.strip())

    assert record[metrics.CAPTURE_DROPPED] == 1
    assert record["Reason"] == metrics.REASON_THROTTLE
    assert record["request_id"] == "r-1"
    assert record["_aws"]["CloudWatchMetrics"][0]["Namespace"] == metrics.NAMESPACE
    assert record["_aws"]["CloudWatchMetrics"][0]["Dimensions"] == [[], ["Reason"]]


def test_metrics_without_a_reason_have_no_dimension(capsys):
    metrics.count(metrics.CAPTURED)
    record = json.loads(capsys.readouterr().out.strip())
    assert record["_aws"]["CloudWatchMetrics"][0]["Dimensions"] == [[]]
    assert "Reason" not in record


RFC_3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")


@pytest.mark.parametrize(
    ("metric", "reason", "level"),
    [
        (metrics.CAPTURED, "", "INFO"),
        (metrics.CAPTURE_DROPPED, metrics.REASON_SINK, "WARN"),
        (metrics.CAPTURE_DROPPED, metrics.REASON_CONFIG, "WARN"),
        (metrics.UNKNOWN_INPUT_VERSION, "", "WARN"),
        (metrics.UNEXPECTED_PHASE, "", "WARN"),
        (metrics.UNKNOWN_SHAPE, "", "WARN"),
    ],
)
def test_metric_lines_carry_the_level_lambda_filters_on(capsys, metric, reason, level):
    metrics.count(metric, reason)
    record = json.loads(capsys.readouterr().out.strip())

    assert record["level"] == level
    assert RFC_3339.fullmatch(record["timestamp"])
    stamped = datetime.fromisoformat(record["timestamp"]).timestamp() * 1000
    assert abs(stamped - record["_aws"]["Timestamp"]) <= 1


def test_a_field_cannot_replace_what_the_metric_line_needs(capsys):
    metrics.count(
        metrics.CAPTURE_DROPPED,
        metrics.REASON_SINK,
        level="INFO",
        Reason="other",
        CaptureDropped=5,
        _aws={},
    )
    record = json.loads(capsys.readouterr().out.strip())

    assert record["level"] == "WARN"
    assert record["Reason"] == metrics.REASON_SINK
    assert record[metrics.CAPTURE_DROPPED] == 1
    assert record["_aws"]["CloudWatchMetrics"][0]["Namespace"] == metrics.NAMESPACE


def test_metrics_never_raise(monkeypatch, capsys):
    monkeypatch.setattr(json, "dumps", boom)
    metrics.count(metrics.CAPTURED)


@pytest.mark.parametrize(
    "reason",
    [
        metrics.REASON_SINK,
        metrics.REASON_THROTTLE,
        metrics.REASON_TIMEOUT,
        metrics.REASON_DEADLINE,
        metrics.REASON_OVERSIZE,
        metrics.REASON_HANDLER,
        metrics.REASON_CONFIG,
    ],
)
def test_every_reason_is_a_short_label(reason):
    assert reason == reason.lower()
    assert " " not in reason
