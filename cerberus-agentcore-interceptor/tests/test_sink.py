import json

import pytest

from cerberus_agentcore_interceptor import metrics
from cerberus_agentcore_interceptor.sink import MAX_RECORD_BYTES, FirehoseSink


class FakeFirehose:
    def __init__(self, raises=None):
        self.calls = []
        self._raises = raises

    def put_record(self, **kwargs):
        self.calls.append(kwargs)
        if self._raises is not None:
            raise self._raises
        return {"RecordId": "r-1"}


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


def test_one_stream_needs_no_hashing():
    assert sink().stream_for("anything") == "stream-a"


def test_keys_spread_across_streams():
    chosen = sink(streams=("a", "b", "c"))
    picked = {chosen.stream_for(f"gateway-{index}") for index in range(50)}
    assert len(picked) > 1


def test_prepare_does_not_raise_without_credentials(monkeypatch):
    broken = FirehoseSink(("s",), 250, 500)
    monkeypatch.setattr(broken, "_firehose", _boom)
    broken.prepare()


def _boom(*args, **kwargs):
    raise RuntimeError("no credentials")


def test_metrics_emit_one_embedded_metric_line(capsys):
    metrics.count(metrics.CAPTURE_DROPPED, metrics.REASON_THROTTLE, request_id="r-1")
    record = json.loads(capsys.readouterr().out.strip())

    assert record[metrics.CAPTURE_DROPPED] == 1
    assert record["Reason"] == metrics.REASON_THROTTLE
    assert record["request_id"] == "r-1"
    assert record["_aws"]["CloudWatchMetrics"][0]["Namespace"] == metrics.NAMESPACE
    assert record["_aws"]["CloudWatchMetrics"][0]["Dimensions"] == [["Reason"]]


def test_metrics_without_a_reason_have_no_dimension(capsys):
    metrics.count(metrics.CAPTURED)
    record = json.loads(capsys.readouterr().out.strip())
    assert record["_aws"]["CloudWatchMetrics"][0]["Dimensions"] == [[]]
    assert "Reason" not in record


def test_metrics_never_raise(monkeypatch, capsys):
    monkeypatch.setattr(json, "dumps", _boom)
    metrics.count(metrics.CAPTURED)


@pytest.mark.parametrize(
    "reason",
    [
        metrics.REASON_SINK,
        metrics.REASON_THROTTLE,
        metrics.REASON_TIMEOUT,
        metrics.REASON_OVERSIZE,
        metrics.REASON_HANDLER,
    ],
)
def test_every_reason_is_a_short_label(reason):
    assert reason == reason.lower()
    assert " " not in reason
