import json
import socket
import struct
import threading
from time import monotonic

import pytest
from botocore import exceptions as botocore_errors

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


class ForgetfulFirehose:
    """A local PutRecord endpoint that, once told to forget, resets older connections."""

    def __init__(self):
        self.forget = threading.Event()
        self.connections = 0
        self.records = 0
        self.sock = socket.create_server(("127.0.0.1", 0))
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.sock.getsockname()[1]}"

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        opened_before = not self.forget.is_set()
        reader = conn.makefile("rb")
        while _read_request(reader):
            if opened_before and self.forget.is_set():
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                break
            self.records += 1
            head = f"HTTP/1.1 200 OK\r\nContent-Length: {len(OK)}\r\n"
            conn.sendall(head.encode() + b"Content-Type: application/x-amz-json-1.1\r\n\r\n" + OK)
        reader.close()
        conn.close()


def _read_request(reader):
    line = reader.readline()
    length = 0
    while line not in (b"\r\n", b""):
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value)
        line = reader.readline()
    return bool(line) and len(reader.read(length)) == length


@pytest.fixture
def forgetful(monkeypatch, tmp_path):
    endpoint = ForgetfulFirehose()
    env = {
        "AWS_ENDPOINT_URL_FIREHOSE": endpoint.url,
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_ACCESS_KEY_ID": "AKIDEXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "example",
        "AWS_CONFIG_FILE": str(tmp_path / "none"),
        "AWS_SHARED_CREDENTIALS_FILE": str(tmp_path / "none"),
        "AWS_EC2_METADATA_DISABLED": "true",
        "NO_PROXY": "127.0.0.1",
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    for name in ("AWS_PROFILE", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)
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
    assert forgetful.records == 2


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
        metrics.REASON_DEADLINE,
        metrics.REASON_OVERSIZE,
        metrics.REASON_HANDLER,
        metrics.REASON_CONFIG,
    ],
)
def test_every_reason_is_a_short_label(reason):
    assert reason == reason.lower()
    assert " " not in reason
