from __future__ import annotations

import json
import socket

import pytest

from pwnx.errors import EndOfStream, ProtocolError, ReadTimeout, ReplayDivergence
from pwnx.trace import RecordingTube, ReplayTube, Trace
from pwnx.transport import DatagramTube, SocketTube, Tube


class ScriptedTube(Tube):
    def __init__(self, reads=()):
        super().__init__(timeout=0.1)
        self.reads = list(reads)
        self.written = bytearray()

    def _recv_raw(self, max_bytes, timeout):
        del max_bytes, timeout
        return self.reads.pop(0) if self.reads else b""

    def _send_raw(self, data, timeout):
        del timeout
        self.written.extend(data)
        return len(data)

    def _close_raw(self):
        pass


def recorded_conversation():
    trace = Trace(metadata={"profile": "test"})
    trace.append("receive", b"hello\n", operation="read_until")
    trace.append("send", b"x", operation="send")
    trace.append("receive", b"bye", operation="read_exact")
    trace.append("close", operation="close")
    return trace


def test_trace_json_round_trip_and_artifact_hash(tmp_path):
    artifact = tmp_path / "binary"
    artifact.write_bytes(b"\x7fELFfixture")
    trace = recorded_conversation()
    digest = trace.add_artifact("exe", artifact)
    path = tmp_path / "run.json"

    trace.save(path)
    loaded = Trace.load(path)

    assert loaded.metadata["artifacts"]["exe"]["sha256"] == digest
    assert loaded.diff(trace) == []
    assert "6 byte(s)" in loaded.explain(0)
    assert "data_base64" in path.read_text()
    assert "pickle" not in path.read_text().lower()


def test_recording_and_replay_allow_different_receive_boundaries():
    underlying = ScriptedTube([b"hello\n", b"bye"])
    recording = RecordingTube(underlying)
    assert recording.read_until(b"\n") == b"hello\n"
    recording.send(b"x")
    assert recording.read_exact(3) == b"bye"
    recording.close()

    replay = ReplayTube(recording.trace)
    assert replay.read_exact(2) == b"he"
    replay.send(b"x")
    assert replay.read_until(b"\n") == b"llo\n"
    assert replay.read_exact(3) == b"bye"
    replay.close()


def test_replay_cannot_read_across_outbound_barrier():
    replay = ReplayTube(recorded_conversation())

    with pytest.raises(ReplayDivergence, match="outbound effect"):
        replay.read_exact(7)

    assert replay.buffered_bytes == b"hello\n"


def test_replay_rejects_changed_and_additional_sends():
    replay = ReplayTube(recorded_conversation())
    replay.read_until(b"\n")
    with pytest.raises(ReplayDivergence, match="outbound divergence"):
        replay.send(b"y")

    trace = Trace()
    trace.append("send", b"x")
    replay = ReplayTube(trace)
    replay.send(b"x")
    with pytest.raises(ReplayDivergence, match="recording has ended"):
        replay.send(b"x")


def test_empty_send_is_a_replayed_effect():
    trace = Trace()
    trace.append("send", b"")
    trace.append("close")
    replay = ReplayTube(trace)
    replay.send(b"")
    replay.close()


def test_replay_close_detects_missing_send():
    replay = ReplayTube(recorded_conversation())
    replay.read_exact(2)

    with pytest.raises(ReplayDivergence, match="expects send"):
        replay.close()


def test_timeout_snapshot_replays_and_preserves_partial_bytes():
    underlying = ScriptedTube([b"ab", None, b"cd"])
    recording = RecordingTube(underlying)
    with pytest.raises(ReadTimeout):
        recording.read_exact(4)
    assert recording.read_exact(4) == b"abcd"
    recording.close()

    assert [event.kind for event in recording.trace.events] == [
        "timeout",
        "receive",
        "close",
    ]
    assert recording.trace.events[0].data == b"ab"
    assert recording.trace.events[1].data == b"cd"

    replay = ReplayTube(recording.trace)
    with pytest.raises(ReadTimeout):
        replay.read_exact(4)
    assert replay.buffered_bytes == b"ab"
    assert replay.read_exact(4) == b"abcd"
    replay.close()


def test_partial_eof_bytes_are_recorded_and_replayed():
    underlying = ScriptedTube([b"ab", b""])
    recording = RecordingTube(underlying)
    with pytest.raises(EndOfStream):
        recording.read_exact(4)
    assert recording.trace.events[0].kind == "error"
    assert recording.trace.events[0].data == b"ab"

    replay = ReplayTube(recording.trace)
    with pytest.raises(EndOfStream):
        replay.read_exact(4)
    assert replay.buffered_bytes == b"ab"
    assert replay.read_exact(2) == b"ab"


def test_recording_tracks_exact_sends_and_receives():
    underlying = ScriptedTube([b"ready"])
    trace = Trace()
    recording = RecordingTube(underlying, trace)

    assert recording.read_exact(5) == b"ready"
    recording.send(b"payload")
    recording.close()

    assert [(event.kind, event.data) for event in trace.events] == [
        ("receive", b"ready"),
        ("send", b"payload"),
        ("close", b""),
    ]
    assert underlying.written == b"payload"


def test_recording_convenience_failure_restores_wrapped_buffer():
    underlying = ScriptedTube([b"abc", None])
    recording = RecordingTube(underlying)
    with pytest.raises(ReadTimeout):
        recording.recvregex(rb"missing")
    assert recording.buffered_bytes == b"abc"
    assert recording.recvn(3) == b"abc"


def test_recording_captures_transport_read_ahead():
    underlying = ScriptedTube([b"abcdef"])
    recording = RecordingTube(underlying)
    assert recording.read_exact(2) == b"ab"
    recording.close()
    assert recording.trace.events[0].data == b"abcdef"

    replay = ReplayTube(recording.trace)
    assert replay.read_exact(6) == b"abcdef"
    replay.close()


def test_datagram_trace_and_replay_preserve_message_boundaries():
    with DatagramTube(bind=("127.0.0.1", 0), timeout=1) as server:
        with DatagramTube(*server.address, timeout=1) as client:
            recording = RecordingTube(client)
            recording.send_datagram(b"request")
            request, peer = server.recv_datagram()
            assert request == b"request" and peer is not None
            server.send_datagram(b"response", peer=peer)
            assert recording.recv_datagram()[0] == b"response"
            recording.close()

    replay = ReplayTube(recording.trace)
    replay.send_datagram(b"request")
    assert replay.recv_datagram()[0] == b"response"
    replay.close()

    replay = ReplayTube(recording.trace)
    with pytest.raises(ReplayDivergence, match="datagram API"):
        replay.read_some()


def test_shutdown_direction_is_causal_in_replay():
    left, right = socket.socketpair()
    try:
        recording = RecordingTube(SocketTube.from_socket(left))
        recording.shutdown("send")
        recording.close()
        right.close()

        replay = ReplayTube(recording.trace)
        replay.shutdown("send")
        replay.close()

        replay = ReplayTube(recording.trace)
        with pytest.raises(ReplayDivergence, match="shutdown divergence"):
            replay.shutdown("receive")
    finally:
        right.close()


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"format": "wrong", "metadata": {}, "events": []},
        {"format": "pwnx.trace.v1", "metadata": [], "events": []},
        {
            "format": "pwnx.trace.v1",
            "metadata": {},
            "events": [{"sequence": 0, "kind": "send", "data_base64": "***"}],
        },
        {
            "format": "pwnx.trace.v1",
            "metadata": {},
            "events": [{"sequence": 2, "kind": "send", "data_base64": ""}],
        },
    ],
)
def test_malformed_trace_rejected(tmp_path, document):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ProtocolError):
        Trace.load(path)


def test_diff_reports_first_level_changes():
    left = recorded_conversation()
    right = recorded_conversation()
    right.metadata["different"] = True
    right.events[1] = type(right.events[1])(
        kind="send",
        data=b"z",
        operation="send",
        sequence=1,
    )

    differences = left.diff(right)
    assert "metadata differs" in differences
    assert any("event 1 differs" in item for item in differences)
