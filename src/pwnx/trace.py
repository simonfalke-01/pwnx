"""Portable event traces, recording, and causality-aware replay."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .errors import EndOfStream, ProtocolError, ReadTimeout, ReplayDivergence
from .transport import Tube

_FORMAT = "pwnx.trace.v1"
_BYTE_EVENTS = {
    "send", "receive", "timeout", "opaque",
    "datagram_send", "datagram_receive",
}
_EVENT_KINDS = _BYTE_EVENTS | {
    "close", "error", "interactive", "opaque_start", "shutdown",
}


@dataclass(frozen=True, slots=True)
class TraceEvent:
    kind: str
    data: bytes = b""
    operation: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    sequence: int = -1
    timestamp_ns: int = 0

    def __post_init__(self) -> None:
        if self.kind not in _EVENT_KINDS:
            raise ProtocolError(f"unknown trace event kind {self.kind!r}")
        if not isinstance(self.data, bytes):
            raise ProtocolError("trace event data must be bytes")
        if not isinstance(self.details, dict):
            raise ProtocolError("trace event details must be an object")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "sequence": self.sequence,
            "kind": self.kind,
            "operation": self.operation,
            "details": self.details,
            "timestamp_ns": self.timestamp_ns,
        }
        if self.kind in _BYTE_EVENTS or self.data:
            result["data_base64"] = base64.b64encode(self.data).decode("ascii")
            result["size"] = len(self.data)
        return result

    @classmethod
    def from_dict(cls, raw: Any, expected_sequence: int) -> TraceEvent:
        if not isinstance(raw, dict):
            raise ProtocolError(f"trace event {expected_sequence} must be an object")
        kind = raw.get("kind")
        if not isinstance(kind, str) or kind not in _EVENT_KINDS:
            raise ProtocolError(f"trace event {expected_sequence} has invalid kind")
        sequence = raw.get("sequence", expected_sequence)
        if sequence != expected_sequence:
            raise ProtocolError(
                f"trace event sequence mismatch: expected {expected_sequence}, got {sequence!r}"
            )
        encoded = raw.get("data_base64", "")
        if not isinstance(encoded, str):
            raise ProtocolError(f"trace event {sequence} data_base64 must be a string")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ProtocolError(f"trace event {sequence} contains invalid base64") from exc
        size = raw.get("size", len(data))
        if not isinstance(size, int) or size != len(data):
            raise ProtocolError(f"trace event {sequence} byte length does not match size")
        operation = raw.get("operation", "")
        details = raw.get("details", {})
        timestamp_ns = raw.get("timestamp_ns", 0)
        if not isinstance(operation, str):
            raise ProtocolError(f"trace event {sequence} operation must be a string")
        if not isinstance(details, dict):
            raise ProtocolError(f"trace event {sequence} details must be an object")
        if not isinstance(timestamp_ns, int) or timestamp_ns < 0:
            raise ProtocolError(f"trace event {sequence} timestamp_ns must be non-negative")
        return cls(kind, data, operation, details, sequence, timestamp_ns)


class Trace:
    """An append-only, JSON-serializable event ledger."""

    def __init__(
        self,
        *,
        metadata: dict[str, Any] | None = None,
        events: list[TraceEvent] | None = None,
    ) -> None:
        self.metadata = dict(metadata or {})
        self.events = list(events or [])
        self._lock = threading.RLock()
        for sequence, event in enumerate(self.events):
            if event.sequence != sequence:
                raise ProtocolError(
                    f"trace event sequence mismatch: expected {sequence}, got {event.sequence}"
                )

    def append(
        self,
        kind: str,
        data: bytes = b"",
        *,
        operation: str = "",
        details: dict[str, Any] | None = None,
    ) -> TraceEvent:
        with self._lock:
            event = TraceEvent(
                kind=kind,
                data=bytes(data),
                operation=operation,
                details=dict(details or {}),
                sequence=len(self.events),
                timestamp_ns=time.time_ns(),
            )
            self.events.append(event)
            return event

    def add_artifact(self, name: str, path: str | os.PathLike[str]) -> str:
        artifact_path = Path(path)
        digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        artifacts = self.metadata.setdefault("artifacts", {})
        if not isinstance(artifacts, dict):
            raise ProtocolError("trace metadata.artifacts must be an object")
        artifacts[name] = {
            "path": os.fspath(artifact_path),
            "sha256": digest,
            "size": artifact_path.stat().st_size,
        }
        return digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": _FORMAT,
            "metadata": self.metadata,
            "events": [event.to_dict() for event in self.events],
        }

    def save(self, path: str | os.PathLike[str]) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            self.to_dict(),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        ) + "\n"
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            text=True,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> Trace:
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ProtocolError(f"could not load trace {os.fspath(path)!r}: {exc}") from exc
        if not isinstance(raw, dict) or raw.get("format") != _FORMAT:
            raise ProtocolError(f"trace must use format {_FORMAT!r}")
        metadata = raw.get("metadata", {})
        events = raw.get("events")
        if not isinstance(metadata, dict):
            raise ProtocolError("trace metadata must be an object")
        if not isinstance(events, list):
            raise ProtocolError("trace events must be an array")
        parsed = [
            TraceEvent.from_dict(event, sequence)
            for sequence, event in enumerate(events)
        ]
        return cls(metadata=metadata, events=parsed)

    def explain(self, sequence: int) -> str:
        try:
            event = self.events[sequence]
        except IndexError as exc:
            raise IndexError(f"trace has no event {sequence}") from exc
        preview = event.data.hex(" ")
        if len(preview) > 95:
            preview = preview[:92] + "..."
        label = event.operation or event.kind
        return (
            f"event {event.sequence}: {event.kind} via {label}; "
            f"{len(event.data)} byte(s)"
            + (f": {preview}" if preview else "")
        )

    def diff(self, other: Trace) -> list[str]:
        differences: list[str] = []
        left_payloads = {
            item.get("send_id"): item
            for item in self.metadata.get("payloads", [])
            if item.get("send_id")
        }
        right_payloads = {
            item.get("send_id"): item
            for item in other.metadata.get("payloads", [])
            if item.get("send_id")
        }
        for send_id in sorted(left_payloads.keys() & right_payloads.keys()):
            left_item = left_payloads[send_id]
            right_item = right_payloads[send_id]
            if left_item.get("sha256") == right_item.get("sha256"):
                continue
            left_bytes = bytes.fromhex(left_item.get("bytes", ""))
            right_bytes = bytes.fromhex(right_item.get("bytes", ""))
            left_layout = left_item.get("layout", [])
            right_layout = right_item.get("layout", [])

            def label(layout, offset):
                matches = [
                    row
                    for row in layout
                    if int(row.get("offset", 0)) <= offset < int(row.get("end", 0))
                ]
                if not matches:
                    return "unlabelled bytes"
                matches.sort(key=lambda row: row.get("kind") == "patch")
                return str(matches[-1].get("label", "unlabelled bytes"))

            boundaries = {0, len(left_bytes), len(right_bytes)}
            for row in (*left_layout, *right_layout):
                boundaries.update((int(row.get("offset", 0)), int(row.get("end", 0))))
            ordered = sorted(boundaries)
            for start, end in zip(ordered, ordered[1:]):
                if left_bytes[start:end] == right_bytes[start:end]:
                    continue
                differences.append(
                    f"payload {left_item.get('name', 'payload')} send {send_id} "
                    f"changed {start:#x}..{end:#x}: "
                    f"{label(left_layout, start)} -> {label(right_layout, start)}"
                )
        if self.metadata != other.metadata:
            differences.append("metadata differs")
        common = min(len(self.events), len(other.events))
        for index in range(common):
            left, right = self.events[index], other.events[index]
            if (left.kind, left.data, left.operation, left.details) != (
                right.kind,
                right.data,
                right.operation,
                right.details,
            ):
                differences.append(
                    f"event {index} differs: "
                    f"{left.kind}/{len(left.data)} bytes != "
                    f"{right.kind}/{len(right.data)} bytes"
                )
        if len(self.events) != len(other.events):
            differences.append(
                f"event count differs: {len(self.events)} != {len(other.events)}"
            )
        return differences


class RecordingTube(Tube):
    """A transparent recording wrapper around another Tube."""

    def __init__(self, tube: Tube, trace: Trace | None = None) -> None:
        super().__init__(timeout=tube.default_timeout)
        self.tube = tube
        self.trace = trace or Trace()
        self._recorded_pending = b""

    @property
    def buffered_bytes(self) -> bytes:
        return self.tube.buffered_bytes

    @property
    def closed(self) -> bool:
        return self.tube.closed

    def unrecv(self, data: bytes | bytearray | memoryview) -> None:
        self.tube.unrecv(data)

    unread = unrecv

    def read_exact(self, n: int, timeout: float | None = None) -> bytes:
        return self._record_read("read_exact", lambda: self.tube.read_exact(n, timeout))

    def read_until(
        self,
        delimiter: bytes,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        details = {"delimiter_base64": base64.b64encode(bytes(delimiter)).decode("ascii")}
        return self._record_read(
            "read_until",
            lambda: self.tube.read_until(delimiter, timeout, max_bytes),
            details,
        )

    def read_some(self, n: int = 4096, timeout: float | None = None) -> bytes:
        return self._record_read("read_some", lambda: self.tube.read_some(n, timeout))

    def send(self, data: bytes, timeout: float | None = None) -> None:
        payload = bytes(data)
        try:
            self.tube.send(payload, timeout)
        except Exception as exc:
            self.trace.append(
                "error",
                operation="send",
                details={"type": type(exc).__name__, "message": str(exc)},
            )
            raise
        self.trace.append("send", payload, operation="send")

    def recv_datagram(
        self, max_size: int = 65535, timeout: float | None = None
    ) -> tuple[bytes, tuple[str, int] | None]:
        receiver = getattr(self.tube, "recv_datagram", None)
        if not callable(receiver):
            raise ProtocolError("wrapped transport is not message-oriented")
        data, peer = receiver(max_size, timeout)
        self.trace.append(
            "datagram_receive",
            data,
            operation="recv_datagram",
            details={"peer": list(peer) if peer is not None else None},
        )
        return data, peer

    def send_datagram(
        self,
        data: bytes,
        *,
        peer: tuple[str, int] | None = None,
        timeout: float | None = None,
    ) -> None:
        sender = getattr(self.tube, "send_datagram", None)
        if not callable(sender):
            raise ProtocolError("wrapped transport is not message-oriented")
        payload = bytes(data)
        sender(payload, peer=peer, timeout=timeout)
        self.trace.append(
            "datagram_send",
            payload,
            operation="send_datagram",
            details={"peer": list(peer) if peer is not None else None},
        )

    def interactive(self) -> None:
        self.trace.append("interactive", operation="interactive")
        self.tube.interactive()

    def close(self) -> None:
        if self.tube.closed:
            return
        self.tube.close()
        self.trace.append("close", operation="close")

    def shutdown(self, direction: str = "both") -> None:
        self.tube.shutdown(direction)
        self.trace.append(
            "shutdown",
            operation="shutdown",
            details={"direction": direction},
        )

    def _record_read(
        self,
        operation: str,
        reader: Callable[[], bytes],
        details: dict[str, Any] | None = None,
    ) -> bytes:
        try:
            data = reader()
        except ReadTimeout:
            snapshot = self.tube.buffered_bytes
            new_data = (
                snapshot[len(self._recorded_pending) :]
                if snapshot.startswith(self._recorded_pending)
                else snapshot
            )
            self._recorded_pending = snapshot
            self.trace.append(
                "timeout",
                new_data,
                operation=operation,
                details={"buffered_size": len(snapshot), **(details or {})},
            )
            raise
        except EndOfStream as exc:
            snapshot = self.tube.buffered_bytes
            new_data = (
                snapshot[len(self._recorded_pending) :]
                if snapshot.startswith(self._recorded_pending)
                else snapshot
            )
            self._recorded_pending = snapshot
            self.trace.append(
                "error",
                new_data,
                operation=operation,
                details={
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "buffered_size": len(snapshot),
                },
            )
            raise

        # Include bytes read ahead by the wrapped Tube, not only bytes returned
        # to this caller. This records the actual incoming stream and lets replay
        # use different parsing boundaries.
        buffered = self.tube.buffered_bytes
        visible_stream = data + buffered
        pending = self._recorded_pending
        new_data = (
            visible_stream[len(pending) :]
            if visible_stream.startswith(pending)
            else visible_stream
        )
        self._recorded_pending = buffered
        if new_data:
            self.trace.append(
                "receive",
                new_data,
                operation=operation,
                details=details,
            )
        return data

    def _recv_raw(self, max_bytes: int, timeout: float) -> bytes | None:
        raise NotImplementedError

    def _send_raw(self, data: memoryview, timeout: float) -> int | None:
        raise NotImplementedError

    def _close_raw(self) -> None:
        self.close()


class ReplayTube(Tube):
    """A Tube backed by a recorded trace.

    Receive boundaries may change. Outbound effects remain exact causal
    barriers.
    """

    def __init__(self, trace: Trace, *, timeout: float = 3.0) -> None:
        super().__init__(timeout=timeout)
        self.trace = trace
        self._event_index = 0
        self.message_oriented = any(
            event.kind in {"datagram_send", "datagram_receive"}
            for event in trace.events
        )

    @property
    def event_index(self) -> int:
        return self._event_index

    def _recv_raw(self, max_bytes: int, timeout: float) -> bytes | None:
        del max_bytes, timeout
        while self._event_index < len(self.trace.events):
            event = self.trace.events[self._event_index]
            if event.kind == "receive":
                self._event_index += 1
                return event.data
            if event.kind == "timeout":
                self._event_index += 1
                if event.data:
                    self._buffer.extend(event.data)
                return None
            if event.kind == "error":
                self._event_index += 1
                if event.data:
                    self._buffer.extend(event.data)
                if event.details.get("type") == "EndOfStream":
                    return b""
                raise ProtocolError(
                    f"recorded {event.operation or 'operation'} failed: "
                    f"{event.details.get('message', event.details.get('type', 'unknown error'))}"
                )
            if event.kind == "close":
                return b""
            if event.kind == "send":
                raise ReplayDivergence(
                    f"replay needs outbound effect at event {event.sequence} "
                    "before additional input can be consumed"
                )
            if event.kind == "interactive":
                raise ReplayDivergence(
                    f"replay reached interactive boundary at event {event.sequence}"
                )
            if event.kind in {"opaque_start", "opaque"}:
                raise ReplayDivergence(
                    f"replay must execute opaque boundary at event {event.sequence} "
                    "before consuming more transport input"
                )
            if event.kind in {"datagram_send", "datagram_receive"}:
                raise ReplayDivergence(
                    f"replay must use datagram API at event {event.sequence}; "
                    "message boundaries cannot be consumed as a byte stream"
                )
        return b""

    def send(self, data: bytes, timeout: float | None = None) -> None:
        payload = bytes(data)
        if payload:
            super().send(payload, timeout)
            return
        self._prefetch_incoming()
        event = self._next_event("send")
        if event.data:
            raise ReplayDivergence(
                f"outbound divergence at event {event.sequence}, byte 0: "
                f"recorded {event.data.hex(' ')}; current <empty>"
            )
        self._event_index += 1

    def recv_datagram(
        self, max_size: int = 65535, timeout: float | None = None
    ) -> tuple[bytes, tuple[str, int] | None]:
        del timeout
        self._prefetch_incoming()
        event = self._next_event("datagram_receive")
        if len(event.data) > max_size:
            raise ProtocolError(
                f"recorded datagram is {len(event.data)} bytes, limit is {max_size}"
            )
        peer_raw = event.details.get("peer")
        peer = (
            (str(peer_raw[0]), int(peer_raw[1]))
            if isinstance(peer_raw, list) and len(peer_raw) == 2
            else None
        )
        self._event_index += 1
        return event.data, peer

    def send_datagram(
        self,
        data: bytes,
        *,
        peer: tuple[str, int] | None = None,
        timeout: float | None = None,
    ) -> None:
        del timeout
        self._prefetch_incoming()
        event = self._next_event("datagram_send")
        actual = bytes(data)
        recorded_peer = event.details.get("peer")
        current_peer = list(peer) if peer is not None else None
        if actual != event.data or current_peer != recorded_peer:
            raise ReplayDivergence(
                f"datagram divergence at event {event.sequence}: "
                f"recorded data={event.data!r} peer={recorded_peer!r}; "
                f"current data={actual!r} peer={current_peer!r}"
            )
        self._event_index += 1

    def _send_raw(self, data: memoryview, timeout: float) -> int | None:
        del timeout
        self._prefetch_incoming()
        event = self._next_event("send")
        actual = bytes(data)
        if actual != event.data:
            mismatch = _first_difference(actual, event.data)
            raise ReplayDivergence(
                f"outbound divergence at event {event.sequence}, byte {mismatch}: "
                f"recorded {event.data.hex(' ') or '<empty>'}; "
                f"current {actual.hex(' ') or '<empty>'}"
            )
        self._event_index += 1
        return len(actual)

    def close(self) -> None:
        if self._closed:
            return
        self._prefetch_incoming()
        if self._event_index >= len(self.trace.events):
            raise ReplayDivergence("current run closed, but the recording has no close event")
        event = self.trace.events[self._event_index]
        if event.kind != "close":
            raise ReplayDivergence(
                f"current run closed at event {self._event_index}; "
                f"recording expects {event.kind}"
            )
        self._event_index += 1
        self._closed = True
        self.assert_complete()

    def shutdown(self, direction: str = "both") -> None:
        self._prefetch_incoming()
        event = self._next_event("shutdown")
        if event.details.get("direction") != direction:
            raise ReplayDivergence(
                f"shutdown divergence at event {event.sequence}: "
                f"recorded {event.details.get('direction')!r}, current {direction!r}"
            )
        self._event_index += 1
        if direction == "both":
            self._closed = True

    def assert_complete(self, *, allow_unread_input: bool = True) -> None:
        index = self._event_index
        while allow_unread_input and index < len(self.trace.events):
            event = self.trace.events[index]
            if event.kind in {"receive", "timeout"}:
                index += 1
                continue
            if event.kind == "error" and event.details.get("type") in {
                "ReadTimeout",
                "EndOfStream",
            }:
                index += 1
                continue
            else:
                break
        if index != len(self.trace.events):
            event = self.trace.events[index]
            raise ReplayDivergence(
                f"replay ended before recorded {event.kind} at event {event.sequence}"
            )

    def interactive(self) -> None:
        self._prefetch_incoming()
        self._next_event("interactive")
        self._event_index += 1

    def consume_opaque(self, identity: str, inputs_sha256: str) -> bytes:
        """Return a recorded opaque result when its code and inputs still match."""

        self._prefetch_incoming()
        start = self._next_event("opaque_start")
        if start.operation != identity:
            raise ReplayDivergence(
                f"opaque action changed at event {start.sequence}: "
                f"recorded {start.operation!r}, current {identity!r}"
            )
        recorded_inputs = start.details.get("inputs_sha256")
        if recorded_inputs != inputs_sha256:
            raise ReplayDivergence(
                f"opaque inputs changed at event {start.sequence}: "
                f"recorded {recorded_inputs!r}, current {inputs_sha256!r}"
            )
        self._event_index += 1
        while self._event_index < len(self.trace.events):
            event = self.trace.events[self._event_index]
            self._event_index += 1
            if event.kind == "opaque" and event.operation == identity:
                encoded_buffer = event.details.get("buffered_base64", "")
                if not isinstance(encoded_buffer, str):
                    raise ReplayDivergence(
                        f"opaque buffer snapshot at event {event.sequence} is malformed"
                    )
                try:
                    snapshot = base64.b64decode(encoded_buffer, validate=True)
                except (binascii.Error, ValueError) as error:
                    raise ReplayDivergence(
                        f"opaque buffer snapshot at event {event.sequence} is malformed"
                    ) from error
                self._buffer[:] = snapshot
                return event.data
        raise ReplayDivergence(
            f"recorded opaque action {identity!r} has no matching result boundary"
        )

    def _prefetch_incoming(self) -> None:
        while self._event_index < len(self.trace.events):
            event = self.trace.events[self._event_index]
            if event.kind in {"receive", "timeout"}:
                self._buffer.extend(event.data)
                self._event_index += 1
                continue
            if event.kind == "error" and event.details.get("type") == "ReadTimeout":
                self._event_index += 1
                continue
            break

    def _next_event(self, expected: str) -> TraceEvent:
        if self._event_index >= len(self.trace.events):
            raise ReplayDivergence(
                f"current run produced {expected}, but the recording has ended"
            )
        event = self.trace.events[self._event_index]
        if event.kind != expected:
            raise ReplayDivergence(
                f"current run produced {expected} at event {event.sequence}; "
                f"recording expects {event.kind}"
            )
        return event

    def _close_raw(self) -> None:
        pass


def _first_difference(left: bytes, right: bytes) -> int:
    limit = min(len(left), len(right))
    for index in range(limit):
        if left[index] != right[index]:
            return index
    return limit
