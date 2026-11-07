from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pwnx.architecture import CredentialReference
from pwnx.errors import ConstraintError, ProtocolError
from pwnx.expressions import Expr
from pwnx.services import (
    AcquireWebArtifact,
    HTTPArtifactBackend,
    JSONCompetitionBackend,
    ShellUploadAction,
    SubmissionRequest,
    WebArtifact,
)
from pwnx.trace import RecordingTube, ReplayTube, Trace
from pwnx.transport import Tube


class NullTube(Tube):
    def _recv_raw(self, max_bytes, timeout):
        return b""

    def _send_raw(self, data, timeout):
        return len(data)

    def _close_raw(self):
        pass


class Runtime:
    def __init__(self, tube, trace):
        self.tube = tube
        self.trace = trace
        self.context = Context()
        self.bound = []

    def bind(self, target, value, *, source):
        self.bound.append((target, value, source))


class Context:
    def __init__(self):
        self.invalidated = []

    def invalidate(self, *values):
        self.invalidated.extend(values)


class FakeShell:
    name = "fixture-shell"
    identity = "fixture-shell:v1"

    def __init__(self, data: bytes, *, oversized: bool = False):
        self.data = data
        self.oversized = oversized
        self.commands = []

    def execute(self, command: str, *, deadline: float) -> bytes:
        self.commands.append((command, deadline))
        if "sha256sum" in command:
            if self.oversized:
                return b"x" * 5000
            digest = hashlib.sha256(self.data).hexdigest()
            return f"{digest}  artifact\n{len(self.data)}\n".encode()
        return b""


def test_submission_requires_explicit_authority_and_idempotency() -> None:
    backend = JSONCompetitionBackend("https://score.example/submit", requester=lambda *a: ())
    with pytest.raises(ConstraintError, match="irreversible"):
        SubmissionRequest(
            backend.endpoint,
            "heap",
            "flag{secret}",
            backend,
            idempotency_key="attempt-1",
        )
    with pytest.raises(ValueError, match="idempotency"):
        SubmissionRequest(
            backend.endpoint,
            "heap",
            "flag{secret}",
            backend,
            authorized=True,
        )


def test_json_submission_uses_credential_reference_and_refuses_redirects() -> None:
    calls = []

    def requester(request, deadline, context):
        calls.append((request, deadline, context))
        body = json.loads(request.data)
        assert body == {"challenge": "heap", "flag": "flag{value}"}
        assert request.headers["Authorization"] == "Bearer resolved-secret"
        return (
            200,
            {"Content-Type": "application/json"},
            b'{"accepted":true,"status":"correct","message":"ok"}',
            "https://score.example/submit",
        )

    backend = JSONCompetitionBackend(
        "https://score.example/submit",
        credential_resolver=lambda reference: f"Bearer {reference.name}-secret",
        requester=requester,
    )
    action = SubmissionRequest(
        backend.endpoint,
        "heap",
        "flag{value}",
        backend,
        credential=CredentialReference("resolved"),
        idempotency_key="attempt-1",
        authorized=True,
    )
    result = action.perform()
    assert result.accepted is True
    assert result.status == "correct"
    assert "flag{value}" not in repr(action)
    assert action.contract().writes == frozenset({"competition:submission"})
    assert len(calls) == 1

    redirected = JSONCompetitionBackend(
        backend.endpoint,
        requester=lambda *args: (200, {}, b"{}", "https://other.example/submit"),
    )
    with pytest.raises(ProtocolError, match="redirect"):
        SubmissionRequest(
            redirected.endpoint,
            "heap",
            "flag{value}",
            redirected,
            idempotency_key="attempt-2",
            authorized=True,
        ).perform()


def test_shell_upload_is_bounded_verified_and_replay_safe() -> None:
    data = b"portable payload"
    backend = FakeShell(data)
    target = Expr.fact("remote.artifact", scope="service")
    action = ShellUploadAction(data, "/tmp/name with spaces", backend, target=target)
    result = action.perform()
    assert result.artifact.sha256 == hashlib.sha256(data).hexdigest()
    assert result.artifact.size == len(data)
    assert result.commands == len(backend.commands)
    assert all(len(command) <= action.codec.max_command_length for command, _ in backend.commands)
    assert action.contract().writes == frozenset(
        {"filesystem:remote", "shell:commands"}
    )

    trace = Trace()
    recording = RecordingTube(NullTube(), trace)
    runtime = Runtime(recording, trace)
    live = action.execute(runtime)
    recording.close()
    call_count = len(backend.commands)
    assert runtime.bound[0][0] is target
    assert runtime.context.invalidated == ["remote.file./tmp/name with spaces"]

    replay = ReplayTube(trace)
    replayed = action.execute(Runtime(replay, None))
    replay.close()
    assert replayed == live
    assert len(backend.commands) == call_count

    with pytest.raises(ConstraintError, match="verification"):
        ShellUploadAction(data, "/tmp/value", FakeShell(data, oversized=True)).perform()


def test_web_artifact_is_content_addressed_cached_and_provenanced(tmp_path) -> None:
    data = b"known library artifact"
    digest = hashlib.sha256(data).hexdigest()
    calls = []

    def requester(request, deadline, context):
        calls.append((request, deadline, context))
        assert request.headers["Authorization"] == "token"
        return (
            200,
            {"Content-Type": "application/x-elf"},
            data,
            "https://artifacts.example/libc.so.6",
        )

    backend = HTTPArtifactBackend(
        credential_resolver=lambda reference: reference.name,
        requester=requester,
    )
    action = AcquireWebArtifact(
        "https://artifacts.example/libc.so.6",
        digest,
        str(tmp_path / "cache"),
        backend,
        credential=CredentialReference("token"),
    )
    assert calls == []
    first = action.perform()
    assert first == WebArtifact.from_dict(first.to_dict())
    assert first.cache_hit is False
    assert first.sha256 == digest
    assert Path(first.cache_path).read_bytes() == data
    assert first.content_type == "application/x-elf"
    assert action.contract().writes == frozenset({"filesystem:artifact-cache"})

    second = action.perform()
    assert second.cache_hit is True
    assert len(calls) == 1


def test_web_artifact_rejects_untrusted_inputs_and_preserves_replay_boundary(tmp_path) -> None:
    data = b"artifact"
    digest = hashlib.sha256(data).hexdigest()
    calls = []

    def requester(request, deadline, context):
        calls.append(request.full_url)
        return 200, {}, data, request.full_url

    backend = HTTPArtifactBackend(requester=requester)
    with pytest.raises(ConstraintError, match="plain HTTP"):
        AcquireWebArtifact("http://example/artifact", digest, str(tmp_path), backend)
    with pytest.raises(ConstraintError, match="cannot be used over plain HTTP"):
        AcquireWebArtifact(
            "http://example/artifact",
            digest,
            str(tmp_path),
            backend,
            credential=CredentialReference("token"),
            allow_insecure_http=True,
        )
    with pytest.raises(ConstraintError, match="same-origin"):
        AcquireWebArtifact(
            "https://example/artifact",
            digest,
            str(tmp_path),
            backend,
            credential=CredentialReference("token"),
            allow_cross_origin_redirects=True,
        )
    with pytest.raises(ValueError, match="SHA-256"):
        AcquireWebArtifact("https://example/artifact", "bad", str(tmp_path), backend)

    wrong = AcquireWebArtifact(
        "https://example/artifact",
        hashlib.sha256(b"different").hexdigest(),
        str(tmp_path / "wrong"),
        backend,
    )
    with pytest.raises(ProtocolError, match="does not match"):
        wrong.perform()
    assert not any((tmp_path / "wrong").iterdir())

    target = Expr.fact("artifact.web", scope="artifact")
    action = AcquireWebArtifact(
        "https://example/artifact",
        digest,
        str(tmp_path / "replay"),
        backend,
        target=target,
    )
    trace = Trace()
    recording = RecordingTube(NullTube(), trace)
    runtime = Runtime(recording, trace)
    live = action.execute(runtime)
    recording.close()
    call_count = len(calls)

    replay = ReplayTube(trace)
    replayed = action.execute(Runtime(replay, None))
    replay.close()
    assert replayed == live
    assert len(calls) == call_count
    assert runtime.bound[0][0] is target


def test_web_artifact_bounds_size_and_origin(tmp_path) -> None:
    data = b"12345"
    digest = hashlib.sha256(data).hexdigest()
    oversized = HTTPArtifactBackend(
        requester=lambda *args: (200, {}, data, "https://example/artifact")
    )
    with pytest.raises(ConstraintError, match="size bound"):
        AcquireWebArtifact(
            "https://example/artifact",
            digest,
            str(tmp_path / "large"),
            oversized,
            max_size=4,
        ).perform()

    redirected = HTTPArtifactBackend(
        requester=lambda *args: (200, {}, data, "https://mirror.example/artifact")
    )
    with pytest.raises(ProtocolError, match="cross-origin"):
        AcquireWebArtifact(
            "https://example/artifact",
            digest,
            str(tmp_path / "redirect"),
            redirected,
        ).perform()
