from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from pwnx.architecture import CredentialReference
from pwnx.errors import ConstraintError, ProtocolError
from pwnx.expressions import Expr
from pwnx.trace import RecordingTube, ReplayTube, Trace
from pwnx.transport import Tube
from pwnx.transfers import (
    ArtifactTransfer,
    OpenSSHBackend,
    RemoteArtifact,
    ShellCommandCodec,
    TransferResult,
)


def completed(argv, *, stdout=b"", stderr=b"", returncode=0):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


class NullTube(Tube):
    def _recv_raw(self, max_bytes, timeout):
        return b""

    def _send_raw(self, data, timeout):
        return len(data)

    def _close_raw(self):
        pass


class Context:
    def __init__(self):
        self.invalidated = []

    def invalidate(self, *values):
        self.invalidated.extend(values)


class Runtime:
    def __init__(self, tube, trace):
        self.tube = tube
        self.trace = trace
        self.context = Context()
        self.bound = []

    def bind(self, target, value, *, source):
        self.bound.append((target, value, source))


def test_shell_codec_quotes_untrusted_paths_and_bounds_commands() -> None:
    codec = ShellCommandCodec(max_command_length=180)
    rendered = codec.command("printf", "%s", "a; touch /tmp/pwned", "$(id)")
    assert "'a; touch /tmp/pwned'" in rendered
    assert "'$(id)'" in rendered
    commands = codec.upload_commands(
        b"A" * 256,
        "/tmp/name with spaces;rm -rf nope",
        executable=True,
    )
    assert all(len(command.encode()) <= 180 for command in commands)
    assert any("base64 -d" in command for command in commands)
    assert commands[-1].startswith("mv -- ")
    with pytest.raises(ValueError, match="NUL"):
        codec.quote("bad\0path")
    with pytest.raises(ConstraintError, match="maximum"):
        codec.command("x" * 500)


def test_transfer_action_is_inspectable_stable_and_serializable(tmp_path) -> None:
    source = tmp_path / "payload"
    source.write_bytes(b"PAYLOAD")
    backend = OpenSSHBackend("host", user="ctf", runner=lambda *a, **k: None)
    target = Expr.fact("remote.payload", scope="service")
    action = ArtifactTransfer.upload(
        source,
        "/tmp/payload",
        backend,
        target=target,
        executable=True,
    )
    assert action.output is target
    assert action.contract().writes == frozenset({"filesystem:remote"})
    assert action.input_digest == action.input_digest
    assert "upload remote artifact" in action.describe()
    assert ";rm" not in backend._ssh_argv(backend.shell.command("true"))

    artifact = RemoteArtifact(
        "/tmp/payload",
        hashlib.sha256(b"PAYLOAD").hexdigest(),
        7,
        "openssh",
        "service:ssh",
        "connection:ssh",
    )
    result = TransferResult("upload", artifact, str(source))
    assert TransferResult.from_dict(result.to_dict()) == result


def test_openssh_upload_uses_temporary_remote_path_and_verifies_hash(tmp_path) -> None:
    source = tmp_path / "payload"
    data = b"hello upload"
    source.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[0] == "ssh" and "sha256sum" in argv[-1]:
            return completed(argv, stdout=f"{digest}  file\n{len(data)}\n".encode())
        return completed(argv)

    backend = OpenSSHBackend(
        "example",
        user="ctf",
        credential=CredentialReference("key"),
        runner=runner,
    )
    action = ArtifactTransfer.upload(
        source,
        "/tmp/name with spaces;not-a-command",
        backend,
        executable=True,
    )
    result = action.perform()

    assert result.artifact is not None
    assert result.artifact.sha256 == digest
    assert calls[0][0][0] == "scp"
    assert ".pwnx-" in calls[0][0][-1]
    assert any("mv --" in call[0][-1] for call in calls if call[0][0] == "ssh")
    assert all(call[1]["timeout"] == action.deadline for call in calls)


def test_openssh_download_is_atomic_and_checks_remote_evidence(tmp_path) -> None:
    data = b"downloaded bytes"
    digest = hashlib.sha256(data).hexdigest()
    destination = tmp_path / "artifact"
    destination.write_bytes(b"old")

    def good_runner(argv, **kwargs):
        if argv[0] == "ssh":
            return completed(argv, stdout=f"{digest}  file\n{len(data)}\n".encode())
        Path(argv[-1]).write_bytes(data)
        return completed(argv)

    backend = OpenSSHBackend("example", runner=good_runner)
    action = ArtifactTransfer.download(
        "/remote/artifact",
        destination,
        backend,
        expected_sha256=digest,
    )
    result = action.perform()
    assert destination.read_bytes() == data
    assert result.local_path == str(destination.resolve())

    destination.write_bytes(b"preserve")

    def bad_runner(argv, **kwargs):
        if argv[0] == "ssh":
            return completed(argv, stdout=f"{digest}  file\n{len(data)}\n".encode())
        Path(argv[-1]).write_bytes(b"wrong")
        return completed(argv)

    bad_backend = OpenSSHBackend("example", runner=bad_runner)
    with pytest.raises(ProtocolError, match="does not match"):
        ArtifactTransfer.download(
            "/remote/artifact",
            destination,
            bad_backend,
        ).perform()
    assert destination.read_bytes() == b"preserve"
    assert not list(tmp_path.glob(".*.pwnx-download"))


def test_transfer_bounds_expected_hash_and_backend_failures(tmp_path) -> None:
    source = tmp_path / "large"
    source.write_bytes(b"12345")
    backend = OpenSSHBackend("example", runner=lambda argv, **kw: completed(argv))
    with pytest.raises(ConstraintError, match="maximum"):
        ArtifactTransfer.upload(source, "/tmp/x", backend, max_size=4).perform()

    failed = OpenSSHBackend(
        "example",
        runner=lambda argv, **kw: completed(argv, stderr=b"denied", returncode=1),
    )
    with pytest.raises(ProtocolError, match="denied"):
        ArtifactTransfer.stat("/tmp/x", failed).perform()


def test_insecure_known_host_policy_is_explicit_not_default() -> None:
    strict = OpenSSHBackend("example")
    insecure = OpenSSHBackend("example", known_hosts="insecure")
    assert "StrictHostKeyChecking=no" not in strict._policy()
    assert "StrictHostKeyChecking=no" in insecure._policy()
    assert strict.identity != insecure.identity


def test_transfer_action_records_and_reuses_result_without_repeating_effect() -> None:
    data = b"remote"
    digest = hashlib.sha256(data).hexdigest()
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return completed(argv, stdout=f"{digest}  file\n{len(data)}\n".encode())

    backend = OpenSSHBackend("example", runner=runner)
    target = Expr.fact("remote.stat", scope="service")
    action = ArtifactTransfer.stat("/tmp/value", backend, target=target)
    trace = Trace()
    recording = RecordingTube(NullTube(), trace)
    live_runtime = Runtime(recording, trace)
    result = action.execute(live_runtime)
    recording.close()
    assert result.artifact is not None
    assert len(calls) == 1
    assert [event.kind for event in trace.events] == [
        "opaque_start",
        "opaque",
        "close",
    ]
    assert live_runtime.bound[0][0] is target

    replay = ReplayTube(trace)
    replay_runtime = Runtime(replay, None)
    replayed = action.execute(replay_runtime)
    replay.close()
    assert replayed == result
    assert len(calls) == 1

    malformed = Trace()
    malformed.append(
        "opaque_start",
        operation=action.identity,
        details={"inputs_sha256": action.input_digest},
    )
    malformed.append(
        "opaque",
        b"[]",
        operation=action.identity,
        details={"buffered_base64": ""},
    )
    with pytest.raises(ProtocolError, match="recorded transfer"):
        action.execute(Runtime(ReplayTube(malformed), None))
