from __future__ import annotations

import hashlib
import platform
import sys

import pytest

from pwnx.architecture import AMD64, ArchitectureSpec, SupportDecision
from pwnx.effects import (
    LinuxProcessSandbox,
    ShellcodeExecutionResult,
    ShellcodeExperiment,
)
from pwnx.errors import ConstraintError, ProtocolError
from pwnx.expressions import Expr
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
        self.bound = []

    def bind(self, target, value, *, source):
        self.bound.append((target, value, source))


class FixtureSandbox:
    name = "fixture-sandbox"
    identity = "fixture-sandbox:v1"

    def __init__(self):
        self.calls = 0

    def support(self, architecture: ArchitectureSpec) -> SupportDecision:
        return SupportDecision(True, (f"fixture supports {architecture.name}",))

    def execute(self, action: ShellcodeExperiment) -> ShellcodeExecutionResult:
        self.calls += 1
        return ShellcodeExecutionResult(
            hashlib.sha256(action.shellcode).hexdigest(),
            action.architecture.name,
            self.name,
            0.01,
            0,
            None,
            False,
            b"stdout",
            b"stderr",
            ("shellcode:0x1000-0x1001 rwx",),
            False,
            ("fixture execution",),
        )


def test_shellcode_experiment_requires_authority_and_bounds() -> None:
    backend = FixtureSandbox()
    with pytest.raises(ConstraintError, match="authorized"):
        ShellcodeExperiment(b"\xc3", backend)
    with pytest.raises(ValueError, match="non-empty"):
        ShellcodeExperiment(b"", backend, authorized=True)
    with pytest.raises(ConstraintError, match="maximum"):
        ShellcodeExperiment(b"AA", backend, authorized=True, max_shellcode_size=1)


def test_shellcode_experiment_is_self_describing_and_replay_safe() -> None:
    backend = FixtureSandbox()
    target = Expr.fact("experiment.shellcode", scope="process")
    shellcode = bytes.fromhex("deadbeefcafebabe")
    action = ShellcodeExperiment(
        shellcode,
        backend,
        authorized=True,
        deadline=0.25,
        max_output=64,
        target=target,
    )
    contract = action.contract()
    assert contract.reads == frozenset({"host:execution"})
    assert contract.writes == frozenset({"sandbox:process"})
    assert contract.provides == (target,)
    assert "fixture-sandbox" in action.describe()
    rendered = repr(action)
    assert "shellcode=" not in rendered
    assert repr(shellcode) not in rendered
    assert shellcode.hex() not in rendered

    trace = Trace()
    recording = RecordingTube(NullTube(), trace)
    runtime = Runtime(recording, trace)
    live = action.execute(runtime)
    recording.close()
    assert backend.calls == 1
    assert live.succeeded
    assert live.maps_sha256 == hashlib.sha256(b"shellcode:0x1000-0x1001 rwx").hexdigest()
    assert runtime.bound[0][0] is target

    replay = ReplayTube(trace)
    replayed = action.execute(Runtime(replay, None))
    replay.close()
    assert replayed == live
    assert backend.calls == 1


def test_shellcode_result_rejects_corrupt_map_evidence() -> None:
    result = FixtureSandbox().execute(
        ShellcodeExperiment(b"\xc3", FixtureSandbox(), authorized=True)
    )
    value = result.to_dict()
    value["maps_sha256"] = "0" * 64
    with pytest.raises(ProtocolError, match="map evidence"):
        ShellcodeExecutionResult.from_dict(value)


def test_linux_backend_reports_support_honestly() -> None:
    backend = LinuxProcessSandbox()
    decision = backend.support(AMD64)
    if not sys.platform.startswith("linux"):
        assert not decision.supported
        assert "Linux" in " ".join(decision.reasons)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="reference sandbox uses Linux resource isolation",
)
def test_linux_backend_executes_host_return_instruction() -> None:
    backend = LinuxProcessSandbox()
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        architecture = AMD64
        code = b"\xc3"
    elif machine in {"aarch64", "arm64"}:
        from pwnx.architecture import AARCH64

        architecture = AARCH64
        code = b"\xc0\x03\x5f\xd6"
    else:
        pytest.skip(f"no return instruction fixture for {machine}")
    result = ShellcodeExperiment(
        code,
        backend,
        architecture,
        authorized=True,
        deadline=2.0,
    ).perform()
    assert result.succeeded
    assert result.maps
    assert result.shellcode_sha256 == hashlib.sha256(code).hexdigest()
    assert "security boundary" in " ".join(result.evidence)
