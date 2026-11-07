"""Bounded experiments for target-side effects.

Effect experiments are explicit external actions.  Construction is pure;
execution happens only through a declared backend and is recorded as one
opaque result so replay never executes the effect a second time.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol

from .actions import Action
from .architecture import AMD64, ArchitectureSpec, SupportDecision
from .domain import EffectContract, Evidence, Scope
from .errors import ConstraintError, ProtocolError, UnsupportedFeature
from .expressions import Expr
from .trace import ReplayTube


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _host_architecture() -> str | None:
    machine = platform.machine().lower()
    return {
        "x86_64": "amd64",
        "amd64": "amd64",
        "i386": "i386",
        "i686": "i386",
        "aarch64": "aarch64",
        "arm64": "aarch64",
    }.get(machine)


@dataclass(frozen=True, slots=True)
class ShellcodeExecutionResult:
    """Portable evidence from one isolated shellcode attempt."""

    shellcode_sha256: str
    architecture: str
    backend: str
    duration: float
    exit_code: int | None
    signal: int | None
    timed_out: bool
    stdout: bytes = b""
    stderr: bytes = b""
    maps: tuple[str, ...] = ()
    output_truncated: bool = False
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if len(self.shellcode_sha256) != 64:
            raise ValueError("shellcode result requires a SHA-256 digest")
        if not self.architecture or not self.backend or self.duration < 0:
            raise ValueError("shellcode result has invalid identity or duration")
        if self.exit_code is not None and self.signal is not None:
            raise ValueError("a process result cannot have both exit code and signal")
        if self.signal is not None and self.signal <= 0:
            raise ValueError("process signal must be positive")

    @property
    def maps_sha256(self) -> str:
        return hashlib.sha256("\n".join(self.maps).encode()).hexdigest()

    @property
    def succeeded(self) -> bool:
        return not self.timed_out and self.signal is None and self.exit_code == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "shellcode_sha256": self.shellcode_sha256,
            "architecture": self.architecture,
            "backend": self.backend,
            "duration": self.duration,
            "exit_code": self.exit_code,
            "signal": self.signal,
            "timed_out": self.timed_out,
            "stdout_base64": base64.b64encode(self.stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(self.stderr).decode("ascii"),
            "maps": list(self.maps),
            "maps_sha256": self.maps_sha256,
            "output_truncated": self.output_truncated,
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ShellcodeExecutionResult":
        try:
            stdout = base64.b64decode(str(value["stdout_base64"]), validate=True)
            stderr = base64.b64decode(str(value["stderr_base64"]), validate=True)
            result = cls(
                str(value["shellcode_sha256"]),
                str(value["architecture"]),
                str(value["backend"]),
                float(value["duration"]),
                None if value.get("exit_code") is None else int(value["exit_code"]),
                None if value.get("signal") is None else int(value["signal"]),
                bool(value["timed_out"]),
                stdout,
                stderr,
                tuple(str(item) for item in value.get("maps", ())),
                bool(value.get("output_truncated", False)),
                tuple(str(item) for item in value.get("evidence", ())),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ProtocolError("recorded shellcode result is malformed") from error
        recorded_maps = value.get("maps_sha256")
        if recorded_maps is not None and str(recorded_maps) != result.maps_sha256:
            raise ProtocolError("recorded shellcode map evidence digest is invalid")
        return result

    def describe(self) -> str:
        if self.timed_out:
            status = "timeout"
        elif self.signal is not None:
            status = f"signal {self.signal}"
        else:
            status = f"exit {self.exit_code}"
        return (
            f"shellcode {self.shellcode_sha256[:12]} on {self.architecture}: "
            f"{status} in {self.duration:.3f}s"
        )


class ShellcodeSandboxBackend(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def identity(self) -> str: ...

    def support(self, architecture: ArchitectureSpec) -> SupportDecision: ...

    def execute(self, action: "ShellcodeExperiment") -> ShellcodeExecutionResult: ...


_HELPER = r"""
import ctypes
import json
import mmap
import pathlib
import sys

code = pathlib.Path(sys.argv[1]).read_bytes()
metadata = pathlib.Path(sys.argv[2])
mapping = mmap.mmap(
    -1,
    len(code),
    flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
    prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
)
mapping.write(code)
address = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
maps = [f"shellcode:{address:#x}-{address + len(code):#x} rwx"]
try:
    maps.extend(pathlib.Path("/proc/self/maps").read_text(errors="replace").splitlines())
except OSError as error:
    maps.append(f"maps-unavailable:{type(error).__name__}:{error}")
metadata.write_text(json.dumps({"maps": maps}, separators=(",", ":")))
function = ctypes.CFUNCTYPE(None)(address)
function()
"""


@dataclass(frozen=True, slots=True)
class LinuxProcessSandbox:
    """Reference Linux subprocess containment backend.

    This backend applies process, CPU, address-space, file-size, descriptor,
    core-dump, deadline, and process-group bounds.  It is a containment aid for
    challenge payloads, not a hardened boundary for hostile native code.
    """

    python: str = sys.executable
    name: str = "linux-process-sandbox"

    @property
    def identity(self) -> str:
        return _digest(
            {"name": self.name, "python": str(Path(self.python).resolve()), "version": 1}
        )

    def support(self, architecture: ArchitectureSpec) -> SupportDecision:
        reasons: list[str] = []
        if not sys.platform.startswith("linux"):
            reasons.append("Linux resource and process-group isolation is required")
        host = _host_architecture()
        if host is None:
            reasons.append(f"host architecture {platform.machine()!r} is unknown")
        elif architecture.name != host:
            reasons.append(f"payload architecture {architecture.name} does not match host {host}")
        if not Path(self.python).is_file():
            reasons.append(f"Python helper {self.python!r} is unavailable")
        return SupportDecision(not reasons, tuple(reasons))

    @staticmethod
    def _limits(action: "ShellcodeExperiment") -> Any:
        def apply() -> None:
            import resource

            cpu = max(1, math.ceil(action.deadline))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            resource.setrlimit(resource.RLIMIT_AS, (action.max_memory, action.max_memory))
            resource.setrlimit(resource.RLIMIT_FSIZE, (action.max_output, action.max_output))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            descriptor_limit = min(64, resource.getrlimit(resource.RLIMIT_NOFILE)[1])
            resource.setrlimit(resource.RLIMIT_NOFILE, (descriptor_limit, descriptor_limit))

        return apply

    @staticmethod
    def _terminate_group(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def execute(self, action: "ShellcodeExperiment") -> ShellcodeExecutionResult:
        decision = self.support(action.architecture)
        decision.require(self.name)
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="pwnx-shellcode-") as directory:
            root = Path(directory)
            payload_path = root / "payload.bin"
            metadata_path = root / "maps.json"
            stdout_path = root / "stdout"
            stderr_path = root / "stderr"
            payload_path.write_bytes(action.shellcode)
            with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                try:
                    process = subprocess.Popen(
                        (self.python, "-I", "-c", _HELPER, str(payload_path), str(metadata_path)),
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        close_fds=True,
                        start_new_session=True,
                        preexec_fn=self._limits(action),
                    )
                except OSError as error:
                    raise UnsupportedFeature(
                        f"cannot start shellcode sandbox helper: {error}"
                    ) from error
                timed_out = False
                try:
                    process.wait(timeout=action.deadline)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    self._terminate_group(process)
                    process.wait()
                else:
                    # A payload may leave descendants behind after returning.
                    self._terminate_group(process)

            duration = time.monotonic() - started
            stdout_size = stdout_path.stat().st_size
            stderr_size = stderr_path.stat().st_size
            stdout = stdout_path.read_bytes()[: action.max_output]
            remaining = max(0, action.max_output - len(stdout))
            stderr = stderr_path.read_bytes()[:remaining]
            output_truncated = stdout_size + stderr_size > action.max_output

            maps: tuple[str, ...]
            map_evidence: str
            try:
                if metadata_path.stat().st_size > action.max_maps_size:
                    raise ConstraintError(f"map evidence exceeds {action.max_maps_size} bytes")
                metadata = json.loads(metadata_path.read_text())
                raw_maps = metadata["maps"]
                if not isinstance(raw_maps, list):
                    raise TypeError("maps must be a list")
                maps = tuple(str(item) for item in raw_maps)
                map_evidence = f"captured {len(maps)} memory map entries"
            except (OSError, KeyError, TypeError, ValueError) as error:
                maps = (f"maps-unavailable:{type(error).__name__}:{error}",)
                map_evidence = "memory maps unavailable; reason retained in result"

            returncode = process.returncode
            terminated_by = -returncode if returncode is not None and returncode < 0 else None
            exit_code = returncode if returncode is not None and returncode >= 0 else None
            return ShellcodeExecutionResult(
                hashlib.sha256(action.shellcode).hexdigest(),
                action.architecture.name,
                self.name,
                duration,
                exit_code,
                terminated_by,
                timed_out,
                stdout,
                stderr,
                maps,
                output_truncated,
                (
                    f"deadline {action.deadline:g}s",
                    f"memory bound {action.max_memory} bytes",
                    f"combined returned output bound {action.max_output} bytes",
                    map_evidence,
                    "process group terminated after the attempt",
                    "containment aid only; not a hardened native-code security boundary",
                ),
            )


@dataclass(frozen=True)
class ShellcodeExperiment(Action):
    """Run raw code as an explicit, bounded, replay-safe experiment."""

    shellcode: bytes = field(repr=False)
    backend: ShellcodeSandboxBackend = field(default_factory=LinuxProcessSandbox)
    architecture: ArchitectureSpec = AMD64
    authorized: bool = False
    deadline: float = 1.0
    max_shellcode_size: int = 64 * 1024
    max_memory: int = 1024 * 1024 * 1024
    max_output: int = 1024 * 1024
    max_maps_size: int = 1024 * 1024
    target: Expr | None = None

    def __post_init__(self) -> None:
        if not self.authorized:
            raise ConstraintError(
                "shellcode execution runs native code; set authorized=True explicitly"
            )
        if not isinstance(self.shellcode, bytes) or not self.shellcode:
            raise ValueError("shellcode must be non-empty bytes")
        if len(self.shellcode) > self.max_shellcode_size:
            raise ConstraintError(
                f"shellcode is {len(self.shellcode)} bytes; maximum is {self.max_shellcode_size}"
            )
        if (
            self.deadline <= 0
            or self.max_shellcode_size <= 0
            or self.max_memory <= 0
            or self.max_output <= 0
            or self.max_maps_size <= 0
        ):
            raise ValueError("shellcode experiment bounds must be positive")
        if self.target is not None and not isinstance(self.target, Expr):
            raise TypeError("shellcode experiment target must be an Expr")

    @property
    def output(self) -> Expr | None:
        return self.target

    @property
    def identity(self) -> str:
        return _digest(
            {
                "kind": "shellcode-experiment",
                "sha256": hashlib.sha256(self.shellcode).hexdigest(),
                "architecture": self.architecture.identity,
                "backend": self.backend.identity,
            }
        )

    @property
    def input_digest(self) -> str:
        return _digest(
            {
                "identity": self.identity,
                "deadline": self.deadline,
                "max_shellcode_size": self.max_shellcode_size,
                "max_memory": self.max_memory,
                "max_output": self.max_output,
                "max_maps_size": self.max_maps_size,
                "target": getattr(self.target, "key", None),
            }
        )

    def contract(self) -> EffectContract:
        support = self.backend.support(self.architecture)
        return EffectContract(
            provides=(self.target,) if self.target is not None else (),
            reads=frozenset({"host:execution"}),
            writes=frozenset({"sandbox:process"}),
            scope=Scope.PROCESS,
            evidence=(
                Evidence(
                    "native-effect-bound",
                    f"{self.deadline:g}s, {self.max_memory} memory bytes, "
                    f"{self.max_output} output bytes",
                    self.backend.name,
                    {
                        "supported": support.supported,
                        "reasons": support.reasons,
                        "shellcode_sha256": hashlib.sha256(self.shellcode).hexdigest(),
                    },
                ),
            ),
        )

    def execute(self, runtime: Any) -> ShellcodeExecutionResult:
        tube = runtime.tube
        if isinstance(tube, ReplayTube):
            raw = tube.consume_opaque(self.identity, self.input_digest)
            try:
                value = json.loads(raw.decode("utf-8"))
                if not isinstance(value, dict):
                    raise TypeError("result must be an object")
                result = ShellcodeExecutionResult.from_dict(value)
            except (UnicodeError, ValueError, TypeError, KeyError) as error:
                raise ProtocolError("recorded shellcode result is malformed") from error
        else:
            trace = runtime.trace
            if trace is not None:
                trace.append(
                    "opaque_start",
                    operation=self.identity,
                    details={"name": self.describe(), "inputs_sha256": self.input_digest},
                )
            result = self.backend.execute(self)
            if trace is not None:
                trace.append(
                    "opaque",
                    json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":")).encode(),
                    operation=self.identity,
                    details={
                        "name": self.describe(),
                        "inputs_sha256": self.input_digest,
                        "buffered_base64": base64.b64encode(
                            getattr(tube, "buffered_bytes", b"")
                        ).decode("ascii"),
                    },
                )
        self._validate_result(result)
        if self.target is not None:
            runtime.bind(self.target, result.to_dict(), source=self.describe())
        return result

    def perform(self) -> ShellcodeExecutionResult:
        result = self.backend.execute(self)
        self._validate_result(result)
        return result

    def _validate_result(self, result: ShellcodeExecutionResult) -> None:
        if result.shellcode_sha256 != hashlib.sha256(self.shellcode).hexdigest():
            raise ProtocolError("shellcode backend returned evidence for another payload")
        if result.architecture != self.architecture.name:
            raise ProtocolError("shellcode backend returned evidence for another architecture")
        if result.backend != self.backend.name:
            raise ProtocolError("shellcode backend returned evidence for another backend")

    def describe(self) -> str:
        return (
            f"experiment with {self.architecture.name} shellcode "
            f"{hashlib.sha256(self.shellcode).hexdigest()[:12]} in {self.backend.name}"
        )
