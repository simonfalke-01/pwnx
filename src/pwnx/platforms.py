"""Purpose-native adapters for devices, Windows targets, and kernel VMs.

The objects here describe outcomes and bounded effects.  Recipes are pure
manifests; actions cross an explicit trace boundary so replay never launches a
second device command, transfer, or debugger operation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import shlex
import shutil
import struct
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Literal, Mapping, Protocol

from .abi import WINDOWS_X64_ARCH
from .actions import Action
from .architecture import (
    AMD64,
    AARCH64,
    ArchitectureSpec,
    ArtifactIdentity,
    CredentialReference,
    LifecyclePolicy,
    MaterializedTarget,
    SupportDecision,
    _target,
)
from .domain import EffectContract, Evidence, Scope
from .errors import ArtifactError, ConstraintError, ProtocolError, UnsupportedFeature
from .expressions import Expr
from .trace import ReplayTube


Runner = Callable[..., subprocess.CompletedProcess[bytes]]
PlatformOperation = Literal["shell", "process", "push", "pull", "forward", "logcat", "debugger"]


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except (PermissionError, ProcessLookupError):
        if process.poll() is None:
            process.kill()


def _bounded_subprocess(
    argv: list[str], *, timeout: float, max_output: int
) -> subprocess.CompletedProcess[bytes]:
    """Capture an argv-only platform command while enforcing its bound live."""

    options: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    if os.name == "posix":
        options["start_new_session"] = True
    else:
        options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    process = subprocess.Popen(argv, **options)
    assert process.stdout is not None
    assert process.stderr is not None

    buffers = (bytearray(), bytearray())
    total = 0
    lock = threading.Lock()
    overflow = threading.Event()

    def read_output(stream: Any, output: bytearray) -> None:
        nonlocal total
        while chunk := stream.read(64 * 1024):
            with lock:
                remaining = max(0, max_output - total)
                output.extend(chunk[:remaining])
                total += len(chunk)
                if total > max_output:
                    overflow.set()
            if overflow.is_set():
                _terminate_process_group(process)
                return

    readers = (
        threading.Thread(target=read_output, args=(process.stdout, buffers[0]), daemon=True),
        threading.Thread(target=read_output, args=(process.stderr, buffers[1]), daemon=True),
    )
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_process_group(process)
        process.wait()
        raise
    else:
        _terminate_process_group(process)
    finally:
        for reader in readers:
            reader.join(timeout=1.0)
    if overflow.is_set():
        raise ConstraintError(f"platform command output exceeds {max_output} bytes")
    return subprocess.CompletedProcess(
        argv,
        process.returncode,
        bytes(buffers[0]),
        bytes(buffers[1]),
    )


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(payload).hexdigest()


def _file_digest(path: str | os.PathLike[str], maximum: int) -> tuple[str, int]:
    source = Path(path)
    try:
        size = source.stat().st_size
    except OSError as error:
        raise ArtifactError(f"cannot inspect artifact {source}: {error}") from error
    if not source.is_file():
        raise ArtifactError(f"artifact is not a regular file: {source}")
    if size > maximum:
        raise ConstraintError(f"artifact {source} is {size} bytes; maximum is {maximum}")
    digest = hashlib.sha256()
    try:
        with source.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise ArtifactError(f"cannot read artifact {source}: {error}") from error
    return digest.hexdigest(), size


def _tool_path(tool: str) -> str | None:
    if os.path.sep in tool or (os.path.altsep and os.path.altsep in tool):
        path = Path(tool).expanduser().resolve()
        return str(path) if path.is_file() else None
    return shutil.which(tool)


def _tool_evidence(tool: str, purpose: str) -> tuple[str, ...]:
    resolved = _tool_path(tool)
    if resolved is None:
        return (f"unsupported: {purpose} tool {tool!r} is unavailable on this host",)
    return (f"{purpose} tool: {resolved}",)


@dataclass(frozen=True, slots=True)
class PlatformArtifact:
    role: str
    path: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if not self.role or not self.path or self.size < 0:
            raise ValueError("platform artifact requires role, path, and non-negative size")
        if len(self.sha256) != 64:
            raise ValueError("platform artifact requires a SHA-256 digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PlatformArtifact":
        return cls(
            str(value["role"]),
            str(value["path"]),
            str(value["sha256"]),
            int(value["size"]),
        )


@dataclass(frozen=True, slots=True)
class PlatformResult:
    operation: PlatformOperation
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""
    artifacts: tuple[PlatformArtifact, ...] = ()
    evidence: tuple[str, ...] = ()

    @property
    def output_sha256(self) -> str:
        return hashlib.sha256(self.stdout).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "argv": list(self.argv),
            "returncode": self.returncode,
            "stdout_base64": base64.b64encode(self.stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(self.stderr).decode("ascii"),
            "artifacts": [item.to_dict() for item in self.artifacts],
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PlatformResult":
        try:
            stdout = base64.b64decode(str(value["stdout_base64"]), validate=True)
            stderr = base64.b64decode(str(value["stderr_base64"]), validate=True)
        except ValueError as error:
            raise ProtocolError("recorded platform result contains invalid base64") from error
        return cls(
            str(value["operation"]),  # type: ignore[arg-type]
            tuple(str(item) for item in value["argv"]),
            int(value["returncode"]),
            stdout,
            stderr,
            tuple(PlatformArtifact.from_dict(item) for item in value["artifacts"]),
            tuple(str(item) for item in value.get("evidence", ())),
        )


class PlatformBackend(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def identity(self) -> str: ...

    def execute(self, action: "PlatformAction") -> PlatformResult: ...


@dataclass(frozen=True, slots=True)
class SubprocessPlatformBackend:
    """An argv-only backend used by explicit platform actions."""

    name: str
    executable: str
    fixed_arguments: tuple[str, ...] = ()
    runner: Runner = field(default=subprocess.run, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not self.name or not self.executable or "\0" in self.executable:
            raise ValueError("backend name and executable are required")
        if any("\0" in item for item in self.fixed_arguments):
            raise ValueError("backend arguments cannot contain NUL")

    @property
    def identity(self) -> str:
        return _digest(
            {
                "name": self.name,
                "executable": self.executable,
                "fixed_arguments": self.fixed_arguments,
            }
        )

    def execute(self, action: "PlatformAction") -> PlatformResult:
        argv = (self.executable, *self.fixed_arguments, *action.arguments)
        artifacts: list[PlatformArtifact] = []
        temporary: str | None = None
        executed_argv = argv

        if action.operation == "push":
            assert action.local_path is not None
            digest, size = _file_digest(action.local_path, action.max_artifact_size)
            artifacts.append(PlatformArtifact("upload-source", action.local_path, digest, size))
        elif action.operation == "pull":
            assert action.local_path is not None
            destination = Path(action.local_path).expanduser().resolve()
            try:
                descriptor, temporary = tempfile.mkstemp(
                    prefix=f".{destination.name}.",
                    suffix=".pwnx-pull",
                    dir=destination.parent,
                )
            except OSError as error:
                raise ArtifactError(
                    f"cannot prepare atomic download beside {destination}: {error}"
                ) from error
            os.close(descriptor)
            executed_argv = (*argv[:-1], temporary)

        try:
            try:
                if self.runner is subprocess.run:
                    completed = _bounded_subprocess(
                        list(executed_argv),
                        timeout=action.deadline,
                        max_output=action.max_output,
                    )
                else:
                    completed = self.runner(
                        list(executed_argv),
                        capture_output=True,
                        timeout=action.deadline,
                        check=False,
                    )
            except FileNotFoundError as error:
                raise UnsupportedFeature(
                    f"platform backend {self.executable!r} is unavailable"
                ) from error
            except subprocess.TimeoutExpired as error:
                raise ProtocolError(
                    f"{action.operation} exceeded {action.deadline:g}s deadline"
                ) from error

            stdout = bytes(completed.stdout or b"")
            stderr = bytes(completed.stderr or b"")
            if len(stdout) + len(stderr) > action.max_output:
                raise ConstraintError(
                    f"{action.operation} produced {len(stdout) + len(stderr)} bytes; "
                    f"maximum is {action.max_output}"
                )
            if action.check and completed.returncode != 0:
                detail = stderr.decode("utf-8", "replace").strip()
                raise ProtocolError(
                    f"{action.operation} failed with status {completed.returncode}"
                    + (f": {detail}" if detail else "")
                )

            if action.operation == "pull":
                assert temporary is not None and action.local_path is not None
                digest, size = _file_digest(temporary, action.max_artifact_size)
                if action.expected_sha256 and digest != action.expected_sha256:
                    raise ProtocolError(
                        f"pulled artifact digest {digest} does not match "
                        f"expected {action.expected_sha256}"
                    )
                destination = Path(action.local_path).resolve()
                os.replace(temporary, destination)
                temporary = None
                artifacts.append(PlatformArtifact("download", str(destination), digest, size))

            return PlatformResult(
                action.operation,
                argv,
                completed.returncode,
                stdout,
                stderr,
                tuple(artifacts),
                (f"bounded by {action.deadline:g}s and {action.max_output} output bytes",),
            )
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass


@dataclass(frozen=True, slots=True)
class PlatformAction(Action):
    operation: PlatformOperation
    arguments: tuple[str, ...]
    backend: PlatformBackend
    deadline: float = 10.0
    max_output: int = 1024 * 1024
    max_artifact_size: int = 64 * 1024 * 1024
    local_path: str | None = None
    expected_sha256: str | None = None
    check: bool = True
    target: Expr | None = None

    def __post_init__(self) -> None:
        if self.operation not in {
            "shell",
            "process",
            "push",
            "pull",
            "forward",
            "logcat",
            "debugger",
        }:
            raise ValueError(f"unsupported platform operation {self.operation!r}")
        if not self.arguments or any("\0" in item for item in self.arguments):
            raise ValueError("platform action requires NUL-free argv")
        if self.deadline <= 0 or self.max_output <= 0 or self.max_artifact_size <= 0:
            raise ValueError("platform action bounds must be positive")
        if self.operation in {"push", "pull"} and self.local_path is None:
            raise ValueError(f"{self.operation} requires a local path")
        if self.expected_sha256 is not None and (
            len(self.expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.expected_sha256)
        ):
            raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")
        if self.target is not None and not isinstance(self.target, Expr):
            raise TypeError("platform action target must be an Expr")

    @property
    def output(self) -> Expr | None:
        return self.target

    @property
    def identity(self) -> str:
        return _digest(
            {
                "operation": self.operation,
                "arguments": self.arguments,
                "backend": self.backend.identity,
                "local_path": self.local_path,
                "expected_sha256": self.expected_sha256,
                "check": self.check,
            }
        )

    @property
    def input_digest(self) -> str:
        local_digest = None
        if self.operation == "push" and self.local_path is not None:
            local_digest = _file_digest(self.local_path, self.max_artifact_size)[0]
        return _digest(
            {
                "identity": self.identity,
                "local_sha256": local_digest,
                "bounds": (self.deadline, self.max_output, self.max_artifact_size),
                "target": getattr(self.target, "key", None),
            }
        )

    def contract(self) -> EffectContract:
        reads: set[str] = {"platform:service"}
        writes: set[str] = set()
        scope = Scope.SERVICE
        if self.operation in {"shell", "process", "debugger"}:
            writes.add("platform:process")
            scope = Scope.PROCESS
        elif self.operation == "push":
            reads.add("filesystem:local")
            writes.add("filesystem:remote")
        elif self.operation == "pull":
            reads.add("filesystem:remote")
            writes.add("filesystem:local")
        elif self.operation == "forward":
            writes.add("platform:forwarding")
        elif self.operation == "logcat":
            reads.add("platform:logs")
        return EffectContract(
            provides=(self.target,) if self.target is not None else (),
            reads=frozenset(reads),
            writes=frozenset(writes),
            scope=scope,
            evidence=(
                Evidence(
                    "platform-effect-bound",
                    f"{self.deadline:g}s and {self.max_output} output bytes",
                    self.backend.name,
                ),
            ),
        )

    def execute(self, runtime: Any) -> PlatformResult:
        tube = runtime.tube
        if isinstance(tube, ReplayTube):
            raw = tube.consume_opaque(self.identity, self.input_digest)
            try:
                decoded = json.loads(raw.decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise TypeError("result must be an object")
                result = PlatformResult.from_dict(decoded)
            except (UnicodeError, ValueError, KeyError, TypeError) as error:
                raise ProtocolError("recorded platform result is malformed") from error
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
        if self.target is not None:
            runtime.bind(self.target, result.to_dict(), source=self.describe())
        return result

    def perform(self) -> PlatformResult:
        """Perform the declared effect explicitly, outside a compiled run."""

        return self.backend.execute(self)

    def describe(self) -> str:
        return (
            f"{self.operation} through {self.backend.name} "
            f"(deadline {self.deadline:g}s, max output {self.max_output} bytes)"
        )


@dataclass(frozen=True, slots=True)
class ADBRecipe:
    """One explicit Android device plus reusable, bounded capabilities."""

    serial: str
    command: tuple[str, ...] = ()
    architecture: ArchitectureSpec = AARCH64
    adb: str = "adb"
    credential: CredentialReference | None = None
    lifecycle: LifecyclePolicy = field(
        default_factory=lambda: LifecyclePolicy("persistent", "fresh-per-run", "fresh-per-run")
    )
    runner: Runner = field(default=subprocess.run, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not self.serial or "\0" in self.serial:
            raise ValueError("ADB device serial must be explicit and NUL-free")
        if any("\0" in item for item in self.command):
            raise ValueError("ADB process arguments cannot contain NUL")

    @property
    def identity(self) -> str:
        return _digest(
            {
                "kind": "adb-device",
                "serial": self.serial,
                "command": self.command,
                "architecture": self.architecture.identity,
                "adb": self.adb,
                "credential": self.credential.name if self.credential else None,
                "lifecycle": self.lifecycle,
            }
        )

    @property
    def backend(self) -> SubprocessPlatformBackend:
        return SubprocessPlatformBackend(
            "adb",
            self.adb,
            ("-s", self.serial),
            self.runner,
        )

    def support(self) -> SupportDecision:
        resolved = _tool_path(self.adb)
        return SupportDecision(
            resolved is not None,
            () if resolved else (f"ADB executable {self.adb!r} is unavailable",),
        )

    def materialize(self, *, epoch_seed: str = "run") -> MaterializedTarget:
        if not self.command:
            raise ConstraintError("ADB target materialization requires a process command")
        evidence = [*_tool_evidence(self.adb, "ADB"), f"device serial: {self.serial}"]
        if self.credential is not None:
            evidence.append(f"device credential reference: {self.credential.name}")
        return _target(
            "adb-process",
            self.architecture,
            (
                self.adb,
                "-s",
                self.serial,
                "shell",
                "--",
                shlex.join(self.command),
            ),
            {},
            None,
            (),
            self.lifecycle,
            self.identity,
            epoch_seed,
            evidence=tuple(evidence),
            options={"serial": self.serial},
        )

    def shell(self, *command: str, **bounds: Any) -> PlatformAction:
        return PlatformAction("shell", ("shell", "--", *command), self.backend, **bounds)

    def process(self, executable: str, *arguments: str, **bounds: Any) -> PlatformAction:
        return PlatformAction(
            "process",
            ("shell", "--", shlex.join((executable, *arguments))),
            self.backend,
            **bounds,
        )

    def push(
        self,
        local_path: str | os.PathLike[str],
        remote_path: str,
        **bounds: Any,
    ) -> PlatformAction:
        local = str(Path(local_path).expanduser().resolve())
        return PlatformAction(
            "push", ("push", "--", local, remote_path), self.backend, local_path=local, **bounds
        )

    def pull(
        self,
        remote_path: str,
        local_path: str | os.PathLike[str],
        **bounds: Any,
    ) -> PlatformAction:
        local = str(Path(local_path).expanduser().resolve())
        return PlatformAction(
            "pull", ("pull", "--", remote_path, local), self.backend, local_path=local, **bounds
        )

    def forward(self, local: str, remote: str, **bounds: Any) -> PlatformAction:
        return PlatformAction("forward", ("forward", local, remote), self.backend, **bounds)

    def logcat(
        self,
        *filters: str,
        lines: int = 200,
        **bounds: Any,
    ) -> PlatformAction:
        if lines <= 0:
            raise ValueError("logcat line bound must be positive")
        return PlatformAction(
            "logcat", ("logcat", "-d", "-t", str(lines), *filters), self.backend, **bounds
        )


@dataclass(frozen=True, slots=True)
class DebuggerScript:
    commands: tuple[str, ...]
    continue_after_load: bool = False

    def __post_init__(self) -> None:
        if not self.commands or any(not item or "\0" in item for item in self.commands):
            raise ValueError("debugger script requires non-empty NUL-free commands")

    def render_cdb(self) -> str:
        commands = [*self.commands]
        if self.continue_after_load:
            commands.append("g")
        return ";".join(commands)


@dataclass(frozen=True, slots=True)
class WindowsProcessRecipe:
    executable: str
    arguments: tuple[str, ...] = ()
    mode: Literal["native", "wine"] = "native"
    wine: str = "wine64"
    architecture: ArchitectureSpec = WINDOWS_X64_ARCH
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str | None = None
    lifecycle: LifecyclePolicy = field(default_factory=LifecyclePolicy)

    def __post_init__(self) -> None:
        object.__setattr__(self, "executable", str(Path(self.executable).expanduser().resolve()))
        object.__setattr__(self, "env", MappingProxyType(dict(self.env)))
        if self.mode not in {"native", "wine"}:
            raise ValueError("Windows process mode must be native or wine")
        if any("\0" in item for item in self.arguments):
            raise ValueError("Windows process arguments cannot contain NUL")

    @classmethod
    def native(cls, executable: str, *arguments: str, **options: Any) -> "WindowsProcessRecipe":
        return cls(executable, tuple(arguments), mode="native", **options)

    @classmethod
    def through_wine(
        cls, executable: str, *arguments: str, wine: str = "wine64", **options: Any
    ) -> "WindowsProcessRecipe":
        return cls(executable, tuple(arguments), mode="wine", wine=wine, **options)

    @property
    def identity(self) -> str:
        return _digest(
            {
                "kind": "windows-process",
                "executable": self.executable,
                "arguments": self.arguments,
                "mode": self.mode,
                "wine": self.wine,
                "architecture": self.architecture.identity,
                "env": dict(self.env),
                "cwd": self.cwd,
                "lifecycle": self.lifecycle,
            }
        )

    def support(self) -> SupportDecision:
        if self.mode == "native":
            return SupportDecision(
                os.name == "nt",
                () if os.name == "nt" else ("native PE execution requires Windows",),
            )
        resolved = _tool_path(self.wine)
        return SupportDecision(
            resolved is not None,
            () if resolved else (f"Wine executable {self.wine!r} is unavailable",),
        )

    def materialize(self, *, epoch_seed: str = "run") -> MaterializedTarget:
        artifacts = [ArtifactIdentity.from_path("executable", self.executable)]
        evidence: list[str] = []
        if self.mode == "wine":
            resolved = _tool_path(self.wine)
            argv = (self.wine, self.executable, *self.arguments)
            evidence.extend(_tool_evidence(self.wine, "Wine"))
            if resolved:
                artifacts.append(ArtifactIdentity.from_path("wine", resolved))
            adapter = "wine-process"
        else:
            argv = (self.executable, *self.arguments)
            adapter = "windows-process"
            if os.name != "nt":
                evidence.append("unsupported: native PE execution requires Windows")
        return _target(
            adapter,
            self.architecture,
            argv,
            self.env,
            self.cwd,
            tuple(artifacts),
            self.lifecycle,
            self.identity,
            epoch_seed,
            evidence=tuple(evidence),
            options={"mode": self.mode},
        )


@dataclass(frozen=True, slots=True)
class CDBRecipe:
    target: WindowsProcessRecipe
    script: DebuggerScript
    debugger: str = "cdb"
    lifecycle: LifecyclePolicy = field(default_factory=LifecyclePolicy)

    @property
    def architecture(self) -> ArchitectureSpec:
        return self.target.architecture

    @property
    def identity(self) -> str:
        return _digest(
            {
                "kind": "cdb-target",
                "target": self.target.identity,
                "debugger": self.debugger,
                "commands": self.script.commands,
                "continue": self.script.continue_after_load,
                "lifecycle": self.lifecycle,
            }
        )

    def support(self) -> SupportDecision:
        resolved = _tool_path(self.debugger)
        return SupportDecision(
            resolved is not None,
            () if resolved else (f"debugger {self.debugger!r} is unavailable",),
        )

    def materialize(self, *, epoch_seed: str = "run") -> MaterializedTarget:
        executable = ArtifactIdentity.from_path("executable", self.target.executable)
        artifacts = [executable]
        resolved = _tool_path(self.debugger)
        if resolved:
            artifacts.append(ArtifactIdentity.from_path("debugger", resolved))
        return _target(
            "cdb-debugger",
            self.architecture,
            (
                self.debugger,
                "-c",
                self.script.render_cdb(),
                self.target.executable,
                *self.target.arguments,
            ),
            self.target.env,
            self.target.cwd,
            tuple(artifacts),
            self.lifecycle,
            self.identity,
            epoch_seed,
            evidence=_tool_evidence(self.debugger, "CDB debugger"),
            options={"commands": self.script.commands},
        )


@dataclass(frozen=True, slots=True)
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)


@dataclass(frozen=True, slots=True)
class PEImport:
    library: str
    symbols: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PEMitigations:
    aslr: bool
    nx: bool
    cfg: bool
    high_entropy_va: bool


@dataclass(frozen=True, slots=True)
class PEImage:
    path: str
    sha256: str
    size: int
    machine: int
    machine_name: str
    bits: int
    image_base: int
    entry_point: int
    sections: tuple[PESection, ...]
    imports: tuple[PEImport, ...]
    mitigations: PEMitigations

    def section(self, name: str) -> PESection:
        try:
            return next(item for item in self.sections if item.name == name)
        except StopIteration as error:
            raise UnsupportedFeature(f"PE image has no section {name!r}") from error


def parse_pe(path: str | os.PathLike[str], *, max_size: int = 64 * 1024 * 1024) -> PEImage:
    source = Path(path).expanduser().resolve()
    digest, size = _file_digest(source, max_size)
    data = source.read_bytes()

    def require(offset: int, length: int, what: str) -> memoryview:
        if offset < 0 or length < 0 or offset + length > len(data):
            raise ArtifactError(f"truncated PE while reading {what}")
        return memoryview(data)[offset : offset + length]

    def u16(offset: int, what: str) -> int:
        return struct.unpack_from("<H", require(offset, 2, what))[0]

    def u32(offset: int, what: str) -> int:
        return struct.unpack_from("<I", require(offset, 4, what))[0]

    def u64(offset: int, what: str) -> int:
        return struct.unpack_from("<Q", require(offset, 8, what))[0]

    if bytes(require(0, 2, "DOS signature")) != b"MZ":
        raise ArtifactError("artifact is not a PE image: missing MZ signature")
    pe_offset = u32(0x3C, "PE header offset")
    if bytes(require(pe_offset, 4, "PE signature")) != b"PE\0\0":
        raise ArtifactError("artifact is not a PE image: missing PE signature")
    coff = pe_offset + 4
    machine = u16(coff, "machine")
    section_count = u16(coff + 2, "section count")
    optional_size = u16(coff + 16, "optional header size")
    optional = coff + 20
    require(optional, optional_size, "optional header")
    magic = u16(optional, "optional header magic")
    if magic == 0x20B:
        bits = 64
        image_base = u64(optional + 24, "image base")
        directory_count_offset = optional + 108
        directories = optional + 112
    elif magic == 0x10B:
        bits = 32
        image_base = u32(optional + 28, "image base")
        directory_count_offset = optional + 92
        directories = optional + 96
    else:
        raise ArtifactError(f"unsupported PE optional header magic {magic:#x}")
    entry_point = u32(optional + 16, "entry point")
    dll_characteristics = u16(optional + 70, "DLL characteristics")
    directory_count = u32(directory_count_offset, "data directory count")
    section_table = optional + optional_size
    sections: list[PESection] = []
    for index in range(section_count):
        offset = section_table + index * 40
        raw_name = bytes(require(offset, 8, f"section {index} name"))
        try:
            name = raw_name.split(b"\0", 1)[0].decode("ascii")
        except UnicodeDecodeError as error:
            raise ArtifactError(f"section {index} name is not ASCII") from error
        sections.append(
            PESection(
                name,
                u32(offset + 12, f"section {name} virtual address"),
                u32(offset + 8, f"section {name} virtual size"),
                u32(offset + 20, f"section {name} raw offset"),
                u32(offset + 16, f"section {name} raw size"),
                u32(offset + 36, f"section {name} characteristics"),
            )
        )

    def rva_offset(rva: int, what: str) -> int:
        for section in sections:
            extent = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + extent:
                offset = section.raw_offset + rva - section.virtual_address
                require(offset, 1, what)
                return offset
        size_of_headers = u32(optional + 60, "size of headers")
        if 0 <= rva < size_of_headers:
            require(rva, 1, what)
            return rva
        raise ArtifactError(f"{what} RVA {rva:#x} is outside mapped PE sections")

    def c_string(offset: int, what: str, maximum: int = 4096) -> str:
        end = data.find(b"\0", offset, min(len(data), offset + maximum + 1))
        if end < 0:
            raise ArtifactError(f"unterminated {what}")
        try:
            return data[offset:end].decode("ascii")
        except UnicodeDecodeError as error:
            raise ArtifactError(f"{what} is not ASCII") from error

    imports: list[PEImport] = []
    if directory_count > 1 and optional_size >= (directories - optional) + 16:
        import_rva = u32(directories + 8, "import directory RVA")
        import_size = u32(directories + 12, "import directory size")
        if import_rva and import_size:
            descriptor = rva_offset(import_rva, "import directory")
            limit = min(len(data), descriptor + import_size)
            while descriptor + 20 <= limit:
                original_thunk = u32(descriptor, "import original thunk")
                name_rva = u32(descriptor + 12, "import library name")
                first_thunk = u32(descriptor + 16, "import first thunk")
                if not any(data[descriptor : descriptor + 20]):
                    break
                library = c_string(rva_offset(name_rva, "import library"), "library name")
                thunk_rva = original_thunk or first_thunk
                symbols: list[str] = []
                if thunk_rva:
                    thunk = rva_offset(thunk_rva, f"{library} import table")
                    width = bits // 8
                    ordinal_bit = 1 << (bits - 1)
                    for symbol_index in range(65536):
                        value = int.from_bytes(
                            require(thunk + symbol_index * width, width, "import thunk"),
                            "little",
                        )
                        if value == 0:
                            break
                        if value & ordinal_bit:
                            symbols.append(f"ordinal:{value & 0xFFFF}")
                        else:
                            symbol_offset = rva_offset(value, "import name")
                            symbols.append(c_string(symbol_offset + 2, "import symbol"))
                    else:
                        raise ArtifactError("PE import table exceeds safety bound")
                imports.append(PEImport(library, tuple(symbols)))
                descriptor += 20

    machine_names = {0x014C: "i386", 0x8664: "amd64", 0xAA64: "aarch64"}
    return PEImage(
        str(source),
        digest,
        size,
        machine,
        machine_names.get(machine, f"machine-{machine:#x}"),
        bits,
        image_base,
        entry_point,
        tuple(sections),
        tuple(imports),
        PEMitigations(
            bool(dll_characteristics & 0x40),
            bool(dll_characteristics & 0x100),
            bool(dll_characteristics & 0x4000),
            bool(dll_characteristics & 0x20),
        ),
    )


@dataclass(frozen=True, slots=True)
class KernelVMRecipe:
    kernel: str
    emulator: str = "qemu-system-x86_64"
    architecture: ArchitectureSpec = AMD64
    initrd: str | None = None
    disk: str | None = None
    machine: str = "q35"
    cpu: str = "max"
    memory_mib: int = 512
    append: tuple[str, ...] = ("console=ttyS0",)
    snapshot: bool = True
    network: Literal["none", "user"] = "none"
    gdb_port: int | None = None
    gdb_host: str = "127.0.0.1"
    unsafe_remote_gdb: bool = False
    paused: bool = False
    extra_arguments: tuple[str, ...] = ()
    lifecycle: LifecyclePolicy = field(default_factory=LifecyclePolicy)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kernel", str(Path(self.kernel).expanduser().resolve()))
        if self.initrd is not None:
            object.__setattr__(self, "initrd", str(Path(self.initrd).expanduser().resolve()))
        if self.disk is not None:
            object.__setattr__(self, "disk", str(Path(self.disk).expanduser().resolve()))
        if self.memory_mib <= 0:
            raise ValueError("kernel VM memory must be positive")
        if self.network not in {"none", "user"}:
            raise ValueError("kernel VM network must be none or user")
        if self.gdb_port is not None and not 0 < self.gdb_port < 65536:
            raise ValueError("gdb_port must be in range 1..65535")
        if not self.gdb_host or "\0" in self.gdb_host or any(
            character.isspace() for character in self.gdb_host
        ):
            raise ValueError("gdb_host must be a non-empty, NUL-free host")
        if (
            self.gdb_port is not None
            and self.gdb_host not in {"127.0.0.1", "::1", "localhost"}
            and not self.unsafe_remote_gdb
        ):
            raise ValueError(
                "non-loopback QEMU GDB listeners require unsafe_remote_gdb=True"
            )
        if any(
            not item or "\0" in item or any(ch.isspace() for ch in item) for item in self.append
        ):
            raise ValueError("kernel append values must be non-empty, NUL-free tokens")
        if any("\0" in item for item in self.extra_arguments):
            raise ValueError("QEMU arguments cannot contain NUL")

    @property
    def identity(self) -> str:
        return _digest(
            {
                "kind": "kernel-vm",
                "kernel": self.kernel,
                "emulator": self.emulator,
                "architecture": self.architecture.identity,
                "initrd": self.initrd,
                "disk": self.disk,
                "machine": self.machine,
                "cpu": self.cpu,
                "memory_mib": self.memory_mib,
                "append": self.append,
                "snapshot": self.snapshot,
                "network": self.network,
                "gdb_port": self.gdb_port,
                "gdb_host": self.gdb_host,
                "unsafe_remote_gdb": self.unsafe_remote_gdb,
                "paused": self.paused,
                "extra_arguments": self.extra_arguments,
                "lifecycle": self.lifecycle,
            }
        )

    def support(self) -> SupportDecision:
        resolved = _tool_path(self.emulator)
        return SupportDecision(
            resolved is not None,
            () if resolved else (f"QEMU system emulator {self.emulator!r} is unavailable",),
        )

    def materialize(self, *, epoch_seed: str = "run") -> MaterializedTarget:
        artifacts = [ArtifactIdentity.from_path("kernel", self.kernel)]
        if self.initrd:
            artifacts.append(ArtifactIdentity.from_path("initrd", self.initrd))
        if self.disk:
            artifacts.append(ArtifactIdentity.from_path("disk", self.disk))
        resolved = _tool_path(self.emulator)
        evidence = list(_tool_evidence(self.emulator, "QEMU system emulator"))
        if resolved:
            artifacts.append(ArtifactIdentity.from_path("emulator", resolved))

        argv = [
            self.emulator,
            "-machine",
            self.machine,
            "-cpu",
            self.cpu,
            "-m",
            str(self.memory_mib),
            "-kernel",
            self.kernel,
            "-append",
            " ".join(self.append),
            "-nographic",
            "-no-reboot",
            "-nic",
            "none" if self.network == "none" else "user,model=virtio-net-pci",
        ]
        if self.initrd:
            argv.extend(("-initrd", self.initrd))
        if self.disk:
            block = json.dumps(
                {
                    "driver": "raw",
                    "file": {"driver": "file", "filename": self.disk},
                    "node-name": "pwnx-disk",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            argv.extend(("-blockdev", block, "-device", "virtio-blk-pci,drive=pwnx-disk"))
        if self.snapshot:
            argv.append("-snapshot")
        if self.gdb_port is not None:
            gdb_host = f"[{self.gdb_host}]" if ":" in self.gdb_host else self.gdb_host
            argv.extend(("-gdb", f"tcp:{gdb_host}:{self.gdb_port}"))
        if self.paused:
            argv.append("-S")
        argv.extend(self.extra_arguments)
        return _target(
            "kernel-vm",
            self.architecture,
            tuple(argv),
            {},
            None,
            tuple(artifacts),
            self.lifecycle,
            self.identity,
            epoch_seed,
            evidence=tuple(evidence),
            options={
                "machine": self.machine,
                "cpu": self.cpu,
                "memory_mib": self.memory_mib,
                "network": self.network,
                "gdb_port": self.gdb_port,
                "gdb_host": self.gdb_host,
                "unsafe_remote_gdb": self.unsafe_remote_gdb,
            },
        )
