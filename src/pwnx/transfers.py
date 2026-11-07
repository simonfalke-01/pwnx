"""Explicit remote artifact transfer actions and OpenSSH backend.

Constructing an ArtifactTransfer performs no I/O. A backend execution is an
external effect whose identity, inputs, hashes, and result are serializable for
the pwnx trace/replay boundary.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Mapping, Protocol

from .actions import Action
from .architecture import CredentialReference
from .domain import EffectContract, Evidence, Scope
from .errors import ConstraintError, ProtocolError, UnsupportedFeature
from .expressions import Expr
from .trace import ReplayTube


TransferOperation = Literal["upload", "download", "stat", "hash"]


@dataclass(frozen=True, slots=True)
class RemoteArtifact:
    path: str
    sha256: str
    size: int
    backend: str
    service_scope: str
    connection_scope: str
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.path or self.size < 0:
            raise ValueError("remote artifact path and non-negative size are required")
        _validate_digest(self.sha256, "remote artifact")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "backend": self.backend,
            "service_scope": self.service_scope,
            "connection_scope": self.connection_scope,
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RemoteArtifact":
        return cls(
            str(value["path"]),
            str(value["sha256"]),
            int(value["size"]),
            str(value["backend"]),
            str(value["service_scope"]),
            str(value["connection_scope"]),
            tuple(str(item) for item in value.get("evidence", ())),
        )


@dataclass(frozen=True, slots=True)
class TransferResult:
    operation: TransferOperation
    artifact: RemoteArtifact | None
    local_path: str | None = None
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "artifact": self.artifact.to_dict() if self.artifact else None,
            "local_path": self.local_path,
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TransferResult":
        artifact = value.get("artifact")
        return cls(
            str(value["operation"]),  # type: ignore[arg-type]
            RemoteArtifact.from_dict(artifact) if artifact else None,
            value.get("local_path"),
            tuple(str(item) for item in value.get("evidence", ())),
        )


@dataclass(frozen=True, slots=True)
class ArtifactTransfer(Action):
    operation: TransferOperation
    remote_path: str
    backend: "TransferBackend"
    local_path: str | None = None
    expected_sha256: str | None = None
    max_size: int = 64 * 1024 * 1024
    deadline: float = 30.0
    service_scope: str = "service:external"
    connection_scope: str = "connection:fresh"
    target: Expr | None = None
    executable: bool = False

    def __post_init__(self) -> None:
        if self.operation not in {"upload", "download", "stat", "hash"}:
            raise ValueError(f"unknown transfer operation {self.operation!r}")
        if not self.remote_path or "\0" in self.remote_path:
            raise ValueError("remote path must not be empty or contain NUL")
        if self.operation in {"upload", "download"} and self.local_path is None:
            raise ValueError(f"{self.operation} requires a local path")
        if self.max_size <= 0 or self.deadline <= 0:
            raise ValueError("transfer size and deadline bounds must be positive")
        if self.expected_sha256 is not None:
            _validate_digest(self.expected_sha256, "expected_sha256")
        if self.target is not None and not isinstance(self.target, Expr):
            raise TypeError("transfer target must be a symbolic expression")

    @property
    def output(self) -> Expr | None:
        return self.target

    @property
    def identity(self) -> str:
        return _digest(
            {
                "operation": self.operation,
                "remote_path": self.remote_path,
                "local_path": self.local_path,
                "expected_sha256": self.expected_sha256,
                "max_size": self.max_size,
                "service_scope": self.service_scope,
                "connection_scope": self.connection_scope,
                "executable": self.executable,
                "backend": self.backend.identity,
            }
        )

    @property
    def input_digest(self) -> str:
        local_hash = None
        if self.operation == "upload" and self.local_path is not None:
            path = Path(self.local_path)
            if path.is_file():
                local_hash = _file_hash(path, self.max_size)[0]
        return _digest(
            {
                "identity": self.identity,
                "local_hash": local_hash,
                "target": getattr(self.target, "key", None),
            }
        )

    @property
    def reads(self) -> tuple[str, ...]:
        return (
            ("filesystem:local",)
            if self.operation == "upload"
            else ("filesystem:remote",)
        )

    @property
    def writes(self) -> tuple[str, ...]:
        if self.operation == "upload":
            return ("filesystem:remote",)
        if self.operation == "download":
            return ("filesystem:local",)
        return ()

    @property
    def invalidates(self) -> tuple[str, ...]:
        return (
            (f"remote.file.{self.remote_path}",)
            if self.operation == "upload"
            else ()
        )

    def contract(self) -> EffectContract:
        return EffectContract(
            provides=(self.target,) if self.target is not None else (),
            reads=frozenset(self.reads),
            writes=frozenset(self.writes),
            invalidates=self.invalidates,
            scope=Scope.SERVICE,
            evidence=(
                Evidence(
                    "transfer-bound",
                    f"max {self.max_size} bytes within {self.deadline:g}s",
                    self.backend.name,
                ),
            ),
        )

    def execute(self, runtime: Any) -> Any:
        tube = runtime.tube
        if isinstance(tube, ReplayTube):
            encoded = tube.consume_opaque(self.identity, self.input_digest)
            try:
                decoded = json.loads(encoded.decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise TypeError("result must be an object")
                result = TransferResult.from_dict(decoded)
            except (UnicodeError, ValueError, TypeError, KeyError) as error:
                raise ProtocolError("recorded transfer result is malformed") from error
        else:
            trace = runtime.trace
            if trace is not None:
                trace.append(
                    "opaque_start",
                    operation=self.identity,
                    details={
                        "name": self.describe(),
                        "inputs_sha256": self.input_digest,
                    },
                )
            result = self.backend.execute(self)
            if trace is not None:
                buffered = getattr(tube, "buffered_bytes", b"")
                trace.append(
                    "opaque",
                    json.dumps(
                        result.to_dict(),
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode(),
                    operation=self.identity,
                    details={
                        "name": self.describe(),
                        "inputs_sha256": self.input_digest,
                        "buffered_base64": base64.b64encode(buffered).decode("ascii"),
                    },
                )
        context = runtime.context
        invalidator = getattr(context, "invalidate", None)
        if callable(invalidator) and self.invalidates:
            invalidator(*self.invalidates)
        if self.target is not None:
            runtime.bind(
                self.target,
                result.to_dict(),
                source=self.describe(),
            )
        return result

    def perform(self) -> TransferResult:
        """Perform the effect explicitly without planner or replay integration."""

        return self.backend.execute(self)

    def describe(self) -> str:
        local = f" <-> {self.local_path}" if self.local_path else ""
        return (
            f"{self.operation} remote artifact {self.remote_path!r}{local} "
            f"through {self.backend.name} (max {self.max_size} bytes, "
            f"deadline {self.deadline:g}s)"
        )

    @classmethod
    def upload(
        cls,
        local_path: str | os.PathLike[str],
        remote_path: str,
        backend: "TransferBackend",
        **options: Any,
    ) -> "ArtifactTransfer":
        return cls("upload", remote_path, backend, os.fspath(local_path), **options)

    @classmethod
    def download(
        cls,
        remote_path: str,
        local_path: str | os.PathLike[str],
        backend: "TransferBackend",
        **options: Any,
    ) -> "ArtifactTransfer":
        return cls("download", remote_path, backend, os.fspath(local_path), **options)

    @classmethod
    def stat(
        cls, remote_path: str, backend: "TransferBackend", **options: Any
    ) -> "ArtifactTransfer":
        return cls("stat", remote_path, backend, **options)

    @classmethod
    def hash(
        cls, remote_path: str, backend: "TransferBackend", **options: Any
    ) -> "ArtifactTransfer":
        return cls("hash", remote_path, backend, **options)


class TransferBackend(Protocol):
    name: str

    @property
    def identity(self) -> str: ...

    def execute(self, action: ArtifactTransfer) -> TransferResult: ...


@dataclass(frozen=True, slots=True)
class ShellCommandCodec:
    dialect: str = "posix-sh"
    max_command_length: int = 4096

    def __post_init__(self) -> None:
        if self.dialect != "posix-sh":
            raise UnsupportedFeature(
                f"shell dialect {self.dialect!r} is unsupported"
            )
        if self.max_command_length < 128:
            raise ValueError("max command length must be at least 128")

    def quote(self, value: str) -> str:
        if "\0" in value:
            raise ValueError("shell values cannot contain NUL")
        return shlex.quote(value)

    def command(self, *argv: str) -> str:
        rendered = " ".join(self.quote(value) for value in argv)
        if len(rendered.encode()) > self.max_command_length:
            raise ConstraintError(
                f"shell command is {len(rendered.encode())} bytes; maximum is "
                f"{self.max_command_length}"
            )
        return rendered

    def upload_commands(
        self,
        data: bytes,
        remote_path: str,
        *,
        executable: bool = False,
    ) -> tuple[str, ...]:
        if not remote_path:
            raise ValueError("remote path must not be empty")
        digest = hashlib.sha256(data).hexdigest()
        temporary = f"{remote_path}.pwnx-{digest[:12]}.tmp"
        prefix = self.command("sh", "-c", f": > {self.quote(temporary)}")
        overhead = len(
            self.command(
                "sh",
                "-c",
                f"printf %s X | base64 -d >> {self.quote(temporary)}",
            )
        )
        chunk_bytes = max(3, ((self.max_command_length - overhead) * 3 // 4) - 3)
        chunk_bytes -= chunk_bytes % 3
        commands = [prefix]
        for offset in range(0, len(data), chunk_bytes):
            encoded = base64.b64encode(data[offset : offset + chunk_bytes]).decode()
            commands.append(
                self.command(
                    "sh",
                    "-c",
                    f"printf %s {self.quote(encoded)} | base64 -d >> "
                    f"{self.quote(temporary)}",
                )
            )
        if executable:
            commands.append(self.command("chmod", "700", temporary))
        commands.append(self.command("mv", "--", temporary, remote_path))
        return tuple(commands)


Runner = Callable[..., subprocess.CompletedProcess[bytes]]


@dataclass(frozen=True)
class OpenSSHBackend:
    host: str
    user: str | None = None
    port: int = 22
    credential: CredentialReference | None = None
    known_hosts: str = "strict"
    ssh: str = "ssh"
    scp: str = "scp"
    options: tuple[str, ...] = ()
    service_scope: str = "service:ssh"
    connection_scope: str = "connection:ssh"
    runner: Runner = field(default=subprocess.run, compare=False, repr=False)
    shell: ShellCommandCodec = field(default_factory=ShellCommandCodec)

    name: str = "openssh"

    def __post_init__(self) -> None:
        if not self.host or not 0 < self.port < 65536:
            raise ValueError("SSH host and port are required")
        if self.known_hosts not in {"strict", "accept-new", "insecure"}:
            raise ValueError("known_hosts must be strict, accept-new, or insecure")

    @property
    def identity(self) -> str:
        return _digest(
            {
                "name": self.name,
                "host": self.host,
                "user": self.user,
                "port": self.port,
                "credential": self.credential.as_dict() if self.credential else None,
                "known_hosts": self.known_hosts,
                "options": list(self.options),
                "shell": {
                    "dialect": self.shell.dialect,
                    "max_command_length": self.shell.max_command_length,
                },
            }
        )

    @property
    def destination(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host

    def _policy(self) -> list[str]:
        values: list[str] = []
        if self.credential and self.credential.identity_file:
            values.extend(("-i", self.credential.identity_file))
        if self.known_hosts == "accept-new":
            values.extend(("-o", "StrictHostKeyChecking=accept-new"))
        elif self.known_hosts == "insecure":
            values.extend(
                ("-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null")
            )
        values.extend(option for item in self.options for option in ("-o", item))
        return values

    def _ssh_argv(self, command: str) -> list[str]:
        return [
            self.ssh,
            "-T",
            "-p",
            str(self.port),
            *self._policy(),
            self.destination,
            "--",
            command,
        ]

    def _scp_argv(self, source: str, destination: str) -> list[str]:
        return [
            self.scp,
            "-P",
            str(self.port),
            *self._policy(),
            "--",
            source,
            destination,
        ]

    def _run(
        self,
        argv: list[str],
        *,
        deadline: float,
        input_: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            result = self.runner(
                argv,
                input=input_,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=deadline,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ProtocolError(f"OpenSSH effect failed to start or timed out: {error}") from error
        if result.returncode:
            diagnostic = result.stderr.decode("utf-8", "replace").strip()
            raise ProtocolError(
                f"OpenSSH effect failed with status {result.returncode}: "
                f"{diagnostic or '<no diagnostic>'}"
            )
        return result

    def _remote_hash(
        self, path: str, *, deadline: float
    ) -> tuple[str, int]:
        command = self.shell.command(
            "sh",
            "-c",
            f"set -- {self.shell.quote(path)}; "
            "sha256sum -- \"$1\"; stat -c %s -- \"$1\"",
        )
        result = self._run(self._ssh_argv(command), deadline=deadline)
        lines = result.stdout.decode("utf-8", "replace").splitlines()
        if len(lines) < 2:
            raise ProtocolError("remote hash/stat response is incomplete")
        digest = lines[0].split(maxsplit=1)[0]
        try:
            size = int(lines[1])
        except ValueError as error:
            raise ProtocolError("remote stat size is invalid") from error
        try:
            _validate_digest(digest, "remote SHA-256 response")
        except ValueError as error:
            raise ProtocolError(str(error)) from error
        return digest, size

    def execute(self, action: ArtifactTransfer) -> TransferResult:
        if action.backend is not self and action.backend.identity != self.identity:
            raise ConstraintError("transfer action belongs to a different backend")
        if action.operation == "upload":
            return self._upload(action)
        if action.operation == "download":
            return self._download(action)
        digest, size = self._remote_hash(action.remote_path, deadline=action.deadline)
        _check_expected(action, digest, size)
        artifact = RemoteArtifact(
            action.remote_path,
            digest,
            size,
            self.name,
            action.service_scope,
            action.connection_scope,
            (f"queried through {self.destination}",),
        )
        return TransferResult(action.operation, artifact, evidence=("read-only remote query",))

    def _upload(self, action: ArtifactTransfer) -> TransferResult:
        assert action.local_path is not None
        local = Path(action.local_path).expanduser().resolve()
        digest, size = _file_hash(local, action.max_size)
        if action.expected_sha256 is not None and action.expected_sha256 != digest:
            raise ConstraintError("local upload artifact does not match expected SHA-256")
        temporary = f"{action.remote_path}.pwnx-{digest[:12]}.tmp"
        remote_temp = f"{self.destination}:{self.shell.quote(temporary)}"
        self._run(
            self._scp_argv(str(local), remote_temp),
            deadline=action.deadline,
        )
        try:
            commands = []
            if action.executable:
                commands.append(self.shell.command("chmod", "700", temporary))
            commands.append(self.shell.command("mv", "--", temporary, action.remote_path))
            self._run(
                self._ssh_argv(" && ".join(commands)),
                deadline=action.deadline,
            )
        except BaseException:
            cleanup = self.shell.command("rm", "-f", "--", temporary)
            try:
                self._run(self._ssh_argv(cleanup), deadline=action.deadline)
            except ProtocolError:
                pass
            raise
        remote_digest, remote_size = self._remote_hash(
            action.remote_path, deadline=action.deadline
        )
        if remote_digest != digest or remote_size != size:
            raise ProtocolError("remote upload verification does not match local artifact")
        artifact = RemoteArtifact(
            action.remote_path,
            digest,
            size,
            self.name,
            action.service_scope,
            action.connection_scope,
            ("atomic temporary upload and rename",),
        )
        return TransferResult("upload", artifact, str(local))

    def _download(self, action: ArtifactTransfer) -> TransferResult:
        assert action.local_path is not None
        destination = Path(action.local_path).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        remote_digest, remote_size = self._remote_hash(
            action.remote_path, deadline=action.deadline
        )
        _check_expected(action, remote_digest, remote_size)
        if remote_size > action.max_size:
            raise ConstraintError(
                f"remote artifact is {remote_size} bytes; maximum is {action.max_size}"
            )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".pwnx-download",
            dir=destination.parent,
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            remote = f"{self.destination}:{self.shell.quote(action.remote_path)}"
            self._run(
                self._scp_argv(remote, str(temporary)),
                deadline=action.deadline,
            )
            digest, size = _file_hash(temporary, action.max_size)
            if digest != remote_digest or size != remote_size:
                raise ProtocolError("downloaded artifact does not match remote evidence")
            os.replace(temporary, destination)
        except BaseException:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise
        artifact = RemoteArtifact(
            action.remote_path,
            remote_digest,
            remote_size,
            self.name,
            action.service_scope,
            action.connection_scope,
            ("downloaded to an atomic local destination",),
        )
        return TransferResult("download", artifact, str(destination))


def _file_hash(path: Path, maximum: int) -> tuple[str, int]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ProtocolError(f"cannot inspect local artifact {path}: {error}") from error
    if size > maximum:
        raise ConstraintError(f"artifact is {size} bytes; maximum is {maximum}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
    except OSError as error:
        raise ProtocolError(f"cannot read local artifact {path}: {error}") from error
    return digest.hexdigest(), size


def _check_expected(action: ArtifactTransfer, digest: str, size: int) -> None:
    if size > action.max_size:
        raise ConstraintError(
            f"remote artifact is {size} bytes; maximum is {action.max_size}"
        )
    if action.expected_sha256 is not None and digest != action.expected_sha256:
        raise ConstraintError("remote artifact does not match expected SHA-256")


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
    ).hexdigest()


def _validate_digest(value: str, label: str) -> None:
    if len(value) != 64:
        raise ValueError(f"{label} requires a hexadecimal SHA-256 digest")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(
            f"{label} requires a hexadecimal SHA-256 digest"
        ) from error
