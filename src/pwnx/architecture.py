"""Explicit target architecture and environment adapter contracts.

The public objects in this module describe targets and backend support without
starting processes, opening sockets, or mutating global context.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Protocol

from .errors import ArtifactError, UnsupportedFeature


_ENDIANS = {"little", "big"}
_SCOPES = {"artifact", "service", "process", "connection"}


@dataclass(frozen=True, slots=True)
class ArchitectureSpec:
    name: str
    bits: int
    endian: str
    os: str
    abi: str
    registers: tuple[str, ...]
    pointer_width: int
    aliases: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not self.os or not self.abi:
            raise ValueError("architecture name, OS, and ABI must not be empty")
        if self.bits <= 0 or self.bits % 8:
            raise ValueError("architecture bits must be a positive multiple of eight")
        if self.pointer_width <= 0 or self.pointer_width > self.bits // 8:
            raise ValueError("pointer width must fit within the architecture word")
        if self.endian not in _ENDIANS:
            raise ValueError("endian must be 'little' or 'big'")
        if not self.registers or len(set(self.registers)) != len(self.registers):
            raise ValueError("architecture registers must be non-empty and unique")
        if self.name in self.aliases:
            raise ValueError("canonical architecture name cannot also be an alias")

    @property
    def identity(self) -> str:
        return _digest(self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "bits": self.bits,
            "endian": self.endian,
            "os": self.os,
            "abi": self.abi,
            "registers": list(self.registers),
            "pointer_width": self.pointer_width,
            "aliases": list(self.aliases),
        }


AMD64 = ArchitectureSpec(
    "amd64",
    64,
    "little",
    "linux",
    "sysv",
    (
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
    ),
    8,
    ("x86_64", "x64"),
)
I386 = ArchitectureSpec(
    "i386",
    32,
    "little",
    "linux",
    "sysv",
    ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"),
    4,
    ("x86",),
)
AARCH64 = ArchitectureSpec(
    "aarch64",
    64,
    "little",
    "linux",
    "aapcs64",
    tuple([*(f"x{index}" for index in range(31)), "sp", "pc"]),
    8,
    ("arm64",),
)
ARM = ArchitectureSpec(
    "arm",
    32,
    "little",
    "linux",
    "aapcs",
    tuple([*(f"r{index}" for index in range(16)), "cpsr"]),
    4,
    ("armv7",),
)
MIPS = ArchitectureSpec(
    "mips",
    32,
    "big",
    "linux",
    "o32",
    (
        "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
        "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
        "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra", "pc",
    ),
    4,
)
MIPSEL = ArchitectureSpec(
    "mipsel",
    32,
    "little",
    "linux",
    "o32",
    MIPS.registers,
    4,
)
RISCV64 = ArchitectureSpec(
    "riscv64",
    64,
    "little",
    "linux",
    "lp64d",
    tuple([*(f"x{index}" for index in range(32)), "pc"]),
    8,
    ("rv64",),
)

BUILTIN_ARCHITECTURES = (
    AMD64,
    I386,
    AARCH64,
    ARM,
    MIPS,
    MIPSEL,
    RISCV64,
)
_ARCHITECTURES = {
    key: spec
    for spec in BUILTIN_ARCHITECTURES
    for key in (spec.name, *spec.aliases)
}


def architecture(value: str | ArchitectureSpec) -> ArchitectureSpec:
    if isinstance(value, ArchitectureSpec):
        return value
    try:
        return _ARCHITECTURES[value.lower()]
    except (AttributeError, KeyError) as error:
        names = ", ".join(spec.name for spec in BUILTIN_ARCHITECTURES)
        raise UnsupportedFeature(
            f"unknown architecture {value!r}; declared specifications: {names}"
        ) from error


@dataclass(frozen=True, slots=True)
class CapabilityPredicate:
    architectures: frozenset[str] = frozenset()
    bits: frozenset[int] = frozenset()
    endians: frozenset[str] = frozenset()
    operating_systems: frozenset[str] = frozenset()
    abis: frozenset[str] = frozenset()
    reason: str = ""

    def __post_init__(self) -> None:
        if any(endian not in _ENDIANS for endian in self.endians):
            raise ValueError("capability predicate contains an invalid endian")

    def evaluate(self, target: ArchitectureSpec) -> "SupportDecision":
        failures: list[str] = []
        if self.architectures and target.name not in self.architectures:
            failures.append(f"architecture {target.name} is unsupported")
        if self.bits and target.bits not in self.bits:
            failures.append(f"{target.bits}-bit targets are unsupported")
        if self.endians and target.endian not in self.endians:
            failures.append(f"{target.endian}-endian targets are unsupported")
        if self.operating_systems and target.os not in self.operating_systems:
            failures.append(f"OS {target.os} is unsupported")
        if self.abis and target.abi not in self.abis:
            failures.append(f"ABI {target.abi} is unsupported")
        if failures and self.reason:
            failures.append(self.reason)
        return SupportDecision(not failures, tuple(failures))

    @classmethod
    def any(cls) -> "CapabilityPredicate":
        return cls()

    @classmethod
    def names(cls, *names: str, reason: str = "") -> "CapabilityPredicate":
        return cls(frozenset(names), reason=reason)


@dataclass(frozen=True, slots=True)
class SupportDecision:
    supported: bool
    reasons: tuple[str, ...] = ()

    def require(self, feature: str) -> None:
        if not self.supported:
            detail = "; ".join(self.reasons) or "unsupported target"
            raise UnsupportedFeature(f"{feature}: {detail}")


@dataclass(frozen=True, slots=True)
class BackendCapabilities:
    name: str
    features: frozenset[str]
    supports: CapabilityPredicate = field(default_factory=CapabilityPredicate.any)
    version: str = ""
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not self.features:
            raise ValueError("backend name and features must not be empty")

    @property
    def identity(self) -> str:
        return _digest(
            {
                "name": self.name,
                "features": sorted(self.features),
                "version": self.version,
                "evidence": list(self.evidence),
            }
        )

    def decision(self, feature: str, target: ArchitectureSpec) -> SupportDecision:
        if feature not in self.features:
            return SupportDecision(False, (f"feature {feature!r} is not provided",))
        return self.supports.evaluate(target)


@dataclass(frozen=True, slots=True)
class BackendSelection:
    feature: str
    architecture: ArchitectureSpec
    capabilities: BackendCapabilities
    implementation: Any
    rejected: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def explain(self) -> str:
        lines = [
            f"{self.feature} for {self.architecture.name}: "
            f"{self.capabilities.name} ({self.capabilities.version or 'unversioned'})"
        ]
        lines.extend(
            f"  rejected {name}: {'; '.join(reasons)}"
            for name, reasons in self.rejected
        )
        return "\n".join(lines)


class BackendRegistry:
    def __init__(self) -> None:
        self._items: dict[str, tuple[BackendCapabilities, Any, int]] = {}

    def register(
        self,
        capabilities: BackendCapabilities,
        implementation: Any,
        *,
        priority: int = 0,
    ) -> None:
        if capabilities.name in self._items:
            raise ValueError(f"backend {capabilities.name!r} is already registered")
        self._items[capabilities.name] = (capabilities, implementation, priority)

    def select(
        self,
        feature: str,
        target: str | ArchitectureSpec,
        *,
        prefer: Iterable[str] = (),
    ) -> BackendSelection:
        spec = architecture(target)
        preference = {name: index for index, name in enumerate(prefer)}
        eligible: list[tuple[int, int, str, BackendCapabilities, Any]] = []
        rejected: list[tuple[str, tuple[str, ...]]] = []
        for name, (capabilities, implementation, priority) in self._items.items():
            decision = capabilities.decision(feature, spec)
            if not decision.supported:
                rejected.append((name, decision.reasons))
                continue
            eligible.append(
                (
                    preference.get(name, len(preference)),
                    -priority,
                    name,
                    capabilities,
                    implementation,
                )
            )
        if not eligible:
            detail = "; ".join(
                f"{name}: {'; '.join(reasons)}" for name, reasons in rejected
            )
            raise UnsupportedFeature(
                f"no backend provides {feature!r} for {spec.name}"
                + (f": {detail}" if detail else "")
            )
        _pref, _priority, _name, capabilities, implementation = min(eligible)
        return BackendSelection(
            feature,
            spec,
            capabilities,
            implementation,
            tuple(sorted(rejected)),
        )

    def explain(self) -> str:
        return "\n".join(
            f"{name}: {', '.join(sorted(capabilities.features))}"
            for name, (capabilities, _implementation, _priority) in sorted(
                self._items.items()
            )
        )


@dataclass(frozen=True, slots=True)
class ArtifactIdentity:
    role: str
    path: str
    sha256: str
    size: int

    @classmethod
    def from_path(cls, role: str, path: str | os.PathLike[str]) -> "ArtifactIdentity":
        artifact = Path(path).expanduser().resolve()
        try:
            data = artifact.read_bytes()
        except OSError as error:
            raise ArtifactError(f"cannot identify artifact {artifact}: {error}") from error
        return cls(role, str(artifact), hashlib.sha256(data).hexdigest(), len(data))


@dataclass(frozen=True, slots=True)
class CredentialReference:
    name: str
    identity_file: str | None = None
    use_agent: bool = True

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("credential reference name must not be empty")
        if self.identity_file is not None:
            object.__setattr__(
                self,
                "identity_file",
                str(Path(self.identity_file).expanduser().resolve()),
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "identity_file": self.identity_file,
            "use_agent": self.use_agent,
        }


@dataclass(frozen=True, slots=True)
class LifecyclePolicy:
    service: str = "persistent"
    process: str = "fresh-per-run"
    connection: str = "fresh-per-run"

    def __post_init__(self) -> None:
        allowed = {"persistent", "fresh-per-run", "fresh-per-connection", "external"}
        if any(value not in allowed for value in (self.service, self.process, self.connection)):
            raise ValueError("invalid lifecycle policy")


@dataclass(frozen=True, slots=True)
class LifecycleEpochs:
    service: str
    process: str
    connection: str

    def scope(self, value: str) -> str:
        if value not in _SCOPES:
            raise ValueError(f"unknown lifetime scope {value!r}")
        return {
            "artifact": "artifact",
            "service": self.service,
            "process": self.process,
            "connection": self.connection,
        }[value]


@dataclass(frozen=True, slots=True)
class MaterializedTarget:
    adapter: str
    architecture: ArchitectureSpec
    argv: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str | None = None
    endpoint: tuple[str, int] | None = None
    artifacts: tuple[ArtifactIdentity, ...] = ()
    lifecycle: LifecyclePolicy = field(default_factory=LifecyclePolicy)
    epochs: LifecycleEpochs = field(
        default_factory=lambda: LifecycleEpochs(
            "service:unbound", "process:unbound", "connection:unbound"
        )
    )
    adapter_identity: str = ""
    evidence: tuple[str, ...] = ()
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "env", MappingProxyType(dict(self.env)))
        object.__setattr__(self, "options", MappingProxyType(dict(self.options)))
        if not self.adapter or not self.adapter_identity:
            raise ValueError("materialized targets require adapter identity")

    @property
    def identity(self) -> str:
        return _digest(
            {
                "adapter": self.adapter,
                "architecture": self.architecture.identity,
                "argv": list(self.argv),
                "env": dict(self.env),
                "cwd": self.cwd,
                "endpoint": self.endpoint,
                "artifacts": [
                    {
                        "role": item.role,
                        "path": item.path,
                        "sha256": item.sha256,
                        "size": item.size,
                    }
                    for item in self.artifacts
                ],
                "adapter_identity": self.adapter_identity,
                "options": dict(self.options),
            }
        )

    def explain(self) -> str:
        lines = [
            f"{self.adapter} target {self.identity[:12]} ({self.architecture.name})",
            f"  lifecycle: service={self.lifecycle.service}, "
            f"process={self.lifecycle.process}, connection={self.lifecycle.connection}",
        ]
        if self.argv:
            lines.append(f"  argv: {self.argv!r}")
        if self.endpoint:
            lines.append(f"  endpoint: {self.endpoint[0]}:{self.endpoint[1]}")
        lines.extend(f"  artifact {item.role}: {item.sha256[:12]} {item.path}" for item in self.artifacts)
        lines.extend(f"  {item}" for item in self.evidence)
        return "\n".join(lines)


class TargetRecipe(Protocol):
    architecture: ArchitectureSpec

    @property
    def identity(self) -> str: ...

    def materialize(self, *, epoch_seed: str = "run") -> MaterializedTarget: ...


@dataclass(frozen=True, slots=True)
class LocalProcessRecipe:
    executable: str
    architecture: ArchitectureSpec = AMD64
    arguments: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str | None = None
    loader: str | None = None
    libraries: tuple[str, ...] = ()
    lifecycle: LifecyclePolicy = field(default_factory=LifecyclePolicy)

    def __post_init__(self) -> None:
        object.__setattr__(self, "executable", str(Path(self.executable).expanduser().resolve()))
        object.__setattr__(self, "env", MappingProxyType(dict(self.env)))
        if self.loader is not None:
            object.__setattr__(self, "loader", str(Path(self.loader).expanduser().resolve()))
        object.__setattr__(
            self,
            "libraries",
            tuple(str(Path(item).expanduser().resolve()) for item in self.libraries),
        )

    @property
    def identity(self) -> str:
        return _digest(_recipe_data(self))

    def materialize(self, *, epoch_seed: str = "run") -> MaterializedTarget:
        artifacts = [ArtifactIdentity.from_path("executable", self.executable)]
        argv: list[str] = []
        if self.loader is not None:
            artifacts.append(ArtifactIdentity.from_path("loader", self.loader))
            argv.append(self.loader)
            if self.libraries:
                library_paths = sorted({str(Path(item).parent) for item in self.libraries})
                argv.extend(("--library-path", ":".join(library_paths)))
        argv.append(self.executable)
        argv.extend(self.arguments)
        artifacts.extend(
            ArtifactIdentity.from_path(f"library:{Path(item).name}", item)
            for item in self.libraries
        )
        return _target(
            "local-process",
            self.architecture,
            tuple(argv),
            self.env,
            self.cwd,
            tuple(artifacts),
            self.lifecycle,
            self.identity,
            epoch_seed,
        )


@dataclass(frozen=True, slots=True)
class QemuUserRecipe:
    executable: str
    architecture: ArchitectureSpec
    emulator: str
    sysroot: str | None = None
    arguments: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str | None = None
    gdb_port: int | None = None
    lifecycle: LifecyclePolicy = field(default_factory=LifecyclePolicy)

    def __post_init__(self) -> None:
        object.__setattr__(self, "executable", str(Path(self.executable).expanduser().resolve()))
        object.__setattr__(self, "emulator", str(Path(self.emulator).expanduser().resolve()))
        object.__setattr__(self, "env", MappingProxyType(dict(self.env)))
        if self.sysroot is not None:
            object.__setattr__(self, "sysroot", str(Path(self.sysroot).expanduser().resolve()))
        if self.gdb_port is not None and not 0 < self.gdb_port < 65536:
            raise ValueError("gdb_port must be in range 1..65535")

    @property
    def identity(self) -> str:
        return _digest(_recipe_data(self))

    def materialize(self, *, epoch_seed: str = "run") -> MaterializedTarget:
        artifacts = (
            ArtifactIdentity.from_path("emulator", self.emulator),
            ArtifactIdentity.from_path("executable", self.executable),
        )
        argv = [self.emulator]
        if self.sysroot is not None:
            argv.extend(("-L", self.sysroot))
        if self.gdb_port is not None:
            argv.extend(("-g", str(self.gdb_port)))
        argv.append(self.executable)
        argv.extend(self.arguments)
        return _target(
            "qemu-user",
            self.architecture,
            tuple(argv),
            self.env,
            self.cwd,
            artifacts,
            self.lifecycle,
            self.identity,
            epoch_seed,
            evidence=("QEMU user-mode execution",),
            options={"sysroot": self.sysroot, "gdb_port": self.gdb_port},
        )


@dataclass(frozen=True, slots=True)
class SSHProcessRecipe:
    host: str
    command: tuple[str, ...]
    architecture: ArchitectureSpec = AMD64
    user: str | None = None
    port: int = 22
    credential: CredentialReference | None = None
    known_hosts: str = "strict"
    options: tuple[str, ...] = ()
    lifecycle: LifecyclePolicy = field(
        default_factory=lambda: LifecyclePolicy(
            "persistent", "fresh-per-connection", "fresh-per-run"
        )
    )

    def __post_init__(self) -> None:
        if not self.host or not self.command:
            raise ValueError("SSH host and command must not be empty")
        if not 0 < self.port < 65536:
            raise ValueError("SSH port must be in range 1..65535")
        if self.known_hosts not in {"strict", "accept-new", "insecure"}:
            raise ValueError("known_hosts must be strict, accept-new, or insecure")

    @property
    def identity(self) -> str:
        return _digest(_recipe_data(self))

    def materialize(self, *, epoch_seed: str = "run") -> MaterializedTarget:
        destination = f"{self.user}@{self.host}" if self.user else self.host
        argv = ["ssh", "-T", "-p", str(self.port)]
        if self.credential and self.credential.identity_file:
            argv.extend(("-i", self.credential.identity_file))
        if self.known_hosts == "accept-new":
            argv.extend(("-o", "StrictHostKeyChecking=accept-new"))
        elif self.known_hosts == "insecure":
            argv.extend(("-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"))
        argv.extend(option for item in self.options for option in ("-o", item))
        remote_command = " ".join(shlex.quote(value) for value in self.command)
        argv.extend((destination, "--", remote_command))
        return _target(
            "ssh-process",
            self.architecture,
            tuple(argv),
            {},
            None,
            (),
            self.lifecycle,
            self.identity,
            epoch_seed,
            evidence=(f"credential reference: {self.credential.name if self.credential else 'agent/default'}",),
            options={
                "host": self.host,
                "user": self.user,
                "port": self.port,
                "known_hosts": self.known_hosts,
            },
        )


@dataclass(frozen=True, slots=True)
class SerialRecipe:
    device: str
    baud: int = 115200
    architecture: ArchitectureSpec = AMD64
    lifecycle: LifecyclePolicy = field(
        default_factory=lambda: LifecyclePolicy("external", "external", "fresh-per-run")
    )

    @property
    def identity(self) -> str:
        return _digest(_recipe_data(self))

    def materialize(self, *, epoch_seed: str = "run") -> MaterializedTarget:
        if not self.device or self.baud <= 0:
            raise ValueError("serial device and positive baud are required")
        return _target(
            "serial",
            self.architecture,
            (),
            {},
            None,
            (),
            self.lifecycle,
            self.identity,
            epoch_seed,
            evidence=(f"serial device {self.device} at {self.baud} baud",),
            options={"device": self.device, "baud": self.baud},
        )


@dataclass(frozen=True, slots=True)
class TcpRecipe:
    host: str
    port: int
    architecture: ArchitectureSpec = AMD64
    tls: bool = False
    lifecycle: LifecyclePolicy = field(
        default_factory=lambda: LifecyclePolicy(
            "persistent", "fresh-per-connection", "fresh-per-run"
        )
    )

    @property
    def identity(self) -> str:
        return _digest(_recipe_data(self))

    def materialize(self, *, epoch_seed: str = "run") -> MaterializedTarget:
        if not self.host or not 0 < self.port < 65536:
            raise ValueError("TCP host and port are required")
        return _target(
            "tls" if self.tls else "tcp",
            self.architecture,
            (),
            {},
            None,
            (),
            self.lifecycle,
            self.identity,
            epoch_seed,
            evidence=("TLS certificate validation enabled",) if self.tls else (),
            endpoint=(self.host, self.port),
            options={"tls": self.tls},
        )


def tcp(
    host: str,
    port: int,
    *,
    tls: bool = False,
    architecture: ArchitectureSpec = AMD64,
    lifecycle: LifecyclePolicy | None = None,
) -> TcpRecipe:
    """Return an immutable TCP target recipe with competition-friendly syntax."""

    if lifecycle is None:
        return TcpRecipe(host, port, architecture=architecture, tls=tls)
    return TcpRecipe(
        host,
        port,
        architecture=architecture,
        tls=tls,
        lifecycle=lifecycle,
    )


def _target(
    adapter: str,
    spec: ArchitectureSpec,
    argv: tuple[str, ...],
    env: Mapping[str, str],
    cwd: str | None,
    artifacts: tuple[ArtifactIdentity, ...],
    lifecycle: LifecyclePolicy,
    adapter_identity: str,
    seed: str,
    *,
    evidence: tuple[str, ...] = (),
    endpoint: tuple[str, int] | None = None,
    options: Mapping[str, Any] = MappingProxyType({}),
) -> MaterializedTarget:
    def epoch(scope: str, policy: str) -> str:
        epoch_seed = adapter_identity if policy == "persistent" else seed
        return f"{scope}:{_digest((adapter_identity, epoch_seed, scope, policy))[:16]}"
    return MaterializedTarget(
        adapter,
        spec,
        argv,
        env,
        cwd,
        endpoint,
        artifacts,
        lifecycle,
        LifecycleEpochs(
            epoch("service", lifecycle.service),
            epoch("process", lifecycle.process),
            epoch("connection", lifecycle.connection),
        ),
        adapter_identity,
        evidence,
        options,
    )


def _recipe_data(value: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for name in value.__dataclass_fields__:
        item = getattr(value, name)
        if isinstance(item, ArchitectureSpec):
            fields[name] = item.as_dict()
        elif isinstance(item, CredentialReference):
            fields[name] = item.as_dict()
        elif isinstance(item, LifecyclePolicy):
            fields[name] = {
                "service": item.service,
                "process": item.process,
                "connection": item.connection,
            }
        elif isinstance(item, Mapping):
            fields[name] = dict(item)
        elif isinstance(item, tuple):
            fields[name] = list(item)
        else:
            fields[name] = item
    return fields


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
