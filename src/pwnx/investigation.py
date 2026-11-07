"""Bounded, evidence-producing investigations.

Investigations never run during planning and never silently turn a hypothesis
into a fact.  Adapters receive explicit budgets and return portable reports;
the Investigation action records and reuses those reports during replay.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol, Sequence

from .actions import Action
from .artifacts import Image
from .diagnostics import Corefile
from .domain import EffectContract, Evidence, Scope
from .errors import ArtifactError, ConstraintError, ProtocolError
from .expressions import Expr
from .trace import ReplayTube


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _file_identity(path: str | os.PathLike[str]) -> tuple[str | None, int | None]:
    candidate = Path(path)
    if not candidate.is_file():
        return None, None
    digest = hashlib.sha256()
    size = 0
    with candidate.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _evidence_dict(value: Evidence) -> dict[str, Any]:
    return {
        "kind": value.kind,
        "summary": value.summary,
        "source": value.source,
        "details": dict(value.details),
    }


def _evidence_from(value: Mapping[str, Any]) -> Evidence:
    return Evidence(
        str(value["kind"]),
        str(value["summary"]),
        str(value.get("source", "")),
        value.get("details", {}),
    )


@dataclass(frozen=True, slots=True)
class InvestigationBudget:
    timeout: float = 30.0
    memory_bytes: int = 512 * 1024 * 1024
    max_states: int = 100_000
    max_results: int = 64
    max_output: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        if (
            self.timeout <= 0
            or self.memory_bytes <= 0
            or self.max_states <= 0
            or self.max_results <= 0
            or self.max_output <= 0
        ):
            raise ValueError("investigation budget values must be positive")

    def to_dict(self) -> dict[str, Any]:
        return {
            "timeout": self.timeout,
            "memory_bytes": self.memory_bytes,
            "max_states": self.max_states,
            "max_results": self.max_results,
            "max_output": self.max_output,
        }


@dataclass(frozen=True, slots=True)
class InvestigationRequest:
    kind: str
    target: str
    architecture: str = "amd64"
    find: tuple[Any, ...] = ()
    avoid: tuple[Any, ...] = ()
    constraints: Mapping[str, Any] = field(default_factory=dict)
    inputs: Mapping[str, Any] = field(default_factory=dict)
    adapter: str | None = None
    budget: InvestigationBudget = field(default_factory=InvestigationBudget)

    def __post_init__(self) -> None:
        if not self.kind or not self.target or not self.architecture:
            raise ValueError("investigation kind, target, and architecture are required")
        object.__setattr__(self, "constraints", MappingProxyType(dict(self.constraints)))
        object.__setattr__(self, "inputs", MappingProxyType(dict(self.inputs)))
        # Validate portability at declaration time.
        json.dumps(self.to_dict(), allow_nan=False)

    @property
    def target_sha256(self) -> str | None:
        return _file_identity(self.target)[0]

    @property
    def input_digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        digest, size = _file_identity(self.target)
        return {
            "kind": self.kind,
            "target": self.target,
            "target_sha256": digest,
            "target_size": size,
            "architecture": self.architecture,
            "find": list(self.find),
            "avoid": list(self.avoid),
            "constraints": dict(self.constraints),
            "inputs": dict(self.inputs),
            "adapter": self.adapter,
            "budget": self.budget.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class Hypothesis:
    kind: str
    claim: str
    confidence: float
    evidence: tuple[Evidence, ...] = ()
    requirements: tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.kind or not self.claim:
            raise ValueError("hypothesis kind and claim are required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("hypothesis confidence must be between 0 and 1")
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))

    def describe(self) -> str:
        return f"{self.kind} ({self.confidence:.0%}): {self.claim}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "claim": self.claim,
            "confidence": self.confidence,
            "evidence": [_evidence_dict(item) for item in self.evidence],
            "requirements": list(self.requirements),
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Hypothesis":
        return cls(
            str(value["kind"]),
            str(value["claim"]),
            float(value["confidence"]),
            tuple(_evidence_from(item) for item in value.get("evidence", ())),
            tuple(str(item) for item in value.get("requirements", ())),
            value.get("details", {}),
        )


@dataclass(frozen=True, slots=True)
class InvestigationRejection:
    adapter: str
    reason: str
    evidence: tuple[Evidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "reason": self.reason,
            "evidence": [_evidence_dict(item) for item in self.evidence],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "InvestigationRejection":
        return cls(
            str(value["adapter"]),
            str(value["reason"]),
            tuple(_evidence_from(item) for item in value.get("evidence", ())),
        )


@dataclass(frozen=True, slots=True)
class InvestigationArtifact:
    path: str
    sha256: str
    size: int
    kind: str = "analysis"

    def __post_init__(self) -> None:
        if not self.path or len(self.sha256) != 64 or self.size < 0:
            raise ValueError("invalid investigation artifact")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "kind": self.kind,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "InvestigationArtifact":
        return cls(
            str(value["path"]),
            str(value["sha256"]),
            int(value["size"]),
            str(value.get("kind", "analysis")),
        )


@dataclass(frozen=True, slots=True)
class InvestigationMetrics:
    adapter: str
    duration: float
    states: int = 0
    output_bytes: int = 0
    exit_status: int | None = None

    def __post_init__(self) -> None:
        if self.duration < 0 or self.states < 0 or self.output_bytes < 0:
            raise ValueError("investigation metrics cannot be negative")

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "duration": self.duration,
            "states": self.states,
            "output_bytes": self.output_bytes,
            "exit_status": self.exit_status,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "InvestigationMetrics":
        status = value.get("exit_status")
        return cls(
            str(value["adapter"]),
            float(value["duration"]),
            int(value.get("states", 0)),
            int(value.get("output_bytes", 0)),
            int(status) if status is not None else None,
        )


@dataclass(frozen=True, slots=True)
class InvestigationReport:
    request_digest: str
    candidates: tuple[Hypothesis, ...]
    rejections: tuple[InvestigationRejection, ...]
    metrics: InvestigationMetrics
    artifacts: tuple[InvestigationArtifact, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def explain(self) -> str:
        lines = [
            f"investigation {self.request_digest[:12]} via {self.metrics.adapter}: "
            f"{len(self.candidates)} candidate(s), {len(self.rejections)} rejection(s)",
        ]
        lines.extend(f"  candidate: {item.describe()}" for item in self.candidates)
        lines.extend(
            f"  rejected {item.adapter}: {item.reason}" for item in self.rejections
        )
        lines.extend(f"  {item.describe()}" for item in self.evidence)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_digest": self.request_digest,
            "candidates": [item.to_dict() for item in self.candidates],
            "rejections": [item.to_dict() for item in self.rejections],
            "metrics": self.metrics.to_dict(),
            "artifacts": [item.to_dict() for item in self.artifacts],
            "evidence": [_evidence_dict(item) for item in self.evidence],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "InvestigationReport":
        return cls(
            str(value["request_digest"]),
            tuple(Hypothesis.from_dict(item) for item in value.get("candidates", ())),
            tuple(
                InvestigationRejection.from_dict(item)
                for item in value.get("rejections", ())
            ),
            InvestigationMetrics.from_dict(value["metrics"]),
            tuple(
                InvestigationArtifact.from_dict(item)
                for item in value.get("artifacts", ())
            ),
            tuple(_evidence_from(item) for item in value.get("evidence", ())),
        )


@dataclass(frozen=True, slots=True)
class AdapterSupport:
    supported: bool
    reason: str = ""
    evidence: tuple[Evidence, ...] = ()


class InvestigationAdapter(Protocol):
    name: str
    identity: str
    reliability: str
    cost: int

    def supports(self, request: InvestigationRequest) -> AdapterSupport: ...

    def investigate(self, request: InvestigationRequest) -> InvestigationReport: ...


class InvestigationAdapterRegistry:
    def __init__(self, adapters: Sequence[InvestigationAdapter] = ()) -> None:
        self._adapters: dict[str, InvestigationAdapter] = {}
        for adapter in adapters:
            self.register(adapter)

    @property
    def adapters(self) -> tuple[InvestigationAdapter, ...]:
        return tuple(self._adapters.values())

    @property
    def identity(self) -> str:
        return _digest(
            [
                (item.name, item.identity, item.reliability, item.cost)
                for item in sorted(self._adapters.values(), key=lambda value: value.name)
            ]
        )

    def register(self, adapter: InvestigationAdapter) -> InvestigationAdapter:
        if adapter.name in self._adapters:
            raise ValueError(f"investigation adapter {adapter.name!r} already exists")
        self._adapters[adapter.name] = adapter
        return adapter

    def candidates(
        self, request: InvestigationRequest
    ) -> tuple[tuple[InvestigationAdapter, AdapterSupport], ...]:
        selected: list[tuple[InvestigationAdapter, AdapterSupport]] = []
        for adapter in self._adapters.values():
            if request.adapter is not None and adapter.name != request.adapter:
                continue
            support = adapter.supports(request)
            selected.append((adapter, support))
        reliability = {"stable": 0, "conditional": 1, "experimental": 2}
        return tuple(
            sorted(
                selected,
                key=lambda item: (
                    not item[1].supported,
                    reliability.get(item[0].reliability, 3),
                    item[0].cost,
                    item[0].name,
                ),
            )
        )

    def investigate(self, request: InvestigationRequest) -> InvestigationReport:
        checked = self.candidates(request)
        unsupported = tuple(
            InvestigationRejection(adapter.name, support.reason, support.evidence)
            for adapter, support in checked
            if not support.supported
        )
        supported = [adapter for adapter, support in checked if support.supported]
        if not supported:
            detail = "; ".join(
                f"{item.adapter}: {item.reason}" for item in unsupported
            )
            raise ConstraintError(
                f"no adapter supports investigation {request.kind!r}: "
                f"{detail or 'no adapters registered'}"
            )
        failures: list[InvestigationRejection] = list(unsupported)
        for adapter in supported:
            try:
                report = adapter.investigate(request)
            except (ArtifactError, ConstraintError, ProtocolError) as error:
                failures.append(InvestigationRejection(adapter.name, str(error)))
                if request.adapter is not None:
                    raise
                continue
            return InvestigationReport(
                report.request_digest,
                report.candidates[: request.budget.max_results],
                tuple((*failures, *report.rejections)),
                report.metrics,
                report.artifacts,
                report.evidence,
            )
        raise ProtocolError(
            "all supported investigation adapters failed: "
            + "; ".join(f"{item.adapter}: {item.reason}" for item in failures)
        )


def _artifact(path: str, kind: str, maximum: int) -> InvestigationArtifact:
    candidate = Path(path)
    try:
        size = candidate.stat().st_size
    except OSError as error:
        raise ArtifactError(f"cannot inspect investigation artifact {path!r}: {error}") from error
    if size > maximum:
        raise ConstraintError(
            f"investigation artifact {path!r} is {size} bytes; maximum is {maximum}"
        )
    digest, _ = _file_identity(candidate)
    assert digest is not None
    return InvestigationArtifact(str(candidate.resolve()), digest, size, kind)


@dataclass(frozen=True)
class StaticTriageAdapter:
    name: str = "static-triage"
    reliability: str = "stable"
    cost: int = 1
    identity: str = "pwnx.static-triage.v1"

    def supports(self, request: InvestigationRequest) -> AdapterSupport:
        if request.kind not in {"static", "static-triage"}:
            return AdapterSupport(False, f"does not support {request.kind!r}")
        if request.architecture != "amd64":
            return AdapterSupport(False, "reference static parser supports amd64 only")
        if not Path(request.target).is_file():
            return AdapterSupport(False, "target artifact does not exist")
        return AdapterSupport(True)

    def investigate(self, request: InvestigationRequest) -> InvestigationReport:
        started = time.monotonic()
        artifact = _artifact(
            request.target, "target", request.budget.memory_bytes
        )
        image = Image(request.target)
        security = image.security
        names = set(image.symbols) | {item.symbol for item in image.relocations}
        candidates: list[Hypothesis] = []
        evidence = (
            Evidence(
                "artifact",
                f"SHA-256 {artifact.sha256}",
                request.target,
                {"size": artifact.size},
            ),
            Evidence(
                "mitigations",
                str(security).replace("\n", "; "),
                request.target,
                dict(security.as_dict()),
            ),
        )
        dangerous = sorted(
            names
            & {
                "gets",
                "strcpy",
                "strcat",
                "sprintf",
                "vsprintf",
                "__isoc99_scanf",
            }
        )
        if dangerous:
            candidates.append(
                Hypothesis(
                    "unsafe-input",
                    f"imports potentially unbounded input routine(s): {', '.join(dangerous)}",
                    0.65,
                    evidence,
                    ("confirm reachable call sites and attacker-controlled sizes",),
                    {"symbols": dangerous},
                )
            )
        if security.canary is False:
            candidates.append(
                Hypothesis(
                    "stack-control",
                    "stack protector import is absent; stack control may be less constrained",
                    0.4,
                    evidence,
                    ("produce a crash and recover the overwrite offset",),
                )
            )
        if security.pie is False:
            candidates.append(
                Hypothesis(
                    "fixed-code-addresses",
                    "executable image is not position independent",
                    0.95,
                    evidence,
                    (),
                )
            )
        if security.relro != "Full" and image.got:
            candidates.append(
                Hypothesis(
                    "writable-relocations",
                    f"{security.relro} RELRO leaves relocation writes worth testing",
                    0.7,
                    evidence,
                    ("confirm target relocation page permissions at runtime",),
                )
            )
        if security.rwx:
            candidates.append(
                Hypothesis(
                    "rwx-segment",
                    "artifact contains a writable and executable load segment",
                    0.9,
                    evidence,
                    ("confirm runtime mapping permissions",),
                )
            )
        candidates = candidates[: request.budget.max_results]
        duration = time.monotonic() - started
        return InvestigationReport(
            request.input_digest,
            tuple(candidates),
            (),
            InvestigationMetrics(
                self.name,
                duration,
                states=len(image.sections),
                output_bytes=sum(len(item.claim) for item in candidates),
            ),
            (artifact,),
            evidence,
        )


@dataclass(frozen=True)
class CrashTriageAdapter:
    name: str = "crash-triage"
    reliability: str = "stable"
    cost: int = 1
    identity: str = "pwnx.crash-triage.v1"

    def supports(self, request: InvestigationRequest) -> AdapterSupport:
        if request.kind not in {"crash", "crash-triage"}:
            return AdapterSupport(False, f"does not support {request.kind!r}")
        if request.architecture != "amd64":
            return AdapterSupport(False, "reference core parser supports amd64 only")
        if not Path(request.target).is_file():
            return AdapterSupport(False, "core artifact does not exist")
        return AdapterSupport(True)

    def investigate(self, request: InvestigationRequest) -> InvestigationReport:
        started = time.monotonic()
        artifact = _artifact(request.target, "core", request.budget.memory_bytes)
        core = Corefile(request.target)
        rip = core.registers.get("rip")
        rsp = core.registers.get("rsp")
        fault = core.fault_addr
        signal = core.signal
        rendered_rip = f"{rip:#x}" if rip is not None else "unknown"
        rendered_fault = f"{fault:#x}" if fault is not None else "unknown"
        evidence = (
            Evidence(
                "crash",
                f"signal {signal}, RIP={rendered_rip}, fault={rendered_fault}",
                request.target,
                {
                    "signal": signal,
                    "rip": rip,
                    "rsp": rsp,
                    "fault_addr": fault,
                },
            ),
        )
        candidates: list[Hypothesis] = []
        if rip is not None:
            try:
                offset = core.cyclic_offset("rip")
            except (ArtifactError, ConstraintError):
                offset = None
        else:
            offset = None
        if offset is not None:
            candidates.append(
                Hypothesis(
                    "instruction-pointer-control",
                    f"RIP matches cyclic input at offset {int(offset)}",
                    0.98,
                    evidence,
                    ("reproduce against the same artifact and launch recipe",),
                    {"offset": int(offset), "register": "rip"},
                )
            )
        candidates.append(
            Hypothesis(
                "crash-cause",
                f"process terminated with signal {signal}",
                0.75,
                evidence,
                ("inspect the faulting instruction and surrounding stack",),
                {"fault_addr": fault},
            )
        )
        return InvestigationReport(
            request.input_digest,
            tuple(candidates[: request.budget.max_results]),
            (),
            InvestigationMetrics(
                self.name,
                time.monotonic() - started,
                states=len(core.maps),
                output_bytes=sum(len(item.claim) for item in candidates),
            ),
            (artifact,),
            evidence,
        )


Runner = Callable[..., subprocess.CompletedProcess[bytes]]


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
    argv: list[str],
    *,
    input_data: bytes,
    timeout: float,
    max_output: int,
    preexec_fn: Callable[[], None] | None,
) -> subprocess.CompletedProcess[bytes]:
    """Run the production adapter without ever retaining over ``max_output`` bytes."""

    options: dict[str, Any] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    if os.name == "posix":
        options["start_new_session"] = True
        options["preexec_fn"] = preexec_fn
    else:
        options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    process = subprocess.Popen(argv, **options)
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    stdin = process.stdin

    buffers = (bytearray(), bytearray())
    total = 0
    lock = threading.Lock()
    overflow = threading.Event()

    def write_input() -> None:
        try:
            stdin.write(input_data)
            stdin.close()
        except (BrokenPipeError, OSError):
            pass

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

    writer = threading.Thread(target=write_input, daemon=True)
    readers = (
        threading.Thread(target=read_output, args=(process.stdout, buffers[0]), daemon=True),
        threading.Thread(target=read_output, args=(process.stderr, buffers[1]), daemon=True),
    )
    writer.start()
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
        writer.join(timeout=0.1)
        for reader in readers:
            reader.join(timeout=1.0)
    if overflow.is_set():
        raise ConstraintError(
            f"investigation output exceeds {max_output} bytes"
        )
    return subprocess.CompletedProcess(
        argv,
        process.returncode,
        bytes(buffers[0]),
        bytes(buffers[1]),
    )


@dataclass(frozen=True)
class SubprocessJSONAdapter:
    name: str
    command: tuple[str, ...]
    kinds: frozenset[str]
    architectures: frozenset[str] = frozenset({"amd64"})
    reliability: str = "experimental"
    cost: int = 10
    runner: Runner = field(default=subprocess.run, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not self.name or not self.command or not self.kinds:
            raise ValueError("adapter name, command, and kinds are required")

    @property
    def identity(self) -> str:
        return _digest(
            {
                "name": self.name,
                "command": list(self.command),
                "kinds": sorted(self.kinds),
                "architectures": sorted(self.architectures),
                "reliability": self.reliability,
                "cost": self.cost,
            }
        )

    def supports(self, request: InvestigationRequest) -> AdapterSupport:
        if request.kind not in self.kinds:
            return AdapterSupport(False, f"does not support {request.kind!r}")
        if request.architecture not in self.architectures:
            return AdapterSupport(
                False, f"does not support architecture {request.architecture!r}"
            )
        return AdapterSupport(True)

    def investigate(self, request: InvestigationRequest) -> InvestigationReport:
        payload = json.dumps(
            request.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode()
        started = time.monotonic()
        preexec_fn = _resource_limiter(request.budget.memory_bytes)
        try:
            if self.runner is subprocess.run:
                result = _bounded_subprocess(
                    list(self.command),
                    input_data=payload,
                    timeout=request.budget.timeout,
                    max_output=request.budget.max_output,
                    preexec_fn=preexec_fn,
                )
            else:
                result = self.runner(
                    list(self.command),
                    input=payload,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=request.budget.timeout,
                    check=False,
                    preexec_fn=preexec_fn,
                )
        except subprocess.TimeoutExpired as error:
            raise ConstraintError(
                f"investigation {self.name!r} exceeded {request.budget.timeout:g}s"
            ) from error
        except OSError as error:
            raise ProtocolError(
                f"investigation adapter {self.name!r} failed to start: {error}"
            ) from error
        if len(result.stdout) + len(result.stderr) > request.budget.max_output:
            raise ConstraintError(
                f"investigation output exceeds {request.budget.max_output} bytes"
            )
        if result.returncode:
            diagnostic = result.stderr.decode("utf-8", "replace").strip()
            raise ProtocolError(
                f"investigation adapter {self.name!r} exited {result.returncode}: "
                f"{diagnostic or '<no diagnostic>'}"
            )
        try:
            decoded = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ProtocolError("investigation adapter returned malformed JSON") from error
        if not isinstance(decoded, dict):
            raise ProtocolError("investigation adapter output must be a JSON object")
        candidates_raw = decoded.get("candidates", ())
        if not isinstance(candidates_raw, list):
            raise ProtocolError("investigation candidates must be an array")
        if len(candidates_raw) > request.budget.max_results:
            raise ConstraintError(
                f"investigation returned {len(candidates_raw)} candidates; "
                f"maximum is {request.budget.max_results}"
            )
        try:
            candidates = tuple(Hypothesis.from_dict(item) for item in candidates_raw)
            rejections = tuple(
                InvestigationRejection.from_dict(item)
                for item in decoded.get("rejections", ())
            )
            evidence = tuple(
                _evidence_from(item) for item in decoded.get("evidence", ())
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ProtocolError(
                f"investigation adapter returned invalid report data: {error}"
            ) from error
        artifacts: list[InvestigationArtifact] = []
        for item in decoded.get("artifacts", ()):
            if not isinstance(item, dict) or "path" not in item:
                raise ProtocolError("investigation artifact entry is invalid")
            artifact = _artifact(
                str(item["path"]),
                str(item.get("kind", "analysis")),
                request.budget.max_output,
            )
            expected = item.get("sha256")
            if expected is not None and expected != artifact.sha256:
                raise ProtocolError(
                    f"investigation artifact {artifact.path!r} hash mismatch"
                )
            artifacts.append(artifact)
        states = int(decoded.get("metrics", {}).get("states", 0))
        if states > request.budget.max_states:
            raise ConstraintError(
                f"investigation explored {states} states; maximum is "
                f"{request.budget.max_states}"
            )
        return InvestigationReport(
            request.input_digest,
            candidates,
            rejections,
            InvestigationMetrics(
                self.name,
                time.monotonic() - started,
                states,
                len(result.stdout) + len(result.stderr),
                result.returncode,
            ),
            tuple(artifacts),
            evidence,
        )


def _resource_limiter(memory_bytes: int):
    # Darwin's RLIMIT_AS rejects limits below the interpreter's large reserved
    # address space in the child before exec. The subprocess still retains the
    # hard time/output/state bounds; Linux applies the requested address bound.
    if os.name != "posix" or sys.platform == "darwin":
        return None
    try:
        import resource
    except ImportError:
        return None

    def limit() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

    return limit


@dataclass(frozen=True)
class Investigation(Action):
    request: InvestigationRequest
    registry: InvestigationAdapterRegistry
    target: Expr | None = None

    def __post_init__(self) -> None:
        if self.target is not None and not isinstance(self.target, Expr):
            raise TypeError("investigation target must be a symbolic expression")

    @property
    def output(self) -> Expr | None:
        return self.target

    @property
    def identity(self) -> str:
        return _digest(
            {
                "request": self.request.to_dict(),
                "registry": self.registry.identity,
                "target": getattr(self.target, "key", None),
            }
        )

    @property
    def input_digest(self) -> str:
        return _digest(
            {
                "identity": self.identity,
                "request_digest": self.request.input_digest,
            }
        )

    def contract(self) -> EffectContract:
        return EffectContract(
            provides=(self.target,) if self.target is not None else (),
            reads=frozenset({"artifact:target", "analysis:adapter"}),
            writes=frozenset({"evidence:hypotheses"}),
            scope=Scope.ARTIFACT,
            evidence=(
                Evidence(
                    "investigation-budget",
                    (
                        f"{self.request.budget.timeout:g}s, "
                        f"{self.request.budget.memory_bytes} bytes, "
                        f"{self.request.budget.max_states} states"
                    ),
                    self.request.adapter or "registry",
                ),
            ),
        )

    def describe(self) -> str:
        return (
            f"investigate {self.request.kind!r} for {self.request.target!r} "
            f"(max {self.request.budget.max_results} hypotheses)"
        )

    def execute(self, runtime: Any) -> InvestigationReport:
        tube = runtime.tube
        if isinstance(tube, ReplayTube):
            encoded = tube.consume_opaque(self.identity, self.input_digest)
            try:
                decoded = json.loads(encoded.decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise TypeError("report must be an object")
                report = InvestigationReport.from_dict(decoded)
            except (UnicodeError, ValueError, TypeError, KeyError) as error:
                raise ProtocolError("recorded investigation result is malformed") from error
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
            report = self.registry.investigate(self.request)
            if trace is not None:
                buffered = getattr(tube, "buffered_bytes", b"")
                trace.append(
                    "opaque",
                    json.dumps(
                        report.to_dict(),
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
                trace.metadata.setdefault("investigations", []).append(
                    report.to_dict()
                )
        if self.target is not None:
            runtime.bind(self.target, report.to_dict(), source=self.describe())
        return report

    def perform(self) -> InvestigationReport:
        return self.registry.investigate(self.request)

