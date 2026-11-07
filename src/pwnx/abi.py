"""Versioned ABI schemas and constants without ambient target context."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, Mapping, Sequence, cast

from .architecture import (
    AARCH64,
    AMD64,
    ARM,
    I386,
    MIPS,
    MIPSEL,
    RISCV64,
    ArchitectureSpec,
)
from .codecs import Codec, word
from .errors import ConstraintError, UnsupportedFeature


Endian = Literal["little", "big"]


@dataclass(frozen=True, slots=True)
class ABIField:
    name: str
    offset: int
    codec: Codec[Any]

    def __post_init__(self) -> None:
        if not self.name or self.offset < 0:
            raise ValueError("ABI field requires a name and non-negative offset")
        if self.codec.size is None:
            raise ValueError("ABI struct fields require fixed-size codecs")

    @property
    def end(self) -> int:
        assert self.codec.size is not None
        return self.offset + self.codec.size


@dataclass(frozen=True, slots=True)
class StructSchema:
    name: str
    size: int
    fields: tuple[ABIField, ...]
    version: str = "1"

    def __post_init__(self) -> None:
        if not self.name or not self.version or self.size <= 0:
            raise ValueError("struct schema requires a name, version, and positive size")
        occupied: list[tuple[int, int]] = []
        names: set[str] = set()
        for item in self.fields:
            if item.name in names:
                raise ValueError(f"duplicate field {item.name!r}")
            if item.end > self.size:
                raise ValueError(f"field {item.name!r} exceeds {self.name}")
            if any(item.offset < end and start < item.end for start, end in occupied):
                raise ValueError(f"field {item.name!r} overlaps another field")
            names.add(item.name)
            occupied.append((item.offset, item.end))

    @property
    def identity(self) -> str:
        return _digest(
            {
                "name": self.name,
                "version": self.version,
                "size": self.size,
                "fields": [
                    {
                        "name": item.name,
                        "offset": item.offset,
                        "codec": repr(item.codec),
                    }
                    for item in self.fields
                ],
            }
        )

    def pack(self, values: Mapping[str, Any], *, strict: bool = True) -> bytes:
        known = {item.name for item in self.fields}
        unknown = set(values) - known
        if strict and unknown:
            raise ConstraintError(f"{self.name} has no field(s): {', '.join(sorted(unknown))}")
        output = bytearray(self.size)
        for item in self.fields:
            if item.name in values:
                encoded = item.codec.build(values[item.name])
                output[item.offset : item.end] = encoded
        return bytes(output)

    def unpack(self, data: bytes | bytearray | memoryview) -> Mapping[str, Any]:
        raw = bytes(data)
        if len(raw) != self.size:
            raise ConstraintError(f"{self.name} requires {self.size} bytes, received {len(raw)}")
        return MappingProxyType(
            {item.name: item.codec.parse(raw[item.offset : item.end]) for item in self.fields}
        )

    def field(self, name: str) -> ABIField:
        try:
            return next(item for item in self.fields if item.name == name)
        except StopIteration as error:
            raise UnsupportedFeature(f"{self.name} has no field {name!r}") from error


@dataclass(frozen=True, slots=True)
class InvocationLayout:
    """Concrete placement of one target-side call or syscall.

    This is deliberately a result, not mutable global ABI context.  ROP,
    shellcode, emulator, and debugger backends can consume the same placement
    without each solve script re-encoding calling-convention trivia.
    """

    kind: str
    registers: Mapping[str, Any]
    stack: tuple[Any, ...] = ()
    stack_alignment: int = 1
    shadow_space: int = 0

    def __post_init__(self) -> None:
        if self.kind not in {"call", "syscall"}:
            raise ValueError("invocation kind must be 'call' or 'syscall'")
        if self.stack_alignment <= 0 or self.shadow_space < 0:
            raise ValueError("invalid invocation stack requirements")
        object.__setattr__(self, "registers", MappingProxyType(dict(self.registers)))


@dataclass(frozen=True, slots=True)
class TargetABI:
    name: str
    architecture: ArchitectureSpec
    calling_arguments: tuple[str, ...]
    return_register: str
    stack_register: str
    syscall_number_register: str
    syscall_arguments: tuple[str, ...]
    constants: Mapping[str, int] = field(default_factory=dict)
    schemas: Mapping[str, StructSchema] = field(default_factory=dict)
    call_stack_alignment: int = 1
    call_shadow_space: int = 0
    version: str = "1"

    def __post_init__(self) -> None:
        if not self.name or not self.version:
            raise ValueError("ABI name and version must not be empty")
        if self.call_stack_alignment <= 0 or self.call_shadow_space < 0:
            raise ValueError("invalid ABI stack requirements")
        object.__setattr__(self, "constants", MappingProxyType(dict(self.constants)))
        object.__setattr__(self, "schemas", MappingProxyType(dict(self.schemas)))

    @property
    def identity(self) -> str:
        return _digest(
            {
                "name": self.name,
                "version": self.version,
                "architecture": self.architecture.identity,
                "calling_arguments": self.calling_arguments,
                "return_register": self.return_register,
                "stack_register": self.stack_register,
                "syscall_number_register": self.syscall_number_register,
                "syscall_arguments": self.syscall_arguments,
                "constants": dict(self.constants),
                "schemas": {name: schema.identity for name, schema in self.schemas.items()},
                "call_stack_alignment": self.call_stack_alignment,
                "call_shadow_space": self.call_shadow_space,
            }
        )

    @property
    def pointer_size(self) -> int:
        return self.architecture.pointer_width

    @property
    def endian(self) -> Endian:
        return cast(Endian, self.architecture.endian)

    def constant(self, name: str) -> int:
        try:
            return self.constants[name]
        except KeyError as error:
            raise UnsupportedFeature(f"{self.name} does not declare constant {name!r}") from error

    def schema(self, name: str) -> StructSchema:
        try:
            return self.schemas[name]
        except KeyError as error:
            raise UnsupportedFeature(f"{self.name} does not declare schema {name!r}") from error

    def pointer(self) -> Codec[int]:
        return word(self.pointer_size * 8, self.endian)

    def call(self, arguments: Sequence[Any]) -> InvocationLayout:
        register_count = len(self.calling_arguments)
        return InvocationLayout(
            "call",
            dict(zip(self.calling_arguments, arguments[:register_count], strict=False)),
            tuple(arguments[register_count:]),
            self.call_stack_alignment,
            self.call_shadow_space,
        )

    def syscall(
        self,
        number: str | int,
        arguments: Sequence[Any] = (),
    ) -> InvocationLayout:
        if not self.syscall_arguments:
            raise UnsupportedFeature(f"{self.name} does not declare a syscall ABI")
        if len(arguments) > len(self.syscall_arguments):
            raise ConstraintError(
                f"{self.name} supports at most {len(self.syscall_arguments)} "
                f"syscall arguments, received {len(arguments)}"
            )
        resolved = self.constant(number) if isinstance(number, str) else number
        if not isinstance(resolved, int) or isinstance(resolved, bool) or resolved < 0:
            raise ConstraintError("syscall number must be a non-negative integer")
        registers = {self.syscall_number_register: resolved}
        registers.update(zip(self.syscall_arguments, arguments, strict=False))
        return InvocationLayout("syscall", registers)


def _linux_schemas(spec: ArchitectureSpec) -> Mapping[str, StructSchema]:
    endian = cast(Endian, spec.endian)
    pointer = word(spec.pointer_width * 8, endian)
    u16 = word(16, endian)
    u32 = word(32, endian)
    u64 = word(64, endian)
    if spec.pointer_width == 8:
        sigaction = StructSchema(
            "sigaction",
            32,
            (
                ABIField("handler", 0, pointer),
                ABIField("flags", 8, u64),
                ABIField("restorer", 16, pointer),
                ABIField("mask", 24, u64),
            ),
        )
        ucontext = StructSchema(
            "ucontext_head",
            48,
            (
                ABIField("flags", 0, u64),
                ABIField("link", 8, pointer),
                ABIField("stack_sp", 16, pointer),
                ABIField("stack_flags", 24, u32),
                ABIField("stack_size", 32, u64),
            ),
        )
    else:
        sigaction = StructSchema(
            "sigaction",
            16,
            (
                ABIField("handler", 0, pointer),
                ABIField("flags", 4, u32),
                ABIField("restorer", 8, pointer),
                ABIField("mask", 12, u32),
            ),
        )
        ucontext = StructSchema(
            "ucontext_head",
            24,
            (
                ABIField("flags", 0, u32),
                ABIField("link", 4, pointer),
                ABIField("stack_sp", 8, pointer),
                ABIField("stack_flags", 12, u32),
                ABIField("stack_size", 16, u32),
            ),
        )
    dirent64 = StructSchema(
        "linux_dirent64_head",
        19,
        (
            ABIField("ino", 0, u64),
            ABIField("off", 8, u64),
            ABIField("reclen", 16, u16),
            ABIField("type", 18, word(8)),
        ),
    )
    schemas = {"sigaction": sigaction, "ucontext": ucontext, "dirent64": dirent64}
    if spec == AMD64:
        sigreturn_offsets = {
            "uc_flags": 0,
            "uc_link": 8,
            "ss_sp": 16,
            "ss_flags": 24,
            "ss_size": 32,
            "r8": 40,
            "r9": 48,
            "r10": 56,
            "r11": 64,
            "r12": 72,
            "r13": 80,
            "r14": 88,
            "r15": 96,
            "rdi": 104,
            "rsi": 112,
            "rbp": 120,
            "rbx": 128,
            "rdx": 136,
            "rax": 144,
            "rcx": 152,
            "rsp": 160,
            "rip": 168,
            "eflags": 176,
            "csgsfs": 184,
            "err": 192,
            "trapno": 200,
            "oldmask": 208,
            "cr2": 216,
            "fpstate": 224,
            "reserved": 232,
            "sigmask": 240,
        }
        schemas["rt_sigreturn"] = StructSchema(
            "linux_amd64_rt_sigreturn",
            248,
            tuple(
                ABIField(name, offset, u64)
                for name, offset in sigreturn_offsets.items()
            ),
            version="linux-amd64-rt-sigframe-v1",
        )
    return schemas


def _linux(
    name: str,
    spec: ArchitectureSpec,
    call_args: tuple[str, ...],
    ret: str,
    stack: str,
    syscall_nr: str,
    syscall_args: tuple[str, ...],
    constants: Mapping[str, int],
) -> TargetABI:
    return TargetABI(
        name,
        spec,
        call_args,
        ret,
        stack,
        syscall_nr,
        syscall_args,
        constants,
        _linux_schemas(spec),
        16 if spec.pointer_width == 8 else 4,
    )


LINUX_AMD64 = _linux(
    "linux-amd64",
    AMD64,
    ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "rax",
    "rsp",
    "rax",
    ("rdi", "rsi", "rdx", "r10", "r8", "r9"),
    {
        "SYS_read": 0,
        "SYS_write": 1,
        "SYS_open": 2,
        "SYS_close": 3,
        "SYS_mmap": 9,
        "SYS_mprotect": 10,
        "SYS_execve": 59,
        "SYS_exit": 60,
        "SYS_openat": 257,
    },
)
LINUX_I386 = _linux(
    "linux-i386",
    I386,
    (),
    "eax",
    "esp",
    "eax",
    ("ebx", "ecx", "edx", "esi", "edi", "ebp"),
    {
        "SYS_exit": 1,
        "SYS_read": 3,
        "SYS_write": 4,
        "SYS_open": 5,
        "SYS_close": 6,
        "SYS_execve": 11,
        "SYS_mprotect": 125,
        "SYS_mmap2": 192,
        "SYS_openat": 295,
    },
)
LINUX_AARCH64 = _linux(
    "linux-aarch64",
    AARCH64,
    tuple(f"x{i}" for i in range(8)),
    "x0",
    "sp",
    "x8",
    tuple(f"x{i}" for i in range(6)),
    {
        "SYS_openat": 56,
        "SYS_close": 57,
        "SYS_read": 63,
        "SYS_write": 64,
        "SYS_exit": 93,
        "SYS_execve": 221,
        "SYS_mmap": 222,
        "SYS_mprotect": 226,
    },
)
LINUX_ARM = _linux(
    "linux-arm",
    ARM,
    ("r0", "r1", "r2", "r3"),
    "r0",
    "r13",
    "r7",
    ("r0", "r1", "r2", "r3", "r4", "r5"),
    {
        "SYS_exit": 1,
        "SYS_read": 3,
        "SYS_write": 4,
        "SYS_open": 5,
        "SYS_close": 6,
        "SYS_execve": 11,
        "SYS_mprotect": 125,
        "SYS_mmap2": 192,
        "SYS_openat": 322,
    },
)


def _mips(spec: ArchitectureSpec, name: str) -> TargetABI:
    base = 4000
    return _linux(
        name,
        spec,
        ("a0", "a1", "a2", "a3"),
        "v0",
        "sp",
        "v0",
        ("a0", "a1", "a2", "a3"),
        {
            "SYS_exit": base + 1,
            "SYS_read": base + 3,
            "SYS_write": base + 4,
            "SYS_open": base + 5,
            "SYS_close": base + 6,
            "SYS_execve": base + 11,
            "SYS_mmap": base + 90,
            "SYS_mprotect": base + 125,
            "SYS_openat": base + 288,
        },
    )


LINUX_MIPS = _mips(MIPS, "linux-mips-o32")
LINUX_MIPSEL = _mips(MIPSEL, "linux-mipsel-o32")
LINUX_RISCV64 = _linux(
    "linux-riscv64",
    RISCV64,
    tuple(f"a{i}" for i in range(8)),
    "a0",
    "sp",
    "a7",
    tuple(f"a{i}" for i in range(6)),
    LINUX_AARCH64.constants,
)
WINDOWS_X64_ARCH = ArchitectureSpec(
    "windows-x64",
    64,
    "little",
    "windows",
    "win64",
    (
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "rip",
    ),
    8,
    ("win64",),
)
WINDOWS_X64 = TargetABI(
    "windows-x64",
    WINDOWS_X64_ARCH,
    ("rcx", "rdx", "r8", "r9"),
    "rax",
    "rsp",
    "rax",
    (),
    {},
    {
        "unicode_string": StructSchema(
            "UNICODE_STRING",
            16,
            (
                ABIField("length", 0, word(16)),
                ABIField("maximum_length", 2, word(16)),
                ABIField("buffer", 8, word(64)),
            ),
        ),
        "list_entry": StructSchema(
            "LIST_ENTRY",
            16,
            (
                ABIField("flink", 0, word(64)),
                ABIField("blink", 8, word(64)),
            ),
        ),
    },
    16,
    32,
)

BUILTIN_ABIS = (
    LINUX_AMD64,
    LINUX_I386,
    LINUX_AARCH64,
    LINUX_ARM,
    LINUX_MIPS,
    LINUX_MIPSEL,
    LINUX_RISCV64,
    WINDOWS_X64,
)
_ABIS = {item.name: item for item in BUILTIN_ABIS}
_ABIS.update({item.architecture.name: item for item in BUILTIN_ABIS})


def target_abi(value: str | ArchitectureSpec | TargetABI) -> TargetABI:
    if isinstance(value, TargetABI):
        return value
    key = value.name if isinstance(value, ArchitectureSpec) else value
    try:
        return _ABIS[key.lower()]
    except (AttributeError, KeyError) as error:
        names = ", ".join(item.name for item in BUILTIN_ABIS)
        raise UnsupportedFeature(f"unsupported ABI {value!r}; available: {names}") from error


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()
