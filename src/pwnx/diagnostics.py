"""Static and runtime diagnostic artifacts.

Parsing these artifacts performs no target execution. Live process helpers may
construct the same immutable data models from explicit procfs reads.
"""

from __future__ import annotations

import os
import struct
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, overload

from .artifacts import (
    ELF_HEADER,
    EM_X86_64,
    PF_R,
    PF_W,
    PF_X,
    PROGRAM_HEADER,
    PT_LOAD,
    Segment,
)
from .errors import ArtifactError


ET_CORE = 4
PT_NOTE = 4
NT_PRSTATUS = 1
NT_SIGINFO = 0x53494749
NT_FILE = 0x46494C45

NOTE_HEADER = struct.Struct("<III")
SIGINFO = struct.Struct("<iii")
CORE_REGISTERS = (
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9",
    "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip",
    "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es",
    "fs", "gs",
)
PRSTATUS_REGISTERS_OFFSET = 112


def _slice(data: bytes, offset: int, size: int, what: str) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ArtifactError(
            f"malformed {what}: range {offset:#x}..{offset + size:#x} "
            f"exceeds artifact size {len(data):#x}"
        )
    return data[offset : offset + size]


def _align4(value: int) -> int:
    return (value + 3) & ~3


@dataclass(frozen=True, slots=True)
class MemoryMap:
    start: int
    end: int
    permissions: str
    offset: int = 0
    device: str = "00:00"
    inode: int = 0
    path: str | None = None

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("memory map requires 0 <= start < end")
        if (
            len(self.permissions) != 4
            or self.permissions[0] not in "r-"
            or self.permissions[1] not in "w-"
            or self.permissions[2] not in "x-"
            or self.permissions[3] not in "ps-"
        ):
            raise ValueError(
                "permissions must use Linux maps form such as 'r-xp'"
            )
        if self.offset < 0 or self.inode < 0:
            raise ValueError("mapping offset and inode must be non-negative")

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def read(self) -> bool:
        return self.permissions[0] == "r"

    @property
    def write(self) -> bool:
        return self.permissions[1] == "w"

    @property
    def execute(self) -> bool:
        return self.permissions[2] == "x"

    @property
    def private(self) -> bool:
        return self.permissions[3] == "p"

    @property
    def shared(self) -> bool:
        return self.permissions[3] == "s"

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end

    def __contains__(self, address: object) -> bool:
        return isinstance(address, int) and self.contains(address)

    def __str__(self) -> str:
        path = f" {self.path}" if self.path else ""
        return (
            f"{self.start:016x}-{self.end:016x} {self.permissions} "
            f"{self.offset:08x} {self.device} {self.inode}{path}"
        )


class ProcessMaps(Sequence[MemoryMap]):
    def __init__(self, mappings: Sequence[MemoryMap]) -> None:
        self._maps = tuple(sorted(mappings, key=lambda item: item.start))

    @classmethod
    def parse(cls, text: str) -> "ProcessMaps":
        mappings: list[MemoryMap] = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            fields = line.split(maxsplit=5)
            if len(fields) < 5:
                raise ArtifactError(
                    f"malformed /proc maps line {number}: {line!r}"
                )
            try:
                start_text, end_text = fields[0].split("-", 1)
                start, end = int(start_text, 16), int(end_text, 16)
                offset = int(fields[2], 16)
                inode = int(fields[4], 10)
            except (ValueError, TypeError) as error:
                raise ArtifactError(
                    f"malformed /proc maps line {number}: {line!r}"
                ) from error
            mappings.append(
                MemoryMap(
                    start,
                    end,
                    fields[1],
                    offset,
                    fields[3],
                    inode,
                    fields[5] if len(fields) == 6 else None,
                )
            )
        return cls(mappings)

    @classmethod
    def from_proc(cls, pid: int) -> "ProcessMaps":
        if not isinstance(pid, int) or pid <= 0:
            raise ValueError("pid must be a positive integer")
        path = Path(f"/proc/{pid}/maps")
        try:
            return cls.parse(path.read_text(encoding="utf-8"))
        except OSError as error:
            raise ArtifactError(f"cannot read {path}: {error}") from error

    @overload
    def __getitem__(self, index: int) -> MemoryMap: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[MemoryMap]: ...

    def __getitem__(
        self, index: int | slice
    ) -> MemoryMap | Sequence[MemoryMap]:
        return self._maps[index]

    def __len__(self) -> int:
        return len(self._maps)

    def __iter__(self) -> Iterator[MemoryMap]:
        return iter(self._maps)

    def find(self, address: int) -> MemoryMap | None:
        return next((item for item in self if address in item), None)

    def at(self, address: int) -> MemoryMap:
        mapping = self.find(address)
        if mapping is None:
            raise ArtifactError(f"address {address:#x} is not mapped")
        return mapping

    def by_path(self, path: str | os.PathLike[str]) -> tuple[MemoryMap, ...]:
        expected = os.fspath(path)
        return tuple(item for item in self if item.path == expected)

    @property
    def libraries(self) -> Mapping[str, int]:
        result: dict[str, int] = {}
        for item in self:
            if not item.path or not item.path.startswith("/"):
                continue
            base = item.start - item.offset
            result[item.path] = min(base, result.get(item.path, base))
        return MappingProxyType(result)

    @property
    def libs(self) -> Mapping[str, int]:
        return self.libraries

    def explain(self) -> str:
        return "\n".join(str(item) for item in self)


def _permissions(flags: int) -> str:
    return "".join(
        (
            "r" if flags & PF_R else "-",
            "w" if flags & PF_W else "-",
            "x" if flags & PF_X else "-",
            "p",
        )
    )


class Corefile:
    """A dependency-free Linux AMD64 ELF core parser."""

    def __init__(self, path: str | Path):
        self.path = str(Path(path))
        try:
            self._data = Path(path).read_bytes()
        except OSError as error:
            raise ArtifactError(
                f"cannot read core artifact {path!s}: {error}"
            ) from error
        self._parse()

    def _parse(self) -> None:
        if len(self._data) < ELF_HEADER.size:
            raise ArtifactError("core artifact is too small for an ELF header")
        header = ELF_HEADER.unpack_from(self._data)
        ident = header[0]
        if ident[:4] != b"\x7fELF":
            raise ArtifactError("core artifact is not ELF")
        if ident[4] != 2 or ident[5] != 1:
            raise ArtifactError(
                "only ELF64 little-endian core files are supported"
            )
        if header[1] != ET_CORE or header[2] != EM_X86_64:
            raise ArtifactError("only Linux AMD64 ELF core files are supported")
        phoff, phentsize, phnum = header[5], header[9], header[10]
        if phentsize < PROGRAM_HEADER.size:
            raise ArtifactError("core program-header entry is too small")
        segments: list[Segment] = []
        for index in range(phnum):
            raw = _slice(
                self._data,
                phoff + index * phentsize,
                PROGRAM_HEADER.size,
                "core program header",
            )
            segments.append(Segment(*PROGRAM_HEADER.unpack(raw)))
        self.segments = tuple(segments)
        self._loads = tuple(item for item in segments if item.type == PT_LOAD)
        registers: dict[str, int] = {}
        signal: int | None = None
        fault_addr: int | None = None
        file_maps: list[tuple[int, int, int, str]] = []
        for segment in segments:
            if segment.type != PT_NOTE:
                continue
            notes = _slice(
                self._data, segment.offset, segment.filesz, "core notes"
            )
            for note_type, description in self._notes(notes):
                if note_type == NT_PRSTATUS:
                    required = PRSTATUS_REGISTERS_OFFSET + 8 * len(
                        CORE_REGISTERS
                    )
                    if len(description) < required:
                        raise ArtifactError("truncated NT_PRSTATUS note")
                    values = struct.unpack_from(
                        f"<{len(CORE_REGISTERS)}Q",
                        description,
                        PRSTATUS_REGISTERS_OFFSET,
                    )
                    registers.update(zip(CORE_REGISTERS, values, strict=True))
                    current_signal = struct.unpack_from(
                        "<H", description, 12
                    )[0]
                    if current_signal:
                        signal = current_signal
                elif note_type == NT_SIGINFO:
                    if len(description) < 24:
                        raise ArtifactError("truncated NT_SIGINFO note")
                    signal = SIGINFO.unpack_from(description)[0]
                    fault_addr = struct.unpack_from(
                        "<Q", description, 16
                    )[0]
                elif note_type == NT_FILE:
                    file_maps.extend(self._file_note(description))
        self.registers = MappingProxyType(registers)
        self.signal = signal
        self.fault_addr = fault_addr

        mappings: list[MemoryMap] = []
        for segment in self._loads:
            path = None
            file_offset = 0
            for start, end, offset, candidate in file_maps:
                if start <= segment.vaddr < end:
                    path = candidate
                    file_offset = offset + (segment.vaddr - start)
                    break
            mappings.append(
                MemoryMap(
                    segment.vaddr,
                    segment.vaddr + segment.memsz,
                    _permissions(segment.flags),
                    file_offset,
                    "00:00",
                    0,
                    path,
                )
            )
        self.maps = ProcessMaps(mappings)

    @staticmethod
    def _notes(data: bytes) -> Iterator[tuple[int, bytes]]:
        offset = 0
        while offset < len(data):
            if len(data) - offset < NOTE_HEADER.size:
                if any(data[offset:]):
                    raise ArtifactError("truncated ELF note header")
                break
            namesz, descsz, note_type = NOTE_HEADER.unpack_from(data, offset)
            offset += NOTE_HEADER.size
            _slice(data, offset, namesz, "ELF note name")
            offset += _align4(namesz)
            description = _slice(
                data, offset, descsz, "ELF note description"
            )
            offset += _align4(descsz)
            yield note_type, description

    @staticmethod
    def _file_note(
        description: bytes,
    ) -> list[tuple[int, int, int, str]]:
        if len(description) < 16:
            raise ArtifactError("truncated NT_FILE note")
        count, page_size = struct.unpack_from("<QQ", description)
        table_size = 16 + count * 24
        if page_size == 0 or table_size > len(description):
            raise ArtifactError("malformed NT_FILE note")
        entries = [
            struct.unpack_from("<QQQ", description, 16 + index * 24)
            for index in range(count)
        ]
        names = description[table_size:].split(b"\0")
        if len(names) < count:
            raise ArtifactError("NT_FILE note has too few filenames")
        result = []
        for entry, raw_name in zip(entries, names, strict=False):
            start, end, page_offset = entry
            result.append(
                (
                    start,
                    end,
                    page_offset * page_size,
                    raw_name.decode("utf-8", "surrogateescape"),
                )
            )
        return result

    def read(self, address: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("read size cannot be negative")
        for segment in self._loads:
            if not (
                segment.vaddr
                <= address
                and address + size <= segment.vaddr + segment.memsz
            ):
                continue
            relative = address - segment.vaddr
            file_size = max(0, min(size, segment.filesz - relative))
            result = (
                _slice(
                    self._data,
                    segment.offset + relative,
                    file_size,
                    "core memory",
                )
                if file_size
                else b""
            )
            return result + b"\0" * (size - file_size)
        raise ArtifactError(
            f"core address range {address:#x}..{address + size:#x} "
            "is not mapped"
        )

    def cyclic_offset(
        self,
        register: str = "rip",
        *,
        alphabet: bytes | str | None = None,
        n: int = 4,
        endian: str = "little",
    ) -> int:
        from .packing import cyclic_find

        try:
            value = self.registers[register]
        except KeyError as error:
            raise ArtifactError(f"core has no register {register!r}") from error
        kwargs: dict[str, Any] = {"n": n, "endian": endian}
        if alphabet is not None:
            kwargs["alphabet"] = alphabet
        return cyclic_find(value, **kwargs)

    def __getattr__(self, name: str) -> int:
        registers = self.__dict__.get("registers", {})
        if name in registers:
            return registers[name]
        raise AttributeError(name)

    def __repr__(self) -> str:
        signal = f", signal={self.signal}" if self.signal is not None else ""
        return f"Corefile({self.path!r}{signal}, mappings={len(self.maps)})"
