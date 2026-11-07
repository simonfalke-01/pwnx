"""Dependency-free static analysis for AMD64 little-endian ELF artifacts."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterator, Mapping

from .errors import ArtifactError
from .expressions import Call, Expr


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")
RELA = struct.Struct("<QQq")
REL = struct.Struct("<QQ")
DYNAMIC = struct.Struct("<QQ")

ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 62
PT_LOAD = 1
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 1
PF_W = 2
PF_R = 4
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
SHN_UNDEF = 0
R_X86_64_GLOB_DAT = 6
R_X86_64_JUMP_SLOT = 7
DT_NULL = 0
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 8
DF_1_NOW = 1


def _slice(data: bytes, offset: int, size: int, what: str) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ArtifactError(
            f"malformed ELF: {what} range {offset:#x}..{offset + size:#x} "
            f"exceeds file size {len(data):#x}"
        )
    return data[offset : offset + size]


def _cstring(table: bytes, offset: int, what: str) -> str:
    if offset < 0 or offset >= len(table):
        raise ArtifactError(f"malformed ELF: {what} string offset {offset:#x} is out of range")
    end = table.find(b"\0", offset)
    if end < 0:
        raise ArtifactError(f"malformed ELF: unterminated {what} string at {offset:#x}")
    return table[offset:end].decode("utf-8", "surrogateescape")


@dataclass(frozen=True, slots=True)
class Segment:
    type: int
    flags: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & PF_X)


@dataclass(frozen=True, slots=True)
class Section:
    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int


@dataclass(frozen=True, slots=True)
class SymbolRecord:
    name: str
    value: int
    size: int
    info: int
    other: int
    shndx: int

    @property
    def defined(self) -> bool:
        return self.shndx != SHN_UNDEF


@dataclass(frozen=True, slots=True)
class Relocation:
    section: str
    offset: int
    type: int
    symbol: str
    addend: int = 0


@dataclass(frozen=True, slots=True)
class SecurityReport(Mapping[str, object]):
    """Pure static mitigation facts for one ELF artifact."""

    pie: bool
    nx: bool | None
    canary: bool
    relro: str
    executable_stack: bool | None
    rwx: bool
    stripped: bool
    fortify: bool

    _KEYS = (
        "pie",
        "nx",
        "canary",
        "relro",
        "executable_stack",
        "rwx",
        "stripped",
        "fortify",
    )

    def __getitem__(self, key: str) -> object:
        if key not in self._KEYS:
            raise KeyError(key)
        return getattr(self, key)

    def __iter__(self) -> Iterator[str]:
        return iter(self._KEYS)

    def __len__(self) -> int:
        return len(self._KEYS)

    def as_dict(self) -> Mapping[str, object]:
        return MappingProxyType({key: self[key] for key in self})

    def __str__(self) -> str:
        def enabled(value: bool | None) -> str:
            if value is None:
                return "Unknown"
            return "Enabled" if value else "Disabled"

        return "\n".join(
            (
                f"RELRO:   {self.relro}",
                f"Canary:  {enabled(self.canary)}",
                f"NX:      {enabled(self.nx)}",
                f"PIE:     {enabled(self.pie)}",
                f"RWX:     {enabled(self.rwx)}",
                f"Stripped:{' Yes' if self.stripped else ' No'}",
                f"Fortify: {enabled(self.fortify)}",
            )
        )


class AddressNamespace(Mapping[str, Expr]):
    """Read-only symbolic addresses for GOT and PLT entries."""

    def __init__(self, image: "Image", values: Mapping[str, int], kind: str):
        self._image = image
        self._values = MappingProxyType(dict(values))
        self._kind = kind

    def __getitem__(self, name: str) -> Expr:
        try:
            value = self._values[name]
        except KeyError as error:
            raise ArtifactError(f"{self._image.name} has no {self._kind} entry for {name!r}") from error
        return self._image.address(value, f"{self._image.name}.{self._kind}.{name}")

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __getattr__(self, name: str) -> Expr:
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self[name]
        except ArtifactError as error:
            raise AttributeError(name) from error

    @property
    def raw(self) -> Mapping[str, int]:
        return self._values


class Image:
    """An immutable static view of one AMD64 ELF image."""

    pointer_size = 8
    endian = "little"
    architecture = "amd64"
    path: str
    name: str
    _data: bytes
    sha256: str
    elf_type: int
    entrypoint: int
    flags: int
    segments: tuple[Segment, ...]
    load_base: int
    relocatable: bool
    base: Expr
    sections: tuple[Section, ...]
    _sections_by_name: dict[str, Section]
    relocations: tuple[Relocation, ...]
    symbols: Mapping[str, int]
    _defined_symbols: frozenset[str]
    got: AddressNamespace
    plt: AddressNamespace
    functions: AddressNamespace
    dynamic: Mapping[int, int]
    security: SecurityReport
    _frozen: bool

    def __init__(self, path: str | Path, name: str = "exe"):
        object.__setattr__(self, "path", str(Path(path)))
        object.__setattr__(self, "name", name)
        try:
            data = Path(path).read_bytes()
        except OSError as error:
            raise ArtifactError(f"cannot read ELF artifact {path!s}: {error}") from error
        object.__setattr__(self, "_data", data)
        object.__setattr__(self, "sha256", hashlib.sha256(data).hexdigest())
        self._parse()
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError("Image objects are immutable")
        object.__setattr__(self, name, value)

    def _parse(self) -> None:
        data = self._data
        if len(data) < ELF_HEADER.size:
            raise ArtifactError(f"{self.path}: file is too small to contain an ELF header")
        header = ELF_HEADER.unpack_from(data)
        ident = header[0]
        if ident[:4] != b"\x7fELF":
            raise ArtifactError(f"{self.path}: not an ELF file")
        if ident[4] != 2:
            raise ArtifactError(f"{self.path}: only ELF64 artifacts are supported")
        if ident[5] != 1:
            raise ArtifactError(f"{self.path}: only little-endian ELF artifacts are supported")
        if ident[6] != 1:
            raise ArtifactError(f"{self.path}: unsupported ELF identification version {ident[6]}")

        (
            _ident,
            elf_type,
            machine,
            version,
            entry,
            phoff,
            shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        ) = header
        if machine != EM_X86_64:
            raise ArtifactError(f"{self.path}: only AMD64 ELF artifacts are supported (machine={machine})")
        if version != 1 or ehsize < ELF_HEADER.size:
            raise ArtifactError(f"{self.path}: malformed or unsupported ELF header")
        if phnum == 0xFFFF or shnum == 0 or shstrndx == 0xFFFF:
            raise ArtifactError(f"{self.path}: extended ELF numbering is not supported")
        if phnum and phentsize < PROGRAM_HEADER.size:
            raise ArtifactError(f"{self.path}: program-header entry is too small")
        if shnum and shentsize < SECTION_HEADER.size:
            raise ArtifactError(f"{self.path}: section-header entry is too small")

        object.__setattr__(self, "elf_type", elf_type)
        object.__setattr__(self, "entrypoint", entry)
        object.__setattr__(self, "flags", flags)

        segments: list[Segment] = []
        for index in range(phnum):
            offset = phoff + index * phentsize
            raw = _slice(data, offset, PROGRAM_HEADER.size, f"program header {index}")
            segments.append(Segment(*PROGRAM_HEADER.unpack(raw)))
        object.__setattr__(self, "segments", tuple(segments))

        loads = [segment for segment in segments if segment.type == PT_LOAD]
        if not loads:
            raise ArtifactError(f"{self.path}: ELF has no loadable segments")
        load_base = min(segment.vaddr for segment in loads)
        object.__setattr__(self, "load_base", load_base)
        object.__setattr__(self, "relocatable", elf_type == ET_DYN)
        base = (
            Expr.fact(f"{self.name}.base", scope="process", kind="address", space=self.name, label=f"{self.name}.base")
            if elf_type == ET_DYN
            else Expr.literal(load_base, kind="address", space=self.name, label=f"{self.name}.base")
        )
        object.__setattr__(self, "base", base)

        raw_sections: list[tuple[int, ...]] = []
        for index in range(shnum):
            offset = shoff + index * shentsize
            raw = _slice(data, offset, SECTION_HEADER.size, f"section header {index}")
            raw_sections.append(SECTION_HEADER.unpack(raw))
        if shstrndx >= len(raw_sections):
            raise ArtifactError(f"{self.path}: section-name string table index is out of range")
        shstr = raw_sections[shstrndx]
        shstr_data = _slice(data, shstr[4], shstr[5], "section-name string table")

        sections: list[Section] = []
        for index, section_raw in enumerate(raw_sections):
            name_offset, section_type, section_flags, addr, offset, size, link, info, align, entsize = section_raw
            name = _cstring(shstr_data, name_offset, "section name") if name_offset else ""
            if section_type != SHT_NOBITS:
                _slice(data, offset, size, f"section {name or index}")
            sections.append(Section(index, name, section_type, section_flags, addr, offset, size, link, info, align, entsize))
        object.__setattr__(self, "sections", tuple(sections))
        object.__setattr__(self, "_sections_by_name", {section.name: section for section in sections if section.name})

        symbol_tables: dict[int, list[SymbolRecord]] = {}
        symbol_values: dict[str, int] = {}
        function_values: dict[str, int] = {}
        defined_symbols: set[str] = set()
        for section in sections:
            if section.type not in {SHT_SYMTAB, SHT_DYNSYM}:
                continue
            if section.link >= len(sections):
                raise ArtifactError(f"{self.path}: symbol table {section.name} has invalid string-table link")
            strings = sections[section.link]
            if strings.type != SHT_STRTAB:
                raise ArtifactError(f"{self.path}: symbol table {section.name} does not link to a string table")
            string_data = _slice(data, strings.offset, strings.size, f"string table {strings.name}")
            entry_size = section.entsize or SYMBOL.size
            if entry_size < SYMBOL.size or section.size % entry_size:
                raise ArtifactError(f"{self.path}: malformed symbol table {section.name}")
            records: list[SymbolRecord] = []
            for entry_offset in range(section.offset, section.offset + section.size, entry_size):
                raw_symbol = SYMBOL.unpack(_slice(data, entry_offset, SYMBOL.size, f"symbol in {section.name}"))
                name_offset, info, other, shndx, value, size = raw_symbol
                symbol_name = _cstring(string_data, name_offset, "symbol") if name_offset else ""
                record = SymbolRecord(symbol_name, value, size, info, other, shndx)
                records.append(record)
                if not symbol_name:
                    continue
                if symbol_name not in symbol_values or record.defined:
                    symbol_values[symbol_name] = value
                if record.defined:
                    defined_symbols.add(symbol_name)
                    if record.info & 0xF == 2:
                        function_values[symbol_name] = value
            symbol_tables[section.index] = records

        relocations: list[Relocation] = []
        got_values: dict[str, int] = {}
        plt_relocations: list[Relocation] = []
        for section in sections:
            if section.type not in {SHT_RELA, SHT_REL}:
                continue
            relocation_records = symbol_tables.get(section.link)
            if relocation_records is None:
                raise ArtifactError(f"{self.path}: relocation section {section.name} has invalid symbol-table link")
            format_ = RELA if section.type == SHT_RELA else REL
            entry_size = section.entsize or format_.size
            if entry_size < format_.size or section.size % entry_size:
                raise ArtifactError(f"{self.path}: malformed relocation section {section.name}")
            for entry_offset in range(section.offset, section.offset + section.size, entry_size):
                values = format_.unpack(_slice(data, entry_offset, format_.size, f"relocation in {section.name}"))
                relocation_offset, info = values[:2]
                addend = values[2] if len(values) == 3 else 0
                symbol_index = info >> 32
                relocation_type = info & 0xFFFFFFFF
                if symbol_index >= len(relocation_records):
                    raise ArtifactError(f"{self.path}: relocation symbol index is out of range")
                symbol_name = relocation_records[symbol_index].name
                relocation = Relocation(section.name, relocation_offset, relocation_type, symbol_name, addend)
                relocations.append(relocation)
                if symbol_name and relocation_type in {R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT}:
                    got_values[symbol_name] = relocation_offset
                if symbol_name and "plt" in section.name and relocation_type == R_X86_64_JUMP_SLOT:
                    plt_relocations.append(relocation)

        plt_values = self._map_plt(plt_relocations)
        object.__setattr__(self, "relocations", tuple(relocations))
        object.__setattr__(self, "symbols", MappingProxyType(symbol_values))
        object.__setattr__(self, "_defined_symbols", frozenset(defined_symbols))
        object.__setattr__(self, "got", AddressNamespace(self, got_values, "got"))
        object.__setattr__(self, "plt", AddressNamespace(self, plt_values, "plt"))
        object.__setattr__(
            self,
            "functions",
            AddressNamespace(self, function_values, "function"),
        )

        dynamic: dict[int, int] = {}
        for section in sections:
            if section.type != SHT_DYNAMIC:
                continue
            entry_size = section.entsize or DYNAMIC.size
            if entry_size < DYNAMIC.size or section.size % entry_size:
                raise ArtifactError(f"{self.path}: malformed dynamic section {section.name}")
            for entry_offset in range(section.offset, section.offset + section.size, entry_size):
                tag, value = DYNAMIC.unpack(_slice(data, entry_offset, DYNAMIC.size, "dynamic entry"))
                if tag == DT_NULL:
                    break
                dynamic[tag] = value
        object.__setattr__(self, "dynamic", MappingProxyType(dynamic))
        object.__setattr__(self, "security", self._security_report())

    def _security_report(self) -> SecurityReport:
        stack = next(
            (segment for segment in self.segments if segment.type == PT_GNU_STACK),
            None,
        )
        executable_stack = (
            bool(stack.flags & PF_X) if stack is not None else None
        )
        has_relro = any(
            segment.type == PT_GNU_RELRO for segment in self.segments
        )
        bind_now = (
            DT_BIND_NOW in self.dynamic
            or bool(self.dynamic.get(DT_FLAGS, 0) & DF_BIND_NOW)
            or bool(self.dynamic.get(DT_FLAGS_1, 0) & DF_1_NOW)
        )
        if has_relro and bind_now:
            relro = "Full"
        elif has_relro:
            relro = "Partial"
        else:
            relro = "None"
        symbol_names = set(self.symbols) | {
            relocation.symbol for relocation in self.relocations
        }
        return SecurityReport(
            pie=self.elf_type == ET_DYN,
            nx=None if executable_stack is None else not executable_stack,
            canary="__stack_chk_fail" in symbol_names,
            relro=relro,
            executable_stack=executable_stack,
            rwx=any(
                segment.type == PT_LOAD
                and segment.flags & PF_X
                and segment.flags & PF_W
                for segment in self.segments
            ),
            stripped=".symtab" not in self._sections_by_name,
            fortify=any(
                name.endswith("_chk") or name.startswith("__fortify_fail")
                for name in symbol_names
            ),
        )

    def _map_plt(self, relocations: list[Relocation]) -> dict[str, int]:
        if not relocations:
            return {}
        section = self._sections_by_name.get(".plt.sec")
        skip = 0
        if section is None:
            section = self._sections_by_name.get(".plt")
            skip = 1
        if section is None:
            return {}
        entry_size = section.entsize or 16
        if entry_size <= 0:
            raise ArtifactError(f"{self.path}: invalid PLT entry size")
        return {
            relocation.symbol: section.addr + (index + skip) * entry_size
            for index, relocation in enumerate(relocations)
        }

    def address(self, vaddr: int, label: str | None = None) -> Expr:
        if not isinstance(vaddr, int):
            raise TypeError("virtual address must be an integer")
        label = label or f"{self.name}@{vaddr:#x}"
        if not self.relocatable:
            return Expr.literal(vaddr, kind="address", space=self.name, label=label)
        return Expr.node(
            "add",
            self.base,
            vaddr - self.load_base,
            kind="address",
            space=self.name,
            label=label,
        )

    def symbol(self, name: str) -> Expr:
        if name in self._defined_symbols:
            return self.address(self.symbols[name], f"{self.name}.{name}")
        if name in self.plt.raw:
            return self.plt[name].with_label(f"{self.name}.{name}")
        if name in self.symbols:
            raise ArtifactError(f"{self.name} symbol {name!r} is undefined and has no PLT entry")
        raise ArtifactError(f"{self.name} has no symbol {name!r}")

    def offset(self, name: str) -> int:
        if name in self._defined_symbols:
            return self.symbols[name] - self.load_base
        if name in self.plt.raw:
            return self.plt.raw[name] - self.load_base
        raise ArtifactError(f"{self.name} has no addressable symbol {name!r}")

    def call(self, name: str, *args: Any) -> Call:
        return Call(self.symbol(name), args, name=f"{self.name}.{name}")

    def checksec(self) -> SecurityReport:
        """Return immutable static mitigation facts without executing the ELF."""

        return self.security

    @property
    def bss(self) -> Expr:
        section = self.section(".bss")
        return self.address(section.addr, f"{self.name}.bss")

    @property
    def entry(self) -> Expr:
        return self.address(self.entrypoint, f"{self.name}.entry")

    @property
    def executable_segments(self) -> tuple[Segment, ...]:
        return tuple(segment for segment in self.segments if segment.executable)

    @property
    def writable_segments(self) -> tuple[Segment, ...]:
        return tuple(segment for segment in self.segments if segment.flags & PF_W)

    def section(self, name: str) -> Section:
        try:
            return self._sections_by_name[name]
        except KeyError as error:
            raise ArtifactError(f"{self.name} has no section {name!r}") from error

    def search(self, needle: bytes, executable: bool = False) -> Iterator[int]:
        if not isinstance(needle, bytes) or not needle:
            raise ValueError("search needle must be non-empty bytes")
        for segment in self.segments:
            if segment.type != PT_LOAD or (executable and not segment.executable):
                continue
            haystack = _slice(self._data, segment.offset, segment.filesz, "loadable segment")
            start = 0
            while True:
                found = haystack.find(needle, start)
                if found < 0:
                    break
                yield segment.vaddr + found
                start = found + 1

    def find(self, needle: bytes, executable: bool = False) -> Expr:
        try:
            address = next(self.search(needle, executable=executable))
        except StopIteration as error:
            raise ArtifactError(f"{needle!r} was not found in {self.name}") from error
        return self.address(address, f"{self.name}.find({needle!r})")

    def read(self, vaddr: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("read size cannot be negative")
        for segment in self.segments:
            if segment.type != PT_LOAD or not (segment.vaddr <= vaddr <= segment.vaddr + segment.memsz):
                continue
            relative = vaddr - segment.vaddr
            if relative + size > segment.memsz:
                break
            file_bytes = max(0, min(size, segment.filesz - relative))
            result = b""
            if file_bytes:
                result = _slice(self._data, segment.offset + relative, file_bytes, "virtual-address read")
            return result + b"\0" * (size - file_bytes)
        raise ArtifactError(f"virtual range {vaddr:#x}..{vaddr + size:#x} is not mapped in {self.name}")

    def vaddr_to_offset(self, vaddr: int) -> int:
        for segment in self.segments:
            if (
                segment.type == PT_LOAD
                and segment.vaddr <= vaddr < segment.vaddr + segment.filesz
            ):
                return segment.offset + (vaddr - segment.vaddr)
        raise ArtifactError(
            f"virtual address {vaddr:#x} has no file-backed offset in {self.name}"
        )

    def offset_to_vaddr(self, offset: int) -> int:
        for segment in self.segments:
            if (
                segment.type == PT_LOAD
                and segment.offset <= offset < segment.offset + segment.filesz
            ):
                return segment.vaddr + (offset - segment.offset)
        raise ArtifactError(
            f"file offset {offset:#x} is not mapped by {self.name}"
        )

    def save(self, output: str | Path) -> Path:
        destination = Path(output)
        destination.write_bytes(self._data)
        return destination

    def patch(
        self,
        vaddr: int,
        data: bytes | bytearray | memoryview,
        *,
        output: str | Path,
    ) -> "Image":
        raw = bytes(data)
        if not raw:
            raise ValueError("patch data cannot be empty")
        segment = next(
            (
                item
                for item in self.segments
                if item.type == PT_LOAD
                and item.vaddr <= vaddr
                and vaddr + len(raw) <= item.vaddr + item.filesz
            ),
            None,
        )
        if segment is None:
            raise ArtifactError(
                "patch range must fit entirely within one file-backed load segment"
            )
        offset = segment.offset + (vaddr - segment.vaddr)
        modified = bytearray(self._data)
        modified[offset : offset + len(raw)] = raw
        destination = Path(output)
        destination.write_bytes(modified)
        return Image(destination, name=self.name)

    def __getattr__(self, name: str) -> Expr:
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self.symbol(name)
        except ArtifactError as error:
            raise AttributeError(name) from error

    def __repr__(self) -> str:
        kind = "PIE/shared" if self.relocatable else "fixed"
        return f"Image({self.path!r}, name={self.name!r}, {kind}, sha256={self.sha256[:12]}…)"
