"""Process-scoped arbitrary reads and bounded dynamic ELF resolution.

The types in this module never open a connection or consult an online service.
They turn a caller-supplied read primitive into cached, explainable memory
observations and, when possible, ELF symbol resolutions.
"""

from __future__ import annotations

import hashlib
import inspect
import struct
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .actions import Action
from .errors import ArtifactError, ConstraintError, ProtocolError, StaleValueError
from .expressions import Expr


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SYMBOL = struct.Struct("<IBBHQQ")
DYNAMIC = struct.Struct("<QQ")

ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 62
PT_LOAD = 1
PT_DYNAMIC = 2
DT_NULL = 0
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11
DT_DEBUG = 21
DT_GNU_HASH = 0x6FFFFEF5


@dataclass(frozen=True, slots=True)
class MemoryReadEvidence:
    address: int
    size: int
    cache_hits: int
    backend_calls: int
    instance_id: str

    def describe(self) -> str:
        return (
            f"read {self.size} byte(s) at {self.address:#x}: "
            f"{self.cache_hits} cached byte(s), "
            f"{self.backend_calls} backend call(s), instance {self.instance_id}"
        )


@dataclass(frozen=True, slots=True)
class MemorySnapshot:
    """An immutable view of bytes observed from one process instance."""

    instance_id: str
    data: Mapping[int, int]
    evidence: tuple[MemoryReadEvidence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "data", MappingProxyType(dict(self.data)))

    def read(self, address: int, size: int) -> bytes:
        _validate_range(address, size)
        missing = [address + offset for offset in range(size) if address + offset not in self.data]
        if missing:
            raise ProtocolError(
                f"snapshot has no byte at {missing[0]:#x}; "
                f"requested {address:#x}..{address + size:#x}"
            )
        return bytes(self.data[address + offset] for offset in range(size))

    @property
    def ranges(self) -> tuple[tuple[int, bytes], ...]:
        if not self.data:
            return ()
        ordered = sorted(self.data)
        ranges: list[tuple[int, bytes]] = []
        start = ordered[0]
        last = start
        chunk = bytearray([self.data[start]])
        for address in ordered[1:]:
            if address == last + 1:
                chunk.append(self.data[address])
            else:
                ranges.append((start, bytes(chunk)))
                start = address
                chunk = bytearray([self.data[address]])
            last = address
        ranges.append((start, bytes(chunk)))
        return tuple(ranges)

    def explain(self) -> str:
        lines = [
            f"memory snapshot for {self.instance_id}: "
            f"{len(self.data)} cached byte(s) in {len(self.ranges)} range(s)"
        ]
        for address, data in self.ranges:
            lines.append(f"  {address:#x}..{address + len(data):#x}: {data.hex()}")
        return "\n".join(lines)


class MemoryOracle:
    """A bounded, process-scoped cache around an arbitrary-read primitive."""

    def __init__(
        self,
        reader: Callable[[int, int], bytes | bytearray | memoryview],
        *,
        instance_id: str,
        max_read: int = 0x1000,
        max_total: int = 0x100000,
        cache_page: int | None = None,
        stable: str = "process",
        name: str = "memory",
    ) -> None:
        if not callable(reader):
            raise TypeError("memory reader must be callable")
        if not instance_id:
            raise ValueError("instance_id must not be empty")
        if max_read <= 0 or max_total <= 0:
            raise ValueError("read limits must be positive")
        if cache_page is not None and (
            cache_page <= 0 or cache_page & (cache_page - 1)
        ):
            raise ValueError("cache_page must be a positive power of two")
        if stable not in {"connection", "process", "service"}:
            raise ValueError("stable must be connection, process, or service")
        if not name:
            raise ValueError("oracle name must not be empty")
        self._reader = reader
        self.identity = _callable_identity(reader)
        self.instance_id = instance_id
        self.max_read = int(max_read)
        self.max_total = int(max_total)
        self.cache_page = cache_page
        self.stable = stable
        self.name = name
        self._cache: dict[int, int] = {}
        self._history: list[MemoryReadEvidence] = []
        self._backend_calls = 0

    @property
    def history(self) -> tuple[MemoryReadEvidence, ...]:
        return tuple(self._history)

    @property
    def backend_calls(self) -> int:
        return self._backend_calls

    @property
    def cached_bytes(self) -> int:
        return len(self._cache)

    def _check_instance(self, instance_id: str | None) -> None:
        if instance_id is not None and instance_id != self.instance_id:
            raise StaleValueError(
                f"{self.name} belongs to instance {self.instance_id!r}; "
                f"requested instance is {instance_id!r}"
            )

    def read(
        self, address: int, size: int, *, instance_id: str | None = None
    ) -> bytes:
        _validate_range(address, size)
        self._check_instance(instance_id)
        if size > self.max_total:
            raise ConstraintError(
                f"memory read of {size:#x} exceeds limit {self.max_total:#x}"
            )
        cache_hits = sum(
            1 for offset in range(size) if address + offset in self._cache
        )
        calls_before = self._backend_calls
        cursor = address
        end = address + size
        while cursor < end:
            if cursor in self._cache:
                cursor += 1
                continue
            run_end = cursor + 1
            while run_end < end and run_end not in self._cache:
                run_end += 1
            self._fill(cursor, run_end - cursor)
        result = bytes(self._cache[address + offset] for offset in range(size))
        self._history.append(
            MemoryReadEvidence(
                address,
                size,
                cache_hits,
                self._backend_calls - calls_before,
                self.instance_id,
            )
        )
        return result

    def __call__(
        self, address: int, size: int = 1, *, instance_id: str | None = None
    ) -> bytes:
        return self.read(address, size, instance_id=instance_id)

    def __getitem__(self, key: int | slice) -> int | bytes:
        if isinstance(key, int):
            return self.byte(key)
        if key.step not in {None, 1} or key.start is None or key.stop is None:
            raise ValueError("memory slices require concrete start/stop and step 1")
        if key.stop < key.start:
            raise ValueError("memory slice stop cannot precede start")
        return self.read(key.start, key.stop - key.start)

    def _fill(self, address: int, needed: int) -> None:
        while needed > 0:
            requested_address = address
            requested_size = min(needed, self.max_read)
            if self.cache_page is not None:
                page = self.cache_page
                requested_address = address & -page
                requested_size = min(page, self.max_read)
            raw = self._backend_read(requested_address, requested_size)
            if requested_address != address and (
                not raw or not requested_address <= address < requested_address + len(raw)
            ):
                raw = self._backend_read(address, min(needed, self.max_read))
                requested_address = address
            if not raw:
                raise ProtocolError(
                    f"memory primitive returned no data at {address:#x}"
                )
            for offset, byte in enumerate(raw):
                self._cache[requested_address + offset] = byte
            if address not in self._cache:
                raise ProtocolError(
                    f"memory primitive did not cover requested address {address:#x}"
                )
            covered = 0
            while covered < needed and address + covered in self._cache:
                covered += 1
            if covered == 0:
                raise ProtocolError(f"memory read made no progress at {address:#x}")
            address += covered
            needed -= covered

    def _backend_read(self, address: int, size: int) -> bytes:
        try:
            value = self._reader(address, size)
        except Exception as error:
            raise ProtocolError(
                f"memory primitive failed at {address:#x} for {size:#x} byte(s): "
                f"{error}"
            ) from error
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise ProtocolError(
                f"memory primitive returned {type(value).__name__}, expected bytes"
            )
        raw = bytes(value)
        if len(raw) > size:
            raise ProtocolError(
                f"memory primitive returned {len(raw)} byte(s) for a {size}-byte request"
            )
        self._backend_calls += 1
        return raw

    def byte(self, address: int, *, instance_id: str | None = None) -> int:
        return self.read(address, 1, instance_id=instance_id)[0]

    def u16(self, address: int, *, instance_id: str | None = None) -> int:
        return int.from_bytes(self.read(address, 2, instance_id=instance_id), "little")

    def u32(self, address: int, *, instance_id: str | None = None) -> int:
        return int.from_bytes(self.read(address, 4, instance_id=instance_id), "little")

    def u64(self, address: int, *, instance_id: str | None = None) -> int:
        return int.from_bytes(self.read(address, 8, instance_id=instance_id), "little")

    def cstring(
        self,
        address: int,
        *,
        max_size: int | None = None,
        encoding: str | None = None,
        instance_id: str | None = None,
    ) -> bytes | str:
        if max_size is None:
            max_size = min(0x1000, self.max_total)
        if max_size <= 0 or max_size > self.max_total:
            raise ValueError("cstring max_size must fit within oracle max_total")
        output = bytearray()
        while len(output) < max_size:
            byte = self.byte(address + len(output), instance_id=instance_id)
            if byte == 0:
                value = bytes(output)
                return value.decode(encoding) if encoding else value
            output.append(byte)
        raise ProtocolError(
            f"unterminated C string at {address:#x} exceeded {max_size} bytes"
        )

    def read_codec(
        self, address: int, codec: Any, *, instance_id: str | None = None
    ) -> Any:
        size = getattr(codec, "size", None)
        if size is None:
            raise ConstraintError("memory codec must have a fixed size")
        return codec.parse(self.read(address, size, instance_id=instance_id))

    def invalidate(self, address: int | None = None, size: int | None = None) -> None:
        if address is None:
            if size is not None:
                raise ValueError("size cannot be supplied without an address")
            self._cache.clear()
            return
        if size is None:
            size = 1
        _validate_range(address, size)
        for current in range(address, address + size):
            self._cache.pop(current, None)

    clear = invalidate

    def rebind(self, instance_id: str) -> None:
        if not instance_id:
            raise ValueError("instance_id must not be empty")
        if instance_id != self.instance_id:
            self.instance_id = instance_id
            self._cache.clear()
            self._history.clear()

    def fork(self, instance_id: str) -> "MemoryOracle":
        return MemoryOracle(
            self._reader,
            instance_id=instance_id,
            max_read=self.max_read,
            max_total=self.max_total,
            cache_page=self.cache_page,
            stable=self.stable,
            name=self.name,
        )

    def resolve(
        self,
        symbol: str,
        *,
        pointer: int | Expr,
        target: Expr,
        module: str | None = None,
        local_image: Any | None = None,
        bind_runtime_instance: bool = True,
    ) -> "ResolveMemorySymbol":
        return ResolveMemorySymbol(
            self,
            pointer,
            symbol,
            target,
            module,
            local_image,
            bind_runtime_instance,
        )

    def snapshot(self) -> MemorySnapshot:
        return MemorySnapshot(self.instance_id, self._cache, tuple(self._history))

    def explain(self) -> str:
        lines = [
            f"{self.name}: {len(self._cache)} cached byte(s), "
            f"{self._backend_calls} backend call(s), scope={self.stable}, "
            f"instance={self.instance_id}"
        ]
        lines.extend(f"  {item.describe()}" for item in self._history)
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class Module:
    name: str
    base: int
    dynamic: int


@dataclass(frozen=True, slots=True)
class Resolution:
    module: str
    base: int
    symbol: str
    address: int
    hash_style: str
    backend_reads: int
    evidence: tuple[str, ...] = ()

    def describe(self) -> str:
        lines = [
            f"{self.module or '<anonymous>'}:{self.symbol} = {self.address:#x}",
            f"  base={self.base:#x}, hash={self.hash_style}, "
            f"backend reads={self.backend_reads}",
        ]
        lines.extend(f"  {item}" for item in self.evidence)
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class _RemoteELF:
    base: int
    bias: int
    elf_type: int
    dynamic_address: int
    dynamic_size: int
    load_min: int
    load_max: int

    def runtime(self, value: int) -> int:
        if self.base <= value < self.load_max:
            return value
        return self.bias + value


class DynResolver:
    """Resolve symbols from a stable arbitrary-read primitive."""

    def __init__(
        self,
        oracle: MemoryOracle,
        pointer: int,
        *,
        local_image: Any | None = None,
        page_size: int = 0x1000,
        max_pages: int = 0x4000,
        max_symbols: int = 0x100000,
        max_modules: int = 256,
    ) -> None:
        if not isinstance(oracle, MemoryOracle):
            raise TypeError("DynResolver requires a MemoryOracle")
        if pointer < 0:
            raise ValueError("pointer cannot be negative")
        if page_size <= 0 or page_size & (page_size - 1):
            raise ValueError("page_size must be a positive power of two")
        if max_pages <= 0 or max_symbols <= 0 or max_modules <= 0:
            raise ValueError("resolver bounds must be positive")
        self.oracle = oracle
        self.pointer = pointer
        self.local_image = local_image
        self.page_size = page_size
        self.max_pages = max_pages
        self.max_symbols = max_symbols
        self.max_modules = max_modules
        self._elf: _RemoteELF | None = None
        self._dynamic: dict[int, int] | None = None

    @property
    def base(self) -> int:
        return self._image().base

    def _image(self) -> _RemoteELF:
        if self._elf is None:
            self._elf = self._find_image(self.pointer)
        return self._elf

    def _find_image(self, pointer: int) -> _RemoteELF:
        page = pointer & -self.page_size
        last_error: Exception | None = None
        for index in range(self.max_pages):
            candidate = page - index * self.page_size
            if candidate < 0:
                break
            try:
                magic = self.oracle.read(candidate, 4)
            except ProtocolError as error:
                last_error = error
                continue
            if magic != b"\x7fELF":
                continue
            try:
                return self._parse_image(candidate)
            except (ArtifactError, ProtocolError) as error:
                last_error = error
                continue
        suffix = f": {last_error}" if last_error else ""
        raise ArtifactError(
            f"no ELF header found within {self.max_pages} page(s) below "
            f"{pointer:#x}{suffix}"
        )


    def _parse_image(self, base: int) -> _RemoteELF:
        raw = self.oracle.read(base, ELF_HEADER.size)
        header = ELF_HEADER.unpack(raw)
        ident = header[0]
        if ident[:4] != b"\x7fELF" or ident[4:7] != bytes((2, 1, 1)):
            raise ArtifactError(f"unsupported ELF header at {base:#x}")
        elf_type, machine = header[1], header[2]
        if elf_type not in {ET_EXEC, ET_DYN} or machine != EM_X86_64:
            raise ArtifactError(
                f"resolver supports AMD64 ET_EXEC/ET_DYN only at {base:#x}"
            )
        phoff, phentsize, phnum = header[5], header[9], header[10]
        if not phnum or phnum > 0x1000 or phentsize < PROGRAM_HEADER.size:
            raise ArtifactError("remote ELF has invalid program-header metadata")
        loads: list[tuple[int, int]] = []
        dynamic: tuple[int, int] | None = None
        for index in range(phnum):
            address = base + phoff + index * phentsize
            values = PROGRAM_HEADER.unpack(
                self.oracle.read(address, PROGRAM_HEADER.size)
            )
            kind, _flags, _offset, vaddr, _paddr, filesz, memsz, _align = values
            if kind == PT_LOAD:
                loads.append((vaddr, memsz))
            elif kind == PT_DYNAMIC:
                dynamic = (vaddr, filesz)
        if not loads or dynamic is None:
            raise ArtifactError("remote ELF lacks PT_LOAD or PT_DYNAMIC")
        load_min = min(vaddr & -self.page_size for vaddr, _size in loads)
        bias = 0 if elf_type == ET_EXEC else base - load_min
        load_max = max(bias + vaddr + size for vaddr, size in loads)
        dynamic_address = bias + dynamic[0]
        return _RemoteELF(
            base, bias, elf_type, dynamic_address, dynamic[1], load_min, load_max
        )

    def dynamic(self) -> Mapping[int, int]:
        if self._dynamic is not None:
            return MappingProxyType(self._dynamic)
        image = self._image()
        limit = min(image.dynamic_size // DYNAMIC.size, 0x10000)
        entries: dict[int, int] = {}
        for index in range(limit):
            tag, value = DYNAMIC.unpack(
                self.oracle.read(
                    image.dynamic_address + index * DYNAMIC.size, DYNAMIC.size
                )
            )
            if tag == DT_NULL:
                break
            entries[tag] = value
        else:
            raise ArtifactError("unterminated or oversized remote PT_DYNAMIC")
        self._dynamic = entries
        return MappingProxyType(entries)

    def _pointer_tag(self, tag: int, name: str) -> int:
        try:
            value = self.dynamic()[tag]
        except KeyError as error:
            raise ArtifactError(f"remote ELF has no {name}") from error
        return self._image().runtime(value)

    def lookup(self, symbol: str, *, module: str | None = None) -> Resolution:
        if not symbol or "\x00" in symbol:
            raise ValueError("symbol name must be non-empty and contain no NUL")
        if module is not None:
            selected = self.module(module)
            resolver = DynResolver(
                self.oracle,
                selected.base,
                page_size=self.page_size,
                max_pages=1,
                max_symbols=self.max_symbols,
                max_modules=self.max_modules,
            )
            module_result = resolver.lookup(symbol)
            return Resolution(
                selected.name,
                module_result.base,
                module_result.symbol,
                module_result.address,
                module_result.hash_style,
                module_result.backend_reads,
                module_result.evidence,
            )

        calls_before = self.oracle.backend_calls
        image = self._image()
        local_evidence: tuple[str, ...] = ()
        if self.local_image is not None:
            try:
                offset = self.local_image.offset(symbol)
            except ArtifactError as error:
                local_evidence = (
                    f"supplied local artifact could not resolve symbol: {error}",
                )
            else:
                return Resolution(
                    getattr(self.local_image, "name", ""),
                    image.base,
                    symbol,
                    image.bias + getattr(self.local_image, "load_base", 0) + offset,
                    "local-image",
                    self.oracle.backend_calls - calls_before,
                    ("symbol offset taken from supplied local artifact",),
                )

        dynamic = self.dynamic()
        if DT_GNU_HASH in dynamic:
            found = self._lookup_gnu(symbol)
            style = "gnu"
        elif DT_HASH in dynamic:
            found = self._lookup_sysv(symbol)
            style = "sysv"
        else:
            raise ArtifactError("remote ELF has neither DT_GNU_HASH nor DT_HASH")
        if found is None:
            raise ArtifactError(f"symbol {symbol!r} was not found in remote ELF")
        index, record = found
        address = image.runtime(record[4])
        return Resolution(
            "",
            image.base,
            symbol,
            address,
            style,
            self.oracle.backend_calls - calls_before,
            (
                *local_evidence,
                f"symbol table index {index}",
                f"st_value={record[4]:#x}",
            ),
        )

    def _tables(self) -> tuple[int, int, int]:
        symtab = self._pointer_tag(DT_SYMTAB, "DT_SYMTAB")
        strtab = self._pointer_tag(DT_STRTAB, "DT_STRTAB")
        syment = int(self.dynamic().get(DT_SYMENT, SYMBOL.size))
        if syment != SYMBOL.size:
            raise ArtifactError(
                f"unexpected remote ELF symbol entry size {syment}"
            )
        return symtab, strtab, syment

    def _symbol(self, symtab: int, index: int) -> tuple[int, int, int, int, int, int]:
        if not 0 <= index < self.max_symbols:
            raise ArtifactError("remote symbol index exceeds configured bound")
        return SYMBOL.unpack(self.oracle.read(symtab + index * SYMBOL.size, SYMBOL.size))

    def _symbol_name(self, strtab: int, record: tuple[int, ...]) -> str:
        offset = record[0]
        if offset > self.oracle.max_total * 64:
            raise ArtifactError("remote symbol string offset is implausibly large")
        value = self.oracle.cstring(strtab + offset, max_size=0x1000)
        assert isinstance(value, bytes)
        return value.decode("utf-8", "surrogateescape")

    def _lookup_sysv(
        self, symbol: str
    ) -> tuple[int, tuple[int, int, int, int, int, int]] | None:
        symtab, strtab, _ = self._tables()
        table = self._pointer_tag(DT_HASH, "DT_HASH")
        nbucket = self.oracle.u32(table)
        nchain = self.oracle.u32(table + 4)
        if not nbucket or not nchain:
            raise ArtifactError("malformed empty DT_HASH table")
        if nbucket > self.max_symbols or nchain > self.max_symbols:
            raise ArtifactError("DT_HASH table size exceeds configured bound")
        buckets = table + 8
        chains = buckets + nbucket * 4
        index = self.oracle.u32(buckets + (_elf_hash(symbol) % nbucket) * 4)
        walked = 0
        while index and index < nchain and walked < self.max_symbols:
            record = self._symbol(symtab, index)
            if record[3] != 0 and self._symbol_name(strtab, record) == symbol:
                return index, record
            index = self.oracle.u32(chains + index * 4)
            walked += 1
        if walked >= self.max_symbols:
            raise ArtifactError("DT_HASH chain exceeds configured bound")
        return None

    def _lookup_gnu(
        self, symbol: str
    ) -> tuple[int, tuple[int, int, int, int, int, int]] | None:
        symtab, strtab, _ = self._tables()
        table = self._pointer_tag(DT_GNU_HASH, "DT_GNU_HASH")
        nbuckets = self.oracle.u32(table)
        symoffset = self.oracle.u32(table + 4)
        bloom_size = self.oracle.u32(table + 8)
        bloom_shift = self.oracle.u32(table + 12)
        if (
            not nbuckets
            or nbuckets > self.max_symbols
            or not bloom_size
            or bloom_size > self.max_symbols
            or symoffset > self.max_symbols
        ):
            raise ArtifactError("malformed GNU hash header")
        hash_value = _gnu_hash(symbol)
        bloom = table + 16
        word = self.oracle.u64(
            bloom + ((hash_value // 64) % bloom_size) * 8
        )
        mask = (1 << (hash_value % 64)) | (
            1 << ((hash_value >> bloom_shift) % 64)
        )
        if word & mask != mask:
            return None
        buckets = bloom + bloom_size * 8
        chains = buckets + nbuckets * 4
        index = self.oracle.u32(buckets + (hash_value % nbuckets) * 4)
        if index < symoffset:
            return None
        for _walked in range(self.max_symbols):
            chain = self.oracle.u32(chains + (index - symoffset) * 4)
            if chain | 1 == hash_value | 1:
                record = self._symbol(symtab, index)
                if record[3] != 0 and self._symbol_name(strtab, record) == symbol:
                    return index, record
            if chain & 1:
                return None
            index += 1
        raise ArtifactError("GNU hash chain exceeds configured bound")

    def modules(self) -> tuple[Module, ...]:
        debug = self.dynamic().get(DT_DEBUG)
        if not debug:
            return ()
        debug_address = self._image().runtime(debug)
        link = self.oracle.u64(debug_address + 8)
        modules: list[Module] = []
        visited: set[int] = set()
        while link and len(modules) < self.max_modules:
            if link in visited:
                raise ArtifactError("link_map contains a cycle")
            visited.add(link)
            base = self.oracle.u64(link)
            name_pointer = self.oracle.u64(link + 8)
            dynamic = self.oracle.u64(link + 16)
            next_link = self.oracle.u64(link + 24)
            if name_pointer:
                value = self.oracle.cstring(name_pointer, max_size=0x4000)
                assert isinstance(value, bytes)
                name = value.decode("utf-8", "surrogateescape")
            else:
                name = ""
            modules.append(Module(name, base, dynamic))
            link = next_link
        if link:
            raise ArtifactError("link_map exceeds configured module bound")
        return tuple(modules)

    def module(self, name: str) -> Module:
        matches = [
            item
            for item in self.modules()
            if item.name == name or item.name.rsplit("/", 1)[-1] == name
            or name in item.name
        ]
        if not matches:
            raise ArtifactError(f"no loaded module matches {name!r}")
        if len(matches) > 1:
            rendered = ", ".join(item.name or "<main>" for item in matches)
            raise ArtifactError(f"module name {name!r} is ambiguous: {rendered}")
        return matches[0]

    def explain(self) -> str:
        image = self._image()
        tags = ", ".join(f"{tag:#x}" for tag in sorted(self.dynamic()))
        return (
            f"dynamic resolver at base {image.base:#x}, bias {image.bias:#x}; "
            f"tags: {tags}; {self.oracle.explain()}"
        )


@dataclass(frozen=True, slots=True)
class ResolveMemorySymbol(Action):
    oracle: MemoryOracle
    pointer: int | Expr
    symbol: str
    target: Expr
    module: str | None = None
    local_image: Any | None = None
    bind_runtime_instance: bool = True

    def __post_init__(self) -> None:
        if not self.symbol:
            raise ValueError("symbol must not be empty")
        if not isinstance(self.target, Expr):
            raise TypeError("resolution target must be a symbolic expression")

    @property
    def output(self) -> Expr:
        return self.target

    @property
    def dependencies(self) -> set[str]:
        return set(getattr(self.pointer, "dependencies", ()))

    @property
    def identity(self) -> str:
        pointer = getattr(self.pointer, "key", repr(self.pointer))
        local = getattr(self.local_image, "sha256", "")
        material = (
            self.oracle.identity,
            self.oracle.name,
            pointer,
            self.symbol,
            self.module,
            self.target.key,
            local,
        )
        return hashlib.sha256(repr(material).encode()).hexdigest()

    def describe(self) -> str:
        module = f" in module matching {self.module!r}" if self.module else ""
        return (
            f"resolve remote ELF symbol {self.symbol!r}{module} through "
            f"{self.oracle.name} -> {self.target.describe()}"
        )


def _validate_range(address: int, size: int) -> None:
    if not isinstance(address, int) or isinstance(address, bool) or address < 0:
        raise ValueError("memory address must be a non-negative integer")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ValueError("memory size must be a non-negative integer")
    if address + size > 1 << 64:
        raise ConstraintError("memory range exceeds the 64-bit address space")


def _callable_identity(function: Any) -> str:
    target = getattr(function, "__call__", function)
    code = getattr(target, "__code__", None)
    material: tuple[Any, ...]
    if code is not None:
        material = (
            getattr(target, "__module__", ""),
            getattr(target, "__qualname__", type(function).__qualname__),
            code.co_code,
            repr(code.co_consts),
        )
    else:
        try:
            source = inspect.getsource(target)
        except (OSError, TypeError):
            source = type(function).__module__ + "." + type(function).__qualname__
        material = (source,)
    return hashlib.sha256(repr(material).encode()).hexdigest()


def _elf_hash(name: str) -> int:
    value = 0
    for byte in name.encode():
        value = (value << 4) + byte
        high = value & 0xF0000000
        if high:
            value ^= high >> 24
        value &= ~high
    return value & 0xFFFFFFFF


def _gnu_hash(name: str) -> int:
    value = 5381
    for byte in name.encode():
        value = ((value << 5) + value + byte) & 0xFFFFFFFF
    return value


__all__ = [
    "DynResolver",
    "MemoryOracle",
    "MemoryReadEvidence",
    "MemorySnapshot",
    "Module",
    "Resolution",
]
