from __future__ import annotations

import struct

import pytest

from elf_factory import make_elf
from pwnx import Challenge, Trace, expect
from pwnx.codecs import pointer
from pwnx.errors import ArtifactError, ConstraintError, ProtocolError, StaleValueError
from pwnx.memory import DynResolver, MemoryOracle, MemorySnapshot
from pwnx.transport import Tube


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SYMBOL = struct.Struct("<IBBHQQ")
DYNAMIC = struct.Struct("<QQ")
BASE = 0x70000000


def elf_hash(name: str) -> int:
    value = 0
    for byte in name.encode():
        value = (value << 4) + byte
        high = value & 0xF0000000
        if high:
            value ^= high >> 24
        value &= ~high
    return value & 0xFFFFFFFF


def gnu_hash(name: str) -> int:
    value = 5381
    for byte in name.encode():
        value = ((value << 5) + value + byte) & 0xFFFFFFFF
    return value


def make_remote_elf(*, style: str = "sysv", debug: bool = False) -> bytes:
    image = bytearray(0x3000)
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + b"\0" * 7
    dynamic_tags = [
        (5, 0x400),
        (6, 0x600),
        (11, SYMBOL.size),
        (4 if style == "sysv" else 0x6FFFFEF5, 0x800),
    ]
    if debug:
        dynamic_tags.append((21, BASE + 0xA00))
    dynamic_tags.append((0, 0))
    dynamic_size = len(dynamic_tags) * DYNAMIC.size
    image[: ELF_HEADER.size] = ELF_HEADER.pack(
        ident,
        3,
        62,
        1,
        0,
        ELF_HEADER.size,
        0,
        0,
        ELF_HEADER.size,
        PROGRAM_HEADER.size,
        2,
        0,
        0,
        0,
    )
    image[ELF_HEADER.size : ELF_HEADER.size + PROGRAM_HEADER.size] = (
        PROGRAM_HEADER.pack(1, 7, 0, 0, 0, len(image), len(image), 0x1000)
    )
    second = ELF_HEADER.size + PROGRAM_HEADER.size
    image[second : second + PROGRAM_HEADER.size] = PROGRAM_HEADER.pack(
        2, 6, 0x200, 0x200, 0, dynamic_size, dynamic_size, 8
    )
    for index, entry in enumerate(dynamic_tags):
        start = 0x200 + index * DYNAMIC.size
        image[start : start + DYNAMIC.size] = DYNAMIC.pack(*entry)

    strings = b"\0target\0other\0"
    image[0x400 : 0x400 + len(strings)] = strings
    image[0x600 : 0x600 + SYMBOL.size] = SYMBOL.pack(0, 0, 0, 0, 0, 0)
    image[0x600 + SYMBOL.size : 0x600 + 2 * SYMBOL.size] = SYMBOL.pack(
        1, 0x12, 0, 1, 0x1234, 8
    )

    if style == "sysv":
        image[0x800 : 0x818] = struct.pack("<IIIIII", 1, 2, 1, 0, 0, 0)
    elif style == "gnu":
        value = gnu_hash("target")
        bloom = (1 << (value % 64)) | (1 << ((value >> 5) % 64))
        image[0x800 : 0x810] = struct.pack("<IIII", 1, 1, 1, 5)
        image[0x810 : 0x818] = struct.pack("<Q", bloom)
        image[0x818 : 0x81C] = struct.pack("<I", 1)
        image[0x81C : 0x820] = struct.pack("<I", value | 1)
    else:
        raise ValueError(style)

    if debug:
        image[0xA00 : 0xA10] = struct.pack("<IIQ", 1, 0, BASE + 0xB00)
        image[0xB00 : 0xB28] = struct.pack(
            "<QQQQQ", BASE, BASE + 0xC00, BASE + 0x200, 0, 0
        )
        image[0xC00 : 0xC0A] = b"libc.so.6\0"
    return bytes(image)


class Reader:
    def __init__(self, data: bytes, *, base: int = BASE, partial: int | None = None):
        self.data = data
        self.base = base
        self.partial = partial
        self.calls: list[tuple[int, int]] = []

    def __call__(self, address: int, size: int) -> bytes:
        self.calls.append((address, size))
        offset = address - self.base
        if offset < 0 or offset >= len(self.data):
            return b""
        limit = min(size, self.partial or size, len(self.data) - offset)
        return self.data[offset : offset + limit]


class ScriptedTube(Tube):
    def __init__(self, incoming: bytes):
        super().__init__(timeout=0.1)
        self.incoming = bytearray(incoming)

    def _recv_raw(self, max_bytes, timeout):
        if not self.incoming:
            return b""
        data = bytes(self.incoming[:max_bytes])
        del self.incoming[:max_bytes]
        return data

    def _send_raw(self, data, timeout):
        return len(data)

    def _close_raw(self):
        pass


def test_oracle_assembles_partial_reads_caches_and_explains():
    reader = Reader(bytes(range(64)), base=0x1000, partial=2)
    oracle = MemoryOracle(
        reader,
        instance_id="process#1",
        max_read=8,
        max_total=64,
    )

    assert oracle.read(0x1003, 7) == bytes(range(3, 10))
    first_calls = len(reader.calls)
    assert first_calls >= 4
    assert oracle.read(0x1003, 7) == bytes(range(3, 10))
    assert len(reader.calls) == first_calls
    assert oracle.history[-1].cache_hits == 7
    assert "process#1" in oracle.explain()

    oracle.invalidate(0x1005, 2)
    assert oracle.read(0x1003, 7) == bytes(range(3, 10))
    assert len(reader.calls) > first_calls


def test_page_cache_falls_back_when_partial_page_misses_requested_address():
    reader = Reader(bytes(range(64)), base=0x2000, partial=4)
    oracle = MemoryOracle(
        reader,
        instance_id="p",
        cache_page=16,
        max_read=16,
        max_total=64,
    )
    assert oracle.read(0x2008, 3) == bytes((8, 9, 10))
    assert reader.calls[:2] == [(0x2000, 16), (0x2008, 3)]


def test_oracle_snapshot_codecs_strings_and_instance_lifetime():
    data = bytearray(64)
    data[8:16] = (0x1122334455667788).to_bytes(8, "little")
    data[20:26] = b"hello\0"
    oracle = MemoryOracle(
        Reader(bytes(data), base=0x3000),
        instance_id="old",
        max_total=64,
    )

    assert oracle.u64(0x3008) == 0x1122334455667788
    assert oracle.read_codec(0x3008, pointer()) == 0x1122334455667788
    assert oracle(0x3008, 2) == data[8:10]
    assert oracle[0x3008] == data[8]
    assert oracle[0x3008:0x3010] == data[8:16]
    assert oracle.cstring(0x3014) == b"hello"
    snapshot = oracle.snapshot()
    assert isinstance(snapshot, MemorySnapshot)
    assert snapshot.read(0x3008, 8) == data[8:16]
    assert snapshot.ranges
    assert "memory snapshot" in snapshot.explain()

    with pytest.raises(StaleValueError):
        oracle.read(0x3008, 1, instance_id="new")
    fork = oracle.fork("new")
    assert fork.cached_bytes == 0
    oracle.rebind("new")
    assert oracle.cached_bytes == 0


def test_oracle_rejects_bad_primitives_and_bounds():
    oracle = MemoryOracle(
        lambda _address, _size: b"",
        instance_id="p",
        max_total=8,
    )
    with pytest.raises(ProtocolError, match="returned no data"):
        oracle.read(0x1000, 1)
    with pytest.raises(ConstraintError, match="exceeds limit"):
        oracle.read(0x1000, 9)
    with pytest.raises(ValueError):
        oracle.read(-1, 1)
    with pytest.raises(ValueError):
        MemoryOracle(lambda _a, _s: b"", instance_id="p", cache_page=3)


@pytest.mark.parametrize("style", ["sysv", "gnu"])
def test_dynresolver_finds_base_and_resolves_hash_tables(style):
    reader = Reader(make_remote_elf(style=style), partial=7)
    oracle = MemoryOracle(
        reader,
        instance_id="remote#1",
        max_read=0x40,
        max_total=0x10000,
    )
    resolver = DynResolver(oracle, BASE + 0x1800, max_pages=4)

    resolution = resolver.lookup("target")
    assert resolver.base == BASE
    assert resolution.address == BASE + 0x1234
    assert resolution.hash_style == style
    assert resolution.backend_reads > 0
    assert "symbol table index 1" in resolution.evidence
    assert "target" in resolution.describe()
    assert resolver.lookup("target").address == resolution.address


def test_dynresolver_link_map_module_selection():
    oracle = MemoryOracle(
        Reader(make_remote_elf(style="gnu", debug=True)),
        instance_id="remote#1",
        max_read=0x100,
        max_total=0x10000,
    )
    resolver = DynResolver(oracle, BASE + 0x1000, max_pages=2)

    modules = resolver.modules()
    assert [(item.name, item.base) for item in modules] == [
        ("libc.so.6", BASE)
    ]
    result = resolver.lookup("target", module="libc")
    assert result.module == "libc.so.6"
    assert result.address == BASE + 0x1234


def test_dynresolver_reports_missing_or_malformed_data():
    oracle = MemoryOracle(
        Reader(make_remote_elf(style="sysv")),
        instance_id="p",
        max_read=0x100,
        max_total=0x10000,
    )
    resolver = DynResolver(oracle, BASE + 0x1000, max_pages=2, max_symbols=16)
    with pytest.raises(ArtifactError, match="was not found"):
        resolver.lookup("missing")

    empty = MemoryOracle(
        Reader(b"\0" * 0x3000),
        instance_id="p",
        max_read=0x100,
        max_total=0x10000,
    )
    with pytest.raises(ArtifactError, match="no ELF header"):
        DynResolver(empty, BASE + 0x1000, max_pages=2).lookup("target")


def test_dynresolver_does_not_hide_unexpected_local_image_failures():
    class BrokenLocalImage:
        def offset(self, _symbol):
            raise RuntimeError("local parser bug")

    oracle = MemoryOracle(
        Reader(make_remote_elf(style="sysv")),
        instance_id="p",
        max_read=0x100,
        max_total=0x10000,
    )
    resolver = DynResolver(
        oracle,
        BASE + 0x1000,
        local_image=BrokenLocalImage(),
        max_pages=2,
    )
    with pytest.raises(RuntimeError, match="local parser bug"):
        resolver.lookup("target")


def test_dynresolver_is_an_inspectable_declarative_action(tmp_path):
    reader = Reader(make_remote_elf(style="gnu"))
    oracle = MemoryOracle(
        reader,
        instance_id="declaration",
        max_read=0x100,
        max_total=0x10000,
    )
    c = Challenge(make_elf(tmp_path / "chall", pie=False))
    target = c.fact("remote.target")
    action = oracle.resolve(
        "target",
        pointer=BASE + 0x1000,
        target=target,
    )
    c.sequence(action, name="resolve remote symbol")
    c.want(expect(b"done\n"))
    trace = Trace()
    run = c.run(transport=ScriptedTube(b"done\n"), trace=trace)
    assert run.value(target) == BASE + 0x1234
    assert trace.metadata["memory_resolutions"][0]["hash_style"] == "gnu"
    assert "resolve remote ELF symbol" in c.plan().show()
    run.close()
    calls = len(reader.calls)
    replay = c.run(replay=trace)
    assert replay.value(target) == BASE + 0x1234
    replay.close()
    assert len(reader.calls) == calls
