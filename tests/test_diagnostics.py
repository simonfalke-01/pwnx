from __future__ import annotations

import struct

import pytest

from pwnx.artifacts import ELF_HEADER, PROGRAM_HEADER
from pwnx.diagnostics import (
    CORE_REGISTERS,
    NT_FILE,
    NT_PRSTATUS,
    NT_SIGINFO,
    Corefile,
    MemoryMap,
    ProcessMaps,
)
from pwnx.errors import ArtifactError


def note(kind: int, description: bytes, name: bytes = b"CORE\0") -> bytes:
    result = struct.pack("<III", len(name), len(description), kind)
    result += name.ljust((len(name) + 3) & ~3, b"\0")
    result += description.ljust((len(description) + 3) & ~3, b"\0")
    return result


def make_core(path):
    registers = {name: 0x1000 + index for index, name in enumerate(CORE_REGISTERS)}
    registers["rip"] = 0x61616162
    registers["rsp"] = 0x400020
    status = bytearray(112 + 8 * len(CORE_REGISTERS))
    struct.pack_into("<H", status, 12, 11)
    struct.pack_into(
        f"<{len(CORE_REGISTERS)}Q",
        status,
        112,
        *(registers[name] for name in CORE_REGISTERS),
    )
    siginfo = bytearray(128)
    struct.pack_into("<iii", siginfo, 0, 11, 0, 1)
    struct.pack_into("<Q", siginfo, 16, 0xDEADBEEF)
    files = (
        struct.pack("<QQ", 1, 0x1000)
        + struct.pack("<QQQ", 0x400000, 0x401000, 0)
        + b"/tmp/chall\0"
    )
    notes = (
        note(NT_PRSTATUS, bytes(status))
        + note(NT_SIGINFO, bytes(siginfo))
        + note(NT_FILE, files)
    )
    memory = b"CORE-MEMORY" + b"\0" * 21
    note_offset = 0x200
    load_offset = 0x800
    image = bytearray(load_offset + len(memory))
    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\0" * 7
    image[: ELF_HEADER.size] = ELF_HEADER.pack(
        ident,
        4,
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
    image[
        ELF_HEADER.size : ELF_HEADER.size + PROGRAM_HEADER.size
    ] = PROGRAM_HEADER.pack(
        4, 4, note_offset, 0, 0, len(notes), len(notes), 4
    )
    image[
        ELF_HEADER.size + PROGRAM_HEADER.size :
        ELF_HEADER.size + 2 * PROGRAM_HEADER.size
    ] = PROGRAM_HEADER.pack(
        1, 6, load_offset, 0x400000, 0, len(memory), 0x1000, 0x1000
    )
    image[note_offset : note_offset + len(notes)] = notes
    image[load_offset : load_offset + len(memory)] = memory
    path.write_bytes(image)
    return path


def test_proc_maps_parse_lookup_and_libraries():
    maps = ProcessMaps.parse(
        "00400000-00401000 r-xp 00000000 08:01 123 /tmp/chall\n"
        "00600000-00601000 rw-p 00001000 08:01 123 /tmp/chall\n"
        "7fff0000-80000000 rw-p 00000000 00:00 0 [stack]\n"
    )
    assert len(maps) == 3
    assert maps.find(0x400123).execute is True
    assert maps.at(0x7FFF1234).path == "[stack]"
    assert maps.by_path("/tmp/chall")[1].write is True
    assert maps.libraries["/tmp/chall"] == 0x400000
    assert "00400000" in maps.explain()
    with pytest.raises(ArtifactError, match="not mapped"):
        maps.at(0x123)


def test_proc_maps_rejects_bad_lines():
    with pytest.raises(ArtifactError, match="line 1"):
        ProcessMaps.parse("not a mapping")
    with pytest.raises(ValueError, match="permissions"):
        MemoryMap(1, 2, "bad!")


def test_corefile_registers_signal_maps_and_memory(tmp_path):
    core = Corefile(make_core(tmp_path / "core"))
    assert core.signal == 11
    assert core.fault_addr == 0xDEADBEEF
    assert core.rip == 0x61616162
    assert core.rsp == 0x400020
    assert core.maps.at(0x400001).path == "/tmp/chall"
    assert core.read(0x400000, 11) == b"CORE-MEMORY"
    assert core.read(0x400000, 40).endswith(b"\0" * 8)
    assert core.cyclic_offset("rip") == 4
    with pytest.raises(ArtifactError, match="not mapped"):
        core.read(0x900000, 1)


def test_corefile_rejects_truncated_and_non_core_artifacts(tmp_path):
    tiny = tmp_path / "tiny"
    tiny.write_bytes(b"\x7fELF")
    with pytest.raises(ArtifactError, match="too small"):
        Corefile(tiny)

    path = make_core(tmp_path / "core")
    data = bytearray(path.read_bytes())
    struct.pack_into("<H", data, 16, 2)
    path.write_bytes(data)
    with pytest.raises(ArtifactError, match="core files"):
        Corefile(path)
