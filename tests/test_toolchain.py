from __future__ import annotations

import shutil

import pytest

from pwnx.errors import UnsupportedFeature
from pwnx.payload import Payload
from pwnx.toolchain import Toolchain


HAS_CLANG = any(shutil.which(tool) is not None for tool in ("clang", "gcc", "cc"))
HAS_OBJDUMP = shutil.which("objdump") is not None


def test_rejects_implicit_or_unsupported_targets() -> None:
    with pytest.raises(UnsupportedFeature, match="architecture"):
        Toolchain(arch="aarch64")
    with pytest.raises(UnsupportedFeature, match="OS"):
        Toolchain(os="freebsd")
    with pytest.raises(UnsupportedFeature, match="little-endian"):
        Toolchain(endian="big")


@pytest.mark.skipif(not HAS_CLANG, reason="Clang is not installed")
def test_assembles_known_bytes_and_caches_by_toolchain(tmp_path) -> None:
    tools = Toolchain(cache_dir=tmp_path)

    assert tools.asm("nop; ret") == b"\x90\xc3"
    cached = list(tmp_path.glob("*.bin"))
    assert len(cached) == 1
    timestamp = cached[0].stat().st_mtime_ns
    assert tools.asm("nop; ret") == b"\x90\xc3"
    assert cached[0].stat().st_mtime_ns == timestamp

    obj = tools.asm("ret", extract=False)
    assert obj.startswith(b"\x7fELF")


@pytest.mark.skipif(not HAS_CLANG, reason="Clang is not installed")
def test_local_relative_labels_work_but_unresolved_relocations_fail(tmp_path) -> None:
    tools = Toolchain(cache_dir=tmp_path)

    assert tools.asm("jmp done; nop; done: ret") == b"\xeb\x01\x90\xc3"
    with pytest.raises(UnsupportedFeature, match="unresolved relocations"):
        tools.asm("mov rax, offset label\nlabel: ret")


@pytest.mark.skipif(
    not (HAS_CLANG and HAS_OBJDUMP),
    reason="Clang and objdump are required",
)
def test_disassembly_is_target_explicit_and_respects_vma(tmp_path) -> None:
    tools = Toolchain(cache_dir=tmp_path)
    rendered = tools.disasm(
        b"\x90\xc3",
        vma=0x401000,
    )

    assert "401000:" in rendered
    assert "nop" in rendered
    assert "ret" in rendered
    assert tools.disasm(b"\x90\xc3", vma=0x401000) == rendered
    assert any(path.suffix == ".txt" for path in tmp_path.iterdir())


@pytest.mark.skipif(not HAS_CLANG, reason="Clang is not installed")
def test_cpp_uses_explicit_definitions(tmp_path) -> None:
    tools = Toolchain(cache_dir=tmp_path)
    rendered = tools.cpp(
        "#define LOCAL 1\nLOCAL + EXTERNAL",
        defines={"EXTERNAL": 2},
    )

    assert rendered.strip() == "1 + 2"
    assert tools.cpp("EXTERNAL", defines={"EXTERNAL": 2}).strip() == "2"
    with pytest.raises(ValueError, match="invalid preprocessor"):
        tools.cpp("X", defines={"bad-name": 1})


@pytest.mark.skipif(not HAS_CLANG, reason="Clang is not installed")
def test_payload_retains_assembly_provenance(tmp_path) -> None:
    payload = Toolchain(cache_dir=tmp_path).payload(
        "xor eax, eax; ret",
        label="zero and return",
    )

    assert isinstance(payload, Payload)
    assert payload.build() == b"\x31\xc0\xc3"
    assert payload.layout()[0]["label"] == "zero and return"


def test_missing_tool_has_actionable_error(tmp_path) -> None:
    tools = Toolchain(clang="/definitely/missing/clang", cache_dir=tmp_path)
    with pytest.raises(UnsupportedFeature, match="was not found"):
        tools.asm("ret")

