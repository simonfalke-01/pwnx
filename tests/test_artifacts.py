import hashlib
import pytest

from pwnx.artifacts import Image
from pwnx.errors import ArtifactError
from pwnx.expressions import BindingContext, Call

from elf_factory import make_elf
from elf_factory import DYNAMIC, ELF_HEADER, PROGRAM_HEADER


def test_parses_pie_symbols_relocations_and_dynamic_section(tmp_path):
    path = make_elf(tmp_path / "fixture.so")
    image = Image(path, name="libc")

    assert image.relocatable is True
    assert image.load_base == 0
    assert image.pointer_size == 8
    assert image.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert image.symbols["win"] == 0x100
    assert image.symbols["puts"] == 0
    assert image.got.raw["puts"] == 0x220
    assert image.plt.raw["puts"] == 0x150
    assert image.dynamic[23] == 0x1F0
    assert image.section(".bss").addr == 0x400
    assert image.relocations[0].symbol == "puts"
    assert image.security.pie is True
    assert image.security.nx is None
    assert image.security.executable_stack is None
    assert image.security.rwx is True
    assert image.security.relro == "None"
    assert image.security.stripped is True
    assert image.checksec() is image.security
    with pytest.raises(TypeError):
        image.security.as_dict()["pie"] = False


def test_addresses_are_relocatable_and_dynamic_symbols_are_callable(tmp_path):
    image = Image(make_elf(tmp_path / "fixture.so"), name="libc")
    context = BindingContext(instance_id="remote#1")
    context.bind(image.win, 0x7F00_0000_0100, source="win leak")

    assert context.resolve(image.base) == 0x7F00_0000_0000
    assert context.resolve(image.win) == 0x7F00_0000_0100
    assert context.resolve(image.got.puts) == 0x7F00_0000_0220
    assert context.resolve(image.plt.puts) == 0x7F00_0000_0150

    call = image.puts("hello")
    assert isinstance(call, Call)
    assert call.name == "libc.puts"
    assert call.dependencies == {"libc.base"}


def test_fixed_executable_addresses_do_not_require_runtime_binding(tmp_path):
    image = Image(make_elf(tmp_path / "fixture", pie=False))
    context = BindingContext(instance_id="local#1")

    assert image.relocatable is False
    assert image.load_base == 0x400000
    assert image.offset("win") == 0x100
    assert context.resolve(image.win) == 0x400100
    assert context.resolve(image.got.puts) == 0x400220
    assert context.resolve(image.plt.puts) == 0x400150


def test_search_read_and_bss_zero_fill(tmp_path):
    image = Image(make_elf(tmp_path / "fixture.so"))

    assert next(image.search(b"/bin/sh\0")) == 0x110
    assert list(image.search(b"\x5f\xc3", executable=True)) == [0x100]
    assert image.find(b"/bin/sh\0").label == "exe.find(b'/bin/sh\\x00')"
    assert image.read(0x100, 5) == b"\x5f\xc3\x5e\xc3\xc3"
    assert image.read(0x400, 8) == b"\0" * 8
    assert image.bss.label == "exe.bss"


def test_entry_functions_address_translation_and_immutable_patch(tmp_path):
    path = make_elf(tmp_path / "fixture", pie=False)
    image = Image(path)
    assert image.entry.label == "exe.entry"
    assert "win" in image.functions
    assert image.vaddr_to_offset(0x400100) == 0x100
    assert image.offset_to_vaddr(0x100) == 0x400100
    assert image.executable_segments
    assert image.writable_segments

    patched_path = tmp_path / "patched"
    patched = image.patch(0x400100, b"\x90", output=patched_path)
    assert image.read(0x400100, 1) == b"\x5f"
    assert patched.read(0x400100, 1) == b"\x90"
    with pytest.raises(ArtifactError, match="one file-backed load segment"):
        image.patch(
            image.segments[0].vaddr + image.segments[0].filesz - 1,
            b"AB",
            output=tmp_path / "cross-segment",
        )


def test_missing_entries_fail_with_context(tmp_path):
    image = Image(make_elf(tmp_path / "fixture.so"))

    with pytest.raises(ArtifactError, match="no symbol"):
        image.symbol("missing")
    with pytest.raises(ArtifactError, match="no got entry"):
        image.got["missing"]
    with pytest.raises(ArtifactError, match="was not found"):
        image.find(b"definitely missing")
    with pytest.raises(ArtifactError, match="not mapped"):
        image.read(0x9000, 8)
    with pytest.raises(AttributeError, match="immutable"):
        image.load_base = 123


@pytest.mark.parametrize(
    "contents, message",
    [
        (b"", "too small"),
        (b"not an elf" + b"\0" * 64, "not an ELF"),
        (b"\x7fELF" + bytes([1, 1, 1]) + b"\0" * 100, "ELF64"),
    ],
)
def test_malformed_or_unsupported_files_fail_cleanly(tmp_path, contents, message):
    path = tmp_path / "bad"
    path.write_bytes(contents)
    with pytest.raises(ArtifactError, match=message):
        Image(path)


def test_checksec_detects_full_relro_and_non_executable_stack(tmp_path):
    path = make_elf(tmp_path / "hardened", pie=False)
    data = bytearray(path.read_bytes())
    header = list(ELF_HEADER.unpack_from(data))
    header[10] = 3
    data[: ELF_HEADER.size] = ELF_HEADER.pack(*header)
    phoff = header[5]
    data[
        phoff + PROGRAM_HEADER.size : phoff + 2 * PROGRAM_HEADER.size
    ] = PROGRAM_HEADER.pack(
        0x6474E551, 6, 0, 0, 0, 0, 0, 16
    )
    data[
        phoff + 2 * PROGRAM_HEADER.size : phoff + 3 * PROGRAM_HEADER.size
    ] = PROGRAM_HEADER.pack(
        0x6474E552, 4, 0x220, 0x400220, 0x400220, 8, 8, 8
    )
    data[0x230 : 0x230 + 2 * DYNAMIC.size] = (
        DYNAMIC.pack(24, 1) + DYNAMIC.pack(0, 0)
    )
    path.write_bytes(data)

    report = Image(path).security
    assert report.pie is False
    assert report.nx is True
    assert report.executable_stack is False
    assert report.relro == "Full"
    assert "RELRO:   Full" in str(report)
