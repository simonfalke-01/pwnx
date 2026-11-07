"""Small deterministic AMD64 ELF fixtures for parser/compiler tests."""

from __future__ import annotations

import struct
from pathlib import Path


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")
RELA = struct.Struct("<QQq")
DYNAMIC = struct.Struct("<QQ")


def make_elf(path: Path, *, pie: bool = True) -> Path:
    base = 0 if pie else 0x400000
    image = bytearray(0x580)

    text_offset = 0x100
    plt_offset = 0x140
    dynstr_offset = 0x180
    dynsym_offset = 0x1A0
    rela_offset = 0x1F0
    got_offset = 0x220
    dynamic_offset = 0x230
    shstr_offset = 0x280
    shoff = 0x300

    text = b"\x5f\xc3\x5e\xc3\xc3" + b"\x90" * 11 + b"/bin/sh\0" + b"\x90" * 16
    image[text_offset : text_offset + len(text)] = text
    image[plt_offset : plt_offset + 0x20] = b"\xcc" * 0x20

    dynstr = b"\0win\0puts\0"
    image[dynstr_offset : dynstr_offset + len(dynstr)] = dynstr
    symbols = b"".join(
        [
            SYMBOL.pack(0, 0, 0, 0, 0, 0),
            SYMBOL.pack(1, 0x12, 0, 1, base + text_offset, 8),
            SYMBOL.pack(5, 0x12, 0, 0, 0, 0),
        ]
    )
    image[dynsym_offset : dynsym_offset + len(symbols)] = symbols
    relocation = RELA.pack(base + got_offset, (2 << 32) | 7, 0)
    image[rela_offset : rela_offset + len(relocation)] = relocation
    image[got_offset : got_offset + 8] = b"\0" * 8
    dynamic = DYNAMIC.pack(23, base + rela_offset) + DYNAMIC.pack(0, 0)
    image[dynamic_offset : dynamic_offset + len(dynamic)] = dynamic

    names = ["", ".text", ".plt", ".dynstr", ".dynsym", ".rela.plt", ".got.plt", ".dynamic", ".bss", ".shstrtab"]
    shstr = b""
    name_offsets: dict[str, int] = {}
    for name in names:
        name_offsets[name] = len(shstr)
        shstr += name.encode() + b"\0"
    image[shstr_offset : shstr_offset + len(shstr)] = shstr

    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\0" * 7
    image[: ELF_HEADER.size] = ELF_HEADER.pack(
        ident,
        3 if pie else 2,
        62,
        1,
        base + text_offset,
        ELF_HEADER.size,
        shoff,
        0,
        ELF_HEADER.size,
        PROGRAM_HEADER.size,
        1,
        SECTION_HEADER.size,
        len(names),
        9,
    )
    image[ELF_HEADER.size : ELF_HEADER.size + PROGRAM_HEADER.size] = PROGRAM_HEADER.pack(
        1,
        7,
        0,
        base,
        base,
        0x2E0,
        0x500,
        0x1000,
    )

    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (name_offsets[".text"], 1, 0x6, base + text_offset, text_offset, 0x40, 0, 0, 16, 0),
        (name_offsets[".plt"], 1, 0x6, base + plt_offset, plt_offset, 0x20, 0, 0, 16, 16),
        (name_offsets[".dynstr"], 3, 0x2, base + dynstr_offset, dynstr_offset, len(dynstr), 0, 0, 1, 0),
        (name_offsets[".dynsym"], 11, 0x2, base + dynsym_offset, dynsym_offset, len(symbols), 3, 1, 8, SYMBOL.size),
        (name_offsets[".rela.plt"], 4, 0x2, base + rela_offset, rela_offset, len(relocation), 4, 6, 8, RELA.size),
        (name_offsets[".got.plt"], 1, 0x3, base + got_offset, got_offset, 8, 0, 0, 8, 0),
        (name_offsets[".dynamic"], 6, 0x3, base + dynamic_offset, dynamic_offset, len(dynamic), 3, 0, 8, DYNAMIC.size),
        (name_offsets[".bss"], 8, 0x3, base + 0x400, 0, 0x80, 0, 0, 16, 0),
        (name_offsets[".shstrtab"], 3, 0, 0, shstr_offset, len(shstr), 0, 0, 1, 0),
    ]
    for index, section in enumerate(sections):
        start = shoff + index * SECTION_HEADER.size
        image[start : start + SECTION_HEADER.size] = SECTION_HEADER.pack(*section)

    path.write_bytes(image)
    return path

