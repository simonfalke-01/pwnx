from __future__ import annotations

import pytest

from pwnx.errors import ConstraintError, UnresolvedValueError
from pwnx.expressions import BindingContext, Expr
from pwnx.packing import (
    CrashOffset,
    CyclicGenerator,
    Packed,
    bits,
    cyclic,
    cyclic_find,
    cyclic_metasploit,
    cyclic_metasploit_find,
    dd,
    enhex,
    fit,
    flat,
    hexdump,
    layout,
    offset_from,
    p16,
    p32,
    p64,
    pack,
    rol,
    ror,
    u16,
    u32,
    u64,
    unbits,
    unhex,
    unpack,
    unpack_many,
    xor_bytes,
)
from pwnx.payload import Payload


def test_pack_unpack_width_endian_sign_and_aliases():
    assert pack(0x1234, 16) == b"\x34\x12"
    assert pack(0x1234, 16, "big") == b"\x12\x34"
    assert pack(-2, 16) == b"\xfe\xff"
    assert unpack(b"\xfe\xff", 16, signed=True) == -2
    assert p16(0x1234) == b"\x34\x12"
    assert p32(0x12345678) == b"xV4\x12"
    assert p64(1) == b"\x01" + b"\0" * 7
    assert u16(b"\x34\x12") == 0x1234
    assert u32(b"xV4\x12") == 0x12345678
    assert u64(b"\x01" + b"\0" * 7) == 1
    assert unpack_many(b"\x01\0\x02\0", 16) == [1, 2]

    with pytest.raises(ConstraintError):
        pack(0x100, 8)
    with pytest.raises(ValueError):
        unpack(b"\0", 16)
    with pytest.raises(ValueError):
        pack(1, 7)


def test_symbolic_packed_value_preserves_dependencies_and_context():
    base = Expr.fact("libc.base", kind="address", space="libc")
    packed = p64(base + 0x1234)
    assert isinstance(packed, Packed)
    assert packed.size == 8
    assert packed.dependencies == {"libc.base"}
    assert "64-bit" in packed.describe()
    with pytest.raises(UnresolvedValueError):
        bytes(packed)

    context = BindingContext(instance_id="one")
    context.bind(base, 0x7F0000000000, source="test")
    assert packed.build(context) == (0x7F0000001234).to_bytes(8, "little")


def test_cyclic_matches_standard_de_bruijn_and_finds_crashes():
    assert cyclic(20) == b"aaaabaaacaaadaaaeaaa"
    assert cyclic(20, n=8) == b"aaaaaaaabaaaaaaacaaa"
    assert cyclic(27, alphabet=b"ABC", n=3) == b"AAABAACABBABCACBACCBBBCBCCC"
    assert cyclic_find(b"baaa") == 4
    assert cyclic_find(b"baaacaaa") == 4
    assert cyclic_find(0x61616162) == 4
    assert cyclic_find(0x61616162, endian="big") == 1
    assert cyclic_find(b"!!!!") == -1

    evidence = offset_from(0x61616162)
    assert isinstance(evidence, CrashOffset)
    assert int(evidence) == 4
    assert "recovered" in evidence.describe()
    with pytest.raises(ConstraintError):
        offset_from(b"!!!!")


def test_cyclic_generator_tracks_stream_position():
    generator = CyclicGenerator()
    assert generator.get(8) == cyclic(8)
    assert generator.get(8) == cyclic(16)[8:]
    assert generator.find(b"baaa") == 4
    remainder = generator.get()
    assert len(remainder) == 26**4 - 16
    with pytest.raises(ValueError):
        generator.get(1)


def test_large_cyclic_domains_are_streamed_and_bounded():
    assert len(cyclic(32, n=8)) == 32
    with pytest.raises(ConstraintError, match="max_work"):
        cyclic_find(b"zzzzzzzz", n=8, max_work=128)
    with pytest.raises(ConstraintError, match="max_size"):
        CyclicGenerator(n=8, max_size=128)


def test_metasploit_pattern_compatibility():
    assert cyclic_metasploit(24) == b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7"
    assert cyclic_metasploit_find(b"Aa3A") == 9


def test_sparse_layout_nested_values_markers_and_explicit_length():
    result = layout(
        {
            4: b"XY",
            b"daaa": [0x1122, b"Z"],
        },
        word_size=2,
        length=20,
    )
    assert isinstance(result, Payload)
    raw = result.build()
    assert raw[:4] == cyclic(4)
    assert raw[4:6] == b"XY"
    marker = cyclic_find(b"daaa")
    assert raw[marker : marker + 2] == b"\x22\x11"
    assert raw[marker + 2] == ord("Z")
    assert len(raw) == 20
    assert any(row["label"].startswith("layout[0]") for row in result.layout())


def test_layout_symbolic_packing_and_flat_concrete_policy():
    fact = Expr.fact("pie.win", kind="address", space="exe")
    symbolic = layout({8: fact}, word_size=8, filler=b".")
    assert symbolic.dependencies == {"pie.win"}
    with pytest.raises(UnresolvedValueError):
        symbolic.build()
    assert isinstance(flat({8: fact}, filler=b"."), Payload)

    context = BindingContext(instance_id="one")
    context.bind(fact, 0x401234, source="test")
    assert symbolic.build(context)[8:] == (0x401234).to_bytes(8, "little")

    concrete = flat(b"AA", 0x4242, word_size=2, filler=b".")
    assert concrete == b"AABB"
    assert fit({2: b"X"}, filler=b".", length=4) == b"..X."


def test_layout_rejects_overlap_unknown_markers_and_short_length():
    with pytest.raises(ConstraintError, match="overlaps"):
        layout({0: b"AAAA", 2: b"BB"}, filler=b".")
    with pytest.raises(ConstraintError, match="not found"):
        layout({b"missing": b"X"}, filler=b"abc")
    with pytest.raises(ConstraintError, match="smaller"):
        layout(b"AAAA", length=2)


def test_byte_helpers_and_copy_primitive():
    assert xor_bytes(b"\x00\x01\x02", 0xFF) == b"\xff\xfe\xfd"
    assert xor_bytes(b"abcd", b"\x01\x02", b"\x10") == b"pprv"
    assert bits(b"\x81") == [1, 0, 0, 0, 0, 0, 0, 1]
    assert bits(b"\x81", endian="little") == [1, 0, 0, 0, 0, 0, 0, 1]
    assert bits(511) == [0, 0, 0, 0, 0, 0, 0, 1] + [1] * 8
    assert unbits(bits(b"\xa5")) == b"\xa5"
    assert unbits([1]) == b"\x80"
    assert unbits([1], endian="little") == b"\x01"
    assert rol(0x81, 1, 8) == 0x03
    assert ror(0x03, 1, 8) == 0x81
    assert rol("abcdefg", 2) == "cdefgab"
    assert ror(b"abcdefg", 2) == b"fgabcde"
    assert enhex(b"\xde\xad") == "dead"
    assert unhex("de ad") == b"\xde\xad"
    assert dd(b"AAAA", b"xy", skip=1) == b"AxyA"
    target = bytearray(b"AAAA")
    assert dd(target, b"xy", skip=1) == bytearray(b"AxyA")

    with pytest.raises(ValueError):
        xor_bytes(b"x", 256)
    with pytest.raises(ValueError):
        unbits([2])


def test_hexdump_offsets_printable_and_compacts_repeated_rows():
    data = b"A" * 16 + b"A" * 16 + bytes(range(16))
    rendered = hexdump(data, offset=0x100)
    assert rendered.splitlines()[0].startswith("00000100")
    assert "*" in rendered.splitlines()
    assert "|AAAAAAAAAAAAAAAA|" in rendered
    assert rendered.splitlines()[-1] == "00000130"

