from __future__ import annotations

import pytest

from pwnx.errors import ConstraintError, UnresolvedValueError
from pwnx.payload import Payload
from pwnx.packing import Packed


class Symbol:
    def __init__(self, name: str):
        self.name = name
        self.dependencies = {name}

    def describe(self):
        return self.name


class Context:
    def __init__(self, values):
        self.values = values

    def resolve(self, value):
        if isinstance(value, int):
            return value
        return self.values[value.name]


def test_payload_builds_sparse_labelled_layout():
    target = Symbol("libc.system")
    payload = (
        Payload(fill=b".")
        .pad(4, fill=b"A")
        .word(target, label="system")
        .place(16, b"tail", label="tail")
    )

    raw = payload.build(Context({"libc.system": 0x1122334455667788}))

    assert raw == b"AAAA" + b"\x88wfUD3\"\x11" + b"....tail"
    assert payload.size == 20
    assert payload.dependencies == {"libc.system"}
    assert payload.layout()[1]["value"] == "libc.system"
    assert payload.layout(Context({"libc.system": 1}))[1]["value"] == "0x1"


def test_payload_rejects_overlap_and_bad_bytes():
    payload = Payload(forbidden=b"\n").place(4, b"abcd")
    with pytest.raises(ConstraintError, match="overlaps"):
        payload.place(6, b"XX")

    with pytest.raises(ConstraintError, match="forbidden"):
        Payload(forbidden=b"\n").append(b"x\n").build()


def test_payload_rejects_unresolved_and_overflowing_words():
    symbol = Symbol("pie.main")
    with pytest.raises(UnresolvedValueError, match="BindingContext"):
        Payload().word(symbol).build()
    with pytest.raises(ConstraintError, match="does not fit"):
        Payload().word(1 << 64).build()


def test_append_payload_preserves_gaps_and_dependencies():
    inner = Payload(fill=b"\x00").place(4, Symbol("x"), word=True)
    outer = Payload().append(b"AB").append(inner)
    assert outer.size == 14
    assert outer.dependencies == {"x"}
    assert outer.build(Context({"x": 3})) == b"AB" + b"AAAA" + (3).to_bytes(8, "little")


def test_payload_supports_pattern_fill_explicit_width_and_encoded_regions():
    symbol = Symbol("x")
    payload = Payload(
        fill=b"abc",
        pointer_size=4,
        byteorder="big",
    ).word(0x11223344).place(
        8,
        Packed(symbol, bits=16, endian="little"),
        encoded=True,
        label="short symbol",
    ).ensure_size(12)

    raw = payload.build(Context({"x": 0x5566}))
    assert raw == b"\x11\x22\x33\x44bcab\x66\x55bc"
    assert payload.dependencies == {"x"}
    assert payload.layout()[2]["kind"] == "encoded"


def test_embed_places_payload_at_sparse_offset():
    inner = Payload(pointer_size=4).word(0x11223344, label="inner")
    outer = Payload(fill=b".").place(0, b"AA").embed(8, inner)
    assert outer.build() == b"AA......D3\x22\x11"
    assert outer.layout()[-1]["label"] == "inner"

