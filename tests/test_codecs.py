from __future__ import annotations

import hashlib

import pytest

from pwnx.codecs import (
    CRC16_CCITT_FALSE,
    CRC16_XMODEM,
    CRC32,
    ChecksumTransform,
    CompressionTransform,
    DigestTransform,
    TransformCodec,
    bytes_,
    cstring,
    frame,
    hex_pointer,
    integer,
    line_codec,
    pointer,
    struct,
    u16be,
    u16le,
    u32le,
    word,
    xor,
)
from pwnx.errors import ConstraintError, ProtocolError


class FakeIO:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        self.calls: list[tuple] = []

    def read_exact(self, n: int, timeout: float | None = None) -> bytes:
        self.calls.append(("exact", n, timeout))
        end = self.offset + n
        if end > len(self.data):
            raise ProtocolError("short")
        result = self.data[self.offset : end]
        self.offset = end
        return result

    def read_until(
        self,
        delimiter: bytes,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        self.calls.append(("until", delimiter, timeout, max_bytes))
        index = self.data.find(delimiter, self.offset)
        if index < 0:
            raise ProtocolError("missing delimiter")
        end = index + len(delimiter)
        if max_bytes is not None and end - self.offset > max_bytes:
            raise ProtocolError("too long")
        result = self.data[self.offset : end]
        self.offset = end
        return result


def test_word_round_trip_and_endianness() -> None:
    assert u16le.build(0x1234) == b"\x34\x12"
    assert u16be.build(0x1234) == b"\x12\x34"
    assert u32le.parse(b"\x78\x56\x34\x12") == 0x12345678
    assert word(16, signed=True).parse(b"\xff\xff") == -1


def test_word_rejects_truncation_overflow_and_bad_types() -> None:
    with pytest.raises(ProtocolError, match="exactly 8"):
        word().parse(b"\0" * 7)
    with pytest.raises(ConstraintError, match="does not fit"):
        word(8).build(256)
    with pytest.raises(ConstraintError, match="does not fit"):
        word(8, signed=True).build(-129)
    with pytest.raises(TypeError):
        word().build(True)


def test_full_pointer_round_trip() -> None:
    codec = pointer()
    value = 0x7F0102030405
    assert codec.parse(codec.build(value)) == value
    assert codec.size == 8


def test_partial_pointer_requires_explicit_extension() -> None:
    with pytest.raises(ValueError, match="partial pointers require"):
        pointer(6)

    leak = b"\x05\x04\x03\x02\x01\x7f"
    codec = pointer(6, extend="zero")
    assert codec.parse(leak) == 0x7F0102030405
    assert codec.build(0x7F0102030405) == leak


def test_sign_extended_partial_pointer_is_checked() -> None:
    codec = pointer(6, extend="sign")
    canonical = 0xFFFF800000001234
    encoded = b"\x34\x12\x00\x00\x00\x80"
    assert codec.parse(encoded) == canonical
    assert codec.build(canonical) == encoded
    with pytest.raises(ConstraintError, match="not a valid sign extension"):
        codec.build(0x0000800000001234)


def test_pointer_rejects_silent_truncation() -> None:
    with pytest.raises(ConstraintError, match="zero-extended"):
        pointer(6, extend="zero").build(1 << 48)
    with pytest.raises(ProtocolError, match="exactly 6"):
        pointer(6, extend="zero").parse(b"\0" * 5)


def test_text_integer_codecs_are_symmetric_and_bounded() -> None:
    decimal = integer(maximum_digits=4)
    assert decimal.parse(b"  -42\n") == -42
    assert decimal.build(-42) == b"-42\n"

    hexadecimal = hex_pointer()
    assert hexadecimal.parse(b" 0x7f00\n") == 0x7F00
    assert hexadecimal.build(0x7F00) == b"0x7f00\n"
    with pytest.raises(ProtocolError, match="not a base-16"):
        hexadecimal.parse(b"0x-1\n")
    with pytest.raises(ConstraintError, match="negative"):
        hexadecimal.build(-1)

    with pytest.raises(ProtocolError, match="base-10"):
        decimal.parse(b"four\n")
    with pytest.raises(ConstraintError, match="exceeds"):
        decimal.build(12345)


def test_delimited_integer_read_uses_a_bound() -> None:
    io = FakeIO(b"1337\nrest")
    assert integer(maximum_digits=5).read(io, timeout=1.5) == 1337
    assert io.calls == [("until", b"\n", 1.5, 7)]
    assert io.offset == 5


def test_unframed_integer_composes_with_external_channel_framing() -> None:
    codec = integer(delimiter=None)
    assert codec.build(42) == b"42"
    assert codec.parse(b"42") == 42
    with pytest.raises(ProtocolError, match="external boundary"):
        codec.read(FakeIO(b"42"))


def test_fixed_and_delimited_bytes() -> None:
    fixed = bytes_(4)
    assert fixed.parse(b"abcd") == b"abcd"
    assert fixed.build(b"abcd") == b"abcd"
    with pytest.raises(ProtocolError, match="exactly 4"):
        fixed.parse(b"abc")
    with pytest.raises(ConstraintError, match="exactly 4"):
        fixed.build(b"abc")

    line = bytes_(until=b"\r\n", max_size=8)
    assert line.parse(b"hello\r\n") == b"hello"
    assert line.build(b"hello") == b"hello\r\n"
    with pytest.raises(ConstraintError, match="delimiter"):
        line.build(b"a\r\nb")


def test_unbounded_bytes_cannot_read_an_unknown_amount() -> None:
    with pytest.raises(ProtocolError, match="without a length or delimiter"):
        bytes_().read(FakeIO(b"anything"))


def test_line_codec_is_distinct_from_input_channel() -> None:
    codec = line_codec(terminator=b"\r\n")
    assert codec.read(FakeIO(b"hello\r\nrest")) == b"hello"
    assert codec.build(b"hello") == b"hello\r\n"

    keepends = line_codec(keepends=True)
    assert keepends.parse(b"hello\n") == b"hello\n"


def test_cstring_bytes_and_text_round_trip() -> None:
    raw = cstring()
    assert raw.parse(b"/bin/sh\0") == b"/bin/sh"
    assert raw.build(b"/bin/sh") == b"/bin/sh\0"

    text = cstring(encoding="utf-8")
    assert text.parse("hé".encode() + b"\0") == "hé"
    assert text.build("hé") == "hé".encode() + b"\0"

    with pytest.raises(ProtocolError, match="trailing"):
        raw.parse(b"a\0b")
    with pytest.raises(ConstraintError, match="embedded"):
        raw.build(b"a\0b")
    with pytest.raises(TypeError, match="encoding"):
        raw.build("text")


def test_struct_composes_fixed_and_delimited_fields() -> None:
    record = struct(kind=word(8), name=cstring(), value=word(16, "big"))
    encoded = b"\x02demo\0\x12\x34"
    value = {"kind": 2, "name": b"demo", "value": 0x1234}
    assert record.parse(encoded) == value
    assert record.build(value) == encoded
    assert record.size is None

    with pytest.raises(ProtocolError, match="trailing"):
        record.parse(encoded + b"x")
    with pytest.raises(ConstraintError, match="missing"):
        record.build({"kind": 2, "name": b"demo"})
    with pytest.raises(ConstraintError, match="unknown"):
        record.build({**value, "extra": 1})


def test_struct_read_preserves_field_boundaries() -> None:
    record = struct(tag=word(8), text=bytes_(until=b"\n"), count=word(16, "big"))
    io = FakeIO(b"\x03hello\n\x00\x07")
    assert record.read(io) == {"tag": 3, "text": b"hello", "count": 7}
    assert io.offset == len(io.data)


def test_length_prefixed_frame_round_trip_and_read() -> None:
    codec = frame(bytes_(), length=word(16, "big"), max_size=8)
    assert codec.build(b"abc") == b"\x00\x03abc"
    assert codec.parse(b"\x00\x03abc") == b"abc"

    io = FakeIO(b"\x00\x03abcnext")
    assert codec.read(io) == b"abc"
    assert io.offset == 5


def test_frame_rejects_length_mismatch_and_oversize() -> None:
    codec = frame(bytes_(), length=word(8), max_size=3)
    with pytest.raises(ProtocolError, match="declares 3"):
        codec.parse(b"\x03ab")
    with pytest.raises(ProtocolError, match="maximum"):
        codec.parse(b"\x04abcd")
    with pytest.raises(ConstraintError, match="maximum"):
        codec.build(b"abcd")


def test_frame_can_count_its_prefix() -> None:
    codec = frame(bytes_(), length=word(8), include_prefix=True)
    assert codec.build(b"abc") == b"\x04abc"
    assert codec.parse(b"\x04abc") == b"abc"
    with pytest.raises(ProtocolError, match="smaller than its prefix"):
        codec.parse(b"\x00")


def test_xor_codec_is_symmetric_and_supports_fixed_reads() -> None:
    codec = xor(word(32), b"\xaa\x55")
    encoded = codec.build(0x12345678)
    assert encoded == bytes(a ^ b for a, b in zip(b"\x78\x56\x34\x12", b"\xaa\x55\xaa\x55"))
    assert codec.parse(encoded) == 0x12345678
    assert codec.read(FakeIO(encoded)) == 0x12345678

    with pytest.raises(ProtocolError, match="must be placed in a frame"):
        xor(cstring(), 0xAA).read(FakeIO(b""))


def test_codec_explain_has_bytes_and_value() -> None:
    explanation = word(16).explain(0x1234)
    assert explanation == {
        "codec": "WordCodec",
        "size": 2,
        "bytes": "3412",
        "value": 0x1234,
    }


def test_crc_algorithms_match_published_check_vectors() -> None:
    message = b"123456789"
    assert CRC32.calculate(message) == 0xCBF43926
    assert CRC16_CCITT_FALSE.calculate(message) == 0x29B1
    assert CRC16_XMODEM.calculate(message) == 0x31C3


def test_checksum_transform_is_symmetric_bounded_and_detects_tampering() -> None:
    codec = bytes_().through(ChecksumTransform(CRC16_CCITT_FALSE, max_payload_size=16))
    encoded = codec.build(b"message")
    assert codec.parse(encoded) == b"message"
    assert codec.size is None
    assert codec.explain(b"message")["transforms"][0]["algorithm"]["name"] == ("CRC-16/CCITT-FALSE")
    with pytest.raises(ProtocolError, match="checksum mismatch"):
        codec.parse(encoded[:-1] + bytes([encoded[-1] ^ 1]))
    with pytest.raises(ConstraintError, match="maximum"):
        codec.build(b"x" * 17)


@pytest.mark.parametrize("algorithm", ["zlib", "gzip", "bz2", "lzma"])
def test_compression_transforms_round_trip_without_hidden_global_state(
    algorithm: str,
) -> None:
    transform = CompressionTransform(
        algorithm,  # type: ignore[arg-type]
        max_encoded_size=4096,
        max_decoded_size=4096,
    )
    codec = bytes_().through(transform)
    value = b"declarative protocol payload" * 8
    encoded = codec.build(value)
    assert encoded != value
    assert codec.parse(encoded) == value
    assert transform.metadata()["algorithm"] == algorithm


def test_compression_transform_rejects_truncation_trailing_data_and_bombs() -> None:
    transform = CompressionTransform("zlib", max_encoded_size=4096, max_decoded_size=4096)
    encoded = transform.encode(b"bounded")
    with pytest.raises(ProtocolError, match="truncated|malformed"):
        transform.decode(encoded[:-1])
    with pytest.raises(ProtocolError, match="trailing"):
        transform.decode(encoded + b"trailing")

    permissive = CompressionTransform("zlib", max_encoded_size=4096, max_decoded_size=4096)
    compressed_bomb = permissive.encode(b"A" * 2048)
    strict = CompressionTransform(
        "zlib",
        max_encoded_size=4096,
        max_decoded_size=4096,
        max_ratio=2,
    )
    with pytest.raises(ProtocolError, match="ratio"):
        strict.decode(compressed_bomb)


def test_hash_and_hmac_transforms_make_integrity_semantics_explicit() -> None:
    digest = DigestTransform("sha256", tag_size=16)
    authenticated = DigestTransform(
        "sha256",
        key=b"secret",
        tag_size=16,
        key_ref="credential:challenge-hmac",
    )
    digest_frame = digest.encode(b"payload")
    hmac_frame = authenticated.encode(b"payload")
    assert digest.decode(digest_frame) == b"payload"
    assert authenticated.decode(hmac_frame) == b"payload"
    assert digest_frame != hmac_frame
    assert "secret" not in repr(authenticated)
    assert authenticated.metadata()["security"] == ("message authentication; not encryption")
    assert authenticated.metadata()["key_ref"] == "credential:challenge-hmac"
    assert "key_sha256" not in authenticated.metadata()
    assert hashlib.sha256(b"secret").hexdigest() not in repr(authenticated.metadata())
    with pytest.raises(ProtocolError, match="authentication"):
        authenticated.decode(hmac_frame[:-1] + bytes([hmac_frame[-1] ^ 1]))


def test_transform_pipeline_reverses_wire_order_and_requires_framing_for_reads() -> None:
    pipeline = bytes_().through(
        CompressionTransform("zlib"),
        DigestTransform("sha256", key=b"key", tag_size=12),
    )
    assert isinstance(pipeline, TransformCodec)
    encoded = pipeline.build(b"hello pipeline")
    assert pipeline.parse(encoded) == b"hello pipeline"
    assert [item.name for item in pipeline.transforms] == [
        "compression:zlib",
        "hmac:sha256",
    ]
    with pytest.raises(ProtocolError, match="must be placed in a frame"):
        pipeline.read(FakeIO(encoded))

    framed = frame(pipeline, length=word(16, "big"), max_size=4096)
    wire = framed.build(b"hello pipeline")
    assert framed.parse(wire) == b"hello pipeline"
