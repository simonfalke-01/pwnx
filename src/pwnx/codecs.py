"""Symmetric binary codecs used by protocols and observations.

Codecs deliberately do not bind symbolic facts.  They only translate between a
Python value and bytes.  This keeps parsing reusable in live and replay runs.
"""

from __future__ import annotations

import bz2
import hashlib
import hmac
import lzma
import zlib
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Generic, Literal, Protocol, TypeVar, cast, runtime_checkable

from .errors import ConstraintError, ProtocolError

T = TypeVar("T")


@runtime_checkable
class Readable(Protocol):
    def read_exact(self, n: int, timeout: float | None = None) -> bytes: ...

    def read_until(
        self,
        delimiter: bytes,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> bytes: ...


def _ensure_bytes(value: bytes | bytearray | memoryview, *, what: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{what} must be bytes-like, got {type(value).__name__}")
    return bytes(value)


def _read_until(
    io: Readable,
    delimiter: bytes,
    *,
    timeout: float | None = None,
    max_bytes: int | None = None,
) -> bytes:
    data = io.read_until(delimiter, timeout=timeout, max_bytes=max_bytes)
    if not data.endswith(delimiter):
        raise ProtocolError(f"read_until returned data without its delimiter {delimiter!r}")
    return data


class Codec(ABC, Generic[T]):
    """A bidirectional, validating byte representation."""

    @property
    def size(self) -> int | None:
        return None

    @abstractmethod
    def parse(self, data: bytes | bytearray | memoryview) -> T:
        raise NotImplementedError

    @abstractmethod
    def build(self, value: T) -> bytes:
        raise NotImplementedError

    def validate(self, value: T) -> None:
        self.build(value)

    def read(self, io: Readable, *, timeout: float | None = None) -> T:
        if self.size is None:
            raise ProtocolError(
                f"{type(self).__name__} has no fixed size; use a framed or delimiter-aware codec"
            )
        return self.parse(io.read_exact(self.size, timeout=timeout))

    def explain(self, value: T) -> dict[str, Any]:
        encoded = self.build(value)
        return {
            "codec": type(self).__name__,
            "size": len(encoded),
            "bytes": encoded.hex(),
            "value": value,
        }

    def through(self, *transforms: "ByteTransform") -> "TransformCodec[T]":
        """Apply named byte transforms in wire order.

        The value is first built by this codec, then passed through each
        transform from left to right. Parsing reverses that exact pipeline.
        """

        if isinstance(self, TransformCodec):
            return TransformCodec(self.inner, self.transforms + tuple(transforms))
        return TransformCodec(self, tuple(transforms))


@runtime_checkable
class ByteTransform(Protocol):
    """A symmetric, inspectable operation over already-encoded bytes."""

    @property
    def name(self) -> str: ...

    def encoded_size(self, input_size: int | None) -> int | None: ...

    def encode(self, data: bytes) -> bytes: ...

    def decode(self, data: bytes) -> bytes: ...

    def metadata(self) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class TransformCodec(Codec[T], Generic[T]):
    """A value codec followed by a declarative byte-transform pipeline."""

    inner: Codec[T]
    transforms: tuple[ByteTransform, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.inner, Codec):
            raise TypeError("transform inner value must be a Codec")
        if not self.transforms:
            raise ValueError("transform pipeline cannot be empty")
        if any(not isinstance(item, ByteTransform) for item in self.transforms):
            raise TypeError("transform pipeline contains an invalid transform")

    @property
    def size(self) -> int | None:
        result = self.inner.size
        for transform in self.transforms:
            result = transform.encoded_size(result)
        return result

    def parse(self, data: bytes | bytearray | memoryview) -> T:
        decoded = _ensure_bytes(data, what="transformed data")
        for transform in reversed(self.transforms):
            decoded = transform.decode(decoded)
        return self.inner.parse(decoded)

    def build(self, value: T) -> bytes:
        encoded = self.inner.build(value)
        for transform in self.transforms:
            encoded = transform.encode(encoded)
        return encoded

    def read(self, io: Readable, *, timeout: float | None = None) -> T:
        if self.size is None:
            raise ProtocolError("variable-size transform pipelines must be placed in a frame")
        return self.parse(io.read_exact(self.size, timeout=timeout))

    def explain(self, value: T) -> dict[str, Any]:
        encoded = self.build(value)
        return {
            "codec": type(self).__name__,
            "size": len(encoded),
            "bytes": encoded.hex(),
            "value": value,
            "inner": self.inner.explain(value),
            "transforms": [dict(item.metadata()) for item in self.transforms],
        }

    def through(self, *transforms: ByteTransform) -> "TransformCodec[T]":
        return TransformCodec(self.inner, self.transforms + tuple(transforms))


def _reflect(value: int, width: int) -> int:
    result = 0
    for _ in range(width):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


@dataclass(frozen=True, slots=True)
class CRCAlgorithm:
    """Fully specified CRC parameters; CRCs detect accidents, not attackers."""

    name: str
    width: int
    polynomial: int
    initial: int
    xor_output: int
    reflect_input: bool
    reflect_output: bool

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("CRC name cannot be empty")
        if self.width < 8 or self.width % 8:
            raise ValueError("CRC width must be a positive whole number of bytes")
        mask = (1 << self.width) - 1
        if not 0 <= self.polynomial <= mask:
            raise ValueError("CRC polynomial does not fit its width")
        if not 0 <= self.initial <= mask or not 0 <= self.xor_output <= mask:
            raise ValueError("CRC initial/xor values do not fit their width")

    @property
    def tag_size(self) -> int:
        return self.width // 8

    def calculate(self, data: bytes | bytearray | memoryview) -> int:
        raw = _ensure_bytes(data, what="CRC input")
        mask = (1 << self.width) - 1
        crc = self.initial
        if self.reflect_input:
            polynomial = _reflect(self.polynomial, self.width)
            for byte in raw:
                crc ^= byte
                for _ in range(8):
                    crc = (crc >> 1) ^ (polynomial if crc & 1 else 0)
        else:
            high_bit = 1 << (self.width - 1)
            for byte in raw:
                crc ^= byte << (self.width - 8)
                for _ in range(8):
                    crc = ((crc << 1) & mask) ^ (self.polynomial if crc & high_bit else 0)
        if self.reflect_output != self.reflect_input:
            crc = _reflect(crc, self.width)
        return (crc ^ self.xor_output) & mask

    def metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "width": self.width,
            "polynomial": f"0x{self.polynomial:x}",
            "initial": f"0x{self.initial:x}",
            "xor_output": f"0x{self.xor_output:x}",
            "reflect_input": self.reflect_input,
            "reflect_output": self.reflect_output,
            "security": "error detection only; not authentication",
        }


CRC32 = CRCAlgorithm(
    "CRC-32/ISO-HDLC",
    32,
    0x04C11DB7,
    0xFFFFFFFF,
    0xFFFFFFFF,
    True,
    True,
)
CRC16_CCITT_FALSE = CRCAlgorithm(
    "CRC-16/CCITT-FALSE",
    16,
    0x1021,
    0xFFFF,
    0x0000,
    False,
    False,
)
CRC16_XMODEM = CRCAlgorithm(
    "CRC-16/XMODEM",
    16,
    0x1021,
    0x0000,
    0x0000,
    False,
    False,
)


@dataclass(frozen=True, slots=True)
class ChecksumTransform:
    algorithm: CRCAlgorithm = CRC32
    byteorder: Literal["little", "big"] = "big"
    max_payload_size: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.byteorder not in {"little", "big"}:
            raise ValueError("checksum byteorder must be 'little' or 'big'")
        if self.max_payload_size < 0:
            raise ValueError("checksum payload bound cannot be negative")

    @property
    def name(self) -> str:
        return f"checksum:{self.algorithm.name}"

    def encoded_size(self, input_size: int | None) -> int | None:
        return None if input_size is None else input_size + self.algorithm.tag_size

    def encode(self, data: bytes) -> bytes:
        if len(data) > self.max_payload_size:
            raise ConstraintError(
                f"checksum payload is {len(data)} bytes, maximum is {self.max_payload_size}"
            )
        tag = self.algorithm.calculate(data).to_bytes(self.algorithm.tag_size, self.byteorder)
        return data + tag

    def decode(self, data: bytes) -> bytes:
        tag_size = self.algorithm.tag_size
        if len(data) < tag_size:
            raise ProtocolError(
                f"{self.algorithm.name} frame is shorter than its {tag_size}-byte tag"
            )
        payload, actual = data[:-tag_size], data[-tag_size:]
        if len(payload) > self.max_payload_size:
            raise ProtocolError(
                f"checksum payload is {len(payload)} bytes, maximum is {self.max_payload_size}"
            )
        expected = self.algorithm.calculate(payload).to_bytes(tag_size, self.byteorder)
        if not hmac.compare_digest(actual, expected):
            raise ProtocolError(f"{self.algorithm.name} checksum mismatch")
        return payload

    def metadata(self) -> Mapping[str, Any]:
        return {
            "transform": "checksum",
            "algorithm": self.algorithm.metadata(),
            "byteorder": self.byteorder,
            "max_payload_size": self.max_payload_size,
        }


CompressionName = Literal["zlib", "gzip", "bz2", "lzma"]


def _compress(data: bytes, algorithm: CompressionName, level: int | None) -> bytes:
    if algorithm == "zlib":
        return zlib.compress(data, -1 if level is None else level)
    if algorithm == "gzip":
        compressor = zlib.compressobj(
            -1 if level is None else level,
            zlib.DEFLATED,
            16 + zlib.MAX_WBITS,
        )
        return compressor.compress(data) + compressor.flush()
    if algorithm == "bz2":
        return bz2.compress(data, compresslevel=9 if level is None else level)
    return lzma.compress(data, preset=6 if level is None else level)


def _decompress_zlib(data: bytes, *, wbits: int, maximum: int) -> bytes:
    decoder = zlib.decompressobj(wbits)
    try:
        result = decoder.decompress(data, maximum + 1)
        if len(result) <= maximum:
            result += decoder.flush(maximum + 1 - len(result))
    except zlib.error as error:
        raise ProtocolError(f"malformed compressed frame: {error}") from error
    if len(result) > maximum or decoder.unconsumed_tail:
        raise ProtocolError(f"decoded data exceeds maximum {maximum} bytes")
    if not decoder.eof:
        raise ProtocolError("compressed frame is truncated")
    if decoder.unused_data:
        raise ProtocolError("compressed frame contains trailing data")
    return result


def _decompress_stream(data: bytes, *, algorithm: CompressionName, maximum: int) -> bytes:
    decoder: bz2.BZ2Decompressor | lzma.LZMADecompressor
    decoder = bz2.BZ2Decompressor() if algorithm == "bz2" else lzma.LZMADecompressor()
    result = bytearray()
    chunk = data
    try:
        while True:
            result.extend(decoder.decompress(chunk, max_length=maximum + 1 - len(result)))
            if len(result) > maximum:
                raise ProtocolError(f"decoded data exceeds maximum {maximum} bytes")
            if decoder.eof:
                if decoder.unused_data:
                    raise ProtocolError("compressed frame contains trailing data")
                return bytes(result)
            if decoder.needs_input:
                raise ProtocolError("compressed frame is truncated")
            chunk = b""
    except (OSError, EOFError, lzma.LZMAError) as error:
        raise ProtocolError(f"malformed compressed frame: {error}") from error


@dataclass(frozen=True, slots=True)
class CompressionTransform:
    algorithm: CompressionName = "zlib"
    level: int | None = None
    max_encoded_size: int = 16 * 1024 * 1024
    max_decoded_size: int = 16 * 1024 * 1024
    max_ratio: float = 1024.0

    def __post_init__(self) -> None:
        if self.algorithm not in {"zlib", "gzip", "bz2", "lzma"}:
            raise ValueError(f"unsupported compression algorithm {self.algorithm!r}")
        if self.max_encoded_size <= 0 or self.max_decoded_size <= 0:
            raise ValueError("compression size bounds must be positive")
        if self.max_ratio <= 0:
            raise ValueError("compression ratio bound must be positive")
        if self.level is not None and not 0 <= self.level <= 9:
            raise ValueError(f"{self.algorithm} level must be in range 0..9")

    @property
    def name(self) -> str:
        return f"compression:{self.algorithm}"

    def encoded_size(self, input_size: int | None) -> int | None:
        del input_size
        return None

    def _check_ratio(self, decoded_size: int, encoded_size: int, error: type[Exception]) -> None:
        ratio = decoded_size / max(1, encoded_size)
        if ratio > self.max_ratio:
            raise error(f"compression ratio {ratio:.2f}:1 exceeds maximum {self.max_ratio:g}:1")

    def encode(self, data: bytes) -> bytes:
        if len(data) > self.max_decoded_size:
            raise ConstraintError(
                f"decoded input is {len(data)} bytes, maximum is {self.max_decoded_size}"
            )
        try:
            encoded = _compress(data, self.algorithm, self.level)
        except (OSError, ValueError, lzma.LZMAError) as error:
            raise ConstraintError(f"cannot compress with {self.algorithm}: {error}") from error
        if len(encoded) > self.max_encoded_size:
            raise ConstraintError(
                f"compressed output is {len(encoded)} bytes, maximum is {self.max_encoded_size}"
            )
        self._check_ratio(len(data), len(encoded), ConstraintError)
        return encoded

    def decode(self, data: bytes) -> bytes:
        if len(data) > self.max_encoded_size:
            raise ProtocolError(
                f"compressed input is {len(data)} bytes, maximum is {self.max_encoded_size}"
            )
        if self.algorithm == "zlib":
            decoded = _decompress_zlib(data, wbits=zlib.MAX_WBITS, maximum=self.max_decoded_size)
        elif self.algorithm == "gzip":
            decoded = _decompress_zlib(
                data, wbits=16 + zlib.MAX_WBITS, maximum=self.max_decoded_size
            )
        else:
            decoded = _decompress_stream(
                data, algorithm=self.algorithm, maximum=self.max_decoded_size
            )
        self._check_ratio(len(decoded), len(data), ProtocolError)
        return decoded

    def metadata(self) -> Mapping[str, Any]:
        return {
            "transform": "compression",
            "algorithm": self.algorithm,
            "level": self.level,
            "max_encoded_size": self.max_encoded_size,
            "max_decoded_size": self.max_decoded_size,
            "max_ratio": self.max_ratio,
        }


@dataclass(frozen=True, slots=True)
class DigestTransform:
    algorithm: str = "sha256"
    key: bytes | None = field(default=None, repr=False)
    tag_size: int | None = None
    max_payload_size: int = 16 * 1024 * 1024
    key_ref: str | None = None

    def __post_init__(self) -> None:
        try:
            digest_size = hashlib.new(self.algorithm).digest_size
        except (ValueError, TypeError) as error:
            raise ValueError(f"unsupported hash algorithm {self.algorithm!r}") from error
        if self.key is not None:
            object.__setattr__(self, "key", _ensure_bytes(self.key, what="HMAC key"))
            if not self.key:
                raise ValueError("HMAC key cannot be empty")
        if self.key_ref is not None and (
            not self.key_ref or "\0" in self.key_ref
        ):
            raise ValueError("key_ref must be a non-empty, NUL-free reference")
        if self.key is None and self.key_ref is not None:
            raise ValueError("key_ref is only valid for an HMAC transform")
        selected_size = digest_size if self.tag_size is None else self.tag_size
        if not isinstance(selected_size, int) or not 1 <= selected_size <= digest_size:
            raise ValueError(f"tag_size must be in range 1..{digest_size}")
        if self.max_payload_size < 0:
            raise ValueError("digest payload bound cannot be negative")
        object.__setattr__(self, "tag_size", selected_size)

    @property
    def name(self) -> str:
        mode = "hmac" if self.key is not None else "hash"
        return f"{mode}:{self.algorithm}"

    def encoded_size(self, input_size: int | None) -> int | None:
        return None if input_size is None else input_size + cast(int, self.tag_size)

    def _tag(self, data: bytes) -> bytes:
        if self.key is None:
            return hashlib.new(self.algorithm, data).digest()[: self.tag_size]
        return hmac.new(self.key, data, self.algorithm).digest()[: self.tag_size]

    def encode(self, data: bytes) -> bytes:
        if len(data) > self.max_payload_size:
            raise ConstraintError(
                f"digest payload is {len(data)} bytes, maximum is {self.max_payload_size}"
            )
        return data + self._tag(data)

    def decode(self, data: bytes) -> bytes:
        tag_size = cast(int, self.tag_size)
        if len(data) < tag_size:
            raise ProtocolError(f"{self.name} frame is shorter than its tag")
        payload, actual = data[:-tag_size], data[-tag_size:]
        if len(payload) > self.max_payload_size:
            raise ProtocolError(
                f"digest payload is {len(payload)} bytes, maximum is {self.max_payload_size}"
            )
        if not hmac.compare_digest(actual, self._tag(payload)):
            kind = "authentication" if self.key is not None else "digest"
            raise ProtocolError(f"{self.algorithm} {kind} tag mismatch")
        return payload

    def metadata(self) -> Mapping[str, Any]:
        mode = "hmac" if self.key is not None else "hash"
        return {
            "transform": mode,
            "algorithm": self.algorithm,
            "tag_size": self.tag_size,
            "max_payload_size": self.max_payload_size,
            "key_ref": self.key_ref,
            "security": (
                "message authentication; not encryption"
                if self.key is not None
                else "accidental integrity only; not authentication or encryption"
            ),
        }


@dataclass(frozen=True, slots=True)
class WordCodec(Codec[int]):
    bits: int = 64
    endian: Literal["little", "big"] = "little"
    signed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.bits, int) or self.bits <= 0 or self.bits % 8:
            raise ValueError("word size must be a positive multiple of 8 bits")
        if self.endian not in {"little", "big"}:
            raise ValueError("endian must be 'little' or 'big'")

    @property
    def size(self) -> int:
        return self.bits // 8

    def parse(self, data: bytes | bytearray | memoryview) -> int:
        raw = _ensure_bytes(data, what="word data")
        if len(raw) != self.size:
            raise ProtocolError(
                f"expected exactly {self.size} bytes for a {self.bits}-bit word, "
                f"received {len(raw)}"
            )
        return int.from_bytes(raw, self.endian, signed=self.signed)

    def build(self, value: int) -> bytes:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"word value must be an int, got {type(value).__name__}")
        minimum = -(1 << (self.bits - 1)) if self.signed else 0
        maximum = (1 << (self.bits - (1 if self.signed else 0))) - 1
        if not minimum <= value <= maximum:
            kind = "signed" if self.signed else "unsigned"
            raise ConstraintError(
                f"{value} does not fit in a {kind} {self.bits}-bit word ({minimum}..{maximum})"
            )
        return value.to_bytes(self.size, self.endian, signed=self.signed)


@dataclass(frozen=True, slots=True)
class PointerCodec(Codec[int]):
    encoded_size: int = 8
    width: int = 8
    endian: Literal["little", "big"] = "little"
    extend: str | None = None

    def __post_init__(self) -> None:
        if self.encoded_size <= 0 or self.width <= 0:
            raise ValueError("pointer sizes must be positive")
        if self.encoded_size > self.width:
            raise ValueError("encoded pointer size cannot exceed pointer width")
        if self.endian not in {"little", "big"}:
            raise ValueError("endian must be 'little' or 'big'")
        if self.encoded_size != self.width and self.extend not in {"zero", "sign"}:
            raise ValueError(
                "partial pointers require extend='zero' or extend='sign'; "
                "implicit padding is not allowed"
            )
        if self.encoded_size == self.width and self.extend not in {None, "zero"}:
            raise ValueError("full-width pointers do not support sign extension")

    @property
    def size(self) -> int:
        return self.encoded_size

    def parse(self, data: bytes | bytearray | memoryview) -> int:
        raw = _ensure_bytes(data, what="pointer data")
        if len(raw) != self.encoded_size:
            raise ProtocolError(
                f"expected exactly {self.encoded_size} pointer bytes, received {len(raw)}"
            )
        value = int.from_bytes(raw, self.endian, signed=False)
        if self.extend == "sign" and self.encoded_size < self.width:
            sign_bit = 1 << (self.encoded_size * 8 - 1)
            if value & sign_bit:
                value |= ((1 << (self.width * 8)) - 1) ^ ((1 << (self.encoded_size * 8)) - 1)
        return value

    def build(self, value: int) -> bytes:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"pointer value must be an int, got {type(value).__name__}")
        full_max = (1 << (self.width * 8)) - 1
        if not 0 <= value <= full_max:
            raise ConstraintError(f"pointer {value} does not fit in {self.width * 8} bits")
        encoded_mask = (1 << (self.encoded_size * 8)) - 1
        if self.encoded_size < self.width:
            if self.extend == "zero" and value > encoded_mask:
                raise ConstraintError(
                    f"pointer {value:#x} cannot be represented by "
                    f"{self.encoded_size} zero-extended bytes"
                )
            if self.extend == "sign":
                low = value & encoded_mask
                sign = 1 << (self.encoded_size * 8 - 1)
                expected = low
                if low & sign:
                    expected |= full_max ^ encoded_mask
                if value != expected:
                    raise ConstraintError(
                        f"pointer {value:#x} is not a valid sign extension of "
                        f"{self.encoded_size} bytes"
                    )
                value = low
        return (value & encoded_mask).to_bytes(self.encoded_size, self.endian, signed=False)


@dataclass(frozen=True, slots=True)
class DelimitedIntegerCodec(Codec[int]):
    base: int = 10
    delimiter: bytes | None = b"\n"
    prefix: bytes = b""
    allow_whitespace: bool = True
    maximum_digits: int = 128
    signed: bool = True

    def __post_init__(self) -> None:
        if not 2 <= self.base <= 36:
            raise ValueError("integer base must be between 2 and 36")
        if self.delimiter == b"":
            raise ValueError("delimiter cannot be empty")
        if self.maximum_digits <= 0:
            raise ValueError("maximum_digits must be positive")

    def parse(self, data: bytes | bytearray | memoryview) -> int:
        raw = _ensure_bytes(data, what="integer data")
        if self.delimiter is not None and raw.endswith(self.delimiter):
            raw = raw[: -len(self.delimiter)]
        if self.allow_whitespace:
            raw = raw.strip()
        if self.prefix:
            if not raw.lower().startswith(self.prefix.lower()):
                raise ProtocolError(f"expected integer prefix {self.prefix!r}, received {raw!r}")
            raw = raw[len(self.prefix) :]
        digit_count = len(raw.lstrip(b"+-"))
        if not raw or not digit_count or digit_count > self.maximum_digits:
            raise ProtocolError(
                f"invalid integer width {digit_count} (maximum {self.maximum_digits})"
            )
        try:
            text = raw.decode("ascii")
            if not self.signed and text.startswith(("-", "+")):
                raise ValueError("sign is not allowed")
            return int(text, self.base)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ProtocolError(f"{raw!r} is not a base-{self.base} integer") from exc

    def build(self, value: int) -> bytes:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"integer value must be an int, got {type(value).__name__}")
        if not self.signed and value < 0:
            raise ConstraintError("negative values are not allowed by this codec")
        if self.base == 10:
            encoded = str(value)
        else:
            sign = "-" if value < 0 else ""
            magnitude = abs(value)
            alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
            if magnitude == 0:
                digits = "0"
            else:
                parts: list[str] = []
                while magnitude:
                    magnitude, digit = divmod(magnitude, self.base)
                    parts.append(alphabet[digit])
                digits = "".join(reversed(parts))
            encoded = sign + digits
        if len(encoded.lstrip("-")) > self.maximum_digits:
            raise ConstraintError(f"integer representation exceeds {self.maximum_digits} digits")
        return self.prefix + encoded.encode("ascii") + (self.delimiter or b"")

    def read(self, io: Readable, *, timeout: float | None = None) -> int:
        if self.delimiter is None:
            raise ProtocolError("unframed integer cannot be read without an external boundary")
        data = _read_until(
            io,
            self.delimiter,
            timeout=timeout,
            max_bytes=self.maximum_digits + len(self.prefix) + len(self.delimiter) + 1,
        )
        return self.parse(data)


@dataclass(frozen=True, slots=True)
class BytesCodec(Codec[bytes]):
    length: int | None = None
    delimiter: bytes | None = None
    drop_delimiter: bool = True
    max_size: int | None = None

    def __post_init__(self) -> None:
        if self.length is not None and self.length < 0:
            raise ValueError("byte length cannot be negative")
        if self.delimiter == b"":
            raise ValueError("delimiter cannot be empty")
        if self.length is not None and self.delimiter is not None:
            raise ValueError("bytes codec cannot have both a length and delimiter")
        if self.max_size is not None and self.max_size < 0:
            raise ValueError("max_size cannot be negative")
        if self.length is not None and self.max_size is not None and self.length > self.max_size:
            raise ValueError("fixed length exceeds max_size")

    @property
    def size(self) -> int | None:
        return self.length

    def parse(self, data: bytes | bytearray | memoryview) -> bytes:
        raw = _ensure_bytes(data, what="byte data")
        if self.length is not None and len(raw) != self.length:
            raise ProtocolError(f"expected exactly {self.length} bytes, received {len(raw)}")
        if self.delimiter is not None:
            if not raw.endswith(self.delimiter):
                raise ProtocolError(f"expected data terminated by {self.delimiter!r}")
            if self.drop_delimiter:
                raw = raw[: -len(self.delimiter)]
        if self.max_size is not None and len(raw) > self.max_size:
            raise ProtocolError(f"received {len(raw)} bytes, maximum is {self.max_size}")
        return raw

    def build(self, value: bytes) -> bytes:
        raw = _ensure_bytes(value, what="byte value")
        if self.length is not None and len(raw) != self.length:
            raise ConstraintError(f"expected exactly {self.length} bytes, received {len(raw)}")
        if self.max_size is not None and len(raw) > self.max_size:
            raise ConstraintError(f"value is {len(raw)} bytes, maximum is {self.max_size}")
        if self.delimiter is not None:
            if self.delimiter in raw:
                raise ConstraintError(f"value contains framing delimiter {self.delimiter!r}")
            return raw + self.delimiter
        return raw

    def read(self, io: Readable, *, timeout: float | None = None) -> bytes:
        if self.length is not None:
            return self.parse(io.read_exact(self.length, timeout=timeout))
        if self.delimiter is None:
            raise ProtocolError("unbounded bytes cannot be read without a length or delimiter")
        data = _read_until(
            io,
            self.delimiter,
            timeout=timeout,
            max_bytes=(None if self.max_size is None else self.max_size + len(self.delimiter)),
        )
        return self.parse(data)


@dataclass(frozen=True, slots=True)
class CStringCodec(Codec[bytes | str]):
    encoding: str | None = None
    max_size: int = 4096

    def __post_init__(self) -> None:
        if self.max_size <= 0:
            raise ValueError("max_size must be positive")

    def parse(self, data: bytes | bytearray | memoryview) -> bytes | str:
        raw = _ensure_bytes(data, what="C string data")
        try:
            end = raw.index(0)
        except ValueError as exc:
            raise ProtocolError("C string is missing its NUL terminator") from exc
        if end + 1 != len(raw):
            raise ProtocolError("C string contains trailing bytes after its terminator")
        value = raw[:end]
        if len(value) > self.max_size:
            raise ProtocolError(f"C string is {len(value)} bytes, maximum is {self.max_size}")
        if self.encoding is not None:
            try:
                return value.decode(self.encoding)
            except UnicodeDecodeError as exc:
                raise ProtocolError(f"C string is not valid {self.encoding}") from exc
        return value

    def build(self, value: bytes | str) -> bytes:
        if isinstance(value, str):
            if self.encoding is None:
                raise TypeError("string values require cstring(encoding=...)")
            raw = value.encode(self.encoding)
        else:
            raw = _ensure_bytes(value, what="C string value")
        if b"\0" in raw:
            raise ConstraintError("C string value contains an embedded NUL")
        if len(raw) > self.max_size:
            raise ConstraintError(f"C string is {len(raw)} bytes, maximum is {self.max_size}")
        return raw + b"\0"

    def read(self, io: Readable, *, timeout: float | None = None) -> bytes | str:
        data = _read_until(io, b"\0", timeout=timeout, max_bytes=self.max_size + 1)
        return self.parse(data)


class _MemoryReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def read_exact(self, n: int, timeout: float | None = None) -> bytes:
        del timeout
        if n < 0:
            raise ValueError("read length cannot be negative")
        end = self.offset + n
        if end > len(self.data):
            raise ProtocolError(
                f"truncated structure: needed {n} bytes, only {self.remaining} remain"
            )
        result = self.data[self.offset : end]
        self.offset = end
        return result

    def read_until(
        self,
        delimiter: bytes,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        del timeout
        start = self.offset
        index = self.data.find(delimiter, start)
        if index < 0:
            raise ProtocolError(f"delimiter {delimiter!r} not found in structure")
        end = index + len(delimiter)
        if max_bytes is not None and end - start > max_bytes:
            raise ProtocolError(f"delimiter {delimiter!r} appears after maximum {max_bytes} bytes")
        self.offset = end
        return self.data[start:end]


@dataclass(frozen=True, slots=True)
class StructCodec(Codec[dict[str, Any]]):
    fields: tuple[tuple[str, Codec[Any]], ...]
    strict: bool = True

    def __post_init__(self) -> None:
        names = [name for name, _ in self.fields]
        if len(set(names)) != len(names):
            raise ValueError("struct field names must be unique")
        if any(not isinstance(codec, Codec) for _, codec in self.fields):
            raise TypeError("all struct fields must be Codec instances")

    @property
    def size(self) -> int | None:
        sizes = [codec.size for _, codec in self.fields]
        if any(size is None for size in sizes):
            return None
        return sum(size for size in sizes if size is not None)

    def parse(self, data: bytes | bytearray | memoryview) -> dict[str, Any]:
        raw = _ensure_bytes(data, what="struct data")
        reader = _MemoryReader(raw)
        result: dict[str, Any] = {}
        for name, codec in self.fields:
            result[name] = codec.read(reader)
        if self.strict and reader.remaining:
            raise ProtocolError(f"struct has {reader.remaining} trailing byte(s)")
        return result

    def build(self, value: Mapping[str, Any]) -> bytes:
        if not isinstance(value, Mapping):
            raise TypeError("struct value must be a mapping")
        expected = {name for name, _ in self.fields}
        missing = expected - value.keys()
        extra = value.keys() - expected
        if missing:
            raise ConstraintError(f"missing struct field(s): {', '.join(sorted(missing))}")
        if self.strict and extra:
            raise ConstraintError(f"unknown struct field(s): {', '.join(sorted(extra))}")
        return b"".join(codec.build(value[name]) for name, codec in self.fields)

    def read(self, io: Readable, *, timeout: float | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, codec in self.fields:
            result[name] = codec.read(io, timeout=timeout)
        return result


@dataclass(frozen=True, slots=True)
class FrameCodec(Codec[T], Generic[T]):
    body: Codec[T]
    length: Codec[int]
    include_prefix: bool = False
    max_size: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.length.size is None:
            raise ValueError("frame length codec must have a fixed size")
        if self.max_size < 0:
            raise ValueError("max_size cannot be negative")

    @property
    def size(self) -> int | None:
        if self.body.size is None:
            return None
        return (self.length.size or 0) + self.body.size

    def _body_length(self, declared: int) -> int:
        if declared < 0:
            raise ProtocolError("frame length cannot be negative")
        body_length = declared - (self.length.size or 0) if self.include_prefix else declared
        if body_length < 0:
            raise ProtocolError("frame length is smaller than its prefix")
        if body_length > self.max_size:
            raise ProtocolError(f"frame body is {body_length} bytes, maximum is {self.max_size}")
        return body_length

    def parse(self, data: bytes | bytearray | memoryview) -> T:
        raw = _ensure_bytes(data, what="frame data")
        prefix_size = self.length.size or 0
        if len(raw) < prefix_size:
            raise ProtocolError("truncated frame length prefix")
        declared = self.length.parse(raw[:prefix_size])
        body_length = self._body_length(declared)
        expected = prefix_size + body_length
        if len(raw) != expected:
            raise ProtocolError(
                f"frame declares {body_length} body bytes but received {len(raw) - prefix_size}"
            )
        return self.body.parse(raw[prefix_size:])

    def build(self, value: T) -> bytes:
        encoded = self.body.build(value)
        if len(encoded) > self.max_size:
            raise ConstraintError(f"frame body is {len(encoded)} bytes, maximum is {self.max_size}")
        declared = len(encoded) + ((self.length.size or 0) if self.include_prefix else 0)
        return self.length.build(declared) + encoded

    def read(self, io: Readable, *, timeout: float | None = None) -> T:
        prefix_size = self.length.size or 0
        prefix = io.read_exact(prefix_size, timeout=timeout)
        declared = self.length.parse(prefix)
        body_length = self._body_length(declared)
        body = io.read_exact(body_length, timeout=timeout)
        return self.body.parse(body)


@dataclass(frozen=True, slots=True)
class XorCodec(Codec[T], Generic[T]):
    inner: Codec[T]
    key: bytes

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError("XOR key cannot be empty")

    @property
    def size(self) -> int | None:
        return self.inner.size

    def _transform(self, data: bytes) -> bytes:
        return bytes(byte ^ self.key[index % len(self.key)] for index, byte in enumerate(data))

    def parse(self, data: bytes | bytearray | memoryview) -> T:
        raw = _ensure_bytes(data, what="XOR data")
        return self.inner.parse(self._transform(raw))

    def build(self, value: T) -> bytes:
        return self._transform(self.inner.build(value))

    def read(self, io: Readable, *, timeout: float | None = None) -> T:
        if self.size is None:
            raise ProtocolError("XOR-wrapped variable-size codecs must be placed in a frame")
        return self.parse(io.read_exact(self.size, timeout=timeout))


def word(
    bits: int = 64,
    endian: Literal["little", "big"] = "little",
    *,
    signed: bool = False,
) -> WordCodec:
    return WordCodec(bits=bits, endian=endian, signed=signed)


def pointer(
    n: int = 8,
    *,
    width: int = 8,
    endian: Literal["little", "big"] = "little",
    extend: str | None = None,
) -> PointerCodec:
    return PointerCodec(encoded_size=n, width=width, endian=endian, extend=extend)


def hex_pointer(
    *,
    delimiter: bytes | None = b"\n",
    prefix: bytes = b"0x",
    maximum_digits: int = 16,
) -> DelimitedIntegerCodec:
    return DelimitedIntegerCodec(
        base=16,
        delimiter=delimiter,
        prefix=prefix,
        maximum_digits=maximum_digits,
        signed=False,
    )


def integer(
    *,
    base: int = 10,
    delimiter: bytes | None = b"\n",
    maximum_digits: int = 128,
    signed: bool = True,
) -> DelimitedIntegerCodec:
    return DelimitedIntegerCodec(
        base=base,
        delimiter=delimiter,
        maximum_digits=maximum_digits,
        signed=signed,
    )


def bytes_(
    n: int | None = None,
    *,
    until: bytes | None = None,
    drop: bool = True,
    max_size: int | None = None,
) -> BytesCodec:
    return BytesCodec(
        length=n,
        delimiter=until,
        drop_delimiter=drop,
        max_size=max_size,
    )


def cstring(*, encoding: str | None = None, max_size: int = 4096) -> CStringCodec:
    return CStringCodec(encoding=encoding, max_size=max_size)


def line_codec(
    *,
    terminator: bytes = b"\n",
    keepends: bool = False,
    max_size: int | None = 1024 * 1024,
) -> BytesCodec:
    """Return a byte-line codec, distinct from the input Channel named line."""

    return BytesCodec(
        delimiter=terminator,
        drop_delimiter=not keepends,
        max_size=max_size,
    )


def struct(*, strict: bool = True, **fields: Codec[Any]) -> StructCodec:
    return StructCodec(tuple(fields.items()), strict=strict)


def frame(
    body: Codec[T] | None = None,
    *,
    length: Codec[int] | None = None,
    include_prefix: bool = False,
    max_size: int = 16 * 1024 * 1024,
) -> FrameCodec[T]:
    selected_body = body if body is not None else cast(Codec[T], bytes_())
    return FrameCodec(
        body=selected_body,
        length=length if length is not None else word(16, "big"),
        include_prefix=include_prefix,
        max_size=max_size,
    )


def xor(inner: Codec[T], key: bytes | bytearray | memoryview | int) -> XorCodec[T]:
    if isinstance(key, int):
        if not 0 <= key <= 0xFF:
            raise ValueError("integer XOR key must be in range 0..255")
        encoded = bytes([key])
    else:
        encoded = _ensure_bytes(key, what="XOR key")
    return XorCodec(inner, encoded)


u8 = word(8)
u16le = word(16, "little")
u16be = word(16, "big")
u32le = word(32, "little")
u32be = word(32, "big")
u64le = word(64, "little")
u64be = word(64, "big")
