"""Explicit packing, cyclic patterns, sparse layouts, and byte presentation.

Unlike ambient-context packing APIs, every integer width and byte order is
carried by the value or supplied explicitly. Symbolic values remain deferred
and retain their dependencies until a Payload is built for one process.
"""

from __future__ import annotations

import string
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from .errors import ConstraintError, UnresolvedValueError
from .expressions import Expr
from .payload import Payload

Endian = Literal["little", "big"]
DEFAULT_ALPHABET = string.ascii_lowercase.encode()
DEFAULT_CYCLIC_WORK = 16 * 1024 * 1024


def _validate_width(bits: int) -> int:
    if not isinstance(bits, int) or bits <= 0 or bits % 8:
        raise ValueError("bit width must be a positive multiple of eight")
    return bits // 8


def _pack_int(value: int, bits: int, endian: Endian, signed: bool) -> bytes:
    size = _validate_width(bits)
    if endian not in {"little", "big"}:
        raise ValueError("endian must be 'little' or 'big'")
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"packed value must be an integer, got {type(value).__name__}")
    minimum = -(1 << (bits - 1)) if signed else 0
    maximum = (1 << (bits - (1 if signed else 0))) - 1
    if not minimum <= value <= maximum:
        kind = "signed" if signed else "unsigned"
        raise ConstraintError(
            f"{value} does not fit in a {kind} {bits}-bit integer"
        )
    return value.to_bytes(size, endian, signed=signed)


@dataclass(frozen=True, slots=True)
class Packed:
    """A fixed-width serialized value which may depend on runtime facts."""

    value: Any
    bits: int = 64
    endian: Endian = "little"
    signed: bool = False
    label: str | None = None

    def __post_init__(self) -> None:
        _validate_width(self.bits)
        if self.endian not in {"little", "big"}:
            raise ValueError("endian must be 'little' or 'big'")

    @property
    def size(self) -> int:
        return self.bits // 8

    @property
    def dependencies(self) -> set[str]:
        return set(getattr(self.value, "dependencies", ()))

    def describe(self) -> str:
        source = self.label
        if source is None:
            method = getattr(self.value, "describe", None)
            source = method() if callable(method) else repr(self.value)
        sign = "signed" if self.signed else "unsigned"
        return f"{source} as {sign} {self.bits}-bit {self.endian}-endian"

    def build(self, context: Any | None = None) -> bytes:
        value = self.value
        if isinstance(value, Expr):
            if value.is_literal:
                value = value.value
            elif context is None:
                raise UnresolvedValueError(
                    f"cannot pack unresolved {value.describe()} without a BindingContext"
                )
            else:
                value = context.resolve(value)
        elif not isinstance(value, int):
            if context is None:
                raise UnresolvedValueError(
                    f"cannot pack unresolved {self.describe()} without a BindingContext"
                )
            value = context.resolve(value)
        if hasattr(value, "value"):
            value = value.value
        return _pack_int(value, self.bits, self.endian, self.signed)

    def __bytes__(self) -> bytes:
        return self.build()


def pack(
    value: Any,
    bits: int = 64,
    endian: Endian = "little",
    signed: bool | None = None,
) -> bytes | Packed:
    """Pack a concrete integer or defer a symbolic fixed-width value."""

    inferred_signed = bool(isinstance(value, int) and value < 0)
    signed = inferred_signed if signed is None else signed
    if isinstance(value, int) and not isinstance(value, bool):
        return _pack_int(value, bits, endian, signed)
    return Packed(value, bits, endian, signed)


def unpack(
    data: bytes | bytearray | memoryview,
    bits: int | None = None,
    endian: Endian = "little",
    signed: bool = False,
) -> int:
    raw = bytes(data)
    bits = len(raw) * 8 if bits is None else bits
    size = _validate_width(bits)
    if len(raw) != size:
        raise ValueError(f"expected {size} bytes, received {len(raw)}")
    if endian not in {"little", "big"}:
        raise ValueError("endian must be 'little' or 'big'")
    return int.from_bytes(raw, endian, signed=signed)


def unpack_many(
    data: bytes | bytearray | memoryview,
    bits: int = 64,
    endian: Endian = "little",
    signed: bool = False,
) -> list[int]:
    raw = bytes(data)
    size = _validate_width(bits)
    if len(raw) % size:
        raise ValueError(f"data length must be a multiple of {size}")
    return [
        unpack(raw[offset : offset + size], bits, endian, signed)
        for offset in range(0, len(raw), size)
    ]


def p8(value: Any, *, signed: bool | None = None):
    return pack(value, 8, "little", signed)


def p16(value: Any, *, endian: Endian = "little", signed: bool | None = None):
    return pack(value, 16, endian, signed)


def p32(value: Any, *, endian: Endian = "little", signed: bool | None = None):
    return pack(value, 32, endian, signed)


def p64(value: Any, *, endian: Endian = "little", signed: bool | None = None):
    return pack(value, 64, endian, signed)


def u8(data, *, signed: bool = False):
    return unpack(data, 8, "little", signed)


def u16(data, *, endian: Endian = "little", signed: bool = False):
    return unpack(data, 16, endian, signed)


def u32(data, *, endian: Endian = "little", signed: bool = False):
    return unpack(data, 32, endian, signed)


def u64(data, *, endian: Endian = "little", signed: bool = False):
    return unpack(data, 64, endian, signed)


def de_bruijn(
    alphabet: bytes | bytearray | str = DEFAULT_ALPHABET,
    n: int = 4,
):
    if isinstance(alphabet, str):
        alphabet = alphabet.encode()
    alphabet = bytes(alphabet)
    if not alphabet:
        raise ValueError("cyclic alphabet cannot be empty")
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("cyclic alphabet symbols must be unique")
    if n <= 0:
        raise ValueError("cyclic subsequence size must be positive")
    indices = [0] * (len(alphabet) * n)

    def generate(t: int, period: int):
        if t > n:
            if n % period == 0:
                for index in range(1, period + 1):
                    yield alphabet[indices[index]]
            return
        indices[t] = indices[t - period]
        yield from generate(t + 1, period)
        for symbol in range(indices[t - period] + 1, len(alphabet)):
            indices[t] = symbol
            yield from generate(t + 1, t)

    return generate(1, 1)


def cyclic(
    length: int | None = None,
    alphabet: bytes | bytearray | str = DEFAULT_ALPHABET,
    n: int = 4,
) -> bytes:
    encoded = alphabet.encode() if isinstance(alphabet, str) else bytes(alphabet)
    maximum = len(encoded) ** n
    length = maximum if length is None else length
    if length < 0:
        raise ValueError("cyclic length cannot be negative")
    if length > maximum:
        raise ValueError(
            f"cannot create {length} bytes with alphabet={len(encoded)} and n={n}"
        )
    if length > DEFAULT_CYCLIC_WORK:
        raise ConstraintError(
            f"cyclic request would generate {length} bytes; explicit chunks are "
            f"limited to {DEFAULT_CYCLIC_WORK} bytes"
        )
    output = bytearray()
    for value in de_bruijn(encoded, n):
        if len(output) == length:
            break
        output.append(value)
    return bytes(output)


def cyclic_find(
    subsequence: bytes | bytearray | memoryview | str | int,
    alphabet: bytes | bytearray | str = DEFAULT_ALPHABET,
    n: int = 4,
    endian: Endian = "little",
    max_work: int = DEFAULT_CYCLIC_WORK,
) -> int:
    if isinstance(subsequence, int):
        if subsequence < 0:
            raise ValueError("cyclic integer cannot be negative")
        mask = (1 << (n * 8)) - 1
        if endian == "little":
            subsequence &= mask
        else:
            while subsequence > mask:
                subsequence >>= 8
        needle = subsequence.to_bytes(n, endian)
    elif isinstance(subsequence, str):
        needle = subsequence.encode()
    else:
        needle = bytes(subsequence)
    needle = needle[:n]
    if not needle:
        return -1
    encoded = alphabet.encode() if isinstance(alphabet, str) else bytes(alphabet)
    if any(value not in encoded for value in needle):
        return -1
    if max_work <= 0:
        raise ValueError("max_work must be positive")
    domain = len(encoded) ** n
    generator = de_bruijn(encoded, n)
    prefix = bytearray()
    window = bytearray()
    examined = 0
    for byte in generator:
        if len(prefix) < n - 1:
            prefix.append(byte)
        window.append(byte)
        if len(window) > len(needle):
            del window[0]
        if len(window) == len(needle) and bytes(window) == needle:
            return examined - len(needle) + 1
        examined += 1
        if examined >= max_work and examined < domain:
            raise ConstraintError(
                f"cyclic search domain is {domain} bytes and exceeds "
                f"max_work={max_work}; increase max_work explicitly"
            )
    for byte in prefix:
        window.append(byte)
        if len(window) > len(needle):
            del window[0]
        if len(window) == len(needle) and bytes(window) == needle:
            return examined - len(needle) + 1
        examined += 1
    return -1


class CrashOffset(int):
    """An integer offset carrying the pattern evidence that established it."""

    crash: bytes | int
    alphabet: bytes
    n: int
    endian: Endian

    def __new__(
        cls,
        value: int,
        *,
        crash: bytes | int,
        alphabet: bytes,
        n: int,
        endian: Endian,
    ):
        obj = int.__new__(cls, value)
        obj.crash = crash
        obj.alphabet = alphabet
        obj.n = n
        obj.endian = endian
        return obj

    def describe(self) -> str:
        rendered = hex(self.crash) if isinstance(self.crash, int) else repr(self.crash)
        return (
            f"offset {int(self)} recovered from {rendered} "
            f"(alphabet={self.alphabet!r}, n={self.n}, {self.endian})"
        )


def offset_from(
    crash: bytes | bytearray | memoryview | str | int,
    *,
    alphabet: bytes | bytearray | str = DEFAULT_ALPHABET,
    n: int = 4,
    endian: Endian = "little",
) -> CrashOffset:
    encoded = alphabet.encode() if isinstance(alphabet, str) else bytes(alphabet)
    offset = cyclic_find(crash, encoded, n, endian)
    if offset < 0:
        raise ConstraintError("crash value does not occur in the cyclic pattern")
    original: bytes | int
    if isinstance(crash, int):
        original = crash
    elif isinstance(crash, str):
        original = crash.encode()
    else:
        original = bytes(crash)
    return CrashOffset(
        offset, crash=original, alphabet=encoded, n=n, endian=endian
    )


class CyclicGenerator:
    def __init__(
        self,
        alphabet: bytes | bytearray | str = DEFAULT_ALPHABET,
        n: int = 4,
        max_size: int = DEFAULT_CYCLIC_WORK,
    ):
        self.alphabet = alphabet.encode() if isinstance(alphabet, str) else bytes(alphabet)
        self.n = n
        domain = len(self.alphabet) ** self.n
        if domain > max_size:
            raise ConstraintError(
                f"stateful cyclic generator would allocate {domain} bytes; "
                f"max_size is {max_size}"
            )
        self._pattern = cyclic(None, self.alphabet, self.n)
        self._offset = 0

    def get(self, length: int | None = None) -> bytes:
        if length is None:
            length = len(self._pattern) - self._offset
        if length < 0 or self._offset + length > len(self._pattern):
            raise ValueError("cyclic generator is exhausted")
        result = self._pattern[self._offset : self._offset + length]
        self._offset += length
        return result

    def find(self, subsequence: bytes | int, *, endian: Endian = "little") -> int:
        return cyclic_find(subsequence, self.alphabet, self.n, endian)


def cyclic_metasploit(
    length: int | None = None,
    sets: Sequence[bytes | str] = (
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
    ),
) -> bytes:
    encoded = tuple(item.encode() if isinstance(item, str) else bytes(item) for item in sets)
    if not encoded or any(not item for item in encoded):
        raise ValueError("metasploit pattern sets cannot be empty")
    maximum = len(encoded) * math.prod(len(item) for item in encoded)
    length = maximum if length is None else length
    if not 0 <= length <= maximum:
        raise ValueError(f"metasploit pattern length must be in range 0..{maximum}")
    output = bytearray()
    offsets = [0] * len(encoded)
    while len(output) < length:
        for alphabet, index in zip(encoded, offsets, strict=True):
            if len(output) == length:
                break
            output.append(alphabet[index])
        for position in reversed(range(len(offsets))):
            offsets[position] = (offsets[position] + 1) % len(encoded[position])
            if offsets[position]:
                break
        else:
            break
    return bytes(output)


def cyclic_metasploit_find(
    subsequence: bytes | bytearray | memoryview | str | int,
    *,
    sets: Sequence[bytes | str] = (
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
    ),
    endian: Endian = "little",
) -> int:
    if isinstance(subsequence, int):
        if subsequence < 0:
            raise ValueError("cyclic integer cannot be negative")
        width = max(1, (subsequence.bit_length() + 7) // 8)
        needle = subsequence.to_bytes(width, endian)
    elif isinstance(subsequence, str):
        needle = subsequence.encode()
    else:
        needle = bytes(subsequence)
    return cyclic_metasploit(None, sets).find(needle)


def _marker_offset(marker: bytes | str, filler: bytes, default_cyclic: bool, n: int) -> int:
    needle = marker.encode() if isinstance(marker, str) else marker
    offset = cyclic_find(needle, n=n) if default_cyclic else filler.find(needle)
    if offset < 0:
        raise ConstraintError(f"layout marker {needle!r} was not found in filler")
    return offset


def _measure(
    value: Any,
    *,
    word_size: int,
    filler: bytes,
    default_cyclic: bool,
    cyclic_n: int,
) -> int:
    if isinstance(value, Payload):
        return value.size
    if isinstance(value, Packed):
        return value.size
    if isinstance(value, (Expr, int)) or getattr(value, "dependencies", None):
        return word_size
    if isinstance(value, str):
        return len(value.encode())
    if isinstance(value, (bytes, bytearray, memoryview)):
        return len(value)
    if isinstance(value, Mapping):
        extent = 0
        for key, item in value.items():
            relative = (
                key
                if isinstance(key, int)
                else _marker_offset(key, filler, default_cyclic, cyclic_n)
            )
            extent = max(
                extent,
                relative
                + _measure(
                    item,
                    word_size=word_size,
                    filler=filler,
                    default_cyclic=default_cyclic,
                    cyclic_n=cyclic_n,
                ),
            )
        return extent
    if isinstance(value, Sequence):
        return sum(
            _measure(
                item,
                word_size=word_size,
                filler=filler,
                default_cyclic=default_cyclic,
                cyclic_n=cyclic_n,
            )
            for item in value
        )
    raise TypeError(f"cannot place {type(value).__name__} in a payload layout")


def _place(
    output: Payload,
    offset: int,
    value: Any,
    *,
    word_size: int,
    endian: Endian,
    signed: bool,
    label: str,
    filler: bytes,
    default_cyclic: bool,
    cyclic_n: int,
) -> int:
    if isinstance(value, Payload):
        output.embed(offset, value, label=label)
        return offset + value.size
    if isinstance(value, Packed):
        output.place(offset, value, label=label, encoded=True)
        return offset + value.size
    if isinstance(value, (Expr, int)) or getattr(value, "dependencies", None):
        packed = Packed(value, word_size * 8, endian, signed, label)
        output.place(offset, packed, label=label, encoded=True)
        return offset + packed.size
    if isinstance(value, str):
        raw = value.encode()
        output.place(offset, raw, label=label)
        return offset + len(raw)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        output.place(offset, raw, label=label)
        return offset + len(raw)
    if isinstance(value, Mapping):
        end = offset
        for key, item in value.items():
            relative = (
                key
                if isinstance(key, int)
                else _marker_offset(key, filler, default_cyclic, cyclic_n)
            )
            end = max(
                end,
                _place(
                    output,
                    offset + relative,
                    item,
                    word_size=word_size,
                    endian=endian,
                    signed=signed,
                    label=f"{label}[{key!r}]",
                    filler=filler,
                    default_cyclic=default_cyclic,
                    cyclic_n=cyclic_n,
                ),
            )
        return end
    if isinstance(value, Sequence):
        cursor = offset
        for index, item in enumerate(value):
            cursor = _place(
                output,
                cursor,
                item,
                word_size=word_size,
                endian=endian,
                signed=signed,
                label=f"{label}[{index}]",
                filler=filler,
                default_cyclic=default_cyclic,
                cyclic_n=cyclic_n,
            )
        return cursor
    raise TypeError(f"cannot place {type(value).__name__} in a payload layout")


def layout(
    *values: Any,
    target: Any | None = None,
    word_size: int | None = None,
    endian: Endian | None = None,
    signed: bool = False,
    filler: bytes | bytearray | str | None = None,
    length: int | None = None,
    forbidden: bytes = b"",
    cyclic_n: int = 4,
) -> Payload:
    """Construct a labelled sparse Payload from nested values."""

    if target is not None:
        word_size = word_size or getattr(target, "pointer_size", None)
        endian = endian or getattr(target, "endian", None)
    word_size = 8 if word_size is None else word_size
    endian = "little" if endian is None else endian
    if word_size <= 0:
        raise ValueError("word_size must be positive")
    default_cyclic = filler is None
    if filler is None:
        # A short probe is enough to resolve ordinary literal markers. Marker
        # lookup itself uses the full streaming cyclic domain.
        probe = cyclic(min(4096, len(DEFAULT_ALPHABET) ** cyclic_n), n=cyclic_n)
        required = sum(
            _measure(
                value,
                word_size=word_size,
                filler=probe,
                default_cyclic=True,
                cyclic_n=cyclic_n,
            )
            for value in values
        )
        required = max(required, length or 0, 1)
        filler_bytes = cyclic(required, n=cyclic_n)
    elif isinstance(filler, str):
        filler_bytes = filler.encode()
    else:
        filler_bytes = bytes(filler)
    if not filler_bytes:
        raise ValueError("layout filler cannot be empty")
    output = Payload(
        fill=filler_bytes,
        forbidden=forbidden,
        pointer_size=word_size,
        byteorder=endian,
    )
    cursor = 0
    for index, value in enumerate(values):
        cursor = _place(
            output,
            cursor,
            value,
            word_size=word_size,
            endian=endian,
            signed=signed,
            label=f"layout[{index}]",
            filler=filler_bytes,
            default_cyclic=default_cyclic,
            cyclic_n=cyclic_n,
        )
    if length is not None:
        output.ensure_size(length)
    return output


def flat(*values: Any, **kwargs: Any) -> bytes | Payload:
    """Return bytes for a concrete layout and Payload for a symbolic layout."""

    result = layout(*values, **kwargs)
    return result if result.dependencies else result.build()


def fit(*values: Any, **kwargs: Any) -> bytes | Payload:
    return flat(*values, **kwargs)


def dd(
    destination: bytes | bytearray,
    source: bytes | bytearray | memoryview,
    *,
    count: int = 0,
    skip: int = 0,
    seek: int = 0,
    truncate: bool = False,
) -> bytes | bytearray:
    if min(count, skip, seek) < 0:
        raise ValueError("count, skip, and seek must be non-negative")
    src = bytes(source)[seek:]
    if count:
        src = src[:count]
    mutable = bytearray(destination)
    required = skip + len(src)
    if required > len(mutable):
        mutable.extend(b"\x00" * (required - len(mutable)))
    mutable[skip:required] = src
    if truncate:
        del mutable[required:]
    return mutable if isinstance(destination, bytearray) else bytes(mutable)


def xor_bytes(
    data: bytes | bytearray | memoryview,
    *keys: bytes | bytearray | memoryview | int,
) -> bytes:
    raw = bytes(data)
    encoded_keys = [
        bytes([key]) if isinstance(key, int) else bytes(key) for key in keys
    ]
    if any(not key for key in encoded_keys):
        raise ValueError("XOR keys cannot be empty")
    if any(isinstance(key, int) and not 0 <= key <= 255 for key in keys):
        raise ValueError("integer XOR keys must be in range 0..255")
    result = bytearray(raw)
    for index in range(len(result)):
        for key in encoded_keys:
            result[index] ^= key[index % len(key)]
    return bytes(result)


def bits(data: bytes | bytearray | memoryview | int, *, endian: Endian = "big") -> list[int]:
    if endian not in {"little", "big"}:
        raise ValueError("endian must be 'little' or 'big'")
    if isinstance(data, int):
        if data < 0:
            raise ValueError("negative integers require an explicit two's-complement width")
        width = max(1, (data.bit_length() + 7) // 8)
        raw = data.to_bytes(width, endian)
    else:
        raw = bytes(data)
    result: list[int] = []
    positions = range(7, -1, -1) if endian == "big" else range(8)
    for value in raw:
        result.extend((value >> position) & 1 for position in positions)
    return result


def unbits(values: Iterable[int], *, endian: Endian = "big") -> bytes:
    sequence = list(values)
    if any(value not in {0, 1} for value in sequence):
        raise ValueError("bits must contain only zero and one")
    sequence.extend([0] * (-len(sequence) % 8))
    output = bytearray()
    for offset in range(0, len(sequence), 8):
        chunk = sequence[offset : offset + 8]
        if endian == "little":
            chunk = list(reversed(chunk))
        value = 0
        for bit in chunk:
            value = (value << 1) | bit
        output.append(value)
    return bytes(output)


def rol(value: Any, count: int, bits: int | None = None):
    if isinstance(value, bytes):
        if not value:
            return value
        amount = count % len(value)
        return value[amount:] + value[:amount]
    if isinstance(value, str):
        if not value:
            return value
        amount = count % len(value)
        return value[amount:] + value[:amount]
    if isinstance(value, list):
        if not value:
            return value
        amount = count % len(value)
        return value[amount:] + value[:amount]
    if isinstance(value, tuple):
        if not value:
            return value
        amount = count % len(value)
        return value[amount:] + value[:amount]
    if not isinstance(value, int) or value < 0:
        raise ValueError("rotation value must be a non-negative integer")
    bits = max(8, ((value.bit_length() + 7) // 8) * 8) if bits is None else bits
    if bits <= 0:
        raise ValueError("rotation width must be positive")
    count %= bits
    mask = (1 << bits) - 1
    return ((value << count) | (value >> (bits - count))) & mask


def ror(value: Any, count: int, bits: int | None = None):
    if isinstance(value, (bytes, str, list, tuple)):
        return rol(value, -count, bits)
    if not isinstance(value, int) or value < 0:
        raise ValueError("rotation value must be a non-negative integer")
    bits = max(8, ((value.bit_length() + 7) // 8) * 8) if bits is None else bits
    count %= bits
    return rol(value, bits - count, bits)


def enhex(data: bytes | bytearray | memoryview) -> str:
    return bytes(data).hex()


def unhex(value: str | bytes) -> bytes:
    text = value.decode() if isinstance(value, bytes) else value
    try:
        return bytes.fromhex("".join(text.split()))
    except ValueError as error:
        raise ValueError("invalid hexadecimal input") from error


def hexdump(
    data: bytes | bytearray | memoryview,
    *,
    width: int = 16,
    offset: int = 0,
    compact: bool = True,
) -> str:
    raw = bytes(data)
    if width <= 0 or offset < 0:
        raise ValueError("width must be positive and offset non-negative")
    lines: list[str] = []
    previous: bytes | None = None
    repeated = False
    for position in range(0, len(raw), width):
        chunk = raw[position : position + width]
        if compact and len(chunk) == width and chunk == previous:
            if not repeated:
                lines.append("*")
                repeated = True
            continue
        repeated = False
        previous = chunk
        split = width // 2
        left = " ".join(f"{value:02x}" for value in chunk[:split])
        right = " ".join(f"{value:02x}" for value in chunk[split:])
        hex_column = f"{left:<{max(0, split * 3 - 1)}}  {right:<{max(0, (width-split) * 3 - 1)}}"
        printable = "".join(chr(value) if 32 <= value < 127 else "." for value in chunk)
        lines.append(f"{offset + position:08x}  {hex_column}  |{printable}|")
    lines.append(f"{offset + len(raw):08x}")
    return "\n".join(lines)
