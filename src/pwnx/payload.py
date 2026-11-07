"""Structured payloads whose bytes retain a useful explanation.

Payload deliberately knows very little about exploit techniques. It is a small
layout engine that places raw bytes and pointer-sized symbolic words, resolves
them against a BindingContext, and reports where each byte came from.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Literal

from .errors import ConstraintError, UnresolvedValueError


def _describe(value: Any) -> str:
    describe = getattr(value, "describe", None)
    if callable(describe):
        return str(describe())
    return repr(value)


def _dependencies(value: Any) -> set[str]:
    dependencies = getattr(value, "dependencies", ())
    if callable(dependencies):
        dependencies = dependencies()
    return set(dependencies)


def _resolve(value: Any, context: Any | None) -> int:
    if isinstance(value, bool):
        raise ConstraintError("booleans are not valid payload words")
    if isinstance(value, int):
        return value
    if getattr(value, "is_literal", False):
        literal = getattr(value, "value", None)
        if isinstance(literal, int) and not isinstance(literal, bool):
            return literal
    if context is None:
        evaluate = getattr(value, "evaluate", None)
        if callable(evaluate) and not _dependencies(value):
            try:
                resolved = evaluate(None)
            except (AttributeError, TypeError, KeyError, UnresolvedValueError):
                pass
            else:
                if isinstance(resolved, int):
                    return resolved
        raise UnresolvedValueError(
            f"cannot serialize unresolved payload value {_describe(value)} without a BindingContext"
        )
    resolve = getattr(context, "resolve", None)
    if not callable(resolve):
        raise TypeError("payload context must provide resolve(value)")
    resolved = resolve(value)
    if hasattr(resolved, "value"):
        resolved = resolved.value
    if not isinstance(resolved, int) or isinstance(resolved, bool):
        raise ConstraintError(
            f"payload word {_describe(value)} resolved to non-integer {resolved!r}"
        )
    return resolved


@dataclass(frozen=True, slots=True)
class _Segment:
    offset: int
    size: int
    value: bytes | Any
    kind: str
    label: str
    region_id: str

    @property
    def end(self) -> int:
        return self.offset + self.size


class Payload:
    """An ordered, non-overlapping byte layout."""

    def __init__(
        self,
        data: bytes | bytearray | memoryview | None = None,
        *,
        fill: bytes = b"A",
        forbidden: bytes = b"",
        pointer_size: int = 8,
        byteorder: Literal["little", "big"] = "little",
        name: str | None = None,
        semantic_id: str | None = None,
    ) -> None:
        if not fill:
            raise ValueError("fill must not be empty")
        if pointer_size <= 0:
            raise ValueError("pointer_size must be positive")
        if byteorder not in {"little", "big"}:
            raise ValueError("byteorder must be 'little' or 'big'")
        self.fill = bytes(fill)
        self.forbidden = bytes(forbidden)
        self.pointer_size = pointer_size
        self.byteorder = byteorder
        self.name = name
        self.semantic_id = semantic_id
        self._segments: list[_Segment] = []
        self._region_counter = 0
        self._cursor = 0
        self._declared_size = 0
        if data:
            self.append(bytes(data), label="raw")

    @property
    def size(self) -> int:
        return max(
            self._declared_size,
            max((segment.end for segment in self._segments), default=0),
        )

    def __len__(self) -> int:
        return self.size

    @property
    def dependencies(self) -> set[str]:
        result: set[str] = set()
        for segment in self._segments:
            if segment.kind != "bytes":
                result.update(_dependencies(segment.value))
        return result

    def _check_range(self, offset: int, size: int, label: str = "payload region") -> None:
        if offset < 0 or size < 0:
            raise ValueError("payload offsets and sizes must be non-negative")
        end = offset + size
        for segment in self._segments:
            if offset < segment.end and segment.offset < end:
                raise ConstraintError(
                    f"payload region {label!r} at {offset:#x}..{end:#x} overlaps "
                    f"{segment.label!r} at {segment.offset:#x}..{segment.end:#x}"
                )

    def _next_region_id(self) -> str:
        self._region_counter += 1
        return f"r{self._region_counter:04d}"

    def place(
        self,
        offset: int,
        value: bytes | bytearray | memoryview | Any,
        *,
        label: str | None = None,
        word: bool = False,
        encoded: bool = False,
        region_id: str | None = None,
    ) -> "Payload":
        if word and encoded:
            raise ValueError("a payload region cannot be both word and encoded")
        if word:
            size = self.pointer_size
            kind = "word"
            stored: bytes | Any = value
        elif encoded:
            encoded_size: Any = getattr(value, "size", None)
            if not isinstance(encoded_size, int) or encoded_size < 0:
                raise TypeError("encoded payload regions require an integer size")
            size = encoded_size
            if not callable(getattr(value, "build", None)):
                raise TypeError("encoded payload regions require build(context)")
            kind = "encoded"
            stored = value
        else:
            if not isinstance(value, (bytes, bytearray, memoryview)):
                raise TypeError("raw payload regions require a bytes-like value")
            stored = bytes(value)
            size = len(stored)
            kind = "bytes"
        selected_label = label or _describe(value)
        self._check_range(offset, size, selected_label)
        self._segments.append(
            _Segment(
                offset,
                size,
                stored,
                kind,
                selected_label,
                region_id or self._next_region_id(),
            )
        )
        self._segments.sort(key=lambda segment: segment.offset)
        self._cursor = max(self._cursor, offset + size)
        return self

    def append(
        self,
        value: bytes | bytearray | memoryview | "Payload" | Any,
        *,
        label: str | None = None,
    ) -> "Payload":
        if isinstance(value, Payload):
            base = self._cursor
            for segment in value._segments:
                self._check_range(base + segment.offset, segment.size, label or segment.label)
                self._segments.append(
                    _Segment(
                        base + segment.offset,
                        segment.size,
                        segment.value,
                        segment.kind,
                        label or segment.label,
                        self._next_region_id(),
                    )
                )
            self._segments.sort(key=lambda segment: segment.offset)
            self._cursor = base + value.size
            self._declared_size = max(self._declared_size, self._cursor)
            self.forbidden = bytes(sorted(set(self.forbidden) | set(value.forbidden)))
            return self
        if isinstance(value, (bytes, bytearray, memoryview)):
            return self.place(self._cursor, value, label=label)
        if callable(getattr(value, "build", None)) and isinstance(
            getattr(value, "size", None), int
        ):
            return self.place(self._cursor, value, label=label, encoded=True)
        return self.word(value, label=label)

    def embed(
        self,
        offset: int,
        other: "Payload",
        *,
        label: str | None = None,
    ) -> "Payload":
        if not isinstance(other, Payload):
            raise TypeError("embed requires another Payload")
        for segment in other._segments:
            self._check_range(offset + segment.offset, segment.size, label or segment.label)
            self._segments.append(
                _Segment(
                    offset + segment.offset,
                    segment.size,
                    segment.value,
                    segment.kind,
                    label or segment.label,
                    self._next_region_id(),
                )
            )
        self._segments.sort(key=lambda segment: segment.offset)
        self._cursor = max(self._cursor, offset + other.size)
        self._declared_size = max(self._declared_size, self._cursor)
        self.forbidden = bytes(sorted(set(self.forbidden) | set(other.forbidden)))
        return self

    def word(self, value: Any, *, label: str | None = None) -> "Payload":
        return self.place(self._cursor, value, label=label, word=True)

    def pad(
        self,
        count: int,
        *,
        fill: bytes | None = None,
        label: str = "padding",
    ) -> "Payload":
        if count < 0:
            raise ValueError("padding count must be non-negative")
        byte = self.fill if fill is None else bytes(fill)
        if not byte:
            raise ValueError("padding fill must not be empty")
        if count:
            self.place(
                self._cursor,
                (byte * ((count + len(byte) - 1) // len(byte)))[:count],
                label=label,
            )
        return self

    def pad_to(
        self,
        offset: int,
        *,
        fill: bytes | None = None,
        label: str = "padding",
    ) -> "Payload":
        if offset < self._cursor:
            raise ConstraintError(
                f"cannot pad backwards from {self._cursor:#x} to {offset:#x}"
            )
        return self.pad(offset - self._cursor, fill=fill, label=label)

    def extend(self, values: Iterable[Any]) -> "Payload":
        for value in values:
            self.append(value)
        return self

    def ensure_size(self, size: int) -> "Payload":
        if size < self.size:
            raise ConstraintError(
                f"declared payload length {size} is smaller than current size {self.size}"
            )
        self._declared_size = size
        self._cursor = max(self._cursor, size)
        return self

    def build_unchecked(self, context: Any | None = None) -> bytes:
        output = bytearray(
            (self.fill * ((self.size + len(self.fill) - 1) // len(self.fill)))[
                : self.size
            ]
        )
        for segment in self._segments:
            if segment.kind == "bytes":
                raw = segment.value
            elif segment.kind == "word":
                integer = _resolve(segment.value, context)
                if not 0 <= integer < 1 << (8 * segment.size):
                    raise ConstraintError(
                        f"{segment.label}={integer:#x} does not fit in "
                        f"{segment.size * 8} bits"
                    )
                raw = integer.to_bytes(segment.size, self.byteorder)
            else:
                builder = getattr(segment.value, "build")
                raw = builder(context)
                if not isinstance(raw, bytes):
                    raise ConstraintError(
                        f"{segment.label} build() returned {type(raw).__name__}, expected bytes"
                    )
                if len(raw) != segment.size:
                    raise ConstraintError(
                        f"{segment.label} built {len(raw)} bytes, expected {segment.size}"
                    )
            output[segment.offset : segment.end] = raw
        return bytes(output)

    def validate_bytes(self, result: bytes) -> bytes:
        violations = sorted(set(result) & set(self.forbidden))
        if violations:
            rendered = ", ".join(f"{byte:#04x}" for byte in violations)
            raise ConstraintError(f"payload contains forbidden byte(s): {rendered}")
        return result

    def build(self, context: Any | None = None) -> bytes:
        return self.validate_bytes(self.build_unchecked(context))

    def layout(self, context: Any | None = None) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        cursor = 0
        for segment in self._segments:
            if segment.offset > cursor:
                rows.append(
                    {
                        "id": f"gap:{cursor:04x}-{segment.offset:04x}",
                        "offset": cursor,
                        "size": segment.offset - cursor,
                        "end": segment.offset,
                        "kind": "gap",
                        "label": "implicit fill",
                        "value": self.fill.hex(),
                    }
                )
            if segment.kind == "bytes":
                value: Any = segment.value.hex()
            elif segment.kind == "word":
                try:
                    value = f"{_resolve(segment.value, context):#x}"
                except UnresolvedValueError:
                    value = _describe(segment.value)
            else:
                if context is None and _dependencies(segment.value):
                    value = _describe(segment.value)
                else:
                    try:
                        builder = getattr(segment.value, "build")
                        value = builder(context).hex()
                    except UnresolvedValueError:
                        value = _describe(segment.value)
            rows.append(
                {
                    "id": segment.region_id,
                    "offset": segment.offset,
                    "size": segment.size,
                    "end": segment.end,
                    "kind": segment.kind,
                    "label": segment.label,
                    "value": value,
                    "dependencies": sorted(_dependencies(segment.value))
                    if segment.kind != "bytes"
                    else [],
                }
            )
            cursor = segment.end
        return rows

    def _resized_replace(
        self,
        offset: int,
        size: int,
        data: bytes,
        *,
        label: str,
        materialized: bytes | None = None,
    ) -> "Payload":
        """Materialize a static resize while retaining unaffected region identities."""

        original = self.build() if materialized is None else bytes(materialized)
        old_end = offset + size
        delta = len(data) - size
        changed = original[:offset] + data + original[old_end:]
        result = Payload(
            fill=self.fill,
            forbidden=self.forbidden,
            pointer_size=self.pointer_size,
            byteorder=self.byteorder,
            name=self.name,
            semantic_id=self.semantic_id,
        )
        result._region_counter = self._region_counter

        for segment in self._segments:
            if segment.end <= offset:
                result.place(
                    segment.offset,
                    original[segment.offset : segment.end],
                    label=segment.label,
                    region_id=segment.region_id,
                )
                continue
            if segment.offset >= old_end:
                result.place(
                    segment.offset + delta,
                    original[segment.offset : segment.end],
                    label=segment.label,
                    region_id=segment.region_id,
                )
                continue

            left_end = min(segment.end, offset)
            if segment.offset < left_end:
                result.place(
                    segment.offset,
                    original[segment.offset:left_end],
                    label=segment.label,
                    region_id=segment.region_id,
                )
            right_start = max(segment.offset, old_end)
            if right_start < segment.end:
                right_id = (
                    f"{segment.region_id}:right"
                    if segment.offset < left_end
                    else segment.region_id
                )
                result.place(
                    right_start + delta,
                    original[right_start : segment.end],
                    label=segment.label,
                    region_id=right_id,
                )

        if data:
            result.place(
                offset,
                data,
                label=label,
                region_id=result._next_region_id(),
            )
        result.ensure_size(len(changed))
        return result

    def copy(self) -> "Payload":
        result = Payload(
            fill=self.fill,
            forbidden=self.forbidden,
            pointer_size=self.pointer_size,
            byteorder=self.byteorder,
            name=self.name,
            semantic_id=self.semantic_id,
        )
        result._segments = list(self._segments)
        result._region_counter = self._region_counter
        result._cursor = self._cursor
        result._declared_size = self._declared_size
        return result

    def __add__(self, other: Any) -> "Payload":
        return self.copy().append(other)

    def __repr__(self) -> str:
        dependencies = ", ".join(sorted(self.dependencies))
        suffix = f", dependencies=[{dependencies}]" if dependencies else ""
        return f"Payload(size={self.size}{suffix})"
