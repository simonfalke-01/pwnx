"""Immutable competition-facing byte construction over :class:`Payload`."""

from __future__ import annotations

import hashlib
import builtins
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Callable, Literal

from .codecs import Codec
from .errors import ConstraintError, PlanningError, UnresolvedValueError
from .expressions import Expr
from .packing import hexdump as render_hexdump
from .payload import Payload


def _dependencies(value: Any) -> set[str]:
    result = getattr(value, "dependencies", ())
    return set(result() if callable(result) else result)


def _freeze_layout_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_layout_value(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_layout_value(item) for item in value)
    if isinstance(value, set):
        return frozenset(_freeze_layout_value(item) for item in value)
    return value


def _copy_layout_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _copy_layout_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, frozenset, set)):
        return [_copy_layout_value(item) for item in value]
    return value


def _resolve_integer(value: Any, context: Any | None) -> int:
    if isinstance(value, bool):
        raise ConstraintError("booleans are not bytecraft integers")
    if isinstance(value, int):
        return value
    if context is None:
        missing = ", ".join(sorted(_dependencies(value))) or repr(value)
        raise UnresolvedValueError(
            f"bytecraft value requires runtime fact(s): {missing}"
        )
    resolved = context.resolve(value)
    if not isinstance(resolved, int) or isinstance(resolved, bool):
        raise ConstraintError(f"bytecraft integer resolved to {resolved!r}")
    return resolved


@dataclass(frozen=True, slots=True)
class _IntegerEncoding:
    value: Any
    bits: int
    endian: Literal["little", "big"]
    signed: bool

    @property
    def size(self) -> int:
        return self.bits // 8

    @property
    def dependencies(self) -> set[str]:
        return _dependencies(self.value)

    def build(self, context: Any | None = None) -> bytes:
        value = _resolve_integer(self.value, context)
        low = -(1 << (self.bits - 1)) if self.signed else 0
        high = (1 << (self.bits - (1 if self.signed else 0))) - 1
        if not low <= value <= high:
            raise ConstraintError(
                f"integer {value} does not fit {'signed ' if self.signed else ''}{self.bits} bits"
            )
        return value.to_bytes(self.size, self.endian, signed=self.signed)

    def describe(self) -> str:
        return f"{self.bits}-bit {self.endian} integer"


@dataclass(frozen=True, slots=True)
class _PointerEncoding:
    value: Any
    width: int
    pointer_size: int
    endian: Literal["little", "big"]

    @property
    def size(self) -> int:
        return self.width

    @property
    def dependencies(self) -> set[str]:
        return _dependencies(self.value)

    def build(self, context: Any | None = None) -> bytes:
        value = _resolve_integer(self.value, context)
        if not 0 <= value < 1 << (self.pointer_size * 8):
            raise ConstraintError(
                f"pointer {value:#x} does not fit {self.pointer_size * 8} bits"
            )
        full = value.to_bytes(self.pointer_size, self.endian)
        return full[: self.width] if self.endian == "little" else full[: self.width]

    def describe(self) -> str:
        return f"{self.width}-byte {self.endian} pointer"


@dataclass(frozen=True, slots=True)
class _CodecEncoding:
    codec: Codec[Any]
    value: Any
    size: int

    @property
    def dependencies(self) -> set[str]:
        return _dependencies(self.value)

    def build(self, context: Any | None = None) -> bytes:
        value = context.resolve(self.value) if context is not None and _dependencies(self.value) else self.value
        raw = self.codec.build(value)
        if len(raw) != self.size:
            raise ConstraintError(
                f"{type(self.codec).__name__} built {len(raw)} bytes, expected {self.size}"
            )
        return raw

    def describe(self) -> str:
        return type(self.codec).__name__


@dataclass(frozen=True, slots=True)
class _Patch:
    offset: int
    size: int
    data: bytes
    label: str
    reason: str
    materialized: bool = False
    layout_size: int | None = None


@dataclass(frozen=True, slots=True)
class Craft:
    name: str
    endian: Literal["little", "big"]
    pointer_size: int
    fill: bytes
    _payload: Payload = field(repr=False, compare=False)
    _cursor: int = 0
    _patches: tuple[_Patch, ...] = ()
    _min_size: int | None = None
    _max_size: int | None = None
    _exact_size: int | None = None
    _encodings: tuple[str, ...] = ()
    _predicates: tuple[tuple[Callable[[bytes], bool], str], ...] = field(
        default=(), repr=False, compare=False
    )
    _constraints: tuple[Any, ...] = field(default=(), repr=False, compare=False)

    @classmethod
    def create(
        cls,
        name: str,
        *,
        endian: Literal["little", "big"] = "little",
        pointer_size: int = 8,
        fill: bytes = bytes([0]),
    ) -> "Craft":
        if not name:
            raise ValueError("craft name must not be empty")
        payload = Payload(
            fill=fill,
            pointer_size=pointer_size,
            byteorder=endian,
            name=name,
            semantic_id=f"craft:{name}",
        )
        return cls(name, endian, pointer_size, bytes(fill), payload)

    @property
    def semantic_id(self) -> str:
        return self._payload.semantic_id or f"craft:{self.name}"

    @property
    def defer_dependencies(self) -> bool:
        return True

    @property
    def dependencies(self) -> set[str]:
        return set(self._payload.dependencies)

    @property
    def size(self) -> int:
        return self._payload.size

    def _place(
        self,
        value: Any,
        *,
        size: int,
        label: str,
        encoded: bool = False,
    ) -> "Craft":
        payload = self._payload.copy()
        payload.place(
            self._cursor,
            value,
            label=label,
            encoded=encoded,
        )
        return replace(self, _payload=payload, _cursor=self._cursor + size)

    def raw(self, data: bytes | bytearray | memoryview, *, label: str = "raw") -> "Craft":
        raw = bytes(data)
        return self._place(raw, size=len(raw), label=label)

    def pad(self, count: int, *, fill: bytes | None = None, label: str = "padding") -> "Craft":
        if count < 0:
            raise ValueError("padding count must be non-negative")
        selected = self.fill if fill is None else bytes(fill)
        if not selected:
            raise ValueError("padding fill must not be empty")
        raw = (selected * ((count + len(selected) - 1) // len(selected)))[:count]
        return self.raw(raw, label=label)

    def pad_to(self, offset: int, *, fill: bytes | None = None, label: str = "padding") -> "Craft":
        if offset < self._cursor:
            raise ConstraintError(
                f"cannot pad backwards from {self._cursor:#x} to {offset:#x}"
            )
        return self.pad(offset - self._cursor, fill=fill, label=label)

    def align(self, alignment: int, *, fill: bytes | None = None, label: str = "alignment") -> "Craft":
        if alignment <= 0 or alignment & (alignment - 1):
            raise ValueError("alignment must be a positive power of two")
        target = (self._cursor + alignment - 1) & -alignment
        return self.pad_to(target, fill=fill, label=label)

    def at(self, offset: int) -> "Craft":
        if offset < 0:
            raise ValueError("craft cursor cannot be negative")
        return replace(self, _cursor=int(offset))

    def int(
        self,
        value: Any,
        *,
        bits: int,
        endian: Literal["little", "big"] | None = None,
        signed: bool = False,
        label: str = "integer",
    ) -> "Craft":
        if bits <= 0 or bits % 8:
            raise ValueError("integer bits must be a positive multiple of eight")
        selected_endian = self.endian if endian is None else endian
        encoded = _IntegerEncoding(value, bits, selected_endian, signed)
        return self._place(encoded, size=encoded.size, label=label, encoded=True)

    def word(self, value: Any, *, label: str = "word") -> "Craft":
        return self.int(value, bits=self.pointer_size * 8, label=label)

    def ptr(
        self,
        value: Any,
        *,
        bytes: builtins.int | None = None,
        endian: Literal["little", "big"] | None = None,
        label: str = "pointer",
    ) -> "Craft":
        width = self.pointer_size if bytes is None else int(bytes)
        if width <= 0 or width > self.pointer_size:
            raise ValueError("pointer byte width must be in 1..pointer_size")
        selected_endian = self.endian if endian is None else endian
        encoded = _PointerEncoding(value, width, self.pointer_size, selected_endian)
        return self._place(encoded, size=width, label=label, encoded=True)

    def encoded(self, codec: Codec[Any], value: Any, *, label: str | None = None) -> "Craft":
        if not isinstance(codec, Codec):
            raise TypeError("encoded requires a Codec")
        size = codec.size
        if size is None:
            if _dependencies(value):
                raise PlanningError("symbolic encoded values require a fixed-size codec")
            raw = codec.build(value)
            return self.raw(raw, label=label or type(codec).__name__)
        encoded = _CodecEncoding(codec, value, size)
        return self._place(
            encoded,
            size=size,
            label=label or type(codec).__name__,
            encoded=True,
        )

    def require(
        self,
        *,
        no: bytes = b"",
        min_size: builtins.int | None = None,
        max_size: builtins.int | None = None,
        exact_size: builtins.int | None = None,
        encoding: str | None = None,
        predicate: Callable[[bytes], bool] | None = None,
        explanation: str = "",
        constraint: Any = None,
    ) -> "Craft":
        for name, value in (("min_size", min_size), ("max_size", max_size), ("exact_size", exact_size)):
            if value is not None and value < 0:
                raise ValueError(f"{name} cannot be negative")
        new_min = max(
            value for value in (self._min_size, min_size, 0) if value is not None
        )
        maxima = [value for value in (self._max_size, max_size) if value is not None]
        new_max = min(maxima) if maxima else None
        if self._exact_size is not None and exact_size is not None and self._exact_size != exact_size:
            raise ValueError(
                f"conflicting exact_size declarations: {self._exact_size} and {exact_size}"
            )
        new_exact = self._exact_size if exact_size is None else exact_size
        if new_max is not None and new_min > new_max:
            raise ValueError(
                "accumulated min_size exceeds accumulated max_size"
            )
        if new_exact is not None and (
            new_exact < new_min or (new_max is not None and new_exact > new_max)
        ):
            raise ValueError("exact_size conflicts with accumulated size constraints")
        payload = self._payload.copy()
        payload.forbidden = bytes(sorted(set(payload.forbidden) | set(bytes(no))))
        constraints = self._constraints + ((constraint,) if constraint is not None else ())
        encodings = self._encodings
        if encoding is not None and encoding not in encodings:
            encodings = (*encodings, encoding)
        predicates = self._predicates
        if predicate is not None:
            predicates = (*predicates, (predicate, explanation or "craft predicate rejected payload"))
        return replace(
            self,
            _payload=payload,
            _min_size=new_min or None,
            _max_size=new_max,
            _exact_size=new_exact,
            _encodings=encodings,
            _predicates=predicates,
            _constraints=constraints,
        )

    def replace(
        self,
        offset: builtins.int,
        size: builtins.int,
        data: bytes | bytearray | memoryview,
        *,
        label: str = "replacement",
        reason: str,
        resize: bool = False,
    ) -> "Craft":
        if not reason:
            raise TypeError("craft replacement requires reason=")
        raw = bytes(data)
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ConstraintError("replacement range is outside the craft payload")
        if not resize and len(raw) != size:
            raise ConstraintError(
                f"same-size replacement requires {size} bytes, received {len(raw)}"
            )
        if resize:
            if self.dependencies:
                raise PlanningError("resizing symbolic craft payloads is not supported")
            payload = self._payload._resized_replace(
                offset,
                size,
                raw,
                label=f"{label} bytes",
                materialized=self.build(),
            )
            delta = len(raw) - size
            old_end = offset + size
            materialized = tuple(
                replace(
                    patch,
                    offset=(
                        patch.offset + delta
                        if patch.offset >= old_end
                        else patch.offset
                    ),
                    materialized=True,
                    layout_size=(
                        patch.layout_size
                        if patch.layout_size is not None
                        else len(patch.data)
                    ),
                )
                for patch in self._patches
            )
            resize_patch = _Patch(
                offset,
                size,
                raw,
                label,
                reason,
                materialized=True,
                layout_size=len(raw),
            )
            if self._cursor < offset:
                cursor = self._cursor
            elif self._cursor >= old_end:
                cursor = self._cursor + delta
            else:
                cursor = offset + len(raw)
            return replace(
                self,
                _payload=payload,
                _cursor=cursor,
                _patches=(*materialized, resize_patch),
            )
        patch = _Patch(offset, size, raw, label, reason)
        return replace(self, _patches=(*self._patches, patch))

    def _validate(self, data: bytes) -> bytes:
        if self._min_size is not None and len(data) < self._min_size:
            raise ConstraintError(f"craft size {len(data)} is below minimum {self._min_size}")
        if self._max_size is not None and len(data) > self._max_size:
            raise ConstraintError(f"craft size {len(data)} exceeds maximum {self._max_size}")
        if self._exact_size is not None and len(data) != self._exact_size:
            raise ConstraintError(
                f"craft size {len(data)} must equal exact size {self._exact_size}"
            )
        for encoding in self._encodings:
            try:
                data.decode(encoding)
            except UnicodeDecodeError as error:
                raise ConstraintError(
                    f"craft violates {encoding} at offset {error.start:#x}"
                ) from error
        for constraint in self._constraints:
            validate = getattr(constraint, "validate", None)
            if not callable(validate):
                raise TypeError("craft constraint must provide validate(bytes)")
            validate(data)
        for predicate, explanation in self._predicates:
            if not predicate(data):
                raise ConstraintError(explanation)
        return data

    @property
    def forbidden(self) -> bytes:
        return self._payload.forbidden

    def build_unchecked(self, context: Any | None = None) -> bytes:
        data = bytearray(self._payload.build_unchecked(context))
        for patch in self._patches:
            if patch.materialized:
                continue
            data[patch.offset : patch.offset + patch.size] = patch.data
        return bytes(data)

    def validate_bytes(self, data: bytes) -> bytes:
        return self._validate(self._payload.validate_bytes(data))

    def build(self, context: Any | None = None) -> bytes:
        return self.validate_bytes(self.build_unchecked(context))

    def layout(self, context: Any | None = None) -> tuple[dict[str, Any], ...]:
        rows = list(self._payload.layout(context))
        rows.extend(
            {
                "id": f"patch:{index:04d}",
                "offset": patch.offset,
                "size": (
                    patch.layout_size
                    if patch.layout_size is not None
                    else patch.size
                ),
                "end": patch.offset
                + (
                    patch.layout_size
                    if patch.layout_size is not None
                    else patch.size
                ),
                "kind": "patch",
                "label": patch.label,
                "value": patch.data.hex(),
                "reason": patch.reason,
                "dependencies": [],
            }
            for index, patch in enumerate(self._patches, 1)
        )
        return tuple(
            sorted(rows, key=lambda row: (row["offset"], row["kind"], row["id"]))
        )

    def show(self) -> str:
        lines = [
            f"Craft {self.name!r} ({self.semantic_id})",
            f"size={self.size:#x}, cursor={self._cursor:#x}, endian={self.endian}, pointer={self.pointer_size}",
        ]
        if self.dependencies:
            lines.append("requires: " + ", ".join(sorted(self.dependencies)))
        for row in self.layout():
            line = (
                f"  {row['id']} {row['offset']:#x}..{row['end']:#x} "
                f"{row['kind']} {row['label']}"
            )
            if row.get("reason"):
                line += f" ({row['reason']})"
            lines.append(line)
        return "\n".join(lines)

    def hexdump(self, context: Any | None = None) -> str:
        try:
            return render_hexdump(self.build(context))
        except UnresolvedValueError as error:
            missing = ", ".join(sorted(self.dependencies)) or "unknown facts"
            raise UnresolvedValueError(
                f"cannot hexdump craft {self.name!r}; missing runtime fact(s): {missing}"
            ) from error

    def describe(self) -> str:
        patches = (
            "; patched: " + ", ".join(patch.reason for patch in self._patches)
            if self._patches
            else ""
        )
        return f"Craft({self.name}, id={self.semantic_id}, size={self.size}{patches})"


@dataclass(frozen=True, slots=True)
class PayloadArtifact:
    payload_id: str
    name: str
    stage: str
    send_id: str
    data: bytes
    layout: tuple[Mapping[str, Any], ...]
    dependencies: tuple[str, ...]
    sha256: str
    provenance: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        return self.payload_id

    @property
    def bytes(self) -> bytes:
        return self.data

    @property
    def size(self) -> int:
        return len(self.data)

    def hexdump(self) -> str:
        return render_hexdump(self.data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload_id": self.payload_id,
            "send_id": self.send_id,
            "name": self.name,
            "stage": self.stage,
            "size": self.size,
            "sha256": self.sha256,
            "bytes": self.bytes.hex(),
            "layout": _copy_layout_value(self.layout),
            "dependencies": list(self.dependencies),
            "provenance": list(self.provenance),
        }

    def diff(self, other: "PayloadArtifact") -> tuple[dict[str, Any], ...]:
        if not isinstance(other, PayloadArtifact):
            raise TypeError("payload artifact diff requires another PayloadArtifact")
        boundaries = {0, len(self.data), len(other.data)}
        for row in (*self.layout, *other.layout):
            boundaries.update((int(row["offset"]), int(row["end"])))
        ordered = sorted(value for value in boundaries if value >= 0)
        changes = []
        for start, end in zip(ordered, ordered[1:]):
            left = self.data[start:end]
            right = other.data[start:end]
            if left != right:
                changes.append(
                    {
                        "offset": start,
                        "end": end,
                        "before": left.hex(),
                        "after": right.hex(),
                    }
                )
        return tuple(changes)


@dataclass(frozen=True, slots=True)
class PlannedPayload:
    payload_id: str
    name: str
    stage: str
    send_id: str
    payload: Any = field(repr=False, compare=False)
    action: Any = field(default=None, repr=False, compare=False)

    @property
    def id(self) -> str:
        return self.payload_id


@dataclass(frozen=True, slots=True)
class PatchedPayload:
    base: Any
    semantic_id: str
    name: str
    patches: tuple[_Patch, ...]

    @property
    def dependencies(self) -> set[str]:
        return set(getattr(self.base, "dependencies", ()))

    @property
    def size(self) -> int:
        return int(getattr(self.base, "size"))

    @property
    def forbidden(self) -> bytes:
        return bytes(getattr(self.base, "forbidden", b""))

    def build_unchecked(self, context: Any | None = None) -> bytes:
        builder = getattr(self.base, "build_unchecked", None)
        data = bytearray(builder(context) if callable(builder) else self.base.build(context))
        for patch in self.patches:
            if patch.materialized:
                continue
            data[patch.offset : patch.offset + patch.size] = patch.data
        return bytes(data)

    def validate_bytes(self, data: bytes) -> bytes:
        validator = getattr(self.base, "validate_bytes", None)
        return validator(data) if callable(validator) else data

    def build(self, context: Any | None = None) -> bytes:
        return self.validate_bytes(self.build_unchecked(context))

    def layout(self, context: Any | None = None) -> list[dict[str, Any]]:
        rows = list(self.base.layout(context))
        rows.extend(
            {
                "id": f"plan-patch:{index:04d}",
                "offset": patch.offset,
                "size": (
                    patch.layout_size
                    if patch.layout_size is not None
                    else patch.size
                ),
                "end": patch.offset
                + (
                    patch.layout_size
                    if patch.layout_size is not None
                    else patch.size
                ),
                "kind": "patch",
                "label": patch.label,
                "value": patch.data.hex(),
                "reason": patch.reason,
                "dependencies": [],
            }
            for index, patch in enumerate(self.patches, 1)
        )
        return rows

    def describe(self) -> str:
        return f"patched payload {self.name} ({self.semantic_id})"


def artifact_from_emission(
    item: PlannedPayload,
    data: bytes,
    context: Any,
) -> PayloadArtifact:
    """Snapshot one structured payload using the facts visible at send time."""

    layout = tuple(
        _freeze_layout_value(dict(row))
        for row in item.payload.layout(context)
    )
    dependencies = tuple(sorted(getattr(item.payload, "dependencies", ())))
    provenance = tuple(
        context.explain(Expr.fact(name))
        for name in dependencies
    )
    return PayloadArtifact(
        item.payload_id,
        item.name,
        item.stage,
        item.send_id,
        data,
        layout,
        dependencies,
        hashlib.sha256(data).hexdigest(),
        provenance,
    )

