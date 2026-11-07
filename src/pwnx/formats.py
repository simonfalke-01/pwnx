"""Declarative format-string capabilities and deferred payloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

from .actions import Action
from .channels import Channel, line
from .codecs import Codec, line_codec
from .expressions import Expr
from .techniques import fmtstr_payload


@dataclass(frozen=True)
class FormatLeak:
    position: int
    target: Expr
    adjustment: int = 0

    def describe(self) -> str:
        suffix = f" adjusted by {self.adjustment:+#x}" if self.adjustment else ""
        return f"format argument {self.position} -> {self.target.describe()}{suffix}"

    @property
    def payload(self) -> bytes:
        return f"%{self.position}$p".encode()


@dataclass(frozen=True)
class FormatWrite:
    control: "FormatControl"
    writes: dict[Any, Any]

    def describe(self) -> str:
        return f"format-string write of {len(self.writes)} target value(s)"


@dataclass(frozen=True)
class DeferredFormatPayload:
    control: "FormatControl"
    writes: dict[Any, Any]

    @property
    def dependencies(self) -> set[str]:
        result: set[str] = set()
        result.update(getattr(self.control.offset, "dependencies", ()))
        for key, value in self.writes.items():
            result.update(getattr(key, "dependencies", ()))
            result.update(getattr(value, "dependencies", ()))
        return result

    def build(self, context) -> bytes:
        resolved = {
            context.resolve(address): context.resolve(value)
            for address, value in self.writes.items()
        }
        return fmtstr_payload(
            context.resolve(self.control.offset),
            resolved,
            numbwritten=self.control.numbwritten,
            write_size=self.control.write_size,
            badbytes=self.control.channel.forbidden,
        )

    def layout(self, context=None):
        writes = [
            {
                "target": getattr(address, "describe", lambda: repr(address))(),
                "value": getattr(value, "describe", lambda: repr(value))(),
            }
            for address, value in self.writes.items()
        ]
        if context is None:
            return [{
                "kind": "format-write",
                "offset": 0,
                "size": None,
                "label": "generated positional format-string program",
                "write_size": self.control.write_size,
                "writes": writes,
            }]
        raw = self.build(context)
        return [{
            "kind": "format-write",
            "offset": 0,
            "size": len(raw),
            "end": len(raw),
            "label": "generated positional format-string program and write addresses",
            "value": raw.hex(),
            "write_size": self.control.write_size,
            "writes": writes,
        }]


@dataclass
class FormatControl:
    channel: Channel
    offset: int | Expr
    write_size: str = "short"
    numbwritten: int = 0
    name: str = "format string"
    _leaks: list[FormatLeak] = field(default_factory=list, repr=False)
    discovery: "FormatOffsetDiscovery | None" = None

    def __post_init__(self):
        if isinstance(self.offset, int) and self.offset <= 0:
            raise ValueError("format-string argument offset must be positive")
        if not isinstance(self.offset, (int, Expr)):
            raise TypeError("format-string offset must be an integer or symbolic fact")
        if self.write_size not in {"byte", "short"}:
            raise ValueError("write_size must be 'byte' or 'short'")
        if self.numbwritten < 0:
            raise ValueError("numbwritten cannot be negative")

    def leak(self, position: int, target: Expr, *, adjustment: int = 0) -> FormatLeak:
        if position <= 0 or not isinstance(target, Expr):
            raise TypeError("leak requires a positive position and symbolic target")
        leak = FormatLeak(position, target, adjustment)
        self._leaks.append(leak)
        return leak

    def ptr(self, position: int, *, name: str | None = None) -> Expr:
        target = Expr.fact(name or f"fmt.arg[{position}]", label=name or f"format argument {position}")
        self.leak(position, target)
        return target

    def write(self, target: Any, value: Any) -> FormatWrite:
        return FormatWrite(self, {target: value})

    def writes(self, mapping: dict[Any, Any]) -> FormatWrite:
        return FormatWrite(self, dict(mapping))

    def describe(self) -> str:
        rendered = (
            str(self.offset)
            if isinstance(self.offset, int)
            else self.offset.describe()
        )
        return f"format string at argument {rendered} through {self.channel.describe()}"


@dataclass(frozen=True)
class FormatOffsetDiscovery(Action):
    channel: Channel
    response: Codec[bytes | str]
    target: Expr
    start: int = 1
    stop: int = 128
    marker: bytes = b"AAAABBBB"

    def __post_init__(self):
        if self.start <= 0 or self.stop <= self.start:
            raise ValueError("format discovery requires 0 < start < stop")
        if len(self.marker) != 8:
            raise ValueError("format discovery marker must be exactly eight bytes")

    @property
    def output(self) -> Expr:
        return self.target

    def describe(self) -> str:
        return (
            f"discover format argument offset in {self.start}..{self.stop - 1} "
            f"through {self.channel.describe()}"
        )


def format_string(
    prompt: str | bytes = b"",
    *,
    channel: Channel | None = None,
    offset: int | Expr | str,
    write_size: str = "short",
    numbwritten: int = 0,
    max_size: int | None = None,
    timeout: float = 3,
    response: Codec[bytes | str] | None = None,
    discover_range: tuple[int, int] = (1, 128),
    name: str = "format",
) -> FormatControl:
    selected_channel = channel or line(prompt, max_size=max_size, timeout=timeout)
    discovery = None
    if offset == "auto":
        target = Expr.fact(
            f"fmt.{name}.offset",
            scope="artifact",
            label=f"{name} first controlled format argument",
        )
        discovery = FormatOffsetDiscovery(
            selected_channel,
            response or cast(Codec[bytes | str], line_codec()),
            target,
            discover_range[0],
            discover_range[1],
        )
        offset = target
    elif isinstance(offset, str):
        raise ValueError("format-string offset must be an integer, Expr, or 'auto'")
    return FormatControl(
        selected_channel,
        offset,
        write_size,
        numbwritten,
        name,
        discovery=discovery,
    )
