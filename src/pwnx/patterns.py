"""Bounded observation patterns. Patterns describe bytes, never executable code."""

from __future__ import annotations

import re
from dataclasses import dataclass
from string import Formatter
from typing import Any, Callable

from .errors import PlanningError, ProtocolError
from .expressions import Expr


@dataclass(frozen=True)
class Field:
    target: Expr
    format: str = "hex"


class Pattern:
    def __init__(self, parts: tuple[bytes | Field, ...]):
        if not parts:
            raise ValueError("an observation pattern cannot be empty")
        if not isinstance(parts[-1], bytes) or not parts[-1]:
            raise ValueError("an observation must end with a literal byte boundary")
        self.parts = parts
        self.fields = tuple(p for p in parts if isinstance(p, Field))
        if not self.fields:
            raise ValueError("an observation pattern must capture at least one fact")
        self.terminator = parts[-1]
        self.prefix = parts[0] if isinstance(parts[0], bytes) else b""
        fragments = []
        for part in parts:
            if isinstance(part, bytes):
                fragments.append(re.escape(part))
            elif part.format in {"hex", "ptr"}:
                fragments.append(rb"((?:0x)?[0-9a-fA-F]{1,16})")
            elif part.format in {"int", "dec"}:
                fragments.append(rb"(-?[0-9]{1,20})")
            else:
                raise ValueError(f"unsupported observation format {part.format!r}")
        self.regex = re.compile(b"".join(fragments))

    @property
    def provides(self) -> set[str]:
        return set().union(*(f.target.dependencies for f in self.fields))

    def describe(self) -> str:
        return "".join(
            p.decode("ascii", "backslashreplace") if isinstance(p, bytes)
            else "{" + p.target.describe() + ":" + p.format + "}"
            for p in self.parts
        )

    def read(self, io: Any, *, timeout: float = 3, max_bytes: int = 1048576):
        # A literal prefix anchors the capture after arbitrary startup banners.
        leading = b""
        if self.prefix:
            leading = io.read_until(self.prefix, timeout=timeout, max_bytes=max_bytes)
        remaining = max_bytes - len(leading)
        if remaining <= 0:
            raise ProtocolError("observation exceeded its receive limit")
        tail = io.read_until(self.terminator, timeout=timeout, max_bytes=remaining)
        raw = self.prefix + tail
        match = self.regex.fullmatch(raw)
        if match is None:
            raise ProtocolError(f"observation {self.describe()!r} did not match {raw[:256]!r}")
        values = [int(value, 16 if field.format in {"hex", "ptr"} else 10)
                  for value, field in zip(match.groups(), self.fields)]
        return tuple(zip((field.target for field in self.fields), values)), leading + tail


def template(text: str, lookup: Callable[[str], Expr]) -> Pattern:
    parts: list[bytes | Field] = []
    for literal, name, format_spec, conversion in Formatter().parse(text):
        if literal:
            parts.append(literal.encode("ascii"))
        if name is not None:
            if conversion or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", name):
                raise PlanningError(f"invalid observation field {name!r}")
            parts.append(Field(lookup(name), format_spec or "hex"))
    return Pattern(tuple(parts))


def pattern(*parts: bytes | str | Field) -> Pattern:
    return Pattern(tuple(p.encode("ascii") if isinstance(p, str) else p for p in parts))


def observed(target: Expr, format: str = "hex") -> Field:
    return Field(target, format)
