"""Immutable target-input contracts."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import ConstraintError


def _as_bytes(value: str | bytes | bytearray | memoryview, *, what: str) -> bytes:
    if isinstance(value, str):
        try:
            return value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError(
                f"{what} strings must be ASCII; pass encoded bytes explicitly"
            ) from exc
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{what} must be str or bytes-like, got {type(value).__name__}")


@dataclass(frozen=True, slots=True)
class Channel:
    prompt: bytes = b""
    terminator: bytes | None = None
    max_size: int | None = None
    forbidden: bytes = b""
    timeout: float = 3.0
    max_receive: int = 1024 * 1024
    name: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "prompt", _as_bytes(self.prompt, what="prompt"))
        if self.terminator is not None:
            object.__setattr__(
                self,
                "terminator",
                _as_bytes(self.terminator, what="terminator"),
            )
            if not self.terminator:
                raise ValueError("terminator cannot be empty")
        object.__setattr__(
            self, "forbidden", _as_bytes(self.forbidden, what="forbidden bytes")
        )
        if self.max_size is not None and self.max_size < 0:
            raise ValueError("max_size cannot be negative")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.max_receive <= 0:
            raise ValueError("max_receive must be positive")
        if self.name is not None and not self.name:
            raise ValueError("channel name cannot be empty")

    @property
    def framed(self) -> bool:
        return self.terminator is not None

    def encode(self, payload: bytes | bytearray | memoryview) -> bytes:
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"channel payload must be bytes-like, got {type(payload).__name__}"
            )
        raw = bytes(payload)
        if self.max_size is not None and len(raw) > self.max_size:
            raise ConstraintError(
                f"payload is {len(raw)} bytes, channel maximum is {self.max_size}"
            )

        bad = sorted({byte for byte in raw if byte in self.forbidden})
        if bad:
            rendered = ", ".join(f"0x{byte:02x}" for byte in bad)
            raise ConstraintError(
                f"payload contains forbidden byte(s): {rendered}"
            )

        if self.terminator is not None and self.terminator in raw:
            index = raw.index(self.terminator)
            raise ConstraintError(
                f"payload contains channel terminator {self.terminator!r} "
                f"at offset {index}"
            )
        return raw + (self.terminator or b"")

    def describe(self) -> str:
        kind = "line" if self.terminator is not None else "raw"
        pieces = [f"{kind} channel"]
        if self.name:
            pieces.append(f"named {self.name!r}")
        if self.prompt:
            pieces.append(f"after {self.prompt!r}")
        if self.max_size is not None:
            pieces.append(f"max {self.max_size} bytes")
        if self.forbidden:
            values = ", ".join(f"0x{byte:02x}" for byte in self.forbidden)
            pieces.append(f"forbids {values}")
        if self.terminator is not None:
            pieces.append(f"terminates with {self.terminator!r}")
        return ", ".join(pieces)


def line(
    prompt: str | bytes = b"",
    *,
    terminator: str | bytes = b"\n",
    max_size: int | None = None,
    forbidden: bytes = b"",
    timeout: float = 3.0,
    max_receive: int = 1024 * 1024,
    name: str | None = None,
) -> Channel:
    return Channel(
        prompt=_as_bytes(prompt, what="prompt"),
        terminator=_as_bytes(terminator, what="terminator"),
        max_size=max_size,
        forbidden=forbidden,
        timeout=timeout,
        max_receive=max_receive,
        name=name,
    )


def raw(
    prompt: str | bytes = b"",
    *,
    max_size: int | None = None,
    forbidden: bytes = b"",
    timeout: float = 3.0,
    max_receive: int = 1024 * 1024,
    name: str | None = None,
) -> Channel:
    return Channel(
        prompt=_as_bytes(prompt, what="prompt"),
        terminator=None,
        max_size=max_size,
        forbidden=forbidden,
        timeout=timeout,
        max_receive=max_receive,
        name=name,
    )
