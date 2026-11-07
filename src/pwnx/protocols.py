"""Declarative protocol helpers that lower to the action IR."""

from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .actions import Capture, Emit, Encoded, Sequence
from .channels import line, raw
from .codecs import Codec


def _as_bytes(value: bytes | bytearray | memoryview | str, *, what: str) -> bytes:
    if isinstance(value, str):
        try:
            return value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError(
                f"{what} strings must be ASCII; pass bytes explicitly"
            ) from exc
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{what} must be bytes-like, got {type(value).__name__}")


@dataclass(frozen=True, slots=True)
class Field:
    prompt: bytes
    codec: Codec[Any]
    name: str | None = None
    framing: str = "line"

    def __post_init__(self) -> None:
        object.__setattr__(self, "prompt", _as_bytes(self.prompt, what="field prompt"))
        if not isinstance(self.codec, Codec):
            raise TypeError("field codec must be a Codec")
        if self.name is not None and not self.name:
            raise ValueError("field name cannot be empty")
        if self.framing not in {"line", "raw"}:
            raise ValueError("field framing must be 'line' or 'raw'")

    def describe(self) -> str:
        label = self.name or "positional"
        return (
            f"{label}: {type(self.codec).__name__} through "
            f"{self.framing} input after {self.prompt!r}"
        )


@dataclass(frozen=True, slots=True)
class Choice:
    command: bytes
    fields: tuple[Field, ...] = ()
    returns: Codec[Any] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "command", _as_bytes(self.command, what="choice command")
        )
        if not self.command:
            raise ValueError("choice command cannot be empty")
        if any(not isinstance(item, Field) for item in self.fields):
            raise TypeError("choice fields must be Field instances")
        names = [item.name for item in self.fields if item.name is not None]
        if len(names) != len(set(names)):
            raise ValueError("choice field names must be unique")
        if self.returns is not None and not isinstance(self.returns, Codec):
            raise TypeError("choice return value must be a Codec")

    def describe(self) -> str:
        result = [f"command {self.command!r}"]
        result.extend(item.describe() for item in self.fields)
        if self.returns is not None:
            result.append(f"returns {type(self.returns).__name__}")
        return "; ".join(result)


@dataclass(slots=True)
class Menu:
    prompt: bytes
    choices: Mapping[str, Choice] = dataclass_field(
        default_factory=lambda: MappingProxyType({})
    )
    namespace: str = "menu"
    _next_operation_id: int = 1

    def __post_init__(self) -> None:
        self.prompt = _as_bytes(self.prompt, what="menu prompt")
        if not self.prompt:
            raise ValueError("menu prompt cannot be empty")
        if not self.namespace:
            raise ValueError("menu namespace cannot be empty")
        if not isinstance(self.choices, MappingProxyType):
            self.choices = MappingProxyType(dict(self.choices))
        if any(not isinstance(value, Choice) for value in self.choices.values()):
            raise TypeError("menu definitions must be Choice instances")

    def define(self, **choices: Choice) -> "Menu":
        if any(not isinstance(value, Choice) for value in choices.values()):
            raise TypeError("menu definitions must be Choice instances")
        duplicate = self.choices.keys() & choices.keys()
        if duplicate:
            rendered = ", ".join(sorted(duplicate))
            raise ValueError(f"menu choice(s) already defined: {rendered}")
        definitions = dict(self.choices)
        definitions.update(choices)
        return Menu(self.prompt, definitions, self.namespace)

    def invoke(self, choice_name: str, *args: Any, **kwargs: Any) -> Sequence:
        try:
            definition = self.choices[choice_name]
        except KeyError as exc:
            raise AttributeError(
                f"{self.namespace} has no choice {choice_name!r}"
            ) from exc

        return self.invoke_choice(choice_name, definition, *args, **kwargs)

    def invoke_choice(
        self,
        choice_name: str,
        definition: Choice,
        *args: Any,
        **kwargs: Any,
    ) -> Sequence:
        """Invoke a choice schema while sharing this menu's operation identity."""

        if not isinstance(definition, Choice):
            raise TypeError("menu choice override must be a Choice")

        values = self._bind_fields(definition, args, kwargs)
        operation_id = self._next_operation_id
        self._next_operation_id += 1
        operation_name = f"{self.namespace}.{choice_name}#{operation_id}"

        actions: list[Emit | Capture] = [
            Emit(definition.command, line(self.prompt))
        ]
        for item, value in zip(definition.fields, values, strict=True):
            channel = (
                line(item.prompt)
                if item.framing == "line"
                else raw(item.prompt)
            )
            actions.append(Emit(Encoded(item.codec, value), channel))
        if definition.returns is not None:
            actions.append(
                Capture(
                    definition.returns,
                    name=f"{operation_name}.result",
                )
            )
        return Sequence(tuple(actions), name=operation_name)

    def _bind_fields(
        self,
        definition: Choice,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> tuple[Any, ...]:
        fields = definition.fields
        if len(args) > len(fields):
            raise TypeError(
                f"expected at most {len(fields)} positional field value(s), "
                f"received {len(args)}"
            )
        values: list[Any] = list(args)
        for item in fields[: len(args)]:
            if item.name is not None and item.name in kwargs:
                raise TypeError(
                    f"field {item.name!r} received both positional and keyword values"
                )
        remaining = fields[len(args) :]
        unused = dict(kwargs)
        for index, item in enumerate(remaining, start=len(args)):
            if item.name is None:
                raise TypeError(
                    f"missing positional value for unnamed field {index}"
                )
            if item.name not in unused:
                raise TypeError(f"missing value for field {item.name!r}")
            values.append(unused.pop(item.name))
        if unused:
            rendered = ", ".join(sorted(unused))
            raise TypeError(f"unexpected field value(s): {rendered}")

        return tuple(values)

    def __getattr__(self, name: str) -> Callable[..., Sequence]:
        if name.startswith("_") or name not in self.choices:
            raise AttributeError(name)

        def invoke(*args: Any, **kwargs: Any) -> Sequence:
            return self.invoke(name, *args, **kwargs)

        invoke.__name__ = name
        invoke.__qualname__ = f"{type(self).__name__}.{name}"
        return invoke

    def describe(self) -> str:
        lines = [f"{self.namespace} after {self.prompt!r}:"]
        lines.extend(
            f"  {name}: {definition.describe()}"
            for name, definition in self.choices.items()
        )
        return "\n".join(lines)


class Protocols:
    """Factory namespace exposed as Challenge.protocol."""

    def menu(
        self,
        prompt: bytes | bytearray | memoryview | str,
        *,
        name: str = "menu",
    ) -> Menu:
        return Menu(_as_bytes(prompt, what="menu prompt"), namespace=name)


def field(
    prompt: bytes | bytearray | memoryview | str,
    codec: Codec[Any],
    name: str | None = None,
    *,
    framing: str = "line",
) -> Field:
    return Field(_as_bytes(prompt, what="field prompt"), codec, name, framing)


def choice(
    command: bytes | bytearray | memoryview | str,
    *fields: Field,
    returns: Codec[Any] | None = None,
) -> Choice:
    return Choice(_as_bytes(command, what="choice command"), tuple(fields), returns)

