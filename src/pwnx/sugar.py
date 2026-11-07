"""Optional natural syntax over the existing pwnx semantic objects."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from .actions import Action
from .codecs import BytesCodec, bytes_, integer
from .errors import PlanningError
from .protocols import Choice, Menu, choice, field


def _command(value: bytes | str | int) -> bytes:
    if isinstance(value, int):
        value = str(value)
    if isinstance(value, str):
        value = value.encode("ascii")
    if not isinstance(value, bytes) or not value:
        raise TypeError("menu commands must be non-empty int, str, or bytes values")
    return value


def _codec(marker: Any):
    if marker is bytes:
        return bytes_(max_size=0x100000)
    if marker is int:
        return integer(delimiter=None)
    if hasattr(marker, "build") and hasattr(marker, "read"):
        return marker
    raise TypeError(
        f"unsupported quick-menu field type {marker!r}; use bytes, int, or a Codec"
    )


def _quick_choice(specification: Any):
    if isinstance(specification, (int, str, bytes)):
        return choice(_command(specification))
    if not isinstance(specification, tuple) or not specification:
        raise TypeError("menu operations must be commands or (command, prompt, type, ...) tuples")
    command, *parts = specification
    if len(parts) % 2:
        raise TypeError("menu operation fields must be prompt/type pairs")
    fields = []
    for index in range(0, len(parts), 2):
        prompt, marker = parts[index : index + 2]
        fields.append(field(prompt, _codec(marker)))
    return choice(_command(command), *fields)


@dataclass(frozen=True, slots=True)
class QuickOperation:
    challenge: Any
    menu: Menu
    name: str
    definition: Choice | None = None

    def __call__(self, *args: Any, **kwargs: Any) -> Action:
        if self.definition is None:
            return self.menu.invoke(self.name, *args, **kwargs)
        return self.menu.invoke_choice(
            self.name,
            self.definition,
            *args,
            **kwargs,
        )

    def bind_buffer(self, size: int) -> "QuickOperation":
        definition = self.definition or self.menu.choices[self.name]
        if len(definition.fields) != 1:
            raise PlanningError(
                f"buffer writer {self.name!r} must have exactly one bytes field"
            )
        item = definition.fields[0]
        codec = item.codec
        if not isinstance(codec, BytesCodec):
            raise PlanningError(
                f"buffer writer {self.name!r} field is not bytes-compatible"
            )
        if codec.length is not None and codec.length > size:
            raise PlanningError(
                f"buffer writer fixed length {codec.length:#x} exceeds buffer size {size:#x}"
            )
        maximum = size if codec.max_size is None else min(codec.max_size, size)
        bound_codec = replace(codec, max_size=maximum)
        bound_field = replace(item, codec=bound_codec)
        return replace(
            self,
            definition=replace(definition, fields=(bound_field,)),
        )

    def indexes(
        self,
        *,
        table: int,
        target: Any,
        trigger: Any,
        state: Mapping[str, Any] | None = None,
        **register_state: Any,
    ):
        if state is not None and register_state:
            raise TypeError("pass state= or register keywords, not both")
        declared_state = dict(state or register_state)
        normalized = {
            register: value.address if hasattr(value, "address") else value
            for register, value in declared_state.items()
        }
        return self.challenge.indirect_call(
            table=table,
            index=self,
            target=target,
            trigger=trigger,
            state=normalized,
        )

    def describe(self) -> str:
        return f"quick menu operation {self.menu.namespace}.{self.name}"


@dataclass(frozen=True, slots=True)
class QuickMenu:
    challenge: Any
    menu: Menu
    operations: Mapping[str, QuickOperation]

    def __getattr__(self, name: str) -> QuickOperation:
        try:
            return self.operations[name]
        except KeyError as error:
            raise AttributeError(name) from error

    def describe(self) -> str:
        return self.menu.describe()


def quick_menu(
    challenge: Any,
    prompt: bytes | str,
    *,
    name: str = "store",
    **operations: Any,
) -> QuickMenu:
    if not operations:
        raise PlanningError("Challenge.menu requires at least one named operation")
    menu = challenge.protocol.menu(prompt, name=name).define(
        **{operation: _quick_choice(specification) for operation, specification in operations.items()}
    )
    wrapped = {
        operation: QuickOperation(challenge, menu, operation)
        for operation in operations
    }
    return QuickMenu(challenge, menu, wrapped)

