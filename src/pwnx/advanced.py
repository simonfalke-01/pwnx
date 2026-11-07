"""Explicit advanced construction surfaces outside the primary pwnx namespace."""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping

from .actions import Action
from .control_flow import (
    BufferSlice,
    ByteConstraint,
    ControlledBuffer,
    IndirectCallControl,
    PivotControl,
    RopBuilder,
    RopPalette,
    buffer as _controlled_buffer,
)
from .domain import EffectContract
from .payload import Payload


def rop_palette(
    challenge: Any,
    *,
    pop: Mapping[str, int] | None = None,
    zero: Mapping[str, int] | None = None,
    move: Mapping[tuple[str, str], int] | None = None,
    syscall: int | None = None,
    pinned: Mapping[str, int] | None = None,
    constraints: Iterable[ByteConstraint] = (),
    constraint: ByteConstraint | None = None,
) -> RopPalette:
    """Build an explicit palette for unusual or generated gadget semantics."""

    declared = tuple(constraints)
    if constraint is not None:
        if declared:
            raise TypeError("pass constraint= or constraints=, not both")
        declared = (constraint,)
    return challenge.rop._build_palette(
        pop=pop,
        zero=zero,
        move=move,
        syscall=syscall,
        pinned=pinned,
        constraints=declared,
    )


def controlled_buffer(
    challenge: Any,
    name: str,
    *,
    at: int,
    size: int,
    writer: Callable[..., Action] | None = None,
    constraints: Iterable[ByteConstraint] = (),
) -> ControlledBuffer:
    """Construct the explicit controlled-buffer form used by backend authors."""

    return _controlled_buffer(
        challenge,
        name,
        at=at,
        size=size,
        writer=writer,
        constraints=tuple(constraints),
    )


def pivot(
    control: IndirectCallControl,
    *,
    stack: ControlledBuffer,
    pointer_register: str,
    gadget: int,
) -> PivotControl:
    """Explicit pivot spelling retained for advanced integrations."""

    return control._pivot(
        stack=stack,
        pointer_register=pointer_register,
        gadget=gadget,
    )


__all__ = [
    "BufferSlice",
    "Action",
    "ControlledBuffer",
    "EffectContract",
    "IndirectCallControl",
    "PivotControl",
    "Payload",
    "RopBuilder",
    "RopPalette",
    "controlled_buffer",
    "pivot",
    "rop_palette",
]

