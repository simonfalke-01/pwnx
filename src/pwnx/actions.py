"""Inspectable action IR for target interactions.

Actions contain no transport logic.  Planning produces them and the runtime
interprets them, which keeps plan output faithful to execution.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .channels import Channel, raw
from .codecs import Codec
from .domain import EffectContract, Scope
from .errors import ConstraintError, RetryableInstanceError
from .expressions import Expr


_OUTPUT_ORIGINS: dict[int, "Action"] = {}
_ACTION_EXECUTORS: dict[type["Action"], Callable[["Action", Any], Any]] = {}


@dataclass(frozen=True, slots=True)
class ActionPlanningContext:
    """Read-only information available while actions lower into the plan IR."""

    challenge: Any
    facts: frozenset[str] = frozenset()
    capabilities: tuple[Any, ...] = ()
    policy: Mapping[str, Any] = field(default_factory=dict)


def register_action_executor(
    action_type: type["Action"],
    executor: Callable[["Action", Any], Any],
) -> None:
    if action_type in _ACTION_EXECUTORS:
        raise ValueError(f"executor already registered for {action_type.__name__}")
    _ACTION_EXECUTORS[action_type] = executor


def action_executor(action: "Action"):
    return next(
        (_ACTION_EXECUTORS[item] for item in type(action).__mro__ if item in _ACTION_EXECUTORS),
        None,
    )


def action_origin(expression: Expr) -> "Action | None":
    return _OUTPUT_ORIGINS.get(id(expression))


def _with_origin(expression: Expr, action: "Action") -> Expr:
    _OUTPUT_ORIGINS[id(expression)] = action
    return expression


def _as_bytes(value: bytes | bytearray | memoryview | str, *, what: str) -> bytes:
    if isinstance(value, str):
        try:
            return value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError(f"{what} strings must be ASCII; pass bytes explicitly") from exc
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{what} must be bytes-like, got {type(value).__name__}")


def _describe_value(value: Any) -> str:
    if hasattr(value, "describe") and callable(value.describe):
        return str(value.describe())
    if isinstance(value, bytes):
        return repr(value)
    return repr(value)


class Action(ABC):
    """A node interpreted by the pwnx runtime."""

    @abstractmethod
    def describe(self) -> str:
        raise NotImplementedError

    @property
    def output(self) -> Expr | None:
        return None

    def contract(self) -> EffectContract:
        requires = tuple(Expr.fact(name) for name in sorted(getattr(self, "dependencies", ())))
        output = self.output
        provides = (output,) if output is not None else ()
        return EffectContract(
            requires=requires,
            provides=provides,
            reads=frozenset(getattr(self, "reads", ())),
            writes=frozenset(getattr(self, "writes", ())),
            invalidates=tuple(getattr(self, "invalidates", ())),
            scope=Scope.PROCESS,
        )

    def lower(self, _context: Any = None) -> tuple["Action", ...]:
        return (self,)

    def execute(self, _runtime: Any) -> Any:
        return NotImplemented


@dataclass(frozen=True, slots=True)
class Delay(Action):
    """An explicit live timing boundary for protocols with no observable prompt."""

    seconds: float
    reason: str = "allow target to reach the next input operation"

    def __post_init__(self) -> None:
        if self.seconds < 0:
            raise ValueError("delay cannot be negative")
        if not self.reason:
            raise ValueError("delay reason cannot be empty")

    def describe(self) -> str:
        return f"wait {self.seconds:g}s ({self.reason})"


@dataclass(frozen=True, slots=True)
class Encoded:
    """A value that must be resolved and serialized at execution time."""

    codec: Codec[Any]
    value: Any

    def __post_init__(self) -> None:
        if not isinstance(self.codec, Codec):
            raise TypeError("encoded value codec must be a Codec")

    @property
    def dependencies(self) -> set[str]:
        if isinstance(self.value, Expr):
            return set(self.value.dependencies)
        return set(getattr(self.value, "dependencies", ()))

    def build(self, resolve: Callable[[Any], Any] | None = None) -> bytes:
        if isinstance(self.value, Expr):
            value = resolve(self.value) if resolve is not None else self.value
        else:
            builder = getattr(self.value, "build", None)
            if callable(builder):
                context = getattr(resolve, "__self__", None) if resolve is not None else None
                value = builder(context)
            else:
                value = self.value
        return self.codec.build(value)

    def describe(self) -> str:
        return f"{type(self.codec).__name__}({_describe_value(self.value)})"


@dataclass(frozen=True, slots=True)
class Emit(Action):
    data: Any
    channel: Channel = field(default_factory=raw)
    correlation: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.channel, Channel):
            raise TypeError("emit channel must be a Channel")

    def describe(self) -> str:
        return f"send {_describe_value(self.data)} through {self.channel.describe()}"

    def contract(self) -> EffectContract:
        dependencies = () if getattr(self.data, "defer_dependencies", False) else tuple(
            Expr.fact(name) for name in sorted(getattr(self.data, "dependencies", ()))
        )
        return EffectContract(
            requires=dependencies,
            writes=frozenset({"connection.stream"}),
            scope=Scope.CONNECTION,
        )


@dataclass(frozen=True, slots=True)
class Expect(Action):
    delimiter: bytes
    timeout: float = 3.0
    max_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        delimiter = _as_bytes(self.delimiter, what="expect delimiter")
        if not delimiter:
            raise ValueError("expect delimiter cannot be empty")
        if self.timeout <= 0:
            raise ValueError("expect timeout must be positive")
        if self.max_bytes <= 0:
            raise ValueError("expect max_bytes must be positive")
        object.__setattr__(self, "delimiter", delimiter)

    def describe(self) -> str:
        return f"expect {self.delimiter!r} (timeout {self.timeout:g}s, max {self.max_bytes} bytes)"

    def contract(self) -> EffectContract:
        return EffectContract(
            reads=frozenset({"connection.stream"}),
            writes=frozenset({"connection.cursor"}),
            scope=Scope.CONNECTION,
        )


@dataclass(frozen=True, slots=True)
class Capture(Action):
    codec: Codec[Any]
    target: Expr | None = None
    name: str = "capture"

    def __post_init__(self) -> None:
        if not isinstance(self.codec, Codec):
            raise TypeError("capture codec must be a Codec")
        if self.target is not None and not isinstance(self.target, Expr):
            raise TypeError("capture target must be an Expr")
        if not self.name:
            raise ValueError("capture name cannot be empty")

    @property
    def output(self) -> Expr:
        if self.target is not None:
            return self.target
        return Expr.fact(
            f"capture:{self.name}",
            scope="process",
            label=self.name,
        ).with_origin(self)

    def describe(self) -> str:
        return f"capture {type(self.codec).__name__} as {self.output.describe()}"

    def contract(self) -> EffectContract:
        return EffectContract(
            provides=(self.output,),
            reads=frozenset({"connection.stream"}),
            writes=frozenset({"connection.cursor", "process.facts"}),
            scope=Scope.PROCESS,
        )


@dataclass(frozen=True, slots=True)
class Bind(Action):
    target: Expr
    value: Any

    def __post_init__(self) -> None:
        if not isinstance(self.target, Expr):
            raise TypeError("bind target must be an Expr")

    @property
    def output(self) -> Expr:
        return self.target

    def describe(self) -> str:
        return f"bind {self.target.describe()} to {_describe_value(self.value)}"

    def contract(self) -> EffectContract:
        dependencies = tuple(
            Expr.fact(name) for name in sorted(getattr(self.value, "dependencies", ()))
        )
        return EffectContract(
            requires=dependencies,
            provides=(self.target,),
            writes=frozenset({"process.facts"}),
            scope=Scope.PROCESS,
        )


@dataclass(frozen=True, slots=True)
class Check(Action):
    predicate: Expr
    message: str = "runtime condition failed"

    def __post_init__(self) -> None:
        if not isinstance(self.predicate, Expr):
            raise TypeError("check predicate must be an Expr")
        if self.predicate.kind != "boolean":
            raise TypeError("check predicate must be a boolean expression")
        if not self.message:
            raise ValueError("check message cannot be empty")

    def describe(self) -> str:
        return f"check {self.predicate.describe()}: {self.message}"

    def contract(self) -> EffectContract:
        return EffectContract(
            requires=(self.predicate,),
            reads=frozenset({"process.facts"}),
            scope=Scope.PROCESS,
        )


@dataclass(frozen=True, slots=True)
class PayloadFeasibility(Action):
    """Validate instance-dependent protected words before an outbound effect."""

    payload: Any
    channel: Channel
    protected: tuple[Any, ...] = ()
    correlation: object | None = field(default=None, repr=False, compare=False)

    def describe(self) -> str:
        labels = ", ".join(
            f"{item.label} at offset {item.offset}" for item in self.protected
        ) or "dynamic protected words"
        return (
            f"retryable framing feasibility for {labels} through "
            f"{self.channel.describe()}"
        )

    def contract(self) -> EffectContract:
        requirements = tuple(
            Expr.fact(name)
            for name in sorted(getattr(self.payload, "dependencies", ()))
        )
        return EffectContract(
            requires=requirements,
            reads=frozenset({"process.facts"}),
            scope=Scope.PROCESS,
        )

    def _retry(
        self,
        item: Any,
        *,
        offset: int,
        byte: int,
        reason: str,
    ) -> None:
        channel = self.channel.describe()
        raise RetryableInstanceError(
            f"retryable {item.label} framing failure at payload offset {offset} "
            f"({offset:#x}): "
            f"byte {byte:#04x} {reason} for {channel}",
            label=str(item.label),
            offset=offset,
            byte=byte,
            channel=channel,
        )

    def execute(self, runtime: Any) -> bytes:
        unchecked = getattr(self.payload, "build_unchecked", None)
        raw = (
            unchecked(runtime.context)
            if callable(unchecked)
            else self.payload.build(runtime.context)
        )
        layout_method = getattr(self.payload, "layout", None)
        layout = layout_method(runtime.context) if callable(layout_method) else ()

        def retry_dynamic(offset: int, byte: int, reason: str) -> None:
            covering = [
                row
                for row in layout
                if int(row.get("offset", 0)) <= offset < int(row.get("end", 0))
            ]
            if not covering:
                return
            patches = [row for row in covering if row.get("kind") == "patch"]
            row = patches[-1] if patches else covering[-1]
            if not row.get("dependencies"):
                return
            proxy = type(
                "DynamicRegion",
                (),
                {
                    "label": row.get("label", "dynamic payload region"),
                    "offset": int(row.get("offset", offset)),
                },
            )()
            self._retry(proxy, offset=offset, byte=byte, reason=reason)

        def retry_dynamic_range(start: int, end: int, reason: str) -> None:
            for offset in range(start, end):
                retry_dynamic(offset, raw[offset], reason)

        validator = getattr(self.payload, "validate_bytes", None)
        if callable(validator):
            try:
                validator(raw)
            except ConstraintError:
                forbidden = bytes(getattr(self.payload, "forbidden", b""))
                payload_forbidden_position = next(
                    (index for index, byte in enumerate(raw) if byte in forbidden),
                    None,
                )
                if payload_forbidden_position is not None:
                    retry_dynamic(
                        payload_forbidden_position,
                        raw[payload_forbidden_position],
                        "is forbidden",
                    )
                raise
        try:
            self.channel.encode(raw)
        except ConstraintError:
            channel_forbidden_position = next(
                (
                    index
                    for index, byte in enumerate(raw)
                    if byte in self.channel.forbidden
                ),
                None,
            )
            if channel_forbidden_position is not None:
                retry_dynamic(
                    channel_forbidden_position,
                    raw[channel_forbidden_position],
                    "is forbidden by channel",
                )
            terminator = self.channel.terminator
            if terminator:
                start = raw.find(terminator)
                if start >= 0:
                    end = start + len(terminator)
                    retry_dynamic_range(
                        start,
                        end,
                        f"starts channel terminator {terminator!r}",
                    )
            raise
        return raw


@dataclass(frozen=True, slots=True)
class Sequence(Action):
    actions: tuple[Action, ...]
    name: str = "sequence"

    def __post_init__(self) -> None:
        if not isinstance(self.actions, tuple):
            raise TypeError("sequence actions must be a tuple")
        if any(not isinstance(action, Action) for action in self.actions):
            raise TypeError("sequence contains a value that is not an Action")
        if not self.name:
            raise ValueError("sequence name cannot be empty")

    @property
    def output(self) -> Expr | None:
        if not self.actions:
            return None
        output = self.actions[-1].output
        return _with_origin(output, self) if output is not None else None

    def describe(self) -> str:
        if not self.actions:
            return f"{self.name}: no actions"
        lines = [f"{self.name}:"]
        lines.extend(
            f"  {index}. {action.describe()}" for index, action in enumerate(self.actions, 1)
        )
        return "\n".join(lines)

    def contract(self) -> EffectContract:
        result = EffectContract()
        for action in self.actions:
            result = result.merge(action.contract())
        return result


@dataclass(frozen=True, slots=True)
class Branch(Action):
    predicate: Expr
    then: Sequence
    otherwise: Sequence

    def __post_init__(self) -> None:
        if not isinstance(self.predicate, Expr):
            raise TypeError("branch predicate must be an Expr")
        if self.predicate.kind != "boolean":
            raise TypeError("branch predicate must be a boolean expression")
        if not isinstance(self.then, Sequence) or not isinstance(self.otherwise, Sequence):
            raise TypeError("branch paths must be Sequence instances")

    @property
    def output(self) -> Expr | None:
        then_output = self.then.output
        otherwise_output = self.otherwise.output
        if then_output is not None and then_output == otherwise_output:
            return _with_origin(then_output, self)
        return None

    def describe(self) -> str:
        return (
            f"if {self.predicate.describe()}:\n"
            f"{_indent(self.then.describe())}\n"
            "otherwise:\n"
            f"{_indent(self.otherwise.describe())}"
        )

    def contract(self) -> EffectContract:
        branches = self.then.contract().merge(self.otherwise.contract())
        return EffectContract(
            requires=(self.predicate, *branches.requires),
            provides=branches.provides,
            reads=branches.reads | frozenset({"process.facts"}),
            writes=branches.writes,
            invalidates=branches.invalidates,
            scope=branches.scope,
            constraints=branches.constraints,
            evidence=branches.evidence,
        )


def _indent(value: str) -> str:
    return "\n".join(f"  {line}" for line in value.splitlines())


def send(data: Any, channel: Channel | None = None) -> Emit:
    return Emit(data, channel if channel is not None else raw())


def expect(
    delimiter: bytes | bytearray | memoryview | str,
    *,
    timeout: float = 3.0,
    max_bytes: int = 1024 * 1024,
) -> Expect:
    return Expect(_as_bytes(delimiter, what="expect delimiter"), timeout, max_bytes)


def capture(
    codec: Codec[Any],
    target: Expr | None = None,
    *,
    name: str = "capture",
) -> Capture:
    return Capture(codec, target, name)


def sequence(*actions: Action, name: str = "sequence") -> Sequence:
    return Sequence(tuple(actions), name)
