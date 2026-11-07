"""Typed symbolic values used by pwnx specifications and compiled payloads.

The module deliberately keeps expression construction small.  Expressions are
immutable data; target I/O belongs to actions in the runtime, never here.
"""

from __future__ import annotations

from dataclasses import (
    dataclass,
    field,
    fields as dataclass_fields,
    is_dataclass,
    replace,
)
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable

from .errors import ConstraintError, StaleValueError, UnresolvedValueError


_SCOPE_ORDER = {"artifact": 0, "service": 1, "process": 2, "connection": 3}


def _snapshot_value(
    value: Any,
    *,
    path: str = "value",
    active: set[int] | None = None,
    budget: list[int] | None = None,
) -> Any:
    active = set() if active is None else active
    budget = [10000] if budget is None else budget
    budget[0] -= 1
    if budget[0] < 0:
        raise ConstraintError("binding value exceeds the 10000-node snapshot bound")
    if value is None or isinstance(value, (bool, int, float, str, bytes, Path, Enum)):
        return value
    identity = id(value)
    if identity in active:
        raise ConstraintError(f"{path} contains a cycle and cannot be snapshotted")
    active.add(identity)
    if isinstance(value, tuple):
        tuple_result = tuple(
            _snapshot_value(
                item,
                path=f"{path}[{index}]",
                active=active,
                budget=budget,
            )
            for index, item in enumerate(value)
        )
        active.remove(identity)
        return tuple_result
    if isinstance(value, frozenset):
        frozen_result = frozenset(
            _snapshot_value(item, path=f"{path}.item", active=active, budget=budget)
            for item in value
        )
        active.remove(identity)
        return frozen_result
    if isinstance(value, list):
        list_result = [
            _snapshot_value(
                item,
                path=f"{path}[{index}]",
                active=active,
                budget=budget,
            )
            for index, item in enumerate(value)
        ]
        active.remove(identity)
        return list_result
    if isinstance(value, dict):
        dict_result = {
            _snapshot_value(key, path=f"{path}.key", active=active, budget=budget):
            _snapshot_value(
                item,
                path=f"{path}[{key!r}]",
                active=active,
                budget=budget,
            )
            for key, item in value.items()
        }
        active.remove(identity)
        return dict_result
    if isinstance(value, set):
        set_result = {
            _snapshot_value(item, path=f"{path}.item", active=active, budget=budget)
            for item in value
        }
        active.remove(identity)
        return set_result
    if isinstance(value, MappingProxyType):
        proxy_result = MappingProxyType(
            {
                _snapshot_value(
                    key,
                    path=f"{path}.key",
                    active=active,
                    budget=budget,
                ): _snapshot_value(
                    item,
                    path=f"{path}[{key!r}]",
                    active=active,
                    budget=budget,
                )
                for key, item in value.items()
            }
        )
        active.remove(identity)
        return proxy_result
    if is_dataclass(value) and not isinstance(value, type):
        parameters = getattr(type(value), "__dataclass_params__", None)
        if parameters is not None and parameters.frozen:
            changes = {
                item.name: _snapshot_value(
                    getattr(value, item.name),
                    path=f"{path}.{item.name}",
                    active=active,
                    budget=budget,
                )
                for item in dataclass_fields(value)
            }
            active.remove(identity)
            return replace(value, **changes)
    raise ConstraintError(
        f"{path} is unsnapshotable ({type(value).__name__}); fact bindings "
        "accept bounded portable containers or frozen dataclass values"
    )


def _scope_of(values: Iterable["Expr"]) -> str:
    return max((value.scope for value in values), key=_SCOPE_ORDER.__getitem__, default="artifact")


def _stable_literal(value: Any) -> str:
    if isinstance(value, bytes):
        return f"bytes:{value.hex()}"
    if isinstance(value, str):
        return f"str:{value!r}"
    return repr(value)


def _literal_kind(value: Any) -> str:
    if isinstance(value, bytes):
        return "bytes"
    if isinstance(value, str):
        return "string"
    if isinstance(value, bool):
        return "boolean"
    return "integer"


@dataclass(frozen=True, slots=True)
class Expr:
    """An immutable symbolic expression.

    ``kind`` and ``space`` are runtime metadata rather than a substitute for
    Python typing.  They let address-producing modules retain useful diagnostics
    without forcing users to run a static checker.
    """

    op: str
    operands: tuple["Expr", ...] = ()
    value: Any = None
    name: str | None = None
    scope: str = "artifact"
    kind: str = "integer"
    space: str | None = None
    label: str | None = None
    origin: Any = field(default=None, compare=False, repr=False)
    sort: Any = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.scope not in _SCOPE_ORDER:
            raise ValueError(f"invalid expression scope {self.scope!r}")

    @classmethod
    def fact(
        cls,
        name: str,
        scope: str = "process",
        *,
        kind: str = "integer",
        space: str | None = None,
        label: str | None = None,
        sort: Any = None,
    ) -> "Expr":
        if not name:
            raise ValueError("fact name must not be empty")
        return cls(
            "fact",
            name=name,
            scope=scope,
            kind=kind,
            space=space,
            label=label,
            sort=sort,
        )

    @classmethod
    def literal(
        cls,
        value: Any,
        *,
        kind: str | None = None,
        space: str | None = None,
        label: str | None = None,
    ) -> "Expr":
        inferred = kind or _literal_kind(value)
        return cls(
            "literal", value=value, scope="artifact", kind=inferred, space=space, label=label
        )

    @classmethod
    def node(
        cls,
        op: str,
        *operands: Any,
        kind: str | None = None,
        space: str | None = None,
        label: str | None = None,
    ) -> "Expr":
        exprs = tuple(as_expr(value) for value in operands)
        _validate_operation(op, exprs)
        return cls(
            op,
            exprs,
            scope=_scope_of(exprs),
            kind=kind or _result_kind(op, exprs),
            space=space if space is not None else _result_space(op, exprs),
            label=label,
        )

    @property
    def key(self) -> str:
        if self.op == "fact":
            return self.name or "<unnamed>"
        if self.op == "literal":
            return _stable_literal(self.value)
        children = ",".join(child.key for child in self.operands)
        return f"{self.op}({children})"

    @property
    def dependencies(self) -> set[str]:
        if self.op == "fact":
            return {self.name or "<unnamed>"}
        result: set[str] = set()
        for child in self.operands:
            result.update(child.dependencies)
        return result

    @property
    def is_fact(self) -> bool:
        return self.op == "fact"

    @property
    def is_literal(self) -> bool:
        return self.op == "literal"

    def describe(self) -> str:
        if self.label:
            return self.label
        if self.op == "fact":
            return self.name or "unnamed fact"
        if self.op == "literal":
            return repr(self.value)
        if self.op == "low":
            return f"low {self.operands[1].value} bits of {self.operands[0].describe()}"
        symbols = {
            "add": "+",
            "sub": "-",
            "mul": "*",
            "and": "&",
            "or": "|",
            "xor": "^",
            "lshift": "<<",
            "rshift": ">>",
            "eq": "==",
        }
        if self.op in symbols and len(self.operands) == 2:
            return (
                f"({self.operands[0].describe()} {symbols[self.op]} {self.operands[1].describe()})"
            )
        return f"{self.op}({', '.join(value.describe() for value in self.operands)})"

    def evaluate(self, context: "BindingContext") -> Any:
        return context.resolve(self)

    def equals(self, other: Any) -> "Expr":
        return Expr.node("eq", self, other, kind="boolean")

    def low(self, bits: int) -> "Expr":
        if bits <= 0:
            raise ValueError("low() requires a positive bit count")
        return Expr.node("low", self, bits, kind="integer")

    def with_label(self, label: str) -> "Expr":
        return Expr(
            self.op,
            self.operands,
            self.value,
            self.name,
            self.scope,
            self.kind,
            self.space,
            label,
            self.origin,
            self.sort,
        )

    def with_origin(self, origin: Any) -> "Expr":
        return Expr(
            self.op,
            self.operands,
            self.value,
            self.name,
            self.scope,
            self.kind,
            self.space,
            self.label,
            origin,
            self.sort,
        )

    def __call__(self, *args: Any) -> "Call":
        """Describe a target-side call through this address expression."""

        return Call(self, args, name=self.label or self.name)

    def __add__(self, other: Any) -> "Expr":
        return Expr.node("add", self, other)

    def __radd__(self, other: Any) -> "Expr":
        return Expr.node("add", other, self)

    def __sub__(self, other: Any) -> "Expr":
        return Expr.node("sub", self, other)

    def __rsub__(self, other: Any) -> "Expr":
        return Expr.node("sub", other, self)

    def __mul__(self, other: Any) -> "Expr":
        return Expr.node("mul", self, other)

    def __rmul__(self, other: Any) -> "Expr":
        return Expr.node("mul", other, self)

    def __and__(self, other: Any) -> "Expr":
        return Expr.node("and", self, other)

    def __rand__(self, other: Any) -> "Expr":
        return Expr.node("and", other, self)

    def __or__(self, other: Any) -> "Expr":
        return Expr.node("or", self, other)

    def __ror__(self, other: Any) -> "Expr":
        return Expr.node("or", other, self)

    def __xor__(self, other: Any) -> "Expr":
        return Expr.node("xor", self, other)

    def __rxor__(self, other: Any) -> "Expr":
        return Expr.node("xor", other, self)

    def __lshift__(self, other: Any) -> "Expr":
        return Expr.node("lshift", self, other)

    def __rlshift__(self, other: Any) -> "Expr":
        return Expr.node("lshift", other, self)

    def __rshift__(self, other: Any) -> "Expr":
        return Expr.node("rshift", self, other)

    def __rrshift__(self, other: Any) -> "Expr":
        return Expr.node("rshift", other, self)

    def __bool__(self) -> bool:
        raise UnresolvedValueError(
            f"{self.describe()} is symbolic and cannot be used as a Python condition; "
            "use equals(), a planned branch, or BindingContext.resolve()"
        )

    def __int__(self) -> int:
        raise UnresolvedValueError(
            f"{self.describe()} is symbolic; resolve it through the active BindingContext first"
        )

    def __index__(self) -> int:
        return self.__int__()

    def __bytes__(self) -> bytes:
        raise UnresolvedValueError(
            f"{self.describe()} is symbolic; compile it through a payload with an active BindingContext"
        )


def _result_kind(op: str, values: tuple[Expr, ...]) -> str:
    if op == "eq":
        return "boolean"
    if op == "add":
        if any(value.kind == "address" for value in values):
            return "address"
    if op == "sub":
        if values[0].kind == "address" and values[1].kind != "address":
            return "address"
    return "integer"


def _validate_operation(op: str, values: tuple[Expr, ...]) -> None:
    if len(values) != 2 or op not in {"add", "sub"}:
        return
    left, right = values
    if op == "add" and left.kind == right.kind == "address":
        raise TypeError("adding two target addresses is undefined; add an integer offset instead")
    if op == "sub" and left.kind != "address" and right.kind == "address":
        raise TypeError("subtracting a target address from a plain integer is undefined")
    if op == "sub" and left.kind == right.kind == "address":
        if left.space is not None and right.space is not None and left.space != right.space:
            raise TypeError(
                f"cannot subtract addresses from different images ({left.space!r} and {right.space!r})"
            )


def _result_space(op: str, values: tuple[Expr, ...]) -> str | None:
    spaces = {value.space for value in values if value.space is not None}
    if len(spaces) == 1 and _result_kind(op, values) == "address":
        return spaces.pop()
    return None


def as_expr(value: Any) -> Expr:
    if isinstance(value, Expr):
        return value
    converter = getattr(value, "expr", None)
    if callable(converter):
        converted = converter()
        if isinstance(converted, Expr):
            return converted
    if isinstance(value, Resolved):
        raise TypeError(
            "a Resolved value cannot become an unscoped expression; use its source expression "
            "with the active BindingContext"
        )
    if isinstance(value, (int, bytes, str, bool)):
        return Expr.literal(value)
    raise TypeError(f"cannot use {type(value).__name__} as a pwnx symbolic value")


@dataclass(frozen=True, slots=True)
class Call:
    """A pure description of a target-side function call."""

    target: Expr
    args: tuple[Expr, ...] = ()
    name: str | None = None

    def __init__(self, target: Any, args: Iterable[Any] = (), name: str | None = None):
        object.__setattr__(self, "target", as_expr(target))
        object.__setattr__(self, "args", tuple(as_expr(value) for value in args))
        object.__setattr__(self, "name", name)

    @property
    def dependencies(self) -> set[str]:
        result = set(self.target.dependencies)
        for arg in self.args:
            result.update(arg.dependencies)
        return result

    @property
    def key(self) -> str:
        return f"call:{self.target.key}({','.join(arg.key for arg in self.args)})"

    def describe(self) -> str:
        name = self.name or self.target.describe()
        return f"{name}({', '.join(arg.describe() for arg in self.args)})"


@dataclass(frozen=True, slots=True)
class Resolved:
    """A concrete value that retains the expression and instance that produced it."""

    value: Any
    source: Expr
    instance_id: str | None = None
    evidence: str = ""

    def __int__(self) -> int:
        if not isinstance(self.value, int):
            raise TypeError(f"resolved {self.source.describe()} is not an integer")
        return self.value

    def __bytes__(self) -> bytes:
        if not isinstance(self.value, bytes):
            raise TypeError(f"resolved {self.source.describe()} is not bytes")
        return self.value


@dataclass(slots=True)
class _Binding:
    value: Any
    source: str
    scope: str
    instance_id: str | None
    sort: Any = None
    space: str | None = None
    generation: int = 0


@dataclass(slots=True)
class BindingContext:
    """Concrete bindings for one service/process/connection instance."""

    instance_id: str | None = None
    service_id: str | None = None
    process_id: str | None = None
    connection_id: str | None = None
    _bindings: dict[str, _Binding] = field(default_factory=dict)
    _replaceable: set[str] = field(default_factory=set)
    _generation: int = 0

    def __post_init__(self) -> None:
        """Expand the legacy single instance into independent scope epochs.

        ``instance_id`` remains a source-compatible shorthand for callers that
        do not model target lifecycle boundaries.  Runtime target recipes pass
        the three explicit epoch values instead.
        """

        if self.service_id is None:
            self.service_id = self.instance_id
        if self.process_id is None:
            self.process_id = self.instance_id
        if self.connection_id is None:
            self.connection_id = self.instance_id
        if self.instance_id is None:
            self.instance_id = self.process_id

    @property
    def epochs(self) -> dict[str, str | None]:
        return {
            "artifact": None,
            "service": self.service_id,
            "process": self.process_id,
            "connection": self.connection_id,
        }

    @property
    def bound_keys(self) -> frozenset[str]:
        return frozenset(self._bindings)

    def transition(
        self,
        *,
        service: str | None = None,
        process: str | None = None,
        connection: str | None = None,
    ) -> None:
        """Move to new lifecycle epochs without silently rebinding facts."""

        if service is not None:
            self.service_id = service
        if process is not None:
            self.process_id = process
            self.instance_id = process
        if connection is not None:
            self.connection_id = connection

    def _epoch_for(self, scope: str) -> str | None:
        try:
            return self.epochs[scope]
        except KeyError as error:
            raise ValueError(f"invalid binding scope {scope!r}") from error

    def checkpoint(self) -> dict[str, _Binding]:
        """Return a shallow fact-state checkpoint for transactional actions."""

        return dict(self._bindings)

    def rollback(self, checkpoint: dict[str, _Binding]) -> None:
        self._bindings.clear()
        self._bindings.update(checkpoint)
        self._replaceable.clear()

    def allow_replacements(self, names: Iterable[str]) -> None:
        self._replaceable.update(names)

    def finish_replacements(self) -> None:
        self._replaceable.clear()

    def snapshot_expressions(self, expressions: Iterable[Expr]) -> dict[str, _Binding]:
        names: set[str] = set()
        for expression in expressions:
            self.resolve(expression)
            names.update(expression.dependencies)
        return {
            name: self._bindings[name]
            for name in names
            if name in self._bindings
        }

    def was_written_since(
        self,
        checkpoint: dict[str, _Binding],
        names: Iterable[str],
    ) -> bool:
        for name in names:
            current = self._bindings.get(name)
            previous = checkpoint.get(name)
            if current is None:
                return False
            if previous is not None and current.generation <= previous.generation:
                return False
        return True

    def restore(self, snapshot: dict[str, _Binding]) -> None:
        self._bindings.update(snapshot)

    def bind(self, expression: Expr, value: Any, source: str = "") -> Resolved:
        if isinstance(value, Resolved):
            self._validate_instance(value)
            value = _snapshot_value(value.value)
        expr = as_expr(expression)
        if expr.is_fact:
            self._bind_fact(expr, value, source)
            return self._resolved(expr, value, source)

        linear = _linear(expr)
        if linear is not None:
            fact, coefficient, constant = linear
            if coefficient == 0:
                raise ConstraintError(f"cannot solve constant expression {expr.describe()}")
            delta = value - constant
            if not isinstance(delta, int) or delta % coefficient:
                raise ConstraintError(
                    f"observation {value!r} cannot satisfy linear expression {expr.describe()}"
                )
            self._bind_fact(fact, delta // coefficient, source)
        else:
            dependencies = expr.dependencies
            if dependencies:
                missing = dependencies - self._bindings.keys()
                if missing:
                    raise ConstraintError(
                        f"cannot bind {expr.describe()}: expression is not invertible and depends on "
                        f"{', '.join(sorted(missing))}"
                    )
            actual = self._eval(expr)
            if actual != value:
                raise ConstraintError(
                    f"observation contradicts {expr.describe()}: expected {actual!r}, received {value!r}"
                )
        return self._resolved(expr, value, source)

    def _bind_fact(self, fact: Expr, value: Any, source: str) -> None:
        validator = getattr(fact.sort, "validate", None)
        if callable(validator):
            value = validator(value)
        value = _snapshot_value(value)
        key = fact.name or "<unnamed>"
        existing = self._bindings.get(key)
        instance = self._epoch_for(fact.scope)
        if existing is not None:
            existing_sort = getattr(existing.sort, "semantic_identity", None)
            requested_sort = getattr(fact.sort, "semantic_identity", None)
            has_sort = existing_sort is not None or requested_sort is not None
            if has_sort and existing_sort != requested_sort:
                raise ConstraintError(
                    f"conflicting fact semantics for {key}: existing sort "
                    f"{getattr(existing.sort, 'name', None)!r}, new sort "
                    f"{getattr(fact.sort, 'name', None)!r}"
                )
            if existing.scope != fact.scope:
                raise ConstraintError(
                    f"conflicting fact semantics for {key}: existing scope "
                    f"{existing.scope!r}, new scope {fact.scope!r}"
                )
            if existing.space != fact.space:
                raise ConstraintError(
                    f"conflicting fact semantics for {key}: existing artifact "
                    f"{existing.space!r}, new artifact {fact.space!r}"
                )
            if (
                existing.instance_id == instance
                and existing.value != value
                and key not in self._replaceable
            ):
                raise ConstraintError(
                    f"conflicting values for {key}: {existing.value!r} from "
                    f"{existing.source or 'an earlier binding'} and {value!r} from {source or 'a new binding'}"
                )
        self._generation += 1
        self._bindings[key] = _Binding(
            value,
            source,
            fact.scope,
            instance,
            fact.sort,
            fact.space,
            self._generation,
        )

    def resolve(self, value: Any) -> Any:
        if isinstance(value, Resolved):
            self._validate_instance(value)
            return _snapshot_value(value.value)
        if not isinstance(value, Expr):
            converter = getattr(value, "expr", None)
            if not callable(converter):
                return value
            value = converter()
            if not isinstance(value, Expr):
                return value
        return self._eval(value)

    def _eval(self, expr: Expr) -> Any:
        if expr.is_literal:
            return expr.value
        if expr.is_fact:
            key = expr.name or "<unnamed>"
            binding = self._bindings.get(key)
            if binding is None:
                raise UnresolvedValueError(
                    f"{expr.describe()} is unresolved; it requires a declaration or runtime observation"
                )
            current_epoch = self._epoch_for(binding.scope)
            if binding.instance_id is not None and current_epoch != binding.instance_id:
                raise StaleValueError(
                    f"{expr.describe()} belongs to {binding.scope} epoch "
                    f"{binding.instance_id!r}; the current epoch is {current_epoch!r}"
                )
            requested_sort = getattr(expr.sort, "semantic_identity", None)
            binding_sort = getattr(binding.sort, "semantic_identity", None)
            if requested_sort is not None and requested_sort != binding_sort:
                raise ConstraintError(
                    f"{expr.describe()} requires sort "
                    f"{getattr(expr.sort, 'name', '<unknown>')!r}, but the binding "
                    "has incompatible semantics"
                )
            validator = getattr(expr.sort, "validate", None)
            if callable(validator):
                return _snapshot_value(validator(binding.value))
            return _snapshot_value(binding.value)
        args = [self._eval(value) for value in expr.operands]
        return _apply(expr.op, args)

    def has(self, expression: Expr) -> bool:
        try:
            self.resolve(expression)
        except (UnresolvedValueError, StaleValueError):
            return False
        return True

    def explain(self, expression: Expr) -> str:
        expr = as_expr(expression)
        lines = [expr.describe()]
        for dependency in sorted(expr.dependencies):
            binding = self._bindings.get(dependency)
            if binding is None:
                lines.append(f"  <- {dependency}: unresolved")
            else:
                evidence = f" from {binding.source}" if binding.source else ""
                lines.append(f"  <- {dependency}: {binding.value!r}{evidence}")
        return "\n".join(lines)

    def resolved(self, expression: Expr) -> Resolved:
        expr = as_expr(expression)
        return self._resolved(expr, self.resolve(expr), "derived")

    def invalidate(self, *values: Expr | str) -> None:
        """Forget facts explicitly invalidated by a stateful custom action."""

        names: set[str] = set()
        for value in values:
            if isinstance(value, Expr):
                if value.is_fact:
                    key = value.name or "<unnamed>"
                    binding = self._bindings.get(key)
                    if binding is not None:
                        requested_sort = getattr(
                            value.sort,
                            "semantic_identity",
                            None,
                        )
                        binding_sort = getattr(
                            binding.sort,
                            "semantic_identity",
                            None,
                        )
                        if (
                            requested_sort != binding_sort
                            or value.scope != binding.scope
                            or value.space != binding.space
                        ):
                            raise ConstraintError(
                                f"invalidation for {key!r} has incompatible fact semantics"
                            )
                names.update(value.dependencies)
            elif isinstance(value, str):
                names.add(value)
            else:
                raise TypeError("invalidations must be symbolic expressions or fact names")
        for name in names:
            if name in _SCOPE_ORDER:
                for key, binding in list(self._bindings.items()):
                    if binding.scope == name:
                        self._bindings.pop(key, None)
                continue
            for key in list(self._bindings):
                if key == name or key.startswith(name + "."):
                    self._bindings.pop(key, None)

    def _resolved(self, expr: Expr, value: Any, evidence: str) -> Resolved:
        instance = self._epoch_for(expr.scope)
        return Resolved(_snapshot_value(value), expr, instance, evidence)

    def _validate_instance(self, value: Resolved) -> None:
        current_epoch = self._epoch_for(value.source.scope)
        if value.instance_id is not None and value.instance_id != current_epoch:
            raise StaleValueError(
                f"{value.source.describe()} belongs to {value.source.scope} epoch "
                f"{value.instance_id!r}; the current epoch is {current_epoch!r}"
            )


def _apply(op: str, args: list[Any]) -> Any:
    if op == "add":
        return args[0] + args[1]
    if op == "sub":
        return args[0] - args[1]
    if op == "mul":
        return args[0] * args[1]
    if op == "and":
        return args[0] & args[1]
    if op == "or":
        return args[0] | args[1]
    if op == "xor":
        return args[0] ^ args[1]
    if op == "lshift":
        return args[0] << args[1]
    if op == "rshift":
        return args[0] >> args[1]
    if op == "eq":
        return args[0] == args[1]
    if op == "low":
        return args[0] & ((1 << args[1]) - 1)
    raise UnresolvedValueError(f"unsupported symbolic operation {op!r}")


def _linear(expr: Expr) -> tuple[Expr, int, int] | None:
    """Return ``fact, coefficient, constant`` for a one-variable integer expression."""

    if expr.is_fact:
        return expr, 1, 0
    if expr.is_literal:
        if isinstance(expr.value, int):
            return None
        return None
    if expr.op not in {"add", "sub", "mul"}:
        return None
    left, right = expr.operands
    left_linear = _linear(left)
    right_linear = _linear(right)
    left_literal = left.value if left.is_literal and isinstance(left.value, int) else None
    right_literal = right.value if right.is_literal and isinstance(right.value, int) else None

    if expr.op == "add":
        if left_linear and right_literal is not None:
            fact, coefficient, constant = left_linear
            return fact, coefficient, constant + right_literal
        if right_linear and left_literal is not None:
            fact, coefficient, constant = right_linear
            return fact, coefficient, constant + left_literal
    elif expr.op == "sub":
        if left_linear and right_literal is not None:
            fact, coefficient, constant = left_linear
            return fact, coefficient, constant - right_literal
        if right_linear and left_literal is not None:
            fact, coefficient, constant = right_linear
            return fact, -coefficient, left_literal - constant
    elif expr.op == "mul":
        if left_linear and right_literal is not None:
            fact, coefficient, constant = left_linear
            return fact, coefficient * right_literal, constant * right_literal
        if right_linear and left_literal is not None:
            fact, coefficient, constant = right_linear
            return fact, coefficient * left_literal, constant * left_literal
    return None
