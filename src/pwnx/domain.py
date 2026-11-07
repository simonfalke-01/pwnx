"""Purpose-native semantic types for pwnx 0.3.

The domain layer is deliberately independent from transports, ELF parsers, and
exploit techniques.  Backends consume these contracts; solve authors reason in
facts, capabilities, goals, evidence, environments, and experiments.
"""

from __future__ import annotations

import hashlib
import json
import types
import uuid
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Generic, Iterable, Mapping, TypeVar, cast

from .errors import ConstraintError, StaleValueError, UnresolvedValueError
from .expressions import Expr


T = TypeVar("T")


def _semantic_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _stable_semantic_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, Enum):
        return {
            "enum": f"{type(value).__module__}.{type(value).__qualname__}",
            "value": value.value,
        }
    if isinstance(value, type):
        return {"type": f"{value.__module__}.{value.__qualname__}"}
    if isinstance(value, (tuple, list)):
        return [_stable_semantic_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        encoded = [_stable_semantic_value(item) for item in value]
        return sorted(encoded, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, Mapping):
        return {
            str(key): _stable_semantic_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, types.CodeType):
        return {
            "code": value.co_code.hex(),
            "consts": _stable_semantic_value(value.co_consts),
            "names": list(value.co_names),
        }
    raise ValueError(
        f"value of type {type(value).__qualname__} has no stable semantic identity; "
        "declare semantic_id explicitly"
    )


def _callable_semantic_identity(function: Any) -> str | None:
    if function is None:
        return None
    code = getattr(function, "__code__", None)
    if code is None:
        raise ValueError("callable requires an explicit semantic_id")
    closure = getattr(function, "__closure__", None) or ()
    payload = {
        "code": _stable_semantic_value(code),
        "defaults": _stable_semantic_value(getattr(function, "__defaults__", None)),
        "kwdefaults": _stable_semantic_value(getattr(function, "__kwdefaults__", None)),
        "closure": [_stable_semantic_value(cell.cell_contents) for cell in closure],
    }
    return _semantic_digest(payload)


class Scope(str, Enum):
    ARTIFACT = "artifact"
    SERVICE = "service"
    PROCESS = "process"
    CONNECTION = "connection"


@dataclass(frozen=True, slots=True)
class Epochs:
    """Identity of the environment state in which a fact remains valid."""

    service: str = field(default_factory=lambda: uuid.uuid4().hex)
    process: str = field(default_factory=lambda: uuid.uuid4().hex)
    connection: str = field(default_factory=lambda: uuid.uuid4().hex)

    def token(self, scope: Scope) -> str | None:
        return {
            Scope.ARTIFACT: None,
            Scope.SERVICE: self.service,
            Scope.PROCESS: self.process,
            Scope.CONNECTION: self.connection,
        }[scope]

    def reconnect(self, *, same_process: bool = False) -> "Epochs":
        return Epochs(
            self.service,
            self.process if same_process else uuid.uuid4().hex,
            uuid.uuid4().hex,
        )

    def restart_process(self) -> "Epochs":
        return Epochs(self.service, uuid.uuid4().hex, uuid.uuid4().hex)

    def restart_service(self) -> "Epochs":
        return Epochs()


@dataclass(frozen=True, slots=True)
class Sort(Generic[T]):
    name: str
    python_types: tuple[type, ...]
    validator: Callable[[T], bool] | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("sort name must not be empty")
        if not self.python_types:
            raise ValueError("sort requires at least one Python type")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def validate(self, value: Any) -> T:
        if not isinstance(value, self.python_types):
            expected = ", ".join(item.__name__ for item in self.python_types)
            raise ConstraintError(
                f"{self.name} requires {expected}; received {type(value).__name__}"
            )
        checked = cast(T, value)
        if self.validator is not None and not self.validator(checked):
            raise ConstraintError(f"value {value!r} violates {self.name}")
        return checked

    @property
    def semantic_identity(self) -> tuple[Any, ...]:
        return (
            self.name,
            tuple((item.__module__, item.__qualname__) for item in self.python_types),
            _callable_semantic_identity(self.validator),
            json.dumps(
                _stable_semantic_value(self.metadata),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )


INTEGER = Sort[int]("integer", (int,), lambda value: not isinstance(value, bool))
BOOLEAN = Sort[bool]("boolean", (bool,))
BYTES = Sort[bytes]("bytes", (bytes,))
STRING = Sort[str]("string", (str,))
ADDRESS = Sort[int](
    "address",
    (int,),
    lambda value: not isinstance(value, bool) and 0 <= value < 1 << 64,
)
OFFSET = Sort[int](
    "offset",
    (int,),
    lambda value: not isinstance(value, bool) and -(1 << 63) <= value < 1 << 64,
)


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: str
    summary: str
    source: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.kind or not self.summary:
            raise ValueError("evidence kind and summary must not be empty")
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))

    def describe(self) -> str:
        suffix = f" ({self.source})" if self.source else ""
        return f"{self.kind}: {self.summary}{suffix}"


@dataclass(frozen=True, slots=True)
class Fact(Generic[T]):
    name: str
    sort: Sort[T]
    scope: Scope = Scope.PROCESS
    artifact: str | None = None
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("fact name must not be empty")
        if self.sort.name in {"address", "offset"} and self.artifact is None:
            raise ValueError(f"{self.sort.name} facts require an artifact identity")

    @property
    def key(self) -> str:
        return self.name

    @property
    def dependencies(self) -> set[str]:
        return {self.name}

    def expr(self) -> Expr:
        return Expr.fact(
            self.name,
            scope=self.scope.value,
            kind=self.sort.name,
            space=self.artifact,
            label=self.description or self.name,
            sort=self.sort,
        )

    def describe(self) -> str:
        return self.description or self.name


@dataclass(frozen=True, slots=True)
class FactValue(Generic[T]):
    fact: Fact[T]
    value: T
    epoch: str | None
    evidence: tuple[Evidence, ...] = ()


def fact_satisfies(available: Fact[Any], required: Fact[Any]) -> bool:
    return (
        available.name == required.name
        and available.sort.semantic_identity == required.sort.semantic_identity
        and available.scope == required.scope
        and available.artifact == required.artifact
    )


class FactStore:
    """Typed values with independent service/process/connection epochs."""

    def __init__(self, epochs: Epochs | None = None) -> None:
        self.epochs = epochs or Epochs()
        self._values: dict[str, FactValue[Any]] = {}

    def bind(
        self,
        fact: Fact[T],
        value: Any,
        *,
        evidence: Iterable[Evidence] = (),
    ) -> FactValue[T]:
        checked = fact.sort.validate(value)
        bound = FactValue(
            fact,
            checked,
            self.epochs.token(fact.scope),
            tuple(evidence),
        )
        existing = self._values.get(fact.key)
        current_epoch = self.epochs.token(fact.scope)
        if existing is not None:
            if not fact_satisfies(existing.fact, fact):
                raise ConstraintError(f"binding for {fact.name!r} has incompatible fact semantics")
            if existing.epoch == current_epoch and existing.value != checked:
                raise ConstraintError(
                    f"conflicting bindings for {fact.name}: {existing.value!r} and {checked!r}"
                )
        self._values[fact.key] = bound
        return bound

    def resolve(self, fact: Fact[T]) -> T:
        value = self._values.get(fact.key)
        if value is None:
            raise UnresolvedValueError(f"{fact.name} is unresolved")
        expected = self.epochs.token(fact.scope)
        if value.epoch != expected:
            raise StaleValueError(
                f"{fact.name} belongs to {fact.scope.value} epoch "
                f"{value.epoch!r}; current epoch is {expected!r}"
            )
        return fact.sort.validate(value.value)

    def has(self, fact: Fact[Any]) -> bool:
        try:
            self.resolve(fact)
        except (UnresolvedValueError, StaleValueError):
            return False
        return True

    def invalidate(
        self,
        *,
        facts: Iterable[Fact[Any]] = (),
        scopes: Iterable[Scope] = (),
    ) -> None:
        names = {item.key for item in facts}
        selected_scopes = set(scopes)
        for key, value in tuple(self._values.items()):
            if key in names or value.fact.scope in selected_scopes:
                self._values.pop(key, None)

    def transition(self, epochs: Epochs) -> None:
        self.epochs = epochs

    def evidence(self, fact: Fact[Any]) -> tuple[Evidence, ...]:
        value = self._values.get(fact.key)
        return value.evidence if value is not None else ()


@dataclass(frozen=True, slots=True)
class Constraint:
    name: str
    predicate: Callable[[Mapping[str, Any]], bool] | None = None
    explanation: str = ""
    semantic_id: str | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("constraint name must not be empty")
        if self.semantic_id is not None and not self.semantic_id:
            raise ValueError("constraint semantic_id must not be empty")

    def check(self, values: Mapping[str, Any]) -> bool:
        return True if self.predicate is None else bool(self.predicate(values))

    @property
    def semantic_identity(self) -> str:
        if self.semantic_id is not None:
            return f"explicit:{self.semantic_id}"
        predicate = _callable_semantic_identity(self.predicate)
        payload = {
            "name": self.name,
            "predicate": predicate,
            "explanation": self.explanation,
        }
        return f"derived:{_semantic_digest(payload)}"


@dataclass(frozen=True, slots=True)
class EffectContract:
    requires: tuple[Any, ...] = ()
    provides: tuple[Any, ...] = ()
    reads: frozenset[str] = frozenset()
    writes: frozenset[str] = frozenset()
    invalidates: tuple[Any, ...] = ()
    scope: Scope = Scope.PROCESS
    constraints: tuple[Constraint, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def merge(self, other: "EffectContract") -> "EffectContract":
        return EffectContract(
            self.requires + other.requires,
            self.provides + other.provides,
            self.reads | other.reads,
            self.writes | other.writes,
            canonical_invalidations((*self.invalidates, *other.invalidates)),
            max((self.scope, other.scope), key=_scope_rank),
            self.constraints + other.constraints,
            self.evidence + other.evidence,
        )


def _scope_rank(scope: Scope) -> int:
    return {
        Scope.ARTIFACT: 0,
        Scope.SERVICE: 1,
        Scope.PROCESS: 2,
        Scope.CONNECTION: 3,
    }[scope]


def invalidation_semantic_key(value: Any) -> tuple[Any, ...]:
    if isinstance(value, Fact):
        return (
            "fact",
            value.name,
            value.sort.semantic_identity,
            value.scope.value,
            value.artifact,
        )
    if isinstance(value, Expr):
        sort = getattr(value.sort, "semantic_identity", None)
        if value.is_fact:
            return (
                "fact",
                value.name,
                sort,
                value.scope,
                value.space,
            )
        return (
            "expr",
            value.key,
            value.scope,
            value.kind,
            value.space,
            sort,
        )
    if isinstance(value, Scope):
        return ("scope", value.value)
    if isinstance(value, str):
        if value in {item.value for item in Scope}:
            return ("scope", value)
        return ("name", value)
    raise TypeError(
        "invalidations must be Fact, Expr, Scope, or string values; "
        f"received {type(value).__name__}"
    )


def canonical_invalidations(values: Iterable[Any]) -> tuple[Any, ...]:
    result: list[Any] = []
    seen: set[tuple[Any, ...]] = set()
    for value in values:
        key = invalidation_semantic_key(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class Capability:
    name: str
    contract: EffectContract
    reliability: str = "conditional"
    cost: int = 0
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("capability name must not be empty")
        if self.cost < 0:
            raise ValueError("capability cost cannot be negative")

    def describe(self) -> str:
        return f"{self.name} [{self.reliability}, cost={self.cost}]"


def effect_contract_satisfies(
    available: EffectContract,
    required: EffectContract,
) -> bool:
    if available.scope != required.scope:
        return False
    if not required.reads.issubset(available.reads):
        return False
    if not required.writes.issubset(available.writes):
        return False
    if not all(
        any(requirement_satisfied(product, needed) for product in available.provides)
        for needed in required.provides
    ):
        return False
    if not all(
        any(requirement_satisfied(item, needed) for item in available.requires)
        for needed in required.requires
    ):
        return False
    available_invalidations = {invalidation_semantic_key(item) for item in available.invalidates}
    required_invalidations = {invalidation_semantic_key(item) for item in required.invalidates}
    if not required_invalidations.issubset(available_invalidations):
        return False
    available_constraints = {item.semantic_identity for item in available.constraints}
    return all(item.semantic_identity in available_constraints for item in required.constraints)


def requirement_satisfied(available: Any, required: Any) -> bool:
    """One structural satisfaction relation for facts and capabilities."""

    if isinstance(required, Fact):
        if isinstance(available, Fact):
            return fact_satisfies(available, required)
        if isinstance(available, Expr) and available.is_fact:
            sort = getattr(available, "sort", None)
            return (
                available.name == required.name
                and isinstance(sort, Sort)
                and sort.semantic_identity == required.sort.semantic_identity
                and available.scope == required.scope.value
                and available.space == required.artifact
            )
        return False
    if isinstance(required, Capability):
        return isinstance(available, Capability) and effect_contract_satisfies(
            available.contract, required.contract
        )
    if isinstance(required, Expr):
        return isinstance(available, Expr) and available == required
    return available == required


@dataclass(frozen=True, slots=True)
class TechniqueProof:
    strategy: str
    goal: str
    actions: tuple[Any, ...]
    prerequisites: tuple[Any, ...] = ()
    assumptions: tuple[str, ...] = ()
    rejected_alternatives: tuple[str, ...] = ()
    reliability: str = "conditional"
    cost: int = 0
    evidence: tuple[Evidence, ...] = ()

    def describe(self) -> str:
        return f"{self.strategy} proves {self.goal} [{self.reliability}, cost={self.cost}]"


@dataclass(frozen=True, slots=True)
class Environment:
    adapter: str
    config: Mapping[str, Any] = field(default_factory=dict)
    service_lifecycle: str = "persistent"
    process_lifecycle: str = "fresh-per-run"
    connection_lifecycle: str = "fresh-per-run"
    artifacts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.adapter:
            raise ValueError("environment adapter must not be empty")
        object.__setattr__(self, "config", MappingProxyType(dict(self.config)))

    def with_config(self, **changes: Any) -> "Environment":
        return Environment(
            self.adapter,
            {**self.config, **changes},
            self.service_lifecycle,
            self.process_lifecycle,
            self.connection_lifecycle,
            self.artifacts,
        )

    def describe(self) -> str:
        return f"{self.adapter} environment ({self.process_lifecycle})"


@dataclass(frozen=True, slots=True)
class TargetRecipe:
    name: str
    environment: Environment
    images: tuple[str, ...]
    argv: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("target recipe name must not be empty")
        object.__setattr__(self, "env", MappingProxyType(dict(self.env)))

    def describe(self) -> str:
        return f"{self.name}: {self.environment.describe()}, {len(self.images)} artifact(s)"
