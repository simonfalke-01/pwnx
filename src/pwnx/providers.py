"""Generic provider and strategy graph for pwnx 0.3."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from .domain import (
    Capability,
    Constraint,
    Evidence,
    Fact,
    TechniqueProof,
    requirement_satisfied,
)
from .errors import PlanningError


def semantic_key(value: Any) -> str:
    if isinstance(value, Fact):
        return (
            f"fact:{value.key}:sort={value.sort.semantic_identity!r}:"
            f"scope={value.scope.value}:artifact={value.artifact!r}"
        )
    if isinstance(value, Capability):
        contract = value.contract
        return (
            f"capability:{value.name}:scope={contract.scope.value}:"
            f"reads={sorted(contract.reads)!r}:writes={sorted(contract.writes)!r}:"
            f"provides={[semantic_key(item) for item in contract.provides]!r}"
        )
    key = getattr(value, "key", None)
    if isinstance(key, str):
        return f"fact:{key}"
    if isinstance(value, str):
        return value if ":" in value else f"capability:{value}"
    raise TypeError(f"cannot use {type(value).__name__} as a provider product")


def satisfies(available: Any, required: Any) -> bool:
    if isinstance(available, str) or isinstance(required, str):
        try:
            return semantic_key(available) == semantic_key(required)
        except TypeError:
            return False
    return requirement_satisfied(available, required)


@dataclass(frozen=True, slots=True)
class ProviderContext:
    target: Any = None
    values: Mapping[str, Any] = field(default_factory=dict)
    capabilities: tuple[Capability, ...] = ()
    policy: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Provider:
    name: str
    requires: tuple[Any, ...]
    provides: tuple[Any, ...]
    lower: Callable[[ProviderContext], Iterable[Any]]
    supports: Callable[[ProviderContext], bool] = lambda _context: True
    reliability: str = "conditional"
    cost: int = 0
    evidence: tuple[Evidence, ...] = ()
    kind: str = "fact"

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("provider name must not be empty")
        if not self.provides:
            raise ValueError("provider must declare at least one product")
        if self.cost < 0:
            raise ValueError("provider cost cannot be negative")

    @property
    def requirement_keys(self) -> frozenset[str]:
        return frozenset(semantic_key(item) for item in self.requires)

    @property
    def product_keys(self) -> frozenset[str]:
        return frozenset(semantic_key(item) for item in self.provides)

    def score(self) -> tuple[int, int, str]:
        reliability = {"stable": 0, "conditional": 1, "experimental": 2}
        return reliability.get(self.reliability, 3), self.cost, self.name


@dataclass(frozen=True, slots=True)
class GoalRequest:
    name: str
    requires: tuple[Any, ...] = ()
    constraints: tuple[Any, ...] = ()
    intent: Any = None

    def describe(self) -> str:
        describe = getattr(self.intent, "describe", None)
        if callable(describe):
            return str(describe())
        return self.name.replace(".", " ").replace("-", " ")


@dataclass(frozen=True, slots=True)
class GoalStrategy:
    name: str
    goal: str | Callable[[GoalRequest], bool]
    requires: tuple[Any, ...]
    lower: Callable[[ProviderContext, GoalRequest], Iterable[Any]]
    supports: Callable[[ProviderContext, GoalRequest], bool] = lambda _context, _goal: True
    reliability: str = "conditional"
    cost: int = 0
    evidence: tuple[Evidence, ...] = ()
    assumptions: tuple[str, ...] = ()

    def matches(self, goal: GoalRequest) -> bool:
        return self.goal == goal.name if isinstance(self.goal, str) else self.goal(goal)

    def score(self) -> tuple[int, int, str]:
        reliability = {"stable": 0, "conditional": 1, "experimental": 2}
        return reliability.get(self.reliability, 3), self.cost, self.name


@dataclass(frozen=True, slots=True)
class ProviderSelection:
    providers: tuple[Provider, ...]
    actions: tuple[Any, ...]
    known: frozenset[str]
    rejected: tuple[str, ...] = ()


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, Provider] = {}
        self._strategies: dict[str, GoalStrategy] = {}

    @property
    def providers(self) -> tuple[Provider, ...]:
        return tuple(self._providers.values())

    @property
    def strategies(self) -> tuple[GoalStrategy, ...]:
        return tuple(self._strategies.values())

    def clone(self) -> "ProviderRegistry":
        """Return an independent registry containing the same immutable entries."""

        copied = ProviderRegistry()
        for provider in self.providers:
            copied.register(provider)
        for strategy in self.strategies:
            copied.register_strategy(strategy)
        return copied

    def register(self, provider: Provider) -> Provider:
        if provider.name in self._providers:
            raise ValueError(f"provider {provider.name!r} is already registered")
        self._providers[provider.name] = provider
        return provider

    def register_strategy(self, strategy: GoalStrategy) -> GoalStrategy:
        if strategy.name in self._strategies:
            raise ValueError(f"strategy {strategy.name!r} is already registered")
        self._strategies[strategy.name] = strategy
        return strategy

    def provider(
        self,
        *,
        name: str,
        requires=(),
        provides=(),
        supports=lambda _context: True,
        reliability="conditional",
        cost=0,
        evidence=(),
        kind="fact",
    ):
        def decorate(function):
            return self.register(
                Provider(
                    name,
                    tuple(requires),
                    tuple(provides),
                    function,
                    supports,
                    reliability,
                    cost,
                    tuple(evidence),
                    kind,
                )
            )

        return decorate

    def strategy(
        self,
        *,
        name: str,
        goal,
        requires=(),
        supports=lambda _context, _goal: True,
        reliability="conditional",
        cost=0,
        evidence=(),
        assumptions=(),
    ):
        def decorate(function):
            return self.register_strategy(
                GoalStrategy(
                    name,
                    goal,
                    tuple(requires),
                    function,
                    supports,
                    reliability,
                    cost,
                    tuple(evidence),
                    tuple(assumptions),
                )
            )

        return decorate

    def candidates(self, product: Any, context: ProviderContext) -> tuple[Provider, ...]:
        return tuple(
            sorted(
                (
                    provider
                    for provider in self._providers.values()
                    if any(satisfies(item, product) for item in provider.provides)
                    and provider.supports(context)
                ),
                key=Provider.score,
            )
        )

    def goal_candidates(
        self, goal: GoalRequest, context: ProviderContext
    ) -> tuple[GoalStrategy, ...]:
        configured = context.policy.get("strategy_order", ())
        allowed_value = context.policy.get("allowed_strategies")
        allowed = (
            frozenset(str(name) for name in allowed_value)
            if isinstance(allowed_value, (tuple, list, set, frozenset))
            else None
        )
        order: dict[str, int] = {}
        if isinstance(configured, (tuple, list)):
            order = {str(name): index for index, name in enumerate(configured)}
        return tuple(
            sorted(
                (
                    strategy
                    for strategy in self._strategies.values()
                    if strategy.matches(goal)
                    and (allowed is None or strategy.name in allowed)
                    and strategy.supports(context, goal)
                ),
                key=lambda strategy: (
                    order.get(strategy.name, len(order)),
                    *strategy.score(),
                ),
            )
        )


class ProviderPlanner:
    def __init__(self, registry: ProviderRegistry) -> None:
        self.registry = registry

    def acquire(
        self,
        required: Iterable[Any],
        *,
        known: Iterable[Any] = (),
        context: ProviderContext | None = None,
    ) -> ProviderSelection:
        context = context or ProviderContext()
        available = list(known)
        selected: list[Provider] = []
        actions: list[Any] = []
        rejected: list[str] = []
        visiting: set[str] = set()

        def ensure(product: Any) -> None:
            key = semantic_key(product)
            if any(satisfies(item, product) for item in available):
                return
            if key in visiting:
                raise PlanningError(f"provider cycle while acquiring {key}")
            visiting.add(key)
            candidates = self.registry.candidates(product, context)
            if not candidates:
                raise PlanningError(f"no provider can acquire {key}")
            last_error: Exception | None = None
            for provider in candidates:
                checkpoint = (
                    len(available),
                    len(selected),
                    len(actions),
                )
                try:
                    for dependency in provider.requires:
                        ensure(dependency)
                    lowered = tuple(provider.lower(context))
                    selected.append(provider)
                    actions.extend(lowered)
                    available.extend(provider.provides)
                    visiting.remove(key)
                    return
                except PlanningError as error:
                    last_error = error
                    rejected.append(f"{provider.name}: {error}")
                    del available[checkpoint[0] :]
                    del selected[checkpoint[1] :]
                    del actions[checkpoint[2] :]
            visiting.remove(key)
            raise PlanningError(
                f"all providers for {key} failed: {last_error or 'unknown failure'}"
            )

        for product in required:
            ensure(product)
        return ProviderSelection(
            tuple(selected),
            tuple(actions),
            frozenset(semantic_key(item) for item in available),
            tuple(rejected),
        )

    def prove(
        self,
        goal: GoalRequest,
        *,
        known: Iterable[Any] = (),
        context: ProviderContext | None = None,
    ) -> TechniqueProof:
        context = context or ProviderContext()
        known_items = tuple(known)
        known_keys = frozenset(semantic_key(item) for item in known_items)
        constraint_values = {
            **context.values,
            "goal": goal,
            "known": known_keys,
            "capabilities": context.capabilities,
            "policy": context.policy,
        }
        for constraint in goal.constraints:
            if not _constraint_passes(constraint, constraint_values):
                name = getattr(constraint, "name", repr(constraint))
                explanation = getattr(constraint, "explanation", "")
                detail = f": {explanation}" if explanation else ""
                raise PlanningError(f"goal constraint {name!r} is not satisfied{detail}")
        candidates = self.registry.goal_candidates(goal, context)
        if not candidates:
            raise PlanningError(f"no strategy supports goal {goal.name!r}")
        rejected: list[str] = []
        for strategy in candidates:
            try:
                acquisition = self.acquire(
                    (*goal.requires, *strategy.requires),
                    known=known_items,
                    context=context,
                )
                actions = acquisition.actions + tuple(strategy.lower(context, goal))
                return TechniqueProof(
                    strategy.name,
                    goal.name,
                    actions,
                    (*goal.requires, *strategy.requires),
                    assumptions=strategy.assumptions,
                    rejected_alternatives=tuple(rejected + list(acquisition.rejected)),
                    reliability=strategy.reliability,
                    cost=strategy.cost + sum(provider.cost for provider in acquisition.providers),
                    evidence=strategy.evidence
                    + tuple(
                        evidence
                        for provider in acquisition.providers
                        for evidence in provider.evidence
                    ),
                )
            except PlanningError as error:
                rejected.append(f"{strategy.name}: {error}")
        raise PlanningError(f"all strategies for {goal.name!r} failed: {'; '.join(rejected)}")


def _constraint_passes(constraint: Any, values: Mapping[str, Any]) -> bool:
    """Evaluate a declarative goal constraint or reject an invalid contract."""

    if isinstance(constraint, Constraint):
        return constraint.check(values)
    check = getattr(constraint, "check", None)
    if callable(check):
        return bool(check(values))
    if callable(constraint):
        return bool(constraint(values))
    raise PlanningError(f"goal constraint {constraint!r} is not a Constraint or callable predicate")
