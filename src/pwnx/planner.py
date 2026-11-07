"""Deterministic lowering from declarations to an inspectable action plan."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .actions import (
    Action,
    ActionPlanningContext,
    Branch,
    Capture,
    Delay,
    Emit,
    Sequence,
    action_origin,
    capture,
    sequence,
)
from .challenge import Control, DynamicCall, Goal, Learn, Opaque, Tactic
from .channels import raw
from .domain import (
    Capability,
    Constraint,
    Fact,
    Scope,
    canonical_invalidations,
    invalidation_semantic_key,
    requirement_satisfied,
)
from .errors import PlanningError, UnsupportedFeature
from .expressions import Call, Expr
from .formats import (
    DeferredFormatPayload,
    FormatControl,
    FormatLeak,
    FormatOffsetDiscovery,
    FormatWrite,
)
from .payload import Payload
from .providers import (
    GoalRequest,
    GoalStrategy,
    ProviderContext,
    ProviderPlanner,
)
from .techniques import ROPCompiler, build_dlresolve


@dataclass(frozen=True)
class Stage:
    name: str
    actions: tuple[Any, ...]
    reason: str = ""

    def describe(self, *, expanded: bool = False) -> str:
        lines = [self.name]
        if self.reason:
            lines.append(f"  reason: {self.reason}")
        for action in self.actions:
            description = (
                action.describe()
                if expanded or not isinstance(action, Sequence)
                else _compact_sequence(action)
            )
            for index, line in enumerate(description.splitlines()):
                lines.append(f"  {'- ' if index == 0 else '  '}{line}")
        effects = _stage_effects(self.actions)
        if effects["reads"] or effects["writes"] or effects["invalidates"]:
            lines.append(
                "  effects: "
                f"reads={','.join(effects['reads']) or '-'}; "
                f"writes={','.join(effects['writes']) or '-'}; "
                f"invalidates={','.join(effects['invalidates']) or '-'}"
            )
        return "\n".join(lines)


def _compact_sequence(action: Sequence) -> str:
    lines = [f"{action.name}:"]
    for child in action.actions:
        if isinstance(child, Sequence):
            lines.append(f"  - {child.name}")
            continue
        description = child.describe() if hasattr(child, "describe") else repr(child)
        child_lines = description.splitlines()
        lines.append(f"  - {child_lines[0]}")
        lines.extend(f"    {line}" for line in child_lines[1:])
    return "\n".join(lines)


@dataclass
class Plan:
    challenge: Any
    stages: list[Stage]
    selected_tactic: str
    alternatives: tuple[dict[str, str], ...] = ()
    assumptions: tuple[str, ...] = ()
    rejected: tuple[dict[str, str], ...] = ()
    auto_interactive: bool = False
    effect_barriers: tuple[dict[str, Any], ...] = ()

    @property
    def selected(self):
        return self

    @property
    def actions(self):
        return tuple(action for stage in self.stages for action in stage.actions)

    def show(self) -> str:
        goals = ", ".join(_describe(goal.effect) for goal in self.challenge._goals)
        lines = [
            f"Goal: {goals}",
            f"Selected tactic: {self.selected_tactic}",
            "",
        ]
        for stage in self.stages:
            lines.extend((stage.describe(), ""))
        if self.alternatives:
            lines.append("Alternatives")
            lines.extend(f"  {item['name']}: {item['reason']}" for item in self.alternatives)
        if self.assumptions:
            lines.append("Assumptions")
            lines.extend(f"  - {value}" for value in self.assumptions)
        if self.effect_barriers:
            lines.append("Effect ordering")
            counts: dict[tuple[str, ...], int] = {}
            for item in self.effect_barriers:
                key = tuple(item["domains"])
                counts[key] = counts.get(key, 0) + 1
            lines.extend(
                f"  - {', '.join(domains)}: {count} ordered transition(s)"
                for domains, count in sorted(counts.items())
            )
        return "\n".join(lines).rstrip()

    def expand(self, stage: int | str) -> str:
        """Render the raw action choreography for one semantic stage."""

        selected: Stage | None = None
        if isinstance(stage, int):
            try:
                selected = self.stages[stage]
            except IndexError as error:
                raise PlanningError(f"plan has no stage at index {stage}") from error
        else:
            selected = next((item for item in self.stages if item.name == stage), None)
        if selected is None:
            raise PlanningError(f"plan has no stage named {stage!r}")
        return selected.describe(expanded=True)

    def explain_selection(self) -> str:
        lines = [f"selected {self.selected_tactic}"]
        lines.extend(f"rejected {item['name']}: {item['reason']}" for item in self.rejected)
        lines.extend(f"alternative {item['name']}: {item['reason']}" for item in self.alternatives)
        return "\n".join(lines)

    def explain(self, subject: Any) -> str:
        if hasattr(subject, "describe"):
            description = subject.describe()
            dependencies = sorted(getattr(subject, "dependencies", ()))
            if dependencies:
                return description + "\n  depends on " + ", ".join(dependencies)
            return description
        return repr(subject)

    def payload(self, name: str | int = -1):
        payloads = [
            action.data
            for action in self.actions
            if isinstance(action, Emit) and hasattr(action.data, "layout")
        ]
        if not payloads:
            raise PlanningError("plan contains no structured payloads")
        if isinstance(name, int):
            return payloads[name]
        for stage in self.stages:
            if stage.name == name:
                for action in stage.actions:
                    if isinstance(action, Emit) and hasattr(action.data, "layout"):
                        return action.data
        raise PlanningError(f"plan has no payload named {name!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal": [_describe(goal.effect) for goal in self.challenge._goals],
            "selected_tactic": self.selected_tactic,
            "stages": [
                {
                    "name": stage.name,
                    "reason": stage.reason,
                    "actions": [
                        action.describe() if hasattr(action, "describe") else repr(action)
                        for action in stage.actions
                    ],
                    "effects": _stage_effects(stage.actions),
                }
                for stage in self.stages
            ],
            "alternatives": list(self.alternatives),
            "assumptions": list(self.assumptions),
            "auto_interactive": self.auto_interactive,
            "effect_barriers": list(self.effect_barriers),
        }

    def run(self, **kwargs):
        from .runtime import execute

        run = execute(self, **kwargs)
        if self.auto_interactive:
            run.interactive()
        return run

    def experiment(self, *, environment=None, target=None):
        from .experiment import Experiment

        return Experiment(self, environment=environment, target=target)

    def __str__(self) -> str:
        return self.show()


class RecipeBuilder:
    def __init__(self, challenge):
        self.challenge = challenge

    def sequence(self, *actions, name="recipe"):
        return sequence(*actions, name=name)

    def capture(self, codec, target=None, name="capture"):
        return capture(codec, target, name=name)


@dataclass(frozen=True)
class TechniqueContext:
    challenge: Any
    goal: Goal
    control: Control

    @property
    def images(self):
        return self.challenge.images

    def sequence(self, *actions, name="technique"):
        return sequence(*actions, name=name)

    def capture(self, codec, target=None, name="capture"):
        return capture(codec, target, name=name)

    def rop(self):
        return ROPCompiler(self.challenge.images)


def _describe(value: Any) -> str:
    method = getattr(value, "describe", None)
    return method() if callable(method) else repr(value)


def _dependencies(value: Any) -> set[str]:
    result = set(getattr(value, "dependencies", ()))
    if isinstance(value, Call):
        result.update(value.dependencies)
    if isinstance(value, FormatWrite):
        result.update(getattr(value.control.offset, "dependencies", ()))
        for key, item in value.writes.items():
            result.update(getattr(key, "dependencies", ()))
            result.update(getattr(item, "dependencies", ()))
    return result


def _learn_dependencies(recipe: Learn) -> set[str]:
    result = _dependencies(recipe.using)
    if isinstance(recipe.using, Opaque):
        result.update(set().union(*(value.dependencies for value in recipe.using.consumes)))
    if recipe.resume is not None:
        result.update(recipe.resume.dependencies)
    for requirement in recipe.requires:
        result.update(getattr(requirement, "dependencies", ()))
    return result


def _action_outputs(action: Any) -> set[str]:
    if isinstance(action, Action):
        products = set().union(
            *(getattr(item, "dependencies", set()) for item in action.contract().provides)
        )
    else:
        products = set()
    if isinstance(action, Sequence):
        return products | set().union(*(_action_outputs(child) for child in action.actions))
    if isinstance(action, Branch):
        return _action_outputs(action.then) & _action_outputs(action.otherwise)
    if isinstance(action, Opaque):
        return set().union(*(value.dependencies for value in action.produces))
    output = getattr(action, "output", None)
    return products | (set(getattr(output, "dependencies", ())) if output is not None else set())


def _action_products(action: Any) -> tuple[Any, ...]:
    if isinstance(action, Sequence):
        return tuple(product for child in action.actions for product in _action_products(child))
    if isinstance(action, Branch):
        then_products = _action_products(action.then)
        otherwise_products = _action_products(action.otherwise)
        return tuple(
            product
            for product in then_products
            if any(requirement_satisfied(other, product) for other in otherwise_products)
        )
    return action.contract().provides if isinstance(action, Action) else ()


def _action_requirements(action: Any) -> tuple[Any, ...]:
    if isinstance(action, Sequence):
        return tuple(
            requirement for child in action.actions for requirement in _action_requirements(child)
        )
    if isinstance(action, Branch):
        return (
            action.predicate,
            *_action_requirements(action.then),
            *_action_requirements(action.otherwise),
        )
    return action.contract().requires if isinstance(action, Action) else ()


def _ordered_action_steps(actions: Iterable[Action]) -> tuple[Action, ...]:
    return tuple(
        step
        for action in actions
        for step in (
            _ordered_action_steps(action.actions) if isinstance(action, Sequence) else (action,)
        )
    )


def _action_dependencies(action: Any) -> set[str]:
    if isinstance(action, Action):
        contract_dependencies = set().union(
            *(getattr(item, "dependencies", set()) for item in action.contract().requires)
        )
    else:
        contract_dependencies = set()
    if isinstance(action, Sequence):
        return contract_dependencies | set().union(
            *(_action_dependencies(child) for child in action.actions)
        )
    if isinstance(action, Branch):
        return contract_dependencies | (
            set(action.predicate.dependencies)
            | _action_dependencies(action.then)
            | _action_dependencies(action.otherwise)
        )
    if isinstance(action, Opaque):
        return set().union(*(value.dependencies for value in action.consumes))
    if isinstance(action, Emit):
        return contract_dependencies | set(getattr(action.data, "dependencies", ()))
    if isinstance(action, Capture):
        return set()
    if isinstance(action, Action):
        result: set[str] = contract_dependencies | set(getattr(action, "dependencies", ()))
        for name in ("predicate", "value"):
            result.update(getattr(getattr(action, name, None), "dependencies", ()))
        for value in getattr(action, "consumes", ()):
            result.update(getattr(value, "dependencies", ()))
        return result
    return set()


def _action_invalidations(action: Any) -> tuple[Any, ...]:
    if isinstance(action, Sequence):
        return canonical_invalidations(
            value
            for child in action.actions
            for value in _action_invalidations(child)
        )
    if isinstance(action, Branch):
        return canonical_invalidations(
            (
                *_action_invalidations(action.then),
                *_action_invalidations(action.otherwise),
            )
        )
    contract = action.contract() if isinstance(action, Action) else None
    return canonical_invalidations(
        (
            *getattr(action, "invalidates", ()),
            *(contract.invalidates if contract is not None else ()),
        )
    )


def _action_state_domains(action: Any) -> tuple[set[str], set[str]]:
    if isinstance(action, Sequence):
        reads: set[str] = set()
        writes: set[str] = set()
        for child in action.actions:
            child_reads, child_writes = _action_state_domains(child)
            reads.update(child_reads)
            writes.update(child_writes)
        return reads, writes
    if isinstance(action, Branch):
        then_reads, then_writes = _action_state_domains(action.then)
        else_reads, else_writes = _action_state_domains(action.otherwise)
        return then_reads | else_reads, then_writes | else_writes
    if not isinstance(action, Action):
        return set(), set()
    contract = action.contract()
    return set(contract.reads), set(contract.writes)


def _stage_effects(actions: Iterable[Any]) -> dict[str, list[str]]:
    reads: set[str] = set()
    writes: set[str] = set()
    invalidates: set[str] = set()
    for action in actions:
        action_reads, action_writes = _action_state_domains(action)
        reads.update(action_reads)
        writes.update(action_writes)
        invalidates.update(
            repr(invalidation_semantic_key(item))
            for item in _action_invalidations(action)
        )
    return {
        "reads": sorted(reads),
        "writes": sorted(writes),
        "invalidates": sorted(invalidates),
    }


def _proof_rejections(reasons: Iterable[str]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for reason in reasons:
        name, separator, detail = reason.partition(": ")
        result.append(
            {
                "name": name if separator else "provider/strategy",
                "reason": detail if separator else reason,
            }
        )
    return result


def _lower_action(
    action: Action,
    context: ActionPlanningContext,
    *,
    ancestry: tuple[int, ...] = (),
) -> tuple[Action, ...]:
    if len(ancestry) >= 64:
        raise PlanningError(f"action lowering exceeded 64 steps at {_describe(action)}")
    if id(action) in ancestry:
        raise PlanningError(f"action lowering cycle at {_describe(action)}")
    path = (*ancestry, id(action))
    if isinstance(action, Sequence):
        children = tuple(
            lowered
            for child in action.actions
            for lowered in _lower_action(child, context, ancestry=path)
        )
        return (Sequence(children, action.name),)
    if isinstance(action, Branch):
        then = _lower_action(action.then, context, ancestry=path)
        otherwise = _lower_action(action.otherwise, context, ancestry=path)
        if len(then) != 1 or not isinstance(then[0], Sequence):
            raise PlanningError("a lowered branch then-path must remain one Sequence")
        if len(otherwise) != 1 or not isinstance(otherwise[0], Sequence):
            raise PlanningError("a lowered branch otherwise-path must remain one Sequence")
        return (Branch(action.predicate, then[0], otherwise[0]),)
    lowered = tuple(action.lower(context))
    if any(not isinstance(item, Action) for item in lowered):
        raise PlanningError(f"{_describe(action)} lowered to a non-Action value")
    if len(lowered) == 1 and lowered[0] is action:
        return (action,)
    return tuple(item for child in lowered for item in _lower_action(child, context, ancestry=path))


def _lower_actions(
    actions: Iterable[Action],
    context: ActionPlanningContext,
) -> tuple[Action, ...]:
    return tuple(item for action in actions for item in _lower_action(action, context))


def _control(challenge, goal: Goal | None = None) -> Control:
    selected = goal.via if goal and goal.via is not None else None
    controls = [item for item in challenge._controls if isinstance(item, Control)]
    if selected is not None:
        if not isinstance(selected, Control):
            raise PlanningError("the selected goal route is not return-address control")
        return selected
    if not controls:
        raise PlanningError(
            "the goal requires control-flow transfer; declare c.control(line(...), return_at=N)"
        )
    return controls[0]


def _compile_call(challenge, control: Control, call: Call, *, resume=None) -> Payload:
    chain = ROPCompiler(challenge.images).call(
        call,
        resume=resume,
        entry_sp_mod16=control.entry_sp_mod16,
        forbidden=control.channel.forbidden,
    )
    return (
        Payload(fill=control.fill, forbidden=control.channel.forbidden)
        .pad(control.return_at, fill=control.fill)
        .append(chain)
    )


def _compile_learn(challenge, recipe: Learn, control: Control | None) -> tuple[Any, ...]:
    using = recipe.using
    if callable(using) and not isinstance(using, (Call, Opaque)):
        using = using(RecipeBuilder(challenge))
    if isinstance(using, Call):
        selected_control = recipe.via or control
        if selected_control is None:
            raise PlanningError(
                f"call-based recipe {recipe.name!r} requires return-address control"
            )
        payload = _compile_call(challenge, selected_control, using, resume=recipe.resume)
        actions: list[Any] = [Emit(payload, selected_control.channel)]
        if recipe.receive is not None:
            if len(recipe.targets) != 1:
                raise PlanningError(
                    "one codec cannot bind multiple learn targets; use a struct recipe"
                )
            actions.append(Capture(recipe.receive, recipe.targets[0], recipe.name))
        return tuple(actions)
    if isinstance(using, FormatLeak):
        fmt_control = next(
            (item for item in challenge._controls if isinstance(item, FormatControl)), None
        )
        if fmt_control is None:
            raise PlanningError("format leak requires a declared format-string control")
        return (
            Emit(using.payload, fmt_control.channel),
            Capture(recipe.receive, using.target, recipe.name),
        )
    if isinstance(using, Action):
        actions = [using]
        if recipe.receive is not None:
            if len(recipe.targets) != 1:
                raise PlanningError("one codec cannot bind multiple learn targets")
            actions.append(Capture(recipe.receive, recipe.targets[0], recipe.name))
        return tuple(actions)
    if isinstance(using, Opaque):
        return (using,)
    raise UnsupportedFeature(
        f"recipe {recipe.name!r} uses unsupported operation {_describe(using)}"
    )


def _requested_tactic(goal: Goal) -> str | None:
    using = goal.using
    return using.name if isinstance(using, Tactic) else str(using) if using else None


def _dlresolve_actions(challenge, goal: Goal, effect, control: Control, tactic=None):
    symbol = (
        effect.symbol
        if isinstance(effect, DynamicCall)
        else (effect.name or effect.target.describe()).split(".")[-1]
    )
    args = (
        effect.args
        if isinstance(effect, DynamicCall)
        else tuple(arg.value if arg.is_literal else arg for arg in effect.args)
    )
    built = build_dlresolve(
        challenge.exe,
        symbol,
        args,
        entry_sp_mod16=control.entry_sp_mod16,
        forbidden=control.channel.forbidden,
    )
    first = (
        Payload(fill=control.fill, forbidden=control.channel.forbidden)
        .pad(control.return_at, fill=control.fill)
        .append(built.first_stage)
    )
    options = tactic.options if isinstance(tactic, Tactic) else {}
    stage_delay = float(
        options.get(
            "stage_delay",
            0.0 if control.channel.terminator is not None else 0.05,
        )
    )
    actions: list[Any] = [Emit(first, control.channel)]
    if stage_delay:
        actions.append(Delay(stage_delay, "separate the vulnerable read from the staging read"))
    actions.append(Emit(Payload(built.data), raw(timeout=control.channel.timeout)))
    return tuple(actions), symbol


def build_plan(challenge) -> Plan:
    if not challenge._goals:
        raise PlanningError("the challenge has no goal; declare c.want(...)")
    stages: list[Stage] = []
    provided = {
        dependency
        for expression, _value, _reason in challenge._assumptions
        for dependency in expression.dependencies
    }
    semantic_provided: list[Any] = [
        *(expression for expression, _value, _reason in challenge._assumptions),
        *challenge.capabilities,
    ]

    def planning_context() -> ActionPlanningContext:
        return ActionPlanningContext(
            challenge,
            frozenset(provided),
            tuple(challenge.capabilities),
            dict(challenge._requirements),
        )

    startup = [
        observation
        for observation in challenge._observations
        if observation.source is None or observation.source == "startup"
    ]
    if len(startup) > 1:
        raise PlanningError(
            "multiple startup observations can consume the same stream ambiguously; "
            "combine them into one pattern or attach observations to explicit actions"
        )
    if startup:
        startup_actions = _lower_actions(tuple(startup), planning_context())
        stages.append(
            Stage(
                "Stage 1: observe startup",
                startup_actions,
                "bind natural target output",
            )
        )
        for observation in startup:
            provided.update(observation.pattern.provides)
            semantic_provided.extend(field.target for field in observation.pattern.fields)

    triggered_observations = [
        observation for observation in challenge._observations if observation not in startup
    ]
    format_leaks = [
        (fmt_control, leak)
        for fmt_control in challenge._controls
        if isinstance(fmt_control, FormatControl)
        for leak in fmt_control._leaks
    ]
    format_discoveries: list[FormatOffsetDiscovery] = [
        item.discovery
        for item in challenge._controls
        if isinstance(item, FormatControl) and item.discovery is not None
    ]

    selected_names: list[str] = []
    alternatives: list[dict[str, str]] = []
    rejected: list[dict[str, str]] = []
    compiled_recipes: set[int] = set()
    compiled_derivations: set[int] = set()
    compiled_discoveries: set[int] = set()
    proof_assumptions: list[str] = []
    effect_history: list[tuple[str, set[str], set[str]]] = []
    effect_barriers: list[dict[str, Any]] = []
    barrier_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    provider_context = ProviderContext(
        target=challenge,
        values={"challenge": challenge},
        capabilities=tuple(challenge.capabilities),
        policy=dict(challenge._requirements),
    )

    def provider_known() -> tuple[Any, ...]:
        return (
            *semantic_provided,
            *challenge.capabilities,
            *(f"fact:{name}" for name in sorted(provided)),
        )

    fact_scopes: dict[str, str] = {}

    def register(value: Any) -> None:
        if isinstance(value, Expr):
            if value.is_fact and value.name is not None:
                fact_scopes[value.name] = value.scope
            for operand in value.operands:
                register(operand)
            return
        if isinstance(value, Call):
            register(value.target)
            for argument in value.args:
                register(argument)
            return
        if isinstance(value, Opaque):
            for expression in (*value.consumes, *value.produces):
                register(expression)
            return
        if isinstance(value, Sequence):
            for action in value.actions:
                register(action)
            return
        if isinstance(value, Branch):
            register(value.predicate)
            register(value.then)
            register(value.otherwise)
            return
        for name in ("target", "value", "predicate", "output"):
            candidate_expr: Any = getattr(value, name, None)
            if isinstance(candidate_expr, Expr):
                register(candidate_expr)
        data: Any = getattr(value, "data", None)
        if isinstance(data, Expr):
            register(data)
        else:
            encoded_value: Any = getattr(data, "value", None)
            if isinstance(encoded_value, Expr):
                register(encoded_value)

    for image in challenge.images:
        register(image.base)
    for expression, _value, _reason in challenge._assumptions:
        register(expression)
    for observation in challenge._observations:
        for pattern_field in observation.pattern.fields:
            register(pattern_field.target)
    for recipe in challenge._learns:
        for expression in recipe.targets:
            register(expression)
        register(recipe.using)
        if recipe.resume is not None:
            register(recipe.resume)
    for derivation in challenge._derivations:
        register(derivation.target)
        for value in derivation.inputs:
            register(value)
    for action in challenge._sequences:
        register(action)
    for goal in challenge._goals:
        register(goal.effect)

    def invalidate(values: Iterable[Any]) -> None:
        for value in values:
            if isinstance(value, Fact):
                provided.discard(value.name)
                semantic_provided[:] = [
                    item
                    for item in semantic_provided
                    if not requirement_satisfied(item, value)
                ]
                continue
            if isinstance(value, Expr):
                dependencies = set(value.dependencies)
                provided.difference_update(dependencies)
                semantic_provided[:] = [
                    item
                    for item in semantic_provided
                    if not (
                        isinstance(item, Fact)
                        and item.name in dependencies
                    )
                    and not (
                        isinstance(item, Expr)
                        and bool(item.dependencies & dependencies)
                    )
                ]
                continue
            if isinstance(value, Scope):
                value = value.value
            if not isinstance(value, str):
                continue
            provided.difference_update(
                fact
                for fact in tuple(provided)
                if fact == value or fact.startswith(value + ".") or fact_scopes.get(fact) == value
            )
            semantic_provided[:] = [
                item
                for item in semantic_provided
                if not (
                    isinstance(item, Fact)
                    and (
                        item.name == value
                        or item.name.startswith(value + ".")
                        or item.scope.value == value
                    )
                )
                and not (
                    isinstance(item, Expr)
                    and (
                        item.key == value or item.key.startswith(value + ".") or item.scope == value
                    )
                )
            ]

    def validate_contract(action: Any) -> None:
        if isinstance(action, Sequence):
            for child in action.actions:
                validate_contract(child)
            return
        if isinstance(action, Branch):
            validate_contract(action.then)
            validate_contract(action.otherwise)
            return
        if not isinstance(action, Action):
            return
        contract = action.contract()
        for domain in contract.reads | contract.writes:
            if not isinstance(domain, str) or not domain:
                raise PlanningError(
                    f"{_describe(action)} declares an invalid state domain {domain!r}"
                )
        for constraint in contract.constraints:
            if not isinstance(constraint, Constraint):
                raise PlanningError(
                    f"{_describe(action)} has a non-Constraint contract entry {constraint!r}"
                )

    def record_effect_order(action: Any) -> None:
        reads, writes = _action_state_domains(action)
        if not reads and not writes:
            return
        label = _describe(action)
        for previous, previous_reads, previous_writes in effect_history:
            domains = (previous_writes & (reads | writes)) | (previous_reads & writes)
            if not domains:
                continue
            key = (previous, label, tuple(sorted(domains)))
            if key in barrier_keys:
                continue
            barrier_keys.add(key)
            effect_barriers.append(
                {
                    "before": previous,
                    "after": label,
                    "domains": list(key[2]),
                }
            )
        effect_history.append((label, reads, writes))

    def apply_effects(action: Any) -> None:
        validate_contract(action)
        register(action)
        if isinstance(action, Sequence):
            for child in action.actions:
                apply_effects(child)
            return
        if isinstance(action, Branch):
            record_effect_order(action)
            invalidate(
                canonical_invalidations(
                    (
                        *_action_invalidations(action.then),
                        *_action_invalidations(action.otherwise),
                    )
                )
            )
            provided.update(_action_outputs(action))
            for product in action.contract().provides:
                if not any(requirement_satisfied(item, product) for item in semantic_provided):
                    semantic_provided.append(product)
            return
        record_effect_order(action)
        invalidate(_action_invalidations(action))
        provided.update(_action_outputs(action))
        if isinstance(action, Action):
            for product in action.contract().provides:
                if not any(requirement_satisfied(item, product) for item in semantic_provided):
                    semantic_provided.append(product)

    def ensure(required: set[str], control: Control | None) -> None:
        visiting: set[str] = set()

        def acquire(fact: str) -> None:
            if fact in provided:
                return
            if fact in visiting:
                raise PlanningError(f"cyclic fact acquisition dependency involving {fact}")
            visiting.add(fact)
            provider_candidates = challenge.providers.candidates(f"fact:{fact}", provider_context)
            if not provider_candidates:
                provider_candidates = tuple(
                    provider
                    for provider in challenge.providers.providers
                    if any(
                        (isinstance(product, Fact) and product.name == fact)
                        or (isinstance(product, Expr) and fact in product.dependencies)
                        for product in provider.provides
                    )
                    and provider.supports(provider_context)
                )
            if provider_candidates:
                requested_product = next(
                    product
                    for product in provider_candidates[0].provides
                    if (isinstance(product, Fact) and product.name == fact)
                    or (isinstance(product, Expr) and fact in product.dependencies)
                    or product == f"fact:{fact}"
                )
                selection = ProviderPlanner(challenge.providers).acquire(
                    (requested_product,),
                    known=provider_known(),
                    context=provider_context,
                )
                if any(not isinstance(action, Action) for action in selection.actions):
                    raise PlanningError(f"provider for {fact} returned non-Action values")
                actions = ensure_actions(selection.actions)
                names = ", ".join(item.name for item in selection.providers)
                products = tuple(
                    product for item in selection.providers for product in item.provides
                )
                product_labels = tuple(
                    getattr(product, "name", getattr(product, "key", repr(product)))
                    for product in products
                )
                stages.append(
                    Stage(
                        f"Stage {len(stages) + 1}: provider {names}",
                        actions,
                        f"acquire {', '.join(sorted(map(str, product_labels)))}",
                    )
                )
                for action in actions:
                    apply_effects(action)
                for product in products:
                    if isinstance(product, Fact):
                        provided.add(product.name)
                    elif isinstance(product, Expr):
                        provided.update(product.dependencies)
                    elif isinstance(product, str) and product.startswith("fact:"):
                        provided.add(product[5:])
                    if not any(requirement_satisfied(item, product) for item in semantic_provided):
                        semantic_provided.append(product)
                visiting.remove(fact)
                return
            discovery = next(
                (
                    item
                    for item in format_discoveries
                    if id(item) not in compiled_discoveries and fact in item.output.dependencies
                ),
                None,
            )
            if discovery is not None:
                stages.append(
                    Stage(
                        f"Stage {len(stages) + 1}: discover format offset",
                        (discovery,),
                        discovery.describe(),
                    )
                )
                compiled_discoveries.add(id(discovery))
                apply_effects(discovery)
                visiting.remove(fact)
                return
            derivation = next(
                (
                    item
                    for item in challenge._derivations
                    if id(item) not in compiled_derivations and fact in item.target.dependencies
                ),
                None,
            )
            if derivation is not None:
                for dependency in set().union(
                    *(getattr(value, "dependencies", set()) for value in derivation.inputs)
                ):
                    acquire(dependency)
                compiled_derivations.add(id(derivation))
                provided.update(derivation.target.dependencies)
                visiting.remove(fact)
                return

            recipe = next(
                (
                    item
                    for item in challenge._learns
                    if id(item) not in compiled_recipes and fact in item.provides
                ),
                None,
            )
            if recipe is None:
                raise PlanningError(
                    f"cannot acquire {fact}; declare observe(), learn(), derive(), or assume()"
                )
            for requirement in recipe.requires:
                if isinstance(requirement, Control) and requirement not in challenge._controls:
                    raise PlanningError(
                        f"recipe {recipe.name!r} requires an undeclared control capability"
                    )
                if not isinstance(requirement, (Control, Expr)):
                    raise UnsupportedFeature(
                        f"recipe requirement {requirement!r} is not a symbolic fact or control"
                    )
            for dependency in _learn_dependencies(recipe):
                acquire(dependency)
            actions = ensure_actions(_compile_learn(challenge, recipe, control))
            for dependency in set().union(*(_action_dependencies(action) for action in actions)):
                acquire(dependency)
            actual_outputs = set().union(*(_action_outputs(action) for action in actions))
            missing_outputs = recipe.provides - actual_outputs
            if missing_outputs:
                raise PlanningError(
                    f"recipe {recipe.name!r} declares facts it does not bind: "
                    f"{', '.join(sorted(missing_outputs))}"
                )
            stages.append(
                Stage(
                    f"Stage {len(stages) + 1}: {recipe.name}",
                    actions,
                    "acquire " + ", ".join(sorted(recipe.provides)),
                )
            )
            compiled_recipes.add(id(recipe))
            for action in actions:
                apply_effects(action)
            visiting.remove(fact)

        for needed in sorted(required - provided):
            acquire(needed)

    semantic_visiting: set[str] = set()

    def ensure_semantic(requirement: Fact[Any] | Capability) -> None:
        if any(requirement_satisfied(item, requirement) for item in semantic_provided):
            return
        key = repr(requirement)
        if key in semantic_visiting:
            raise PlanningError(f"cyclic semantic requirement involving {requirement!r}")
        semantic_visiting.add(key)
        try:
            selection = ProviderPlanner(challenge.providers).acquire(
                (requirement,),
                known=provider_known(),
                context=provider_context,
            )
            provider_actions = ensure_actions(selection.actions)
            actual_products = tuple(
                product for action in provider_actions for product in _action_products(action)
            )
            missing = [
                product
                for provider in selection.providers
                for product in provider.provides
                if not any(requirement_satisfied(actual, product) for actual in actual_products)
            ]
            if missing:
                raise PlanningError(
                    "provider actions do not declare their promised products: "
                    + ", ".join(map(repr, missing))
                )
            names = ", ".join(item.name for item in selection.providers)
            stages.append(
                Stage(
                    f"Stage {len(stages) + 1}: provider {names}",
                    provider_actions,
                    f"satisfy {requirement!r}",
                )
            )
            for provider_action in provider_actions:
                apply_effects(provider_action)
            if not any(requirement_satisfied(item, requirement) for item in semantic_provided):
                raise PlanningError(f"provider actions did not satisfy {requirement!r}")
        finally:
            semantic_visiting.remove(key)

    def ensure_actions(actions: Iterable[Any]) -> tuple[Action, ...]:
        raw_actions = tuple(actions)
        if any(not isinstance(action, Action) for action in raw_actions):
            raise PlanningError("plans may contain only Action values")
        action_items = _lower_actions(raw_actions, planning_context())
        local_semantic = list(semantic_provided)
        local_names = set(provided)
        for action in _ordered_action_steps(action_items):
            register(action)
            missing_names = _action_dependencies(action) - local_names
            if missing_names:
                controls = [item for item in challenge._controls if isinstance(item, Control)]
                ensure(missing_names, controls[0] if controls else None)
                local_names.update(provided)
            for requirement in _action_requirements(action):
                if isinstance(requirement, (Fact, Capability)):
                    if not any(requirement_satisfied(item, requirement) for item in local_semantic):
                        ensure_semantic(requirement)
                        local_semantic = list(semantic_provided)
            for product in _action_products(action):
                if not any(requirement_satisfied(item, product) for item in local_semantic):
                    local_semantic.append(product)
            local_names.update(_action_outputs(action))
            for invalidation in _action_invalidations(action):
                if isinstance(invalidation, Expr):
                    local_names.difference_update(invalidation.dependencies)
                elif isinstance(invalidation, Fact):
                    local_names.discard(invalidation.name)
                elif isinstance(invalidation, str) and invalidation not in {
                    "artifact", "service", "process", "connection"
                }:
                    local_names.discard(invalidation.removeprefix("fact:"))
        for action in action_items:
            validate_contract(action)
        return action_items

    def prove_call(
        declaration: Goal,
        effect: Call | DynamicCall,
        explicit: str | None,
        preferred: str | None,
    ):
        """Adapt common call intent into the same registered strategy graph."""

        try:
            control: Control | None = _control(challenge, declaration)
            control_error: PlanningError | None = None
        except PlanningError as error:
            control = None
            control_error = error
        ensure(_dependencies(effect), control)
        request = GoalRequest("target.call", intent=effect)
        registry = challenge.providers.clone()
        plugins = sorted(
            challenge._plugins,
            key=lambda name: (
                {
                    "stable": 0,
                    "conditional": 1,
                    "experimental": 2,
                }.get(challenge._plugins[name]["reliability"], 3),
                challenge._plugins[name]["cost"],
                name,
            ),
        )
        custom_strategies = [
            strategy.name for strategy in registry.strategies if strategy.matches(request)
        ]
        if control is None and not custom_strategies:
            assert control_error is not None
            raise control_error
        order = (
            [explicit]
            if explicit is not None
            else list(dict.fromkeys([preferred, "rop", "dlresolve", *plugins, *custom_strategies]))
        )
        order = [name for name in order if name]
        if explicit is not None and explicit in challenge._forbidden:
            raise PlanningError(f"pinned tactic {explicit!r} is forbidden by policy")

        if (
            control is not None
            and "rop" not in challenge._forbidden
            and all(strategy.name != "rop" for strategy in registry.strategies)
        ):

            def lower_rop(_context, call_goal):
                intent = call_goal.intent
                if not isinstance(intent, Call):
                    raise PlanningError("ROP requires a statically addressed call")
                try:
                    return (Emit(_compile_call(challenge, control, intent), control.channel),)
                except UnsupportedFeature as error:
                    raise PlanningError(str(error)) from error

            registry.register_strategy(
                GoalStrategy(
                    "rop",
                    "target.call",
                    (),
                    lower_rop,
                    reliability="stable",
                    assumptions=(
                        "declared return-address control reaches the selected call chain",
                    ),
                )
            )

        if (
            control is not None
            and "dlresolve" not in challenge._forbidden
            and all(strategy.name != "dlresolve" for strategy in registry.strategies)
        ):

            def lower_dlresolve(_context, call_goal):
                intent = call_goal.intent
                if not isinstance(intent, (Call, DynamicCall)):
                    raise PlanningError("ret2dlresolve requires call intent")
                if isinstance(intent, Call) and intent.target.space == "exe":
                    raise PlanningError(
                        "target is defined by the executable rather than the dynamic linker"
                    )
                try:
                    actions, _symbol = _dlresolve_actions(
                        challenge,
                        declaration,
                        intent,
                        control,
                        declaration.using if explicit else Tactic("dlresolve"),
                    )
                except UnsupportedFeature as error:
                    raise PlanningError(str(error)) from error
                return actions

            registry.register_strategy(
                GoalStrategy(
                    "dlresolve",
                    "target.call",
                    (),
                    lower_dlresolve,
                    reliability="conditional",
                    cost=10,
                    assumptions=(
                        "the dynamic loader metadata is reachable and writable staging is available",
                    ),
                )
            )

        for plugin_name in plugins:
            if (
                control is None
                or plugin_name in challenge._forbidden
                or any(strategy.name == plugin_name for strategy in registry.strategies)
            ):
                continue
            plugin = challenge._plugins[plugin_name]

            def lower_plugin(_context, _call_goal, *, item=plugin):
                for requirement in item["requires"]:
                    if isinstance(requirement, Control):
                        if requirement not in challenge._controls:
                            raise PlanningError("requires undeclared control")
                    elif not isinstance(requirement, Expr):
                        raise PlanningError(f"unsupported requirement {requirement!r}")
                try:
                    custom = item["lower"](TechniqueContext(challenge, declaration, control))
                except UnsupportedFeature as error:
                    raise PlanningError(str(error)) from error
                actions = custom.actions if isinstance(custom, Sequence) else (custom,)
                declared_outputs = set().union(
                    *(value.dependencies for value in item["provides"] if isinstance(value, Expr))
                )
                actual_outputs = set().union(*(_action_outputs(action) for action in actions))
                if declared_outputs - actual_outputs:
                    raise PlanningError(
                        "technique declares facts it does not bind: "
                        + ", ".join(sorted(declared_outputs - actual_outputs))
                    )
                return actions

            registry.register_strategy(
                GoalStrategy(
                    plugin_name,
                    "target.call",
                    (),
                    lower_plugin,
                    reliability=plugin["reliability"],
                    cost=plugin["cost"],
                    assumptions=(
                        f"custom strategy {plugin_name!r} satisfies its declared contract",
                    ),
                )
            )

        call_context = ProviderContext(
            target=challenge,
            values={
                **provider_context.values,
                "declaration": declaration,
                "effect": effect,
                "control": control,
            },
            capabilities=provider_context.capabilities,
            policy={
                **provider_context.policy,
                "strategy_order": tuple(order),
                "allowed_strategies": tuple(order),
            },
        )
        proof = ProviderPlanner(registry).prove(
            request,
            known=provider_known(),
            context=call_context,
        )
        if proof.strategy in challenge._plugins:
            for requirement in challenge._plugins[proof.strategy]["requires"]:
                if isinstance(requirement, Expr):
                    ensure(set(requirement.dependencies), control)
        return proof

    def prove_format_write(declaration: Goal, effect: FormatWrite, requested: str | None):
        """Adapt format-write intent into the registered strategy graph."""

        if requested not in {None, "format", "fmtstr"}:
            raise PlanningError(f"{requested!r} cannot lower a format-string write")
        dependencies = _dependencies(effect)
        if dependencies - provided:
            controls = [item for item in challenge._controls if isinstance(item, Control)]
            ensure(dependencies, controls[0] if controls else None)
        registry = challenge.providers.clone()
        request = GoalRequest("memory.write.format", intent=effect)
        if all(strategy.name != "format" for strategy in registry.strategies):

            def lower_format(_context, format_goal):
                intent = format_goal.intent
                if not isinstance(intent, FormatWrite):
                    raise PlanningError("format strategy requires format-write intent")
                payload = DeferredFormatPayload(intent.control, intent.writes)
                return (Emit(payload, intent.control.channel),)

            registry.register_strategy(
                GoalStrategy(
                    "format",
                    "memory.write.format",
                    (),
                    lower_format,
                    reliability="stable",
                    assumptions=(
                        "the declared format-string offset and write primitive remain valid",
                    ),
                )
            )
        context = ProviderContext(
            target=challenge,
            values={
                **provider_context.values,
                "declaration": declaration,
                "effect": effect,
            },
            capabilities=provider_context.capabilities,
            policy={
                **provider_context.policy,
                "strategy_order": ("format",),
                "allowed_strategies": ("format",),
            },
        )
        return ProviderPlanner(registry).prove(
            request,
            known=provider_known(),
            context=context,
        )

    for observation in triggered_observations:
        actions = []
        producer = observation.source
        if isinstance(producer, Expr):
            producer = getattr(producer, "origin", None) or action_origin(producer)
        if isinstance(producer, Action):
            actions.append(producer)
        else:
            raise PlanningError(
                "an action-bound observation must use from_=action or "
                "from_=action.output so the producer remains inspectable"
            )
        actions.append(observation)
        actions = list(ensure_actions(actions))
        stages.append(
            Stage(
                f"Stage {len(stages) + 1}: triggered observation",
                tuple(actions),
                "bind output produced by an explicit action",
            )
        )
        for action in actions:
            apply_effects(action)
        provided.update(observation.pattern.provides)

    for fmt_control, leak in format_leaks:
        from .codecs import hex_pointer

        stages.append(
            Stage(
                f"Stage {len(stages) + 1}: format leak",
                (
                    Emit(leak.payload, fmt_control.channel),
                    Capture(
                        hex_pointer(),
                        leak.target - leak.adjustment if leak.adjustment else leak.target,
                        leak.describe(),
                    ),
                ),
                leak.describe(),
            )
        )
        for action in stages[-1].actions:
            apply_effects(action)

    for explicit in challenge._sequences:
        lowered = ensure_actions((explicit,))
        lowered_explicit = lowered[0] if len(lowered) == 1 else Sequence(lowered, explicit.name)
        stages.append(
            Stage(
                f"Stage {len(stages) + 1}: {explicit.name}",
                (lowered_explicit,),
                "explicit stateful sequence",
            )
        )
        apply_effects(lowered_explicit)

    for goal in challenge._goals:
        effect = goal.effect
        explicit = _requested_tactic(goal)
        preferred = next(
            (name for name in challenge._preferred if name not in challenge._forbidden),
            None,
        )
        requested = explicit
        if isinstance(effect, GoalRequest):
            known_before_proof = provider_known()
            proof = ProviderPlanner(challenge.providers).prove(
                effect,
                known=known_before_proof,
                context=provider_context,
            )
            if any(not isinstance(action, Action) for action in proof.actions):
                raise PlanningError(f"strategy {proof.strategy!r} returned non-Action values")
            strategy_actions = ensure_actions(proof.actions)
            provider_names: list[str] = []
            for prerequisite in proof.prerequisites:
                if any(requirement_satisfied(item, prerequisite) for item in known_before_proof):
                    continue
                candidates = challenge.providers.candidates(prerequisite, provider_context)
                if candidates:
                    provider_names.append(candidates[0].name)
            provider_detail = (
                "; " + ", ".join(f"provider {name}" for name in dict.fromkeys(provider_names))
                if provider_names
                else ""
            )
            stages.append(
                Stage(
                    f"Stage {len(stages) + 1}: strategy {proof.strategy}",
                    strategy_actions,
                    proof.describe() + provider_detail,
                )
            )
            for action in strategy_actions:
                apply_effects(action)
            selected_names.append(proof.strategy)
            proof_assumptions.extend(proof.assumptions)
            rejected.extend(_proof_rejections(proof.rejected_alternatives))
            continue
        if isinstance(effect, FormatWrite):
            proof = prove_format_write(goal, effect, requested)
            strategy_actions = ensure_actions(proof.actions)
            stages.append(
                Stage(
                    f"Stage {len(stages) + 1}: format-string write",
                    strategy_actions,
                    f"{effect.describe()} [{proof.reliability}, cost={proof.cost}]",
                )
            )
            for action in strategy_actions:
                apply_effects(action)
            selected_names.append(proof.strategy)
            proof_assumptions.extend(proof.assumptions)
            rejected.extend(_proof_rejections(proof.rejected_alternatives))
            continue

        if not isinstance(effect, (Call, DynamicCall)):
            if isinstance(effect, Action):
                goal_actions = ensure_actions((effect,))
                stages.append(
                    Stage(
                        f"Stage {len(stages) + 1}: goal",
                        goal_actions,
                        _describe(effect),
                    )
                )
                for goal_action in goal_actions:
                    apply_effects(goal_action)
                selected_names.append("actions")
                continue
            raise UnsupportedFeature(f"unsupported goal {_describe(effect)}")

        proof = prove_call(goal, effect, explicit, preferred)
        if any(not isinstance(action, Action) for action in proof.actions):
            raise PlanningError(f"strategy {proof.strategy!r} returned non-Action values")
        strategy_actions = ensure_actions(proof.actions)
        stage_label = {
            "rop": "call goal",
            "dlresolve": "ret2dlresolve",
        }.get(proof.strategy, proof.strategy)
        stages.append(
            Stage(
                f"Stage {len(stages) + 1}: {stage_label}",
                strategy_actions,
                f"{_describe(effect)} [{proof.reliability}, cost={proof.cost}]",
            )
        )
        for action in strategy_actions:
            apply_effects(action)
        selected_names.append(proof.strategy)
        proof_assumptions.extend(proof.assumptions)
        rejected.extend(_proof_rejections(proof.rejected_alternatives))

        # Preserve only alternatives that pass a bounded applicability check.
        if (
            proof.strategy == "rop"
            and isinstance(effect, Call)
            and effect.target.space != "exe"
            and "dlresolve" not in challenge._forbidden
        ):
            try:
                _dlresolve_actions(
                    challenge,
                    goal,
                    effect,
                    _control(challenge, goal),
                    Tactic("dlresolve"),
                )
            except (PlanningError, UnsupportedFeature):
                pass
            else:
                alternatives.append(
                    {
                        "name": "dlresolve",
                        "reason": "applicable but ranked after the lower-cost ROP plan",
                    }
                )

    assumptions = tuple(
        f"{expr.describe()} = {value!r}: {reason}" for expr, value, reason in challenge._assumptions
    ) + tuple(
        dict.fromkeys((*challenge._narrative_assumptions, *proof_assumptions))
    )
    return Plan(
        challenge,
        stages,
        "+".join(dict.fromkeys(selected_names)),
        tuple(alternatives),
        assumptions,
        tuple(rejected),
        any(goal.terminal for goal in challenge._goals),
        tuple(effect_barriers),
    )
