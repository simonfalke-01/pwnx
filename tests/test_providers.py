import pytest

from elf_factory import make_elf
from pwnx.actions import Action, ActionPlanningContext, Check, register_action_executor
from pwnx.challenge import Challenge
from pwnx.domain import ADDRESS, Capability, Constraint, EffectContract, Fact, Scope
from pwnx.domain import INTEGER
from pwnx.errors import ConstraintError, PlanningError, UnresolvedValueError
from pwnx.expressions import Expr
from pwnx.providers import (
    GoalRequest,
    GoalStrategy,
    Provider,
    ProviderContext,
    ProviderPlanner,
    ProviderRegistry,
)
from pwnx.trace import Trace
from pwnx.transport import Tube


class EmptyTube(Tube):
    def _recv_raw(self, max_bytes, timeout):
        return b""

    def _send_raw(self, data, timeout):
        return len(data)

    def _close_raw(self):
        pass


class PluginBind(Action):
    def __init__(self, target: Expr, fact: Fact, value: int):
        self.target = target
        self.fact = fact
        self.value = value

    @property
    def output(self):
        return self.target

    def contract(self):
        return EffectContract(provides=(self.fact,), writes=frozenset({"facts"}))

    def describe(self):
        return f"plugin binds {self.target.describe()}"

    def execute(self, runtime):
        return runtime.bind(self.target, self.value, source="test plugin")


class StateAction(Action):
    def __init__(
        self,
        name,
        *,
        reads=(),
        writes=(),
        constraints=(),
        invalidates=(),
    ):
        self.name = name
        self.reads = frozenset(reads)
        self.writes = frozenset(writes)
        self.constraints = tuple(constraints)
        self.invalidates = tuple(invalidates)

    def contract(self):
        return EffectContract(
            reads=self.reads,
            writes=self.writes,
            constraints=self.constraints,
            invalidates=self.invalidates,
        )

    def describe(self):
        return self.name


class RuntimeContractAction(Action):
    def __init__(self, name, contract, callback):
        self.name = name
        self._contract = contract
        self.callback = callback

    def contract(self):
        return self._contract

    def describe(self):
        return self.name

    def execute(self, runtime):
        return self.callback(runtime)


class LowerAtPlan(Action):
    def __init__(self, inner, counter):
        self.inner = inner
        self.counter = counter

    def describe(self):
        return "lower at plan time"

    def lower(self, context):
        assert isinstance(context, ActionPlanningContext)
        assert not hasattr(context, "tube")
        self.counter["lower"] += 1
        return (self.inner,)

    def execute(self, _runtime):
        raise AssertionError("lowered wrapper reached runtime")


class RegistryBindAction(Action):
    def __init__(self, fact, value):
        self.fact = fact
        self.value = value

    def contract(self):
        return EffectContract(provides=(self.fact,))

    def describe(self):
        return f"registry bind {self.fact.name}"


class RegistryNoopReplacementAction(Action):
    def __init__(self, fact):
        self.fact = fact

    def contract(self):
        return EffectContract(
            requires=(self.fact,),
            provides=(self.fact,),
            invalidates=(self.fact,),
        )

    def describe(self):
        return f"registry no-op {self.fact.name}"


class RegistryMutableFailureAction(Action):
    def __init__(self, fact, contexts):
        self.fact = fact
        self.contexts = contexts

    def contract(self):
        return EffectContract(requires=(self.fact,), invalidates=(self.fact,))

    def describe(self):
        return f"registry mutable failure {self.fact.describe()}"


def test_provider_graph_acquires_transitive_facts_by_stable_cost():
    leak = Fact("puts", ADDRESS, Scope.PROCESS, artifact="libc")
    base = Fact("libc.base", ADDRESS, Scope.PROCESS, artifact="libc")
    registry = ProviderRegistry()
    registry.register(Provider("expensive", (), (leak,), lambda _ctx: ("bad",), cost=10))
    registry.register(Provider("leak", (), (leak,), lambda _ctx: ("leak",), reliability="stable"))
    registry.register(Provider("rebase", (leak,), (base,), lambda _ctx: ("rebase",), reliability="stable"))

    selection = ProviderPlanner(registry).acquire((base,))
    assert [item.name for item in selection.providers] == ["leak", "rebase"]
    assert selection.actions == ("leak", "rebase")


def test_provider_cycle_and_missing_provider_are_explained():
    a = Fact("a", ADDRESS, Scope.PROCESS, artifact="x")
    b = Fact("b", ADDRESS, Scope.PROCESS, artifact="x")
    registry = ProviderRegistry()
    registry.register(Provider("a", (b,), (a,), lambda _ctx: ()))
    registry.register(Provider("b", (a,), (b,), lambda _ctx: ()))
    with pytest.raises(PlanningError, match="cycle"):
        ProviderPlanner(registry).acquire((a,))


def test_provider_known_values_do_not_satisfy_weaker_name_only_matches():
    required_fact = Fact("shared", INTEGER, Scope.PROCESS)
    wrong_fact = Fact("shared", INTEGER, Scope.CONNECTION)
    required_capability = Capability(
        "memory",
        EffectContract(
            writes=frozenset({"process.memory"}),
            scope=Scope.PROCESS,
        ),
    )
    weak_capability = Capability(
        "memory",
        EffectContract(
            reads=frozenset({"process.memory"}),
            scope=Scope.PROCESS,
        ),
    )
    planner = ProviderPlanner(ProviderRegistry())
    with pytest.raises(PlanningError, match="no provider"):
        planner.acquire((required_fact,), known=(wrong_fact,))
    with pytest.raises(PlanningError, match="no provider"):
        planner.acquire((required_capability,), known=(weak_capability,))


def test_goal_strategies_produce_technique_proofs_and_rejections():
    control = Capability("rip", EffectContract(), reliability="stable")
    registry = ProviderRegistry()
    registry.register_strategy(
        GoalStrategy(
            "rop",
            "shell",
            (control,),
            lambda _ctx, _goal: ("chain",),
            reliability="stable",
            assumptions=("stack is aligned",),
        )
    )
    proof = ProviderPlanner(registry).prove(
        GoalRequest("shell"),
        known=(control,),
        context=ProviderContext(capabilities=(control,)),
    )
    assert proof.strategy == "rop"
    assert proof.actions == ("chain",)
    assert proof.assumptions == ("stack is aligned",)


def test_goal_constraints_are_evaluated_against_provider_context():
    registry = ProviderRegistry()
    registry.register_strategy(
        GoalStrategy("checked", "shell", (), lambda _ctx, _goal: ("chain",))
    )
    goal = GoalRequest(
        "shell",
        constraints=(
            Constraint(
                "seccomp permits execve",
                lambda values: values["policy"].get("execve") is True,
                "declare an allowed syscall policy",
            ),
        ),
    )
    with pytest.raises(PlanningError, match="seccomp permits execve"):
        ProviderPlanner(registry).prove(
            goal,
            context=ProviderContext(policy={"execve": False}),
        )
    proof = ProviderPlanner(registry).prove(
        goal,
        context=ProviderContext(policy={"execve": True}),
    )
    assert proof.strategy == "checked"


def test_support_predicates_prevent_invalid_backend_selection():
    fact = Fact("x", ADDRESS, Scope.PROCESS, artifact="x")
    registry = ProviderRegistry()
    registry.register(
        Provider(
            "unsupported",
            (),
            (fact,),
            lambda _ctx: (),
            supports=lambda _ctx: False,
        )
    )
    with pytest.raises(PlanningError, match="no provider"):
        ProviderPlanner(registry).acquire((fact,))


def test_challenge_uses_provider_graph_and_plugin_action_without_core_switch(tmp_path):
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    answer = challenge.typed_fact("answer", INTEGER)
    expression = answer.expr()

    @challenge.provider(
        name="answer provider",
        provides=[answer],
        reliability="stable",
    )
    def answer_provider(_context):
        return (PluginBind(expression, answer, 42),)

    @challenge.strategy(
        name="answer strategy",
        goal="answer-ready",
        requires=[answer],
        reliability="stable",
    )
    def answer_strategy(_context, _goal):
        return (Check(expression.equals(42)),)

    challenge.want(challenge.goal("answer-ready"))
    plan = challenge.plan()
    assert "provider answer provider" in plan.show()
    assert "strategy answer strategy" in plan.show()
    run = plan.run(transport=EmptyTube())
    assert run.value(expression) == 42
    run.close()


def test_action_contract_constraints_and_effect_order_are_operational(tmp_path):
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    challenge.sequence(
        StateAction(
            "write memory",
            writes=("process.memory",),
            constraints=(
                Constraint(
                    "target selected",
                    lambda values: values["challenge"] is challenge,
                ),
            ),
        ),
        StateAction("read memory", reads=("process.memory",)),
        name="stateful work",
    )
    challenge.want(Check(Expr.literal(True)))

    plan = challenge.plan()
    assert plan.effect_barriers == (
        {
            "before": "write memory",
            "after": "read memory",
            "domains": ["process.memory"],
        },
    )
    assert plan.to_dict()["stages"][0]["effects"] == {
        "reads": ["process.memory"],
        "writes": ["process.memory"],
        "invalidates": [],
    }

    rejected = Challenge(make_elf(tmp_path / "rejected", pie=False))
    rejected.sequence(
        StateAction(
            "unsafe",
            constraints=(Constraint("never", lambda _values: False, "test"),),
        )
    )
    rejected.want(Check(Expr.literal(True)))
    with pytest.raises(ConstraintError, match="violates constraint 'never'"):
        rejected.plan().run(transport=EmptyTube())


def test_planner_canonicalizes_mixed_invalidation_values_deterministically(tmp_path):
    fact = Fact("state.value", INTEGER, Scope.PROCESS)
    expression = fact.expr()
    action = StateAction(
        "invalidate state",
        invalidates=(
            fact,
            fact,
            expression,
            expression,
            Scope.PROCESS,
            Scope.PROCESS,
            "process",
            "state",
            "state",
        ),
    )
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    challenge.sequence(action)
    challenge.want(Check(Expr.literal(True)))
    plan = challenge.plan()
    invalidations = plan.to_dict()["stages"][0]["effects"]["invalidates"]
    assert len(invalidations) == 3
    assert invalidations == sorted(invalidations)


def test_derived_invalidation_removes_typed_fact_and_reacquires_it(tmp_path):
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    base = challenge.typed_fact("typed.base", INTEGER)
    challenge.assume(base.expr(), 1)

    @challenge.provider(name="reacquire typed base", provides=(base,))
    def reacquire(_context):
        return (PluginBind(base.expr(), base, 42),)

    challenge.sequence(
        RuntimeContractAction(
            "invalidate derived base",
            EffectContract(invalidates=(base.expr() + 8,)),
            lambda _runtime: True,
        )
    )
    challenge.want(Check(base.expr().equals(42)))
    plan = challenge.plan()
    assert "provider reacquire typed base" in plan.show()
    run = plan.run(transport=EmptyTube())
    assert run.value(base.expr()) == 42
    run.close()


def test_common_call_intent_uses_registered_goal_strategy(tmp_path):
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))

    @challenge.strategy(
        name="intent-strategy",
        goal="target.call",
        reliability="stable",
        assumptions=("custom call strategy selected",),
    )
    def intent_strategy(_context, request):
        assert request.intent == challenge.exe.win()
        return (Check(Expr.literal(True)),)

    challenge.prefer("intent-strategy")
    challenge.want(challenge.exe.win())
    plan = challenge.plan()

    assert plan.selected_tactic == "intent-strategy"
    assert "custom call strategy selected" in plan.assumptions


def test_generic_action_contract_is_enforced_once_after_plan_time_lowering(tmp_path):
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    seed = challenge.typed_fact("seed", INTEGER)
    result = challenge.typed_fact("result", INTEGER)
    stale = challenge.fact("stale")
    memory_write = Capability(
        "memory",
        EffectContract(
            writes=frozenset({"process.memory"}),
            scope=Scope.PROCESS,
        ),
    )
    challenge.capability(memory_write)
    challenge.assume(seed.expr(), 1)
    challenge.assume(stale, 99)
    counts = {"lower": 0, "constraint": 0, "execute": 0}

    def allowed(values):
        counts["constraint"] += 1
        return values["challenge"] is challenge

    def execute(runtime):
        counts["execute"] += 1
        value = runtime.resolve(seed.expr()) + 1
        runtime.bind(result.expr(), value, source="contract action")
        return value

    inner = RuntimeContractAction(
        "contract action",
        EffectContract(
            requires=(seed, memory_write),
            provides=(result,),
            invalidates=(stale,),
            constraints=(Constraint("allowed", allowed),),
        ),
        execute,
    )

    class Lowered(RuntimeContractAction):
        def lower(self, context):
            assert isinstance(context, ActionPlanningContext)
            counts["lower"] += 1
            return (inner,)

        def execute(self, runtime):
            raise AssertionError("wrapper reached runtime")

    wrapper = Lowered("wrapper", EffectContract(), lambda _runtime: None)
    challenge.sequence(wrapper, name="lowered contract")
    challenge.want(Check(result.expr().equals(2)))
    plan = challenge.plan()
    assert wrapper not in plan.actions
    assert counts == {"lower": 1, "constraint": 0, "execute": 0}

    trace = Trace()
    run = plan.run(transport=EmptyTube(), trace=trace)
    assert run.value(result.expr()) == 2
    with pytest.raises(UnresolvedValueError):
        run.value(stale)
    run.close()
    replay = plan.run(replay=trace)
    replay.close()
    assert counts == {"lower": 1, "constraint": 2, "execute": 2}


def test_generic_action_products_and_capabilities_must_materialize(tmp_path):
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    output = challenge.typed_fact("output", INTEGER)
    missing = RuntimeContractAction(
        "missing output",
        EffectContract(provides=(output,)),
        lambda _runtime: None,
    )
    challenge.want(missing)
    trace = Trace()
    with pytest.raises(ConstraintError, match="completed execution"):
        challenge.plan().run(transport=EmptyTube(), trace=trace)
    assert trace.metadata["contract_failures"] == [
        {
            "action": "missing output",
            "phase": "product-validation",
            "error": (
                "ConstraintError: missing output did not bind declared fact "
                "'output'"
            ),
            "external_effect_status": "completed",
            "fact_state": "rolled-back",
        }
    ]

    capability = Capability(
        "write",
        EffectContract(
            writes=frozenset({"process.memory"}),
            scope=Scope.PROCESS,
        ),
    )
    supplied = Challenge(make_elf(tmp_path / "supplied", pie=False))
    producer = RuntimeContractAction(
        "produce write",
        EffectContract(provides=(capability,)),
        lambda _runtime: capability,
    )
    consumer = RuntimeContractAction(
        "consume write",
        EffectContract(requires=(capability,)),
        lambda _runtime: True,
    )
    supplied.sequence(producer, consumer, name="capability flow")
    supplied.want(Check(Expr.literal(True)))
    run = supplied.plan().run(transport=EmptyTube())
    assert capability in run.capabilities
    run.close()


def test_registry_executor_uses_same_product_verification(tmp_path):
    result = Fact("registry.result", INTEGER, Scope.PROCESS)

    def registry_bind(action, runtime):
        return runtime.bind(result.expr(), action.value, source="registry")

    register_action_executor(RegistryBindAction, registry_bind)
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    challenge.want(RegistryBindAction(result, 7))
    run = challenge.plan().run(transport=EmptyTube())
    assert run.value(result.expr()) == 7
    run.close()


def test_action_capability_requirement_rejects_same_name_weaker_primitive(tmp_path):
    required = Capability(
        "memory",
        EffectContract(
            writes=frozenset({"process.memory"}),
            scope=Scope.PROCESS,
        ),
    )
    weak = Capability(
        "memory",
        EffectContract(
            reads=frozenset({"process.memory"}),
            scope=Scope.PROCESS,
        ),
    )
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    challenge.capability(weak)
    challenge.want(
        RuntimeContractAction(
            "needs write",
            EffectContract(requires=(required,)),
            lambda _runtime: True,
        )
    )
    with pytest.raises(PlanningError, match="no provider"):
        challenge.plan()


def test_action_fact_transaction_orders_consume_replace_and_invalidate(tmp_path):
    fact = Fact("session.value", INTEGER, Scope.CONNECTION)
    challenge = Challenge(make_elf(tmp_path / "replace", pie=False))
    challenge.assume(fact.expr(), 1)
    observed = []

    def replace(runtime):
        observed.append(runtime.resolve(fact.expr()))
        runtime.bind(fact.expr(), 2, source="replacement")
        return 2

    challenge.sequence(
        RuntimeContractAction(
            "consume and replace",
            EffectContract(
                requires=(fact,),
                provides=(fact,),
                invalidates=(fact,),
            ),
            replace,
        )
    )
    challenge.want(Check(fact.expr().equals(2)))
    run = challenge.plan().run(transport=EmptyTube())
    assert observed == [1]
    assert run.value(fact.expr()) == 2
    run.close()

    consumed = Challenge(make_elf(tmp_path / "consume", pie=False))
    consumed.assume(fact.expr(), 3)
    seen = []
    consumed.sequence(
        RuntimeContractAction(
            "consume and invalidate",
            EffectContract(requires=(fact,), invalidates=(fact,)),
            lambda runtime: seen.append(runtime.resolve(fact.expr())),
        )
    )
    consumed.want(Check(Expr.literal(True)))
    run = consumed.plan().run(transport=EmptyTube())
    assert seen == [3]
    with pytest.raises(UnresolvedValueError):
        run.value(fact.expr())
    run.close()


def test_action_exception_rolls_back_fact_state_without_committing_invalidation(tmp_path):
    fact = Fact("stable", INTEGER, Scope.PROCESS)
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    challenge.assume(fact.expr(), 1)
    captured = {}

    def fail(runtime):
        captured["context"] = runtime.context
        assert runtime.resolve(fact.expr()) == 1
        raise RuntimeError("before effect")

    challenge.want(
        RuntimeContractAction(
            "failing action",
            EffectContract(requires=(fact,), invalidates=(fact,)),
            fail,
        )
    )
    trace = Trace()
    with pytest.raises(RuntimeError, match="before effect"):
        challenge.plan().run(transport=EmptyTube(), trace=trace)
    assert captured["context"].resolve(fact.expr()) == 1
    assert trace.metadata["contract_failures"][0]["phase"] == "execution"
    assert (
        trace.metadata["contract_failures"][0]["external_effect_status"]
        == "unknown"
    )


def test_overlapping_product_invalidation_requires_transaction_local_write(tmp_path):
    fact = Fact("replace.me", INTEGER, Scope.PROCESS)
    challenge = Challenge(make_elf(tmp_path / "direct", pie=False))
    challenge.assume(fact.expr(), 7)
    contexts = []
    inner = RuntimeContractAction(
        "no-op replacement",
        EffectContract(
            requires=(fact,),
            provides=(fact,),
            invalidates=(fact,),
        ),
        lambda runtime: (
            contexts.append(runtime.context),
            runtime.resolve(fact.expr()),
        )[-1],
    )

    class LoweredNoop(RuntimeContractAction):
        def lower(self, _context):
            return (inner,)

    challenge.want(LoweredNoop("wrapper", EffectContract(), lambda _runtime: None))
    plan = challenge.plan()
    trace = Trace()
    with pytest.raises(ConstraintError) as failure:
        plan.run(transport=EmptyTube(), trace=trace)
    assert "did not explicitly rebind" in str(failure.value.__cause__)
    assert contexts[-1].resolve(fact.expr()) == 7
    with pytest.raises(ConstraintError) as replay_failure:
        plan.run(replay=trace)
    assert "did not explicitly rebind" in str(replay_failure.value.__cause__)

    registry_challenge = Challenge(make_elf(tmp_path / "registry", pie=False))
    registry_challenge.assume(fact.expr(), 7)
    register_action_executor(
        RegistryNoopReplacementAction,
        lambda action, runtime: runtime.resolve(action.fact.expr()),
    )
    registry_challenge.want(RegistryNoopReplacementAction(fact))
    with pytest.raises(ConstraintError) as registry_failure:
        registry_challenge.plan().run(transport=EmptyTube())
    assert "did not explicitly rebind" in str(registry_failure.value.__cause__)


def test_mutable_fact_rollback_isolated_for_direct_registry_and_replay(tmp_path):
    fact = Expr.fact("mutable")
    original = {"items": [1]}
    direct = Challenge(make_elf(tmp_path / "direct", pie=False))
    direct.assume(fact, original)
    direct_contexts = []

    def mutate_then_fail(runtime):
        direct_contexts.append(runtime.context)
        value = runtime.resolve(fact)
        value["items"].append(2)
        raise RuntimeError("mutable direct failure")

    direct.want(
        RuntimeContractAction(
            "mutable direct",
            EffectContract(requires=(fact,), invalidates=(fact,)),
            mutate_then_fail,
        )
    )
    plan = direct.plan()
    trace = Trace()
    with pytest.raises(RuntimeError, match="mutable direct failure"):
        plan.run(transport=EmptyTube(), trace=trace)
    assert original == {"items": [1]}
    assert direct_contexts[-1].resolve(fact) == {"items": [1]}
    with pytest.raises(RuntimeError, match="mutable direct failure"):
        plan.run(replay=trace)
    assert direct_contexts[-1].resolve(fact) == {"items": [1]}

    registry_contexts = []

    def registry_failure(action, runtime):
        registry_contexts.append(runtime.context)
        value = runtime.resolve(action.fact)
        value["items"].append(9)
        raise RuntimeError("mutable registry failure")

    register_action_executor(RegistryMutableFailureAction, registry_failure)
    registry_challenge = Challenge(make_elf(tmp_path / "registry", pie=False))
    registry_challenge.assume(fact, {"items": [3]})
    registry_challenge.want(
        RegistryMutableFailureAction(fact, registry_contexts)
    )
    with pytest.raises(RuntimeError, match="mutable registry failure"):
        registry_challenge.plan().run(transport=EmptyTube())
    assert registry_contexts[-1].resolve(fact) == {"items": [3]}
