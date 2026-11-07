import pytest

from pwnx.domain import (
    ADDRESS,
    INTEGER,
    Capability,
    EffectContract,
    Environment,
    Epochs,
    Evidence,
    Fact,
    FactStore,
    Constraint,
    Scope,
    Sort,
    TargetRecipe,
    TechniqueProof,
    effect_contract_satisfies,
    invalidation_semantic_key,
    requirement_satisfied,
)
from pwnx.errors import ConstraintError, StaleValueError


def test_typed_facts_validate_and_track_independent_epochs():
    epochs = Epochs("service-1", "process-1", "connection-1")
    store = FactStore(epochs)
    base = Fact("libc.base", ADDRESS, Scope.PROCESS, artifact="libc")
    banner = Fact("service.banner", INTEGER, Scope.SERVICE)
    store.bind(base, 0x7F0000000000, evidence=[Evidence("leak", "puts")])
    store.bind(banner, 1)
    assert store.resolve(base) == 0x7F0000000000

    store.transition(epochs.reconnect(same_process=True))
    assert store.resolve(base) == 0x7F0000000000
    store.transition(store.epochs.restart_process())
    with pytest.raises(StaleValueError):
        store.resolve(base)
    assert store.resolve(banner) == 1


def test_sort_conflicts_and_invalidation_are_explicit():
    store = FactStore()
    fact = Fact("offset", INTEGER, Scope.PROCESS)
    with pytest.raises(ConstraintError):
        store.bind(fact, True)
    store.bind(fact, 4)
    store.invalidate(scopes=[Scope.PROCESS])
    assert not store.has(fact)


def test_fact_and_capability_satisfaction_is_structural():
    required = Fact("value", INTEGER, Scope.PROCESS)
    wrong_scope = Fact("value", INTEGER, Scope.CONNECTION)
    wrong_sort = Fact("value", ADDRESS, Scope.PROCESS, artifact="exe")
    assert requirement_satisfied(required, required)
    assert not requirement_satisfied(wrong_scope, required)
    assert not requirement_satisfied(wrong_sort, required)

    required_write = Capability(
        "memory",
        EffectContract(
            writes=frozenset({"process.memory"}),
            scope=Scope.PROCESS,
        ),
    )
    read_only = Capability(
        "memory",
        EffectContract(
            reads=frozenset({"process.memory"}),
            scope=Scope.PROCESS,
        ),
    )
    assert not requirement_satisfied(read_only, required_write)
    assert requirement_satisfied(required_write, required_write)
    equivalent_effect = Capability(
        "arbitrary-write",
        EffectContract(
            writes=frozenset({"process.memory"}),
            scope=Scope.PROCESS,
        ),
    )
    assert requirement_satisfied(equivalent_effect, required_write)


def test_fact_store_rebinds_stale_epochs_but_rejects_live_conflicts():
    epochs = Epochs("service", "process-1", "connection-1")
    store = FactStore(epochs)
    fact = Fact("nonce", INTEGER, Scope.CONNECTION)
    store.bind(fact, 1)
    with pytest.raises(ConstraintError, match="conflicting"):
        store.bind(fact, 2)

    store.transition(epochs.reconnect(same_process=True))
    store.bind(fact, 2)
    assert store.resolve(fact) == 2


def test_constraint_semantic_identity_distinguishes_opposite_predicates():
    allow = Constraint("policy", lambda _values: True, "must be allowed")
    deny = Constraint("policy", lambda _values: False, "must be allowed")
    assert allow.semantic_identity != deny.semantic_identity
    assert "0x" not in allow.semantic_identity

    required = EffectContract(constraints=(allow,))
    assert effect_contract_satisfies(required, required)
    assert not effect_contract_satisfies(
        EffectContract(constraints=(deny,)),
        required,
    )

    opaque_value = object()
    explicit = Constraint(
        "closure policy",
        lambda _values: opaque_value is not None,
        semantic_id="closure-policy-v1",
    )
    assert explicit.semantic_identity == "explicit:closure-policy-v1"


def test_effect_contract_invalidation_satisfaction_uses_canonical_semantics():
    fact = Fact("state", INTEGER, Scope.PROCESS)
    available = EffectContract(
        invalidates=(fact, Scope.CONNECTION),
        scope=Scope.PROCESS,
    )
    equivalent = EffectContract(
        invalidates=(fact.expr(), "connection"),
        scope=Scope.PROCESS,
    )
    assert effect_contract_satisfies(available, equivalent)
    assert effect_contract_satisfies(equivalent, available)

    wrong_sort = Fact(
        "state",
        Sort("positive", (int,), lambda value: value > 0),
        Scope.PROCESS,
    )
    wrong_scope = Fact("state", INTEGER, Scope.CONNECTION)
    wrong_artifact = Fact(
        "state",
        INTEGER,
        Scope.PROCESS,
        artifact="exe",
    )
    for different in (wrong_sort, wrong_scope, wrong_artifact):
        assert not effect_contract_satisfies(
            available,
            EffectContract(
                invalidates=(different,),
                scope=Scope.PROCESS,
            ),
        )


def test_callable_semantic_identities_never_use_repr_addresses():
    first = Sort("bounded", (int,), lambda value: 0 <= value < 8)
    second = Sort("bounded", (int,), lambda value: 0 <= value < 8)
    first_fact = Fact("index", first, Scope.PROCESS)
    second_fact = Fact("index", second, Scope.PROCESS)
    assert invalidation_semantic_key(first_fact) == invalidation_semantic_key(
        second_fact
    )
    encoded = repr(invalidation_semantic_key(first_fact))
    assert " at 0x" not in encoded

    predicate = Constraint("bounded", lambda values: values["value"] < 8)
    assert " at 0x" not in predicate.semantic_identity


def test_capability_proof_environment_and_target_recipe_explain_themselves():
    evidence = Evidence("crash", "RIP controlled", "core.1")
    capability = Capability(
        "return-address control",
        EffectContract(
            writes=frozenset({"process.control-flow"}),
            scope=Scope.PROCESS,
            evidence=(evidence,),
        ),
        reliability="stable",
        evidence=(evidence,),
    )
    proof = TechniqueProof(
        "rop",
        "call win",
        (),
        prerequisites=(capability,),
        reliability="stable",
    )
    environment = Environment("local", {"loader": "./ld.so"})
    recipe = TargetRecipe("local", environment, ("chall",), ("./chall",))
    assert "return-address" in capability.describe()
    assert "proves call win" in proof.describe()
    assert "local environment" in recipe.describe()


def test_purpose_native_input_surface_declares_capability_and_legacy_lowering(tmp_path):
    from elf_factory import make_elf
    from pwnx.challenge import Challenge

    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    declaration = challenge.control(
        challenge.input.line(b"payload: ").return_address(at=72)
    )
    challenge.want(challenge.call(challenge.exe.win))
    plan = challenge.plan()
    assert "controls the return address" in declaration.describe()
    assert challenge.capabilities
    assert "call goal" in plan.show()
