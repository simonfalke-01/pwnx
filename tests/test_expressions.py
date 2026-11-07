import pytest

from pwnx.errors import ConstraintError, StaleValueError, UnresolvedValueError
from pwnx.domain import ADDRESS, INTEGER, Fact, Scope
from pwnx.expressions import BindingContext, Call, Expr, Resolved, as_expr


def test_expression_is_symbolic_and_tracks_dependencies():
    base = Expr.fact("libc.base", kind="address", space="libc")
    system = (base + 0x52290).with_label("libc.system")

    assert system.dependencies == {"libc.base"}
    assert system.kind == "address"
    assert system.space == "libc"
    assert system.describe() == "libc.system"
    assert system.key == "add(libc.base,336528)"

    with pytest.raises(UnresolvedValueError, match="symbolic"):
        bool(system)
    with pytest.raises(UnresolvedValueError, match="symbolic"):
        int(system)
    with pytest.raises(UnresolvedValueError, match="symbolic"):
        bytes(system)


def test_binding_linear_address_solves_base_and_explains_evidence():
    base = Expr.fact("libc.base", kind="address", space="libc")
    puts = (base + 0x80ED0).with_label("libc.puts")
    context = BindingContext(instance_id="remote#1")

    observed = context.bind(puts, 0x7F00_0008_0ED0, source="banner bytes 6..19")

    assert isinstance(observed, Resolved)
    assert context.resolve(base) == 0x7F00_0000_0000
    assert context.resolve(puts) == 0x7F00_0008_0ED0
    assert context.has(puts)
    assert "banner bytes 6..19" in context.explain(puts)


def test_conflicting_observation_is_rejected():
    base = Expr.fact("exe.base", kind="address", space="exe")
    symbol = base + 0x1234
    context = BindingContext(instance_id="process#1")
    context.bind(symbol, 0x5555_0000_1234, source="first leak")

    with pytest.raises(ConstraintError, match="conflicting values"):
        context.bind(symbol, 0x6666_0000_1234, source="second leak")


def test_noninvertible_observation_is_rejected_until_dependencies_known():
    left = Expr.fact("left")
    right = Expr.fact("right")
    context = BindingContext()

    with pytest.raises(ConstraintError, match="not invertible"):
        context.bind(left ^ right, 3)


def test_resolved_value_is_instance_scoped():
    leak = Expr.fact("heap.base", scope="process", kind="address", space="heap")
    first = BindingContext(instance_id="process#1")
    first.bind(leak, 0x404000)
    resolved = first.resolved(leak)

    assert first.resolve(resolved) == 0x404000
    with pytest.raises(StaleValueError, match="process#1"):
        BindingContext(instance_id="process#2").resolve(resolved)


def test_binding_context_tracks_independent_lifecycle_epochs():
    service = Expr.fact("service.banner", scope="service")
    process = Expr.fact("libc.base", scope="process")
    connection = Expr.fact("session.nonce", scope="connection")
    context = BindingContext(
        service_id="service#1",
        process_id="process#1",
        connection_id="connection#1",
    )
    context.bind(service, 1, source="banner")
    context.bind(process, 2, source="leak")
    context.bind(connection, 3, source="handshake")

    context.transition(connection="connection#2")
    assert context.resolve(service) == 1
    assert context.resolve(process) == 2
    with pytest.raises(StaleValueError, match="connection epoch"):
        context.resolve(connection)

    context.transition(process="process#2")
    assert context.resolve(service) == 1
    with pytest.raises(StaleValueError, match="process epoch"):
        context.resolve(process)

    context.bind(process, 4, source="new process leak")
    assert context.resolve(process) == 4
    with pytest.raises(ConstraintError, match="conflicting"):
        context.bind(process, 5, source="conflicting live leak")


def test_typed_fact_expression_executes_sort_validator():
    fact = Fact("menu.index", INTEGER, Scope.PROCESS)
    context = BindingContext(instance_id="process")
    with pytest.raises(ConstraintError, match="integer requires int"):
        context.bind(fact.expr(), "not-an-int")

    untyped = BindingContext(instance_id="process")
    untyped.bind(Expr.fact("menu.index"), 7)
    with pytest.raises(ConstraintError, match="incompatible semantics"):
        untyped.resolve(fact.expr())


def test_stale_epoch_never_allows_same_name_semantic_drift():
    original = Fact("base", ADDRESS, Scope.PROCESS, artifact="libc")
    context = BindingContext(instance_id="process-1")
    context.bind(original.expr(), 0x70000000)
    context.transition(process="process-2")

    with pytest.raises(ConstraintError, match="existing sort"):
        context.bind(Fact("base", INTEGER, Scope.PROCESS).expr(), 1)
    with pytest.raises(ConstraintError, match="existing scope"):
        context.bind(
            Fact("base", ADDRESS, Scope.CONNECTION, artifact="libc").expr(),
            0x70000000,
        )
    with pytest.raises(ConstraintError, match="existing artifact"):
        context.bind(
            Fact("base", ADDRESS, Scope.PROCESS, artifact="exe").expr(),
            0x400000,
        )


def test_mutable_bindings_are_isolated_by_bounded_snapshots():
    fact = Expr.fact("portable")
    original = {"items": [1]}
    context = BindingContext(instance_id="process")
    context.bind(fact, original)
    original["items"].append(2)
    assert context.resolve(fact) == {"items": [1]}

    resolved = context.resolve(fact)
    resolved["items"].append(3)
    assert context.resolve(fact) == {"items": [1]}

    cyclic = []
    cyclic.append(cyclic)
    with pytest.raises(ConstraintError, match="cycle"):
        context.bind(Expr.fact("cyclic"), cyclic)


def test_low_bits_and_equality_are_expression_nodes():
    leak = Expr.fact("leak")
    check = leak.low(12).equals(0xD90)
    context = BindingContext()
    context.bind(leak, 0x7F12345D90)

    assert check.kind == "boolean"
    assert context.resolve(check) is True


def test_calls_are_pure_and_track_all_dependencies():
    base = Expr.fact("libc.base", kind="address", space="libc")
    stack = Expr.fact("stack", kind="address", space="stack")
    call = Call(base + 0x50000, [stack, "/bin/sh"], name="system")

    assert call.dependencies == {"libc.base", "stack"}
    assert call.describe().startswith("system(")
    assert call.key.startswith("call:add(libc.base")


def test_as_expr_rejects_arbitrary_python_objects():
    with pytest.raises(TypeError, match="cannot use object"):
        as_expr(object())


def test_address_arithmetic_rejects_category_errors():
    libc = Expr.fact("libc.base", kind="address", space="libc")
    exe = Expr.fact("exe.base", kind="address", space="exe")

    with pytest.raises(TypeError, match="adding two"):
        _ = libc + libc
    with pytest.raises(TypeError, match="different images"):
        _ = libc - exe
    assert (libc - (libc + 8)).kind == "integer"


def test_resolved_value_cannot_shed_instance_scope_via_as_expr():
    fact = Expr.fact("stack", kind="address", space="stack")
    resolved = Resolved(0x7FFF0000, fact, "process#1")

    with pytest.raises(TypeError, match="unscoped"):
        as_expr(resolved)
