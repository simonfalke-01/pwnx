from __future__ import annotations

from pathlib import Path

import pytest

from elf_factory import make_elf
from pwnx import (
    Bind,
    Call,
    Challenge,
    Check,
    Delay,
    Encoded,
    Expr,
    Trace,
    bytes_,
    capture,
    expect,
    format_string,
    integer,
    line,
    observed,
    pattern,
    pointer,
    raw,
    send,
    sequence,
    technique,
)
from pwnx.errors import (
    ConstraintError,
    PlanningError,
    ProtocolError,
    ReplayDivergence,
    UnresolvedValueError,
)
from pwnx.transport import Tube


class ScriptedTube(Tube):
    def __init__(self, incoming: bytes):
        super().__init__(timeout=0.1)
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.interactive_calls = 0

    def _recv_raw(self, max_bytes, timeout):
        if not self.incoming:
            return b""
        chunk = bytes(self.incoming[:max_bytes])
        del self.incoming[:max_bytes]
        return chunk

    def _send_raw(self, data, timeout):
        self.sent.extend(data)
        return len(data)

    def _close_raw(self):
        pass

    def interactive(self):
        self.interactive_calls += 1


class ScriptedDatagram(Tube):
    message_oriented = True

    def __init__(self, incoming):
        super().__init__(timeout=0.1)
        self.incoming = list(incoming)
        self.sent = []

    def recv_datagram(self, max_size=65535, timeout=None):
        if not self.incoming:
            raise AssertionError("no scripted datagram remains")
        data = self.incoming.pop(0)
        return data[:max_size], ("127.0.0.1", 31337)

    def send_datagram(self, data, *, peer=None, timeout=None):
        self.sent.append(bytes(data))

    def _recv_raw(self, max_bytes, timeout):
        raise AssertionError("stream read used for datagram target")

    def _send_raw(self, data, timeout):
        raise AssertionError("stream send used for datagram target")

    def _close_raw(self):
        pass


def fixed_image(tmp_path: Path) -> Path:
    return make_elf(tmp_path / "chall", pie=False)


def test_ret2win_declarations_compile_and_execute(tmp_path):
    binary = fixed_image(tmp_path)
    c = Challenge(binary)
    c.control(raw(b"payload: "), return_at=16)
    c.want(c.exe.win())
    c.want(expect(b"won\n"))

    plan = c.plan()
    assert plan.selected_tactic == "rop+actions"
    assert "call goal" in plan.show()
    tube = ScriptedTube(b"payload: won\n")
    with plan.run(transport=tube) as run:
        assert run.payload().size == 32

    assert bytes(tube.sent).startswith(b"A" * 16)
    assert int.from_bytes(tube.sent[-8:], "little") == 0x400100


def test_direct_observation_binds_image_base_before_payload(tmp_path):
    binary = make_elf(tmp_path / "chall", pie=False)
    libc_path = make_elf(tmp_path / "libc.so", pie=True)
    c = Challenge(binary, libc=libc_path)
    observation = c.observe("win: {libc.win:hex}\n")
    from pwnx.actions import Action

    assert isinstance(observation, Action)
    assert observation.contract().reads == frozenset({"connection.stream"})
    assert observation.contract().writes == frozenset(
        {"connection.cursor", "process.facts"}
    )
    assert observation.contract().provides == (c.libc.win,)
    c.control(raw(b"payload: "), return_at=8)
    c.want(c.libc.win())

    tube = ScriptedTube(b"banner win: 0x70000100\npayload: ")
    trace = Trace()
    run = c.run(transport=tube, trace=trace)
    assert run.value(c.libc.base) == 0x70000000
    assert int.from_bytes(tube.sent[-8:], "little") == 0x70000100
    assert trace.metadata["facts"][0]["kind"] == "observe"
    assert trace.metadata["payloads"][0]["layout"]
    run.close()


def test_learn_recipe_is_scheduled_before_dependent_goal(tmp_path):
    binary = make_elf(tmp_path / "chall", pie=False)
    libc_path = make_elf(tmp_path / "libc.so", pie=True)
    c = Challenge(binary, libc=libc_path)
    control = c.control(raw(b"payload: "), return_at=8)
    c.learn(
        c.libc.win,
        using=c.exe.puts(c.exe.got.puts),
        receive=pointer(8),
        resume=c.exe.win,
        via=control,
    )
    c.want(c.libc.win())

    leaked = (0x7F000100).to_bytes(8, "little")
    tube = ScriptedTube(b"payload: " + leaked + b"payload: ")
    plan = c.plan()
    assert "learn libc.win" in plan.show()
    run = plan.run(transport=tube)
    assert run.value(c.libc.base) == 0x7F000000
    assert bytes(tube.sent).count(b"A" * 8) == 2
    run.close()


def test_trace_replay_accepts_identical_effects_and_rejects_changed_send(tmp_path):
    binary = fixed_image(tmp_path)
    c = Challenge(binary)
    c.control(raw(b"payload: "), return_at=8)
    c.want(c.exe.win())
    c.want(expect(b"won\n"))

    trace = Trace()
    live = c.run(transport=ScriptedTube(b"payload: won\n"), trace=trace)
    live.close()
    replay = c.run(replay=trace)
    replay.close()

    changed = Challenge(binary)
    changed.control(line(b"payload: "), return_at=8)
    changed.want(changed.exe.win())
    changed.want(expect(b"won\n"))
    with pytest.raises(ReplayDivergence):
        changed.run(replay=trace)


def test_missing_fact_and_unresolved_values_have_clear_errors(tmp_path):
    binary = fixed_image(tmp_path)
    libc_path = make_elf(tmp_path / "libc.so", pie=True)
    c = Challenge(binary, libc=libc_path)
    c.control(raw(), return_at=8)
    c.want(c.libc.win())

    with pytest.raises(PlanningError, match="cannot acquire libc.base"):
        c.plan()
    with pytest.raises(UnresolvedValueError):
        bool(c.libc.base)


def test_typed_fact_validator_runs_through_real_plan(tmp_path):
    from pwnx.actions import Bind
    from pwnx.domain import INTEGER

    challenge = Challenge(fixed_image(tmp_path))
    typed = challenge.typed_fact("menu.index", INTEGER)
    challenge.want(Bind(typed.expr(), Expr.literal("wrong")))
    with pytest.raises(ConstraintError, match="integer requires int"):
        challenge.plan().run(transport=ScriptedTube(b""))


def test_runtime_target_recipe_preserves_independent_fact_epochs(tmp_path):
    from pwnx.actions import Check
    from pwnx.architecture import (
        AMD64,
        LifecycleEpochs,
        LifecyclePolicy,
        MaterializedTarget,
    )
    from pwnx.errors import StaleValueError
    from pwnx.runtime import register_environment_adapter

    adapter = f"epoch-test-{tmp_path.name}"
    register_environment_adapter(adapter, lambda _target: ScriptedTube(b""))

    class EpochRecipe:
        def materialize(self, *, epoch_seed="run"):
            return MaterializedTarget(
                adapter,
                AMD64,
                lifecycle=LifecyclePolicy(),
                epochs=LifecycleEpochs("service#1", "process#1", "connection#1"),
                adapter_identity="epoch-test-v1",
            )

    challenge = Challenge(fixed_image(tmp_path))
    service = challenge.fact("service.banner", scope="service")
    process = challenge.fact("process.base", scope="process")
    connection = challenge.fact("connection.nonce", scope="connection")
    challenge.assume(service, 1)
    challenge.assume(process, 2)
    challenge.assume(connection, 3)
    challenge.want(Check(service.equals(1)))
    connection = challenge.fact("connection.nonce", scope="connection")
    challenge.assume(service, 1)
    challenge.assume(process, 2)
    challenge.assume(connection, 3)
    challenge.want(Check(service.equals(1)))

    run = challenge.plan().run(on=EpochRecipe())
    assert run.context.epochs == {
        "artifact": None,
        "service": "service#1",
        "process": "process#1",
        "connection": "connection#1",
    }
    run.context.transition(connection="connection#2")
    assert run.value(service) == 1
    assert run.value(process) == 2
    with pytest.raises(StaleValueError, match="connection epoch"):
        run.value(connection)
    run.context.bind(connection, 4, source="new connection")
    assert run.value(connection) == 4
    with pytest.raises(ConstraintError, match="conflicting"):
        run.context.bind(connection, 5, source="same connection conflict")
    run.close()


def test_sequence_capture_and_pure_derivation_provide_goal_facts(tmp_path):
    binary = fixed_image(tmp_path)
    captured = Expr.fact("captured")
    c = Challenge(binary)
    c.control(raw(b"payload: "), return_at=8)
    c.sequence(capture(pointer(8), captured), name="capture seed")
    derived = c.derive(lambda value: value + 1, captured, name="increment")
    c.want(c.exe.puts(derived))

    tube = ScriptedTube((40).to_bytes(8, "little") + b"payload: ")
    run = c.run(transport=tube)
    assert run.value(derived) == 41
    run.close()


def test_opaque_result_is_recorded_and_not_reexecuted_during_replay(tmp_path):
    binary = fixed_image(tmp_path)
    libc_path = make_elf(tmp_path / "libc.so", pie=True)
    c = Challenge(binary, libc=libc_path)
    c.control(raw(b"payload: "), return_at=8)
    seed = c.fact("seed", scope="artifact")
    c.assume(seed, 1)
    calls = []

    @c.opaque(produces=c.libc.win, consumes=[seed], name="custom leak")
    def custom_leak(_io, values):
        calls.append(values["seed"])
        return 0x70000100

    c.want(c.libc.win())
    trace = Trace()
    live = c.run(transport=ScriptedTube(b"payload: "), trace=trace)
    live.close()
    assert calls == [1]
    assert [event.kind for event in trace.events] == [
        "opaque_start",
        "opaque",
        "receive",
        "send",
        "close",
    ]

    replay = c.run(replay=trace)
    replay.close()
    assert calls == [1]

    c._assumptions[0] = (seed, 2, "changed input")
    with pytest.raises(ReplayDivergence, match="opaque inputs changed"):
        c.run(replay=trace)
    assert calls == [1]


def test_opaque_transaction_can_consume_invalidate_and_replace(tmp_path):
    binary = fixed_image(tmp_path)
    value = Expr.fact("session.value", scope="connection")
    challenge = Challenge(binary)
    challenge.assume(value, 1)

    @challenge.opaque(
        produces=value,
        consumes=[value],
        invalidates=[value],
        name="replace value",
    )
    def replace(_io, values):
        return values[value.key] + 1

    challenge.sequence(replace, name="transactional replacement")
    challenge.want(Check(value.equals(2)))
    run = challenge.plan().run(transport=ScriptedTube(b""))
    assert run.value(value) == 2
    run.close()

    consumed = Expr.fact("session.consumed", scope="connection")
    discard = Challenge(make_elf(tmp_path / "discard", pie=False))
    discard.assume(consumed, 3)
    seen = []

    @discard.opaque(
        consumes=[consumed],
        invalidates=[consumed],
        name="discard value",
    )
    def discard_value(_io, values):
        seen.append(values[consumed.key])
        return None

    discard.sequence(discard_value, name="transactional invalidation")
    discard.want(Check(Expr.literal(True)))
    run = discard.plan().run(transport=ScriptedTube(b""))
    assert seen == [3]
    with pytest.raises(UnresolvedValueError):
        run.value(consumed)
    run.close()


def test_opaque_mutable_values_are_isolated_and_replay_transactionally(tmp_path):
    value = Expr.fact("opaque.mutable", scope="connection")
    original = {"items": [1]}
    challenge = Challenge(fixed_image(tmp_path))
    challenge.assume(value, original)

    @challenge.opaque(
        produces=value,
        consumes=[value],
        invalidates=[value],
        name="portable mutable replacement",
    )
    def replace(_io, values):
        return values[value.key]

    challenge.sequence(replace)
    challenge.want(Check(Expr.literal(True)))
    trace = Trace()
    run = challenge.plan().run(transport=ScriptedTube(b""), trace=trace)
    resolved = run.value(value)
    resolved["items"].append(2)
    assert run.value(value) == {"items": [1]}
    assert original == {"items": [1]}
    run.close()
    replay = challenge.plan().run(replay=trace)
    assert replay.value(value) == {"items": [1]}
    replay.close()

    failed_value = Expr.fact("opaque.failed", scope="connection")
    failed_original = {"items": []}
    failed = Challenge(make_elf(tmp_path / "failed", pie=False))
    failed.assume(failed_value, failed_original)

    @failed.opaque(
        consumes=[failed_value],
        invalidates=[failed_value],
        name="portable mutable failure",
    )
    def fail(_io, values):
        values[failed_value.key]["items"].append("changed")
        raise RuntimeError("opaque mutable failure")

    failed.sequence(fail)
    failed.want(Check(Expr.literal(True)))
    failure_trace = Trace()
    with pytest.raises(RuntimeError, match="opaque mutable failure"):
        failed.plan().run(
            transport=ScriptedTube(b""),
            trace=failure_trace,
        )
    assert failed_original == {"items": []}
    assert failure_trace.metadata["contract_failures"][0]["phase"] == "execution"


def test_replay_rejects_changed_artifact_identity(tmp_path):
    binary = fixed_image(tmp_path)
    c = Challenge(binary)
    c.control(raw(b"payload: "), return_at=8)
    c.want(c.exe.win())
    trace = Trace()
    live = c.run(transport=ScriptedTube(b"payload: "), trace=trace)
    live.close()

    changed_path = tmp_path / "changed"
    changed_path.write_bytes(binary.read_bytes() + b"changed")
    changed = Challenge(changed_path)
    changed.control(raw(b"payload: "), return_at=8)
    changed.want(changed.exe.win())
    with pytest.raises(ReplayDivergence, match="artifact 'exe' changed"):
        changed.run(replay=trace)


def test_supplied_loader_and_libc_define_local_launch(tmp_path):
    binary = fixed_image(tmp_path)
    libc_path = make_elf(tmp_path / "libc.so", pie=True)
    loader = tmp_path / "ld.so"
    loader.write_bytes(b"loader placeholder")
    c = Challenge(binary, libc=libc_path, loader=loader)

    assert c.profiles["local"].argv == (
        str(loader.resolve()),
        "--library-path",
        str(libc_path.parent),
        str(binary.resolve()),
    )


def test_action_output_keeps_its_producer_for_triggered_observation(tmp_path):
    binary = fixed_image(tmp_path)
    c = Challenge(binary)
    trigger = c.fact("trigger")
    leak = c.fact("leak")
    producer = sequence(
        send(b"1", raw(b"> ")),
        Bind(trigger, 1),
        name="show leak",
    )
    c.observe(pattern(b"leak: ", observed(leak), b"\n"), from_=producer.output)
    c.control(raw(b"payload: "), return_at=8)
    c.want(c.exe.win())

    tube = ScriptedTube(b"> leak: 0x2a\npayload: ")
    run = c.run(transport=tube)
    assert run.value(trigger) == 1
    assert run.value(leak) == 42
    assert bytes(tube.sent).startswith(b"1")
    run.close()


def test_explicit_sequence_dependencies_schedule_recipe_first(tmp_path):
    binary = fixed_image(tmp_path)
    libc_path = make_elf(tmp_path / "libc.so", pie=True)
    c = Challenge(binary, libc=libc_path)
    c.control(raw(), return_at=8)

    @c.opaque(produces=c.libc.win, name="obtain runtime address")
    def address(_io, _values):
        return 0x71000100

    from pwnx.actions import Encoded

    c.sequence(
        send(Encoded(pointer(8), c.libc.win), raw(b"value: ")),
        name="use acquired address",
    )
    c.want(expect(b"done\n"))

    tube = ScriptedTube(b"value: done\n")
    plan = c.plan()
    assert plan.stages[0].name.endswith("obtain runtime address")
    run = plan.run(transport=tube)
    assert bytes(tube.sent) == (0x71000100).to_bytes(8, "little")
    run.close()


def test_preference_ranks_applicable_tactics_and_falls_back(tmp_path):
    binary = fixed_image(tmp_path)
    c = Challenge(binary)
    c.control(raw(), return_at=8)
    c.prefer(technique.dlresolve)
    c.want(c.exe.win())

    plan = c.plan()
    assert plan.selected_tactic == "rop"
    assert "rejected dlresolve" in plan.explain_selection()
    assert "target is defined by the executable" in plan.explain_selection()


def test_multiple_startup_observations_are_rejected_as_cursor_ambiguous(tmp_path):
    c = Challenge(fixed_image(tmp_path))
    c.observe("one: {stack.one:hex}\n")
    c.observe("two: {stack.two:hex}\n")
    c.control(raw(), return_at=8)
    c.want(c.exe.win())

    with pytest.raises(PlanningError, match="multiple startup observations"):
        c.plan()


def test_delay_is_explicit_live_and_replay_safe(tmp_path):
    c = Challenge(fixed_image(tmp_path))
    c.sequence(Delay(0.001, "test boundary"))
    c.want(expect(b"done\n"))
    trace = Trace()
    live = c.run(transport=ScriptedTube(b"done\n"), trace=trace)
    live.close()
    replay = c.run(replay=trace)
    replay.close()
    assert "wait 0.001s" in c.plan().show()


def test_shell_goal_enters_interactive_automatically(tmp_path):
    binary = fixed_image(tmp_path)
    libc_path = make_elf(tmp_path / "libc.so", pie=True)
    c = Challenge(binary, libc=libc_path)
    c.assume(c.libc.base, 0x70000000)
    c.control(raw(b"payload: "), return_at=8)
    c.want(Call(c.libc.win, ("/bin/sh",), name="libc.system"))
    tube = ScriptedTube(b"payload: ")

    run = c.run(transport=tube)
    assert run.plan.auto_interactive is True
    assert tube.interactive_calls == 1
    run.close()


def test_custom_technique_uses_same_inspectable_action_ir(tmp_path):
    c = Challenge(fixed_image(tmp_path))
    control = c.control(raw(b"custom: "), return_at=8)

    @c.technique(
        name="custom",
        requires=[control],
        provides=[],
        reliability="stable",
    )
    def custom(ctx):
        assert ctx.control is control
        return send(b"CUSTOM", ctx.control.channel)

    c.want(c.exe.win(), using=custom)
    plan = c.plan()
    assert plan.selected_tactic == "custom"
    assert "send b'CUSTOM'" in plan.show()
    tube = ScriptedTube(b"custom: ")
    run = plan.run(transport=tube)
    assert bytes(tube.sent) == b"CUSTOM"
    run.close()


def test_opaque_io_subtrace_is_reused_without_reexecuting_callback(tmp_path):
    binary = fixed_image(tmp_path)
    libc_path = make_elf(tmp_path / "libc.so", pie=True)
    c = Challenge(binary, libc=libc_path)
    c.control(raw(b"payload: "), return_at=8)
    calls = []

    @c.opaque(produces=c.libc.win, name="interactive custom leak")
    def leak(io, _values):
        calls.append("called")
        io.send(b"LEAK")
        return int.from_bytes(io.read_exact(8), "little")

    c.want(c.libc.win())
    trace = Trace()
    incoming = (0x72000100).to_bytes(8, "little") + b"payload: "
    live = c.run(transport=ScriptedTube(incoming), trace=trace)
    live.close()
    assert calls == ["called"]
    assert [event.kind for event in trace.events[:4]] == [
        "opaque_start",
        "send",
        "receive",
        "opaque",
    ]

    replay = c.run(replay=trace)
    replay.close()
    assert calls == ["called"]


def test_callable_recipe_dependencies_are_acquired_after_lowering(tmp_path):
    binary = fixed_image(tmp_path)
    c = Challenge(binary)
    c.control(raw(b"payload: "), return_at=8)
    first = c.fact("first")
    second = c.fact("second")

    @c.opaque(produces=first, name="first fact")
    def first_fact(_io, _values):
        return 0x41

    @c.recipe(produces=second, name="second fact")
    def second_fact(r):
        return r.sequence(
            send(Encoded(pointer(8), first), raw(b"value: ")),
            r.capture(pointer(8), second),
            name="derive second through target",
        )

    c.want(c.exe.puts(second))
    tube = ScriptedTube(
        b"value: " + (0x42).to_bytes(8, "little") + b"payload: "
    )
    plan = c.plan()
    assert [stage.name.split(": ", 1)[-1] for stage in plan.stages[:2]] == [
        "first fact",
        "second fact",
    ]
    run = plan.run(transport=tube)
    assert run.value(second) == 0x42
    run.close()


def test_branch_body_dependencies_are_planned(tmp_path):
    binary = fixed_image(tmp_path)
    c = Challenge(binary)
    c.control(raw(), return_at=8)
    predicate = c.fact("predicate")
    value = c.fact("branch-value")
    c.assume(predicate, True)

    @c.opaque(produces=value, name="branch dependency")
    def branch_value(_io, _values):
        return 7

    from pwnx import Branch

    branch = Branch(
        predicate.equals(True),
        sequence(send(Encoded(pointer(8), value)), name="then"),
        sequence(send(b"no"), name="otherwise"),
    )
    c.sequence(branch, name="conditional use")
    c.want(expect(b"done\n"))

    tube = ScriptedTube(b"done\n")
    run = c.run(transport=tube)
    assert bytes(tube.sent) == (7).to_bytes(8, "little")
    run.close()


def test_custom_technique_action_dependencies_are_acquired(tmp_path):
    c = Challenge(fixed_image(tmp_path))
    control = c.control(raw(b"custom: "), return_at=8)
    value = c.fact("technique-value")

    @c.opaque(produces=value, name="technique dependency")
    def dependency(_io, _values):
        return 0x55

    @c.technique(name="dependent", requires=[control], provides=[], cost=2)
    def dependent(ctx):
        return send(Encoded(pointer(8), value), ctx.control.channel)

    c.want(c.exe.win(), using=dependent)
    plan = c.plan()
    assert plan.stages[0].name.endswith("technique dependency")
    tube = ScriptedTube(b"custom: ")
    run = plan.run(transport=tube)
    assert bytes(tube.sent) == (0x55).to_bytes(8, "little")
    run.close()


def test_plugin_reliability_and_cost_affect_default_ranking(tmp_path):
    c = Challenge(fixed_image(tmp_path))
    c.control(raw(b"custom: "), return_at=8)
    c.forbid(technique.rop)
    c.forbid(technique.dlresolve)

    @c.technique(name="experimental", reliability="experimental", cost=0)
    def experimental(ctx):
        return send(b"EXPERIMENTAL", ctx.control.channel)

    @c.technique(name="stable", reliability="stable", cost=10)
    def stable(ctx):
        return send(b"STABLE", ctx.control.channel)

    c.want(c.exe.win())
    plan = c.plan()
    assert plan.selected_tactic == "stable"
    assert "[stable, cost=10]" in plan.show()
    tube = ScriptedTube(b"custom: ")
    run = plan.run(transport=tube)
    assert bytes(tube.sent) == b"STABLE"
    run.close()


def test_non_call_fact_acquisition_needs_no_fake_overflow_control(tmp_path):
    c = Challenge(fixed_image(tmp_path))
    value = c.fact("protocol-value")

    @c.opaque(produces=value, name="protocol acquisition")
    def acquire(_io, _values):
        return 9

    c.sequence(
        send(Encoded(pointer(8), value), raw(b"value: ")),
        name="use protocol fact",
    )
    c.want(expect(b"done\n"))

    tube = ScriptedTube(b"value: done\n")
    plan = c.plan()
    assert plan.stages[0].name.endswith("protocol acquisition")
    run = plan.run(transport=tube)
    assert bytes(tube.sent) == (9).to_bytes(8, "little")
    run.close()


def test_planner_reacquires_fact_after_declared_invalidation(tmp_path):
    binary = fixed_image(tmp_path)
    libc_path = make_elf(tmp_path / "libc.so", pie=True)
    c = Challenge(binary, libc=libc_path)
    c.control(raw(b"payload: "), return_at=8)
    c.assume(c.libc.base, 0x70000000, reason="initial process state")
    marker = c.fact("mutation-complete")
    calls = []

    @c.opaque(
        produces=marker,
        invalidates=[c.libc.base],
        name="restart process",
    )
    def restart(_io, _values):
        calls.append("restart")
        return True

    @c.opaque(produces=c.libc.base, name="reacquire libc")
    def reacquire(_io, _values):
        calls.append("reacquire")
        return 0x71000000

    c.sequence(restart, name="state mutation")
    c.want(c.libc.win())

    plan = c.plan()
    assert [stage.name.split(": ", 1)[-1] for stage in plan.stages[:2]] == [
        "state mutation",
        "reacquire libc",
    ]
    tube = ScriptedTube(b"payload: ")
    run = plan.run(transport=tube)
    assert calls == ["restart", "reacquire"]
    assert run.value(c.libc.base) == 0x71000000
    run.close()


def test_explicit_debug_qemu_and_ssh_profiles(tmp_path, monkeypatch):
    binary = fixed_image(tmp_path)
    c = Challenge(binary)
    monkeypatch.setattr(
        "pwnx.challenge.shutil.which",
        lambda name: f"/tools/{name}",
    )

    c.gdb(breakpoints=[c.exe.win, "main"], commands=["continue"])
    assert c.profiles["debug"].debugger[:2] == ("/tools/gdb", "-q")
    assert "break *0x400100" in c.profiles["debug"].debugger

    c.qemu(
        arch="amd64",
        sysroot=tmp_path,
        arguments=("--flag",),
        gdb_port=1234,
    )
    assert c.profiles["qemu"].argv[:4] == (
        "/tools/qemu-x86_64",
        "-L",
        str(tmp_path.resolve()),
        "-g",
    )

    identity = tmp_path / "id"
    identity.write_text("key", encoding="ascii")
    c.ssh(
        "host",
        ("./chall", "--remote"),
        user="ctf",
        identity=identity,
        options=["StrictHostKeyChecking=no"],
    )
    assert c.profiles["ssh"].argv[-4:] == (
        "ctf@host",
        "--",
        "./chall",
        "--remote",
    )

    c.remote("127.0.0.1", 31337, protocol="udp", name="udp")
    assert c.profiles["udp"].kind == "udp"
    c.listen("0.0.0.0", 4444, backlog=3)
    assert c.profiles["listen"].options["backlog"] == 3
    with pytest.raises(ValueError, match="explicit port"):
        c.listen()
    c.serial("/dev/ttyUSB0", baud=57600)
    assert c.profiles["serial"].options["baud"] == 57600


def test_format_offset_discovery_is_a_traced_plan_stage(tmp_path):
    c = Challenge(fixed_image(tmp_path))
    fmt = c.control(
        format_string(
            b"format: ",
            offset="auto",
            discover_range=(1, 5),
        )
    )
    c.want(fmt.write(c.exe.got.puts, c.exe.win))
    marker = b"0x4242424241414141"
    incoming = (
        b"format: nope\n"
        b"format: still-nope\n"
        b"format: " + marker + b"\n"
        b"format: "
    )
    trace = Trace()
    tube = ScriptedTube(incoming)
    run = c.run(transport=tube, trace=trace)
    assert run.value(fmt.offset) == 3
    assert c.plan().stages[0].name.endswith("discover format offset")
    assert trace.metadata["facts"][0]["kind"] == "discover"
    assert bytes(tube.sent).startswith(b"AAAABBBB.%1$p\n")
    run.close()
    replay = c.run(replay=trace)
    assert replay.value(fmt.offset) == 3
    replay.close()


def test_unused_format_discovery_does_not_create_hidden_io(tmp_path):
    c = Challenge(fixed_image(tmp_path))
    c.control(format_string(b"format: ", offset="auto"))
    c.control(raw(b"payload: "), return_at=8)
    c.want(c.exe.win())

    plan = c.plan()
    assert "discover format offset" not in plan.show()


def test_format_discovery_rejects_non_text_response_codec(tmp_path):
    c = Challenge(fixed_image(tmp_path))
    fmt = c.control(
        format_string(
            b"format: ",
            offset="auto",
            response=integer(),
            discover_range=(1, 2),
        )
    )
    c.want(fmt.write(c.exe.got.puts, c.exe.win))
    with pytest.raises(ProtocolError, match="must return bytes or str"):
        c.run(transport=ScriptedTube(b"format: 123\n"))


def test_run_debugger_attachment_is_explicit_and_recorded(tmp_path, monkeypatch):
    c = Challenge(fixed_image(tmp_path))
    c.want(expect(b"ready\n"))
    tube = ScriptedTube(b"ready\n")
    tube.pid = 4242
    trace = Trace()
    run = c.run(transport=tube, trace=trace)
    launched = []

    class FakeDebugger:
        def wait(self):
            launched.append("waited")

    monkeypatch.setattr("pwnx.runtime.shutil.which", lambda _name: "/tools/gdb")
    monkeypatch.setattr(
        "pwnx.runtime.subprocess.Popen",
        lambda argv: launched.append(argv) or FakeDebugger(),
    )
    run.attach_gdb(commands=["break main", "continue"], wait=True)
    assert launched[0] == [
        "/tools/gdb",
        "-q",
        "-p",
        "4242",
        "-ex",
        "break main",
        "-ex",
        "continue",
    ]
    assert trace.metadata["debugger"][0]["pid"] == 4242
    run.close()


def test_declarative_udp_preserves_datagram_boundaries_and_replays(tmp_path):
    c = Challenge(fixed_image(tmp_path))
    result = c.fact("udp-result")
    c.sequence(
        send(b"REQUEST", raw(b"PROMPT")),
        capture(bytes_(4), result),
        name="udp exchange",
    )
    c.want(expect(b"DONE"))
    trace = Trace()
    transport = ScriptedDatagram([b"PROMPT", b"DATA", b"DONE"])
    live = c.run(transport=transport, trace=trace)
    assert live.value(result) == b"DATA"
    live.close()
    assert transport.sent == [b"REQUEST"]
    assert [event.kind for event in trace.events[:4]] == [
        "datagram_receive",
        "datagram_send",
        "datagram_receive",
        "datagram_receive",
    ]
    replay = c.run(replay=trace)
    assert replay.value(result) == b"DATA"
    replay.close()

