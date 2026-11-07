from __future__ import annotations

import dataclasses

import pytest

from pwnx.actions import (
    Bind,
    Branch,
    Capture,
    Check,
    Emit,
    Encoded,
    Expect,
    Sequence,
    capture,
    expect,
    send,
    sequence,
)
from pwnx.channels import line, raw
from pwnx.codecs import integer, pointer
from pwnx.expressions import BindingContext, Expr


def test_emit_defaults_to_raw_channel_and_describes_itself() -> None:
    action = send(b"hello")
    assert action == Emit(b"hello", raw())
    assert action.channel.terminator is None
    assert action.describe() == "send b'hello' through raw channel"


def test_expect_is_bounded_and_accepts_ascii_sugar() -> None:
    action = expect("> ", timeout=1.5, max_bytes=32)
    assert action.delimiter == b"> "
    assert action.describe() == "expect b'> ' (timeout 1.5s, max 32 bytes)"

    with pytest.raises(ValueError, match="empty"):
        expect(b"")
    with pytest.raises(ValueError, match="positive"):
        Expect(b"x", timeout=0)
    with pytest.raises(ValueError, match="positive"):
        Expect(b"x", max_bytes=0)


def test_capture_output_is_explicit_or_deterministic() -> None:
    target = Expr.fact("libc.puts", kind="address", space="libc")
    explicit = capture(pointer(), target, name="puts")
    assert explicit.output is target
    assert "libc.puts" in explicit.describe()

    implicit = capture(pointer(), name="first leak")
    assert implicit.output.key == "capture:first leak"
    assert implicit.output.key == capture(pointer(), name="first leak").output.key
    assert capture(pointer()).output.key == "capture:capture"


def test_encoded_value_resolves_symbolic_input_at_runtime() -> None:
    value = Expr.fact("menu.index")
    encoded = Encoded(integer(delimiter=None), value)
    assert encoded.dependencies == {"menu.index"}

    context = BindingContext()
    context.bind(value, 42, "test")
    assert encoded.build(context.resolve) == b"42"
    assert encoded.describe() == "DelimitedIntegerCodec(menu.index)"


def test_bind_and_check_have_outputs_and_diagnostics() -> None:
    target = Expr.fact("leak")
    binding = Bind(target, 7)
    assert binding.output is target
    assert binding.describe() == "bind leak to 7"

    check = Check(target.equals(7), "leak must match")
    assert check.describe() == "check (leak == 7): leak must match"
    with pytest.raises(TypeError, match="boolean"):
        Check(target, "wrong")


def test_sequence_preserves_order_and_returns_last_output() -> None:
    target = Expr.fact("result")
    actions = sequence(
        expect(b"> "),
        send(b"1", line()),
        capture(pointer(), target),
        name="leak",
    )
    assert isinstance(actions, Sequence)
    assert actions.output is target
    assert actions.actions[0].delimiter == b"> "
    assert actions.actions[1].data == b"1"
    assert actions.actions[2].output is target
    description = actions.describe()
    assert description.startswith("leak:\n")
    assert "1. expect b'> '" in description
    assert "3. capture PointerCodec as result" in description


def test_empty_sequence_has_no_output() -> None:
    actions = sequence(name="empty")
    assert actions.output is None
    assert actions.describe() == "empty: no actions"


def test_branch_requires_planned_boolean_and_sequences() -> None:
    leak = Expr.fact("leak")
    predicate = leak.low(12).equals(0x123)
    result = Expr.fact("result")
    branch = Branch(
        predicate,
        sequence(Bind(result, 1), name="known"),
        sequence(Bind(result, 2), name="unknown"),
    )
    assert branch.output is result
    assert branch.describe().startswith("if (low 12 bits of leak == 291):")
    assert "otherwise:" in branch.describe()

    with pytest.raises(TypeError, match="boolean"):
        Branch(leak, sequence(), sequence())
    with pytest.raises(TypeError, match="Sequence"):
        Branch(predicate, send(b"x"), sequence())  # type: ignore[arg-type]


def test_actions_are_immutable() -> None:
    action = send(b"x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        action.data = b"y"  # type: ignore[misc]


def test_action_validation_rejects_wrong_objects() -> None:
    with pytest.raises(TypeError, match="Channel"):
        Emit(b"x", object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="Codec"):
        Capture(object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="tuple"):
        Sequence([send(b"x")])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="not an Action"):
        Sequence((object(),))  # type: ignore[arg-type]

