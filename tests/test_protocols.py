from __future__ import annotations

import dataclasses

import pytest

from pwnx.actions import Capture, Emit, Encoded, Sequence
from pwnx.codecs import bytes_, integer, line_codec, pointer
from pwnx.expressions import BindingContext, Expr
from pwnx.protocols import Choice, Field, Menu, Protocols, choice, field


def notes_menu() -> Menu:
    return Protocols().menu(b"> ", name="notes").define(
        add=choice(
            b"1",
            field(b"idx: ", integer(delimiter=None), "idx"),
            field(b"size: ", integer(delimiter=None), "size"),
            field(b"content: ", bytes_(), "data", framing="raw"),
        ),
        free=choice(
            b"2",
            field(b"idx: ", integer(delimiter=None), "idx"),
        ),
        show=choice(
            b"3",
            field(b"idx: ", integer(delimiter=None), "idx"),
            returns=line_codec(),
        ),
    )


def test_menu_definition_is_declarative() -> None:
    menu = notes_menu()
    assert tuple(menu.choices) == ("add", "free", "show")
    description = menu.describe()
    assert description.startswith("notes after b'> ':")
    assert "add: command b'1'" in description
    assert "returns BytesCodec" in description


def test_menu_call_lowers_to_action_sequence() -> None:
    action = notes_menu().add(idx=4, size=0x100, data=b"AAAA")
    assert isinstance(action, Sequence)
    assert action.name == "notes.add#1"
    assert len(action.actions) == 4

    command, index, size, content = action.actions
    assert isinstance(command, Emit)
    assert command.data == b"1"
    assert command.channel.prompt == b"> "
    assert command.channel.terminator == b"\n"

    assert isinstance(index.data, Encoded)
    assert index.data.build() == b"4"
    assert index.channel.prompt == b"idx: "
    assert index.channel.terminator == b"\n"

    assert size.data.build() == b"256"
    assert content.data.build() == b"AAAA"
    assert content.channel.prompt == b"content: "
    assert content.channel.terminator is None


def test_menu_supports_positional_and_symbolic_values() -> None:
    idx = Expr.fact("note.index")
    action = notes_menu().free(idx)
    encoded = action.actions[1].data
    assert isinstance(encoded, Encoded)
    assert encoded.dependencies == {"note.index"}

    context = BindingContext()
    context.bind(idx, 7)
    assert encoded.build(context.resolve) == b"7"


def test_return_capture_has_unique_deterministic_operation_name() -> None:
    menu = notes_menu()
    first = menu.show(0)
    second = menu.show(1)
    assert first.name == "notes.show#1"
    assert second.name == "notes.show#2"
    assert isinstance(first.actions[-1], Capture)
    assert first.output is not None
    assert first.output.key == "capture:notes.show#1.result"
    assert second.output is not None
    assert second.output.key == "capture:notes.show#2.result"


def test_operation_ids_span_different_choices() -> None:
    menu = notes_menu()
    assert menu.add(0, 8, b"A").name == "notes.add#1"
    assert menu.free(0).name == "notes.free#2"
    assert menu.show(0).name == "notes.show#3"


def test_menu_call_validates_field_arguments() -> None:
    menu = notes_menu()
    with pytest.raises(TypeError, match="missing value"):
        menu.add(idx=1, size=8)
    with pytest.raises(TypeError, match="unexpected"):
        menu.free(idx=1, other=2)
    with pytest.raises(TypeError, match="at most"):
        menu.free(1, 2)
    with pytest.raises(TypeError, match="both positional and keyword"):
        menu.free(1, idx=1)


def test_unnamed_fields_require_positional_values() -> None:
    menu = Protocols().menu(b"> ").define(
        pick=choice(b"1", field(b"value: ", integer(delimiter=None)))
    )
    assert menu.pick(7).actions[1].data.build() == b"7"
    with pytest.raises(TypeError, match="unnamed field"):
        menu.pick()


def test_unknown_menu_choice_is_an_attribute_error() -> None:
    menu = notes_menu()
    with pytest.raises(AttributeError):
        menu.edit(0)
    with pytest.raises(AttributeError, match="no choice"):
        menu.invoke("edit", 0)


def test_define_rejects_duplicates_and_invalid_definitions() -> None:
    menu = Protocols().menu(b"> ").define(free=choice(b"2"))
    with pytest.raises(ValueError, match="already defined"):
        menu.define(free=choice(b"3"))
    with pytest.raises(TypeError, match="Choice"):
        menu.define(bad=object())  # type: ignore[arg-type]


def test_fields_and_choices_are_immutable_and_validated() -> None:
    item = field(b"x: ", integer(delimiter=None), "x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        item.name = "y"  # type: ignore[misc]
    with pytest.raises(ValueError, match="framing"):
        field(b"x: ", integer(), framing="packet")
    with pytest.raises(ValueError, match="unique"):
        Choice(b"1", (item, item))
    with pytest.raises(TypeError, match="Codec"):
        Field(b"x", object())  # type: ignore[arg-type]


def test_menu_requires_prompt_and_namespace() -> None:
    with pytest.raises(ValueError, match="prompt"):
        Protocols().menu(b"")
    with pytest.raises(ValueError, match="namespace"):
        Protocols().menu(b"> ", name="")


def test_choice_return_output_is_last_action() -> None:
    menu = Protocols().menu(b"> ").define(
        leak=choice(b"4", returns=pointer(6, extend="zero"))
    )
    action = menu.leak()
    assert isinstance(action.actions[-1], Capture)
    assert action.output == action.actions[-1].output
