from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pwnx
import pwnx.runtime as runtime
import pytest

from elf_factory import make_elf
from pwnx import (
    CRC32,
    Challenge,
    ChecksumTransform,
    CompressionTransform,
    ConstraintError,
    DigestTransform,
    PlanningError,
    ReplayDivergence,
    RetryableInstanceError,
    Trace,
    UnresolvedValueError,
    bytes_,
    frame,
    tcp,
    word,
)
from pwnx.transport import Tube


EXAMPLE = Path(__file__).parents[1] / "examples" / "bytecraft.py"
CANARY = 0x00A1A2A3A4A5A600
LIBC_BASE = 0x7F1234500000
BAD_DYNAMIC_WORD = 0x4141410A41414141
GOOD_DYNAMIC_WORD = 0x4242424242424242


class ScriptedTube(Tube):
    def __init__(self, incoming: bytes = b"") -> None:
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


class TrackingRecipe:
    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.seeds: list[str] = []

    @property
    def architecture(self):
        return self.delegate.architecture

    @property
    def identity(self):
        return self.delegate.identity

    @property
    def lifecycle(self):
        return self.delegate.lifecycle

    def materialize(self, *, epoch_seed: str = "run"):
        self.seeds.append(epoch_seed)
        return self.delegate.materialize(epoch_seed=epoch_seed)


def target(tmp_path: Path, name: str = "target") -> Challenge:
    return Challenge(make_elf(tmp_path / name, pie=False))


def execute(challenge: Challenge, incoming: bytes = b""):
    tube = ScriptedTube(incoming)
    trace = Trace()
    run = challenge.plan().run(transport=tube, trace=trace)
    return run, tube, trace


def test_canonical_bytecraft_example_uses_no_internal_types_or_user_classes() -> None:
    source = EXAMPLE.read_text()
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}

    assert imported == {"Challenge"}
    assert not {
        "Action",
        "Payload",
        "Packed",
        "Emit",
        "ROPCompiler",
        "p64",
        "u64",
    } & names
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Lambda))
        for node in ast.walk(tree)
    )
    assert "x.craft(" in source
    assert "x.send(" in source


def test_primary_namespace_exports_only_the_user_visible_payload_artifact_type() -> None:
    assert "PayloadArtifact" in pwnx.__all__
    assert not {"Craft", "PlannedPayload"} & set(pwnx.__all__)


def test_manual_canary_and_rop_craft_matches_exact_reference(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    canary = challenge.fact("stack.cookie")
    challenge.assume(canary, CANARY, reason="captured stack cookie")
    payload = (
        challenge.craft("manual stack payload")
        .pad_to(24, fill=b"A", label="buffer")
        .word(canary, label="stack cookie")
        .pad(8, fill=b"B", label="saved frame")
        .word(0x4012D3, label="pop rdi")
        .word(0x404080, label="command")
        .word(0x401050, label="system")
    )
    challenge.send(payload, to=challenge.input.raw())

    run, tube, _trace = execute(challenge)
    run.close()

    expected = (
        b"A" * 24
        + CANARY.to_bytes(8, "little")
        + b"B" * 8
        + (0x4012D3).to_bytes(8, "little")
        + (0x404080).to_bytes(8, "little")
        + (0x401050).to_bytes(8, "little")
    )
    assert bytes(tube.sent) == expected


def test_sparse_overlap_reports_both_labels_and_ranges(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    header = (
        challenge.craft("sparse frame", fill=b"_")
        .at(4)
        .raw(b"HEAD", label="header")
    )

    with pytest.raises(ConstraintError) as raised:
        header.at(6).raw(b"BODY", label="body")

    message = str(raised.value)
    assert "header" in message and "body" in message
    assert "0x4..0x8" in message
    assert "0x6..0xa" in message


@pytest.mark.parametrize("bits", (16, 24, 32, 64))
@pytest.mark.parametrize("endian", ("little", "big"))
def test_craft_supports_explicit_integer_widths_and_endianness(
    tmp_path: Path,
    bits: int,
    endian: str,
) -> None:
    challenge = target(tmp_path)
    value = (1 << bits) - 0x123
    payload = challenge.craft(
        f"{bits}-bit {endian}", endian=endian
    ).int(value, bits=bits, label="integer")
    challenge.send(payload, to=challenge.input.raw())

    run, tube, _trace = execute(challenge)
    run.close()

    assert bytes(tube.sent) == value.to_bytes(bits // 8, endian)


@pytest.mark.parametrize(
    ("endian", "expected"),
    (("little", bytes.fromhex("887766")), ("big", bytes.fromhex("112233"))),
)
def test_partial_pointer_width_is_explicit(
    tmp_path: Path,
    endian: str,
    expected: bytes,
) -> None:
    challenge = target(tmp_path)
    payload = challenge.craft(
        "partial pointer", endian=endian, pointer_size=8
    ).ptr(0x1122334455667788, bytes=3, label="partial function pointer")
    challenge.send(payload, to=challenge.input.raw())

    run, tube, _trace = execute(challenge)
    run.close()

    assert bytes(tube.sent) == expected


def test_pad_align_and_at_are_immutable(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    empty = challenge.craft("immutable layout", fill=b"_")
    padded = empty.pad(2, fill=b"P", label="prefix")
    aligned = padded.align(8, fill=b"X", label="alignment")
    sparse = aligned.at(10).raw(b"Z", label="tail")

    assert not empty.layout()
    assert [row["label"] for row in padded.layout()] == ["prefix"]
    assert [row["label"] for row in aligned.layout()] == ["prefix", "alignment"]
    assert [row["label"] for row in sparse.layout()][-1] == "tail"
    assert "50 50" in padded.hexdump()
    assert "58 58 58 58 58 58" in aligned.hexdump()


def test_replace_requires_explicit_reason(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    original = challenge.craft("replaceable").raw(b"ABCDEFGH", label="original")

    with pytest.raises(TypeError, match="reason"):
        original.replace(2, 2, b"zz", label="replacement")


def test_replace_returns_changed_copy_without_mutating_original(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    original = challenge.craft("replaceable").raw(b"ABCDEFGH", label="original")
    changed = original.replace(
        2,
        2,
        b"zz",
        label="replacement",
        reason="partial overwrite primitive",
    )

    assert "41 42 43 44 45 46 47 48" in original.hexdump()
    assert "41 42 7a 7a 45 46 47 48" in changed.hexdump()
    assert "partial overwrite primitive" in changed.show()


def test_replace_rejects_implicit_size_change(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    original = challenge.craft("replaceable").raw(b"ABCDEFGH", label="original")

    with pytest.raises(ConstraintError, match="same-size|2 bytes"):
        original.replace(
            2,
            2,
            b"LONG",
            label="resized",
            reason="must opt in to resize",
        )


@pytest.mark.parametrize(
    ("requirement", "match"),
    (
        ({"no": b"\n"}, "forbidden|0x0a"),
        ({"max_size": 3}, "maximum|max"),
        ({"min_size": 5}, "minimum|min"),
        ({"exact_size": 5}, "exact"),
    ),
)
def test_size_and_forbidden_constraints_fail_before_send(
    tmp_path: Path,
    requirement: dict,
    match: str,
) -> None:
    challenge = target(tmp_path)
    payload = challenge.craft("constrained").raw(
        b"A\nBC", label="user bytes"
    ).require(**requirement)
    challenge.send(payload, to=challenge.input.raw())
    tube = ScriptedTube()

    with pytest.raises(ConstraintError, match=match):
        challenge.plan().run(transport=tube)

    assert bytes(tube.sent) == b""


def test_utf8_constraint_names_the_invalid_region_before_send(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    payload = (
        challenge.craft("utf8 shellcode")
        .raw(b"OK\xff", label="decoder stub")
        .require(encoding="utf8")
    )
    challenge.send(payload, to=challenge.input.raw())
    tube = ScriptedTube()

    with pytest.raises(ConstraintError, match="UTF-8|utf8|decoder stub"):
        challenge.plan().run(transport=tube)

    assert bytes(tube.sent) == b""


def test_custom_final_byte_constraint_uses_explanation(tmp_path: Path) -> None:
    challenge = target(tmp_path)

    def has_magic(data: bytes) -> bool:
        return data.startswith(b"MAGIC")

    payload = (
        challenge.craft("custom constrained")
        .raw(b"NOPE", label="packet")
        .require(predicate=has_magic, explanation="packet must start with MAGIC")
    )
    challenge.send(payload, to=challenge.input.raw())

    with pytest.raises(ConstraintError, match="packet must start with MAGIC"):
        challenge.plan().run(transport=ScriptedTube())


def test_length_codec_can_be_embedded_in_craft(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    codec = frame(bytes_(), length=word(16, "big"))
    payload = challenge.craft("length packet").encoded(
        codec, b"ABC", label="length-prefixed body"
    )
    challenge.send(payload, to=challenge.input.raw())

    run, tube, _trace = execute(challenge)
    run.close()

    assert bytes(tube.sent) == b"\x00\x03ABC"


def test_crc_codec_can_be_embedded_in_craft(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    codec = bytes_().through(ChecksumTransform(CRC32, byteorder="big"))
    payload = challenge.craft("checksum packet").encoded(
        codec, b"ABC", label="body and CRC"
    )
    challenge.send(payload, to=challenge.input.raw())

    run, tube, _trace = execute(challenge)
    run.close()

    assert bytes(tube.sent) == b"ABC" + CRC32.calculate(b"ABC").to_bytes(4, "big")


def test_compression_and_authentication_codec_can_be_embedded(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    codec = bytes_().through(
        CompressionTransform("zlib"),
        DigestTransform(key=b"shared-secret", tag_size=16),
    )
    body = b"A" * 128
    payload = challenge.craft("authenticated packet").encoded(
        codec, body, label="compressed authenticated body"
    )
    challenge.send(payload, to=challenge.input.raw())

    run, tube, _trace = execute(challenge)
    run.close()

    assert bytes(tube.sent) == codec.build(body)


def test_same_craft_bytes_flow_through_raw_and_menu_inputs(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    payload = challenge.craft("shared packet").raw(
        b"PAYLOAD", label="application bytes"
    )
    menu = challenge.menu(b"menu> ", upload=(1, b"data: ", bytes))
    challenge.send(payload, to=challenge.input.raw(b"raw> "))
    challenge.send(payload, to=menu.upload)

    run, tube, _trace = execute(challenge, b"raw> menu> data: ")
    run.close()

    assert bytes(tube.sent) == b"PAYLOAD1\nPAYLOAD\n"


def test_runtime_leak_resolves_symbolic_craft_only_after_capture(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    leaks = challenge.input.line(b"query> ").format_leak(
        b"%17$p",
        after=b"value=",
        separator=(b"#",),
        pointer="hex",
    )
    payload = challenge.craft("leak dependent").word(
        leaks.pointer, label="captured pointer"
    )
    challenge.send(payload, to=challenge.input.raw(b"payload> "))

    run, tube, _trace = execute(
        challenge,
        b"query> value=0x1122334455667788#payload> ",
    )
    run.close()

    assert bytes(tube.sent) == b"%17$p\n" + bytes.fromhex("8877665544332211")


def test_missing_symbolic_fact_fails_before_send(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    missing = challenge.fact("runtime.missing")
    challenge.send(
        challenge.craft("missing fact").word(missing, label="missing pointer"),
        to=challenge.input.raw(),
    )
    tube = ScriptedTube()

    with pytest.raises(PlanningError, match="runtime.missing|missing pointer"):
        challenge.plan().run(transport=tube)

    assert bytes(tube.sent) == b""


def test_stale_symbolic_fact_fails_before_send(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    value = challenge.fact("runtime.rotated")
    challenge.assume(value, 0x41414141, reason="initial epoch")

    @challenge.opaque(
        invalidates=[value],
        name="rotate epoch",
        register_learn=False,
    )
    def rotate_epoch(_io, _facts):
        return None

    challenge.sequence(rotate_epoch, name="invalidate old epoch")
    challenge.send(
        challenge.craft("stale fact").word(value, label="old pointer"),
        to=challenge.input.raw(),
    )
    tube = ScriptedTube()

    with pytest.raises(PlanningError, match="runtime.rotated|stale"):
        challenge.plan().run(transport=tube)

    assert bytes(tube.sent) == b""


def test_symbolic_layout_is_inspectable_but_hexdump_refuses_placeholder_bytes(
    tmp_path: Path,
) -> None:
    challenge = target(tmp_path)
    pointer = challenge.fact("runtime.pointer")
    payload = (
        challenge.craft("symbolic layout")
        .raw(b"HEAD", label="header")
        .word(pointer, label="dynamic pointer")
    )

    layout = payload.layout()
    shown = payload.show()

    assert layout[1]["label"] == "dynamic pointer"
    assert layout[1]["dependencies"] == ["runtime.pointer"]
    assert "runtime.pointer" in shown
    with pytest.raises(UnresolvedValueError, match="runtime.pointer"):
        payload.hexdump()


def test_plan_payloads_recurses_into_nested_menu_and_generated_recipe_actions(
    tmp_path: Path,
) -> None:
    challenge = target(tmp_path)
    menu = challenge.menu(b"> ", upload=(1, b"data: ", bytes))
    nested = challenge.craft("nested packet").raw(b"NESTED", label="body")
    challenge.send(nested, to=menu.upload)
    control = challenge.control(
        challenge.input.raw(b"overflow: ").return_address(at=40)
    )
    challenge.want(challenge.call(challenge.exe.win), via=control, terminal=False)

    plan = challenge.plan()
    payloads = plan.payloads()

    assert len(payloads) == 2
    assert len({item.id for item in payloads}) == 2
    assert len({item.send_id for item in payloads}) == 2
    assert plan.payload("nested packet") is nested
    assert any(item.payload is nested for item in payloads)
    assert any(item.payload is not nested for item in payloads)


def test_run_payload_returns_resolved_artifact_with_trace_correlation(
    tmp_path: Path,
) -> None:
    challenge = target(tmp_path)
    pointer = challenge.fact("runtime.pointer")
    challenge.assume(pointer, 0x1122334455667788, reason="fixture leak")
    payload = challenge.craft("artifact packet").word(
        pointer, label="resolved pointer"
    )
    challenge.send(payload, to=challenge.input.raw())

    run, tube, trace = execute(challenge)
    artifact = run.payload("artifact packet")
    run.close()

    assert artifact.bytes == bytes.fromhex("8877665544332211")
    assert artifact.sha256 == hashlib.sha256(artifact.bytes).hexdigest()
    assert artifact.layout[0]["label"] == "resolved pointer"
    assert "runtime.pointer" in repr(artifact.provenance)
    assert "fixture leak" in repr(artifact.provenance)
    assert artifact.send_id
    assert artifact.stage
    assert "88 77 66 55 44 33 22 11" in artifact.hexdump()
    metadata = trace.metadata["payloads"][0]
    assert metadata["send_id"] == artifact.send_id
    assert metadata["payload_id"] == artifact.id
    assert bytes(tube.sent) == artifact.bytes


def patchable_plan(tmp_path: Path):
    challenge = target(tmp_path)
    first = challenge.craft("patchable stage").raw(b"ABCDEF", label="base bytes")
    second = challenge.craft("unchanged stage").raw(b"TAIL", label="tail bytes")
    challenge.send(first, to=challenge.input.raw())
    challenge.send(second, to=challenge.input.raw())
    return challenge.plan()


def test_plan_patch_payload_changes_one_stage_and_leaves_original_unchanged(
    tmp_path: Path,
) -> None:
    original = patchable_plan(tmp_path)
    patched = original.patch_payload(
        "patchable stage",
        offset=2,
        data=b"ZZ",
        label="remote variant",
        reason="remote build differs",
    )
    original_tube = ScriptedTube()
    patched_tube = ScriptedTube()

    original_run = original.run(transport=original_tube)
    original_run.close()
    patched_run = patched.run(transport=patched_tube)
    patched_run.close()

    assert bytes(original_tube.sent) == b"ABCDEFTAIL"
    assert bytes(patched_tube.sent) == b"ABZZEFTAIL"
    assert original is not patched
    assert [stage.name for stage in original.stages] == [
        stage.name for stage in patched.stages
    ]
    assert "remote build differs" not in original.payload("patchable stage").show()
    assert "remote build differs" in patched.payload("patchable stage").show()


def test_plan_patch_payload_requires_reason(
    tmp_path: Path,
) -> None:
    plan = patchable_plan(tmp_path)

    with pytest.raises(TypeError, match="reason"):
        plan.patch_payload(
            "patchable stage",
            offset=2,
            data=b"ZZ",
            label="missing reason",
        )


def test_plan_patch_payload_rejects_patch_that_would_resize_payload(
    tmp_path: Path,
) -> None:
    plan = patchable_plan(tmp_path)

    with pytest.raises(ConstraintError, match="same-size|extends beyond"):
        plan.patch_payload(
            "patchable stage",
            offset=2,
            data=b"TOO-LONG",
            label="resized",
            reason="must be rejected",
        )


def test_plan_patch_payload_rejects_new_symbolic_dependency(tmp_path: Path) -> None:
    plan = patchable_plan(tmp_path)

    with pytest.raises(PlanningError, match="depend"):
        plan.patch_payload(
            "patchable stage",
            offset=2,
            data=plan.challenge.fact("new.runtime.fact"),
            label="new dependency",
            reason="must recompile",
        )


def test_patched_plan_rejects_replay_from_unpatched_payload(tmp_path: Path) -> None:
    original = patchable_plan(tmp_path)
    trace = Trace()
    run = original.run(transport=ScriptedTube(), trace=trace)
    run.close()
    patched = original.patch_payload(
        "patchable stage",
        offset=2,
        data=b"ZZ",
        label="remote variant",
        reason="remote build differs",
    )

    with pytest.raises(ReplayDivergence, match="send|payload|diverg"):
        patched.run(replay=trace)


def test_trace_diff_reports_changed_payload_region_labels_and_send_correlation(
    tmp_path: Path,
) -> None:
    original = patchable_plan(tmp_path)
    patched = original.patch_payload(
        "patchable stage",
        offset=2,
        data=b"ZZ",
        label="remote variant",
        reason="remote build differs",
    )
    original_trace = Trace()
    patched_trace = Trace()
    original_run = original.run(transport=ScriptedTube(), trace=original_trace)
    original_run.close()
    patched_run = patched.run(transport=ScriptedTube(), trace=patched_trace)
    patched_run.close()

    rendered = "\n".join(original_trace.diff(patched_trace)).lower()

    assert "patchable stage" in rendered
    assert "0x2..0x4" in rendered
    assert "base bytes" in rendered
    assert "remote variant" in rendered
    assert "send" in rendered


def test_big_endian_packet_fixture_is_not_stack_specific(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    packet = (
        challenge.craft("big endian packet", endian="big", fill=b"\x00")
        .int(0x1337, bits=16, label="opcode")
        .at(4)
        .int(0x01020304, bits=32, label="sequence")
    )
    challenge.send(packet, to=challenge.input.raw())

    run, tube, _trace = execute(challenge)
    run.close()

    assert bytes(tube.sent) == bytes.fromhex("1337000001020304")


def test_bad_byte_shellcode_fixture_fails_before_send(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    shellcode = (
        challenge.craft("bad byte shellcode")
        .raw(b"\x48\x31\xc0\x00\x0f\x05", label="shellcode")
        .require(no=b"\x00\x0a")
    )
    challenge.send(shellcode, to=challenge.input.raw())
    tube = ScriptedTube()

    with pytest.raises(ConstraintError, match="shellcode|0x00"):
        challenge.plan().run(transport=tube)

    assert bytes(tube.sent) == b""


def test_multistage_pivot_fixture_preserves_stage_identity(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    pivot = challenge.craft("pivot stage").raw(b"PIVOT", label="pivot chain")
    rop = challenge.craft("second stage").raw(b"ROPCHAIN", label="second chain")
    challenge.send(pivot, to=challenge.input.raw(b"first> "))
    challenge.send(rop, to=challenge.input.raw(b"second> "))

    plan = challenge.plan()
    tube = ScriptedTube(b"first> second> ")
    run = plan.run(transport=tube)
    artifacts = (run.payload("pivot stage"), run.payload("second stage"))
    run.close()

    assert bytes(tube.sent) == b"PIVOTROPCHAIN"
    assert [item.name for item in plan.payloads()] == ["pivot stage", "second stage"]
    assert [item.name for item in artifacts] == ["pivot stage", "second stage"]


def test_heap_edit_fixture_can_replace_only_encoded_forward_pointer(
    tmp_path: Path,
) -> None:
    challenge = target(tmp_path)
    edit = (
        challenge.craft("heap edit", pointer_size=8)
        .raw(b"A" * 16, label="chunk data")
        .ptr(0x5555555592A0, label="encoded tcache fd")
    )
    challenge.send(edit, to=challenge.input.raw())
    plan = challenge.plan()
    patched = plan.patch_payload(
        "heap edit",
        offset=16,
        data=(0x55555555A3B0).to_bytes(8, "little"),
        label="remote encoded tcache fd",
        reason="remote heap base differs",
    )
    original_tube = ScriptedTube()
    patched_tube = ScriptedTube()
    original_run = plan.run(transport=original_tube)
    original_run.close()
    patched_run = patched.run(transport=patched_tube)
    patched_run.close()

    assert bytes(original_tube.sent)[:16] == bytes(patched_tube.sent)[:16] == b"A" * 16
    assert bytes(original_tube.sent)[16:] == (0x5555555592A0).to_bytes(8, "little")
    assert bytes(patched_tube.sent)[16:] == (0x55555555A3B0).to_bytes(8, "little")


def test_craft_replace_revalidates_forbidden_bytes(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    original = challenge.craft("forbidden patch").raw(
        b"SAFE", label="body"
    ).require(no=b"\n")
    changed = original.replace(
        1,
        1,
        b"\n",
        label="bad byte",
        reason="adversarial replacement",
    )

    assert original.build() == b"SAFE"
    with pytest.raises(ConstraintError, match="forbidden|0x0a"):
        changed.build()


def test_craft_replace_revalidates_encoding(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    original = challenge.craft("encoding patch").raw(
        b"TEXT", label="body"
    ).require(encoding="utf8")
    changed = original.replace(
        2,
        1,
        b"\xff",
        label="invalid UTF-8",
        reason="adversarial replacement",
    )

    with pytest.raises(ConstraintError, match="utf8|UTF-8|encoding"):
        changed.build()


def test_craft_replace_revalidates_custom_predicate(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    original = (
        challenge.craft("predicate patch")
        .raw(b"MAGIC", label="body")
        .require(
            predicate=lambda data: data.startswith(b"MAGIC"),
            explanation="packet must retain MAGIC prefix",
        )
    )
    changed = original.replace(
        0,
        1,
        b"X",
        label="bad magic",
        reason="adversarial replacement",
    )

    with pytest.raises(ConstraintError, match="packet must retain MAGIC prefix"):
        changed.build()


def test_craft_resize_revalidates_size_constraint(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    original = challenge.craft("bounded resize").raw(
        b"DATA", label="body"
    ).require(max_size=4)
    changed = original.replace(
        0,
        1,
        b"LONG",
        label="resized prefix",
        reason="explicit resize test",
        resize=True,
    )

    with pytest.raises(ConstraintError, match="maximum|size"):
        changed.build()


@pytest.mark.parametrize(
    ("requirement", "patch", "match"),
    (
        ({"no": b"\n"}, b"\n", "forbidden|0x0a"),
        ({"encoding": "ascii"}, b"\xff", "ascii|encoding"),
        (
            {
                "predicate": lambda data: data.startswith(b"A"),
                "explanation": "payload must start with A",
            },
            b"X",
            "payload must start with A",
        ),
    ),
)
def test_plan_patch_revalidates_craft_constraints_before_send(
    tmp_path: Path,
    requirement: dict,
    patch: bytes,
    match: str,
) -> None:
    challenge = target(tmp_path)
    payload = challenge.craft("constrained plan patch").raw(
        b"AAAA", label="body"
    ).require(**requirement)
    challenge.send(payload, to=challenge.input.raw())
    patched = challenge.plan().patch_payload(
        "constrained plan patch",
        offset=0,
        data=patch,
        label="constraint violation",
        reason="adversarial plan patch",
    )
    tube = ScriptedTube()

    with pytest.raises(ConstraintError, match=match):
        patched.run(transport=tube)

    assert bytes(tube.sent) == b""


def generated_ret2win_plan(tmp_path: Path, *, forbidden: bytes = b""):
    challenge = target(tmp_path)
    control = challenge.control(
        challenge.input.raw(forbidden=forbidden).return_address(at=24)
    )
    challenge.want(challenge.call(challenge.exe.win), via=control, terminal=False)
    return challenge.plan()


def test_generated_ret2win_payload_patch_is_permanent_and_immutable(
    tmp_path: Path,
) -> None:
    original = generated_ret2win_plan(tmp_path)
    patched = original.patch_payload(
        0,
        offset=0,
        data=b"B" * 8,
        label="alternate prefix",
        reason="challenge-specific prefix",
    )
    original_tube = ScriptedTube()
    patched_tube = ScriptedTube()
    original_run = original.run(transport=original_tube)
    original_run.close()
    patched_run = patched.run(transport=patched_tube)
    artifact = patched_run.payload(0)
    patched_run.close()

    assert bytes(original_tube.sent)[:8] == b"A" * 8
    assert bytes(patched_tube.sent)[:8] == b"B" * 8
    assert bytes(original_tube.sent)[8:] == bytes(patched_tube.sent)[8:]
    assert artifact.bytes == bytes(patched_tube.sent)
    assert "challenge-specific prefix" in repr(artifact.layout)


def test_generated_ret2win_plan_patch_revalidates_forbidden_bytes(
    tmp_path: Path,
) -> None:
    plan = generated_ret2win_plan(tmp_path, forbidden=b"Z")
    patched = plan.patch_payload(
        0,
        offset=0,
        data=b"Z",
        label="forbidden prefix",
        reason="adversarial generated patch",
    )
    tube = ScriptedTube()

    with pytest.raises(ConstraintError, match="forbidden|0x5a"):
        patched.run(transport=tube)

    assert bytes(tube.sent) == b""


def dynamic_line_craft(tmp_path: Path):
    challenge = target(tmp_path)
    leaks = challenge.input.line(b"leak> ").format_leak(
        b"%17$p",
        after=b"value=",
        separator=(b"#",),
        pointer="hex",
    )
    payload = challenge.craft("fresh symbolic line").word(
        leaks.pointer, label="fresh pointer"
    )
    challenge.send(payload, to=challenge.input.line(b"payload> "))
    return challenge, leaks


def dynamic_line_input(value: int) -> bytes:
    return b"leak> value=" + f"0x{value:x}".encode() + b"#payload> "


def test_symbolic_line_craft_framing_failure_is_retryable_before_send(
    tmp_path: Path,
) -> None:
    challenge, _leaks = dynamic_line_craft(tmp_path)
    tube = ScriptedTube(dynamic_line_input(BAD_DYNAMIC_WORD))

    with pytest.raises(RetryableInstanceError) as raised:
        challenge.plan().run(transport=tube)

    assert raised.value.label == "fresh pointer"
    assert raised.value.offset == 4
    assert raised.value.byte == 0x0A
    assert "line channel" in raised.value.channel
    assert bytes(tube.sent) == b"%17$p\n"


def test_symbolic_line_craft_retries_fresh_target_then_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge, leaks = dynamic_line_craft(tmp_path)
    tubes = [
        ScriptedTube(dynamic_line_input(BAD_DYNAMIC_WORD)),
        ScriptedTube(dynamic_line_input(GOOD_DYNAMIC_WORD)),
    ]
    recipe = TrackingRecipe(tcp("challenge.example", 31337))
    opened = []

    def open_target(materialized):
        opened.append(materialized)
        return tubes[len(opened) - 1]

    monkeypatch.setitem(runtime._ENVIRONMENT_OPENERS, "tcp", open_target)
    trace = Trace()

    with challenge.run(on=recipe, attempts=2, trace=trace) as run:
        assert run.value(leaks.pointer) == GOOD_DYNAMIC_WORD
        assert run.payload("fresh symbolic line").bytes == GOOD_DYNAMIC_WORD.to_bytes(
            8, "little"
        )

    assert len(recipe.seeds) == 2
    assert len(set(recipe.seeds)) == 2
    assert bytes(tubes[0].sent) == b"%17$p\n"
    assert bytes(tubes[1].sent) == (
        b"%17$p\n" + GOOD_DYNAMIC_WORD.to_bytes(8, "little") + b"\n"
    )
    assert trace.metadata["retry"]["used"] == 2


def test_static_line_craft_framing_failure_is_not_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge = target(tmp_path)
    payload = challenge.craft("static bad line").raw(
        b"BAD\n", label="static bytes"
    )
    challenge.send(payload, to=challenge.input.line(b"payload> "))
    tube = ScriptedTube(b"payload> ")
    recipe = TrackingRecipe(tcp("challenge.example", 31337))
    opened = []

    def open_target(materialized):
        opened.append(materialized)
        return tube

    monkeypatch.setitem(runtime._ENVIRONMENT_OPENERS, "tcp", open_target)

    with pytest.raises(ConstraintError) as raised:
        challenge.run(on=recipe, attempts=3)

    assert not isinstance(raised.value, RetryableInstanceError)
    assert len(recipe.seeds) == 1
    assert len(opened) == 1
    assert bytes(tube.sent) == b""


def test_raw_craft_accepts_symbolic_newline_bytes(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    pointer = challenge.fact("fresh.pointer")
    challenge.assume(pointer, BAD_DYNAMIC_WORD, reason="fixture fresh value")
    payload = challenge.craft("raw symbolic bytes").word(
        pointer, label="fresh pointer"
    )
    challenge.send(payload, to=challenge.input.raw())

    run, tube, _trace = execute(challenge)
    run.close()

    assert bytes(tube.sent) == BAD_DYNAMIC_WORD.to_bytes(8, "little")


def test_run_payload_artifact_survives_fact_invalidation_after_send(
    tmp_path: Path,
) -> None:
    challenge = target(tmp_path)
    pointer = challenge.fact("ephemeral.pointer")
    challenge.assume(pointer, CANARY, reason="captured before send")
    payload = challenge.craft("ephemeral artifact").word(
        pointer, label="ephemeral pointer"
    )
    challenge.send(payload, to=challenge.input.raw())

    @challenge.opaque(
        consumes=[pointer],
        invalidates=[pointer],
        name="expire pointer",
        register_learn=False,
    )
    def expire_pointer(_io, _facts):
        return None

    challenge.want(expire_pointer, terminal=False)
    run, tube, _trace = execute(challenge)

    with pytest.raises((UnresolvedValueError, pwnx.StaleValueError)):
        run.value(pointer)
    artifact = run.payload("ephemeral artifact")
    run.close()

    assert artifact.bytes == CANARY.to_bytes(8, "little")
    assert artifact.bytes == bytes(tube.sent)
    assert "captured before send" in repr(artifact.provenance)


def test_run_payload_artifact_preserves_send_value_after_fact_rebind(
    tmp_path: Path,
) -> None:
    challenge = target(tmp_path)
    pointer = challenge.fact("rotating.pointer")
    challenge.assume(pointer, CANARY, reason="first pointer")
    payload = challenge.craft("rebound artifact").word(
        pointer, label="rotating pointer"
    )
    challenge.send(payload, to=challenge.input.raw())

    @challenge.opaque(
        produces=pointer,
        consumes=[pointer],
        invalidates=[pointer],
        name="rebind pointer",
    )
    def rebind_pointer(_io, _facts):
        return GOOD_DYNAMIC_WORD

    challenge.want(rebind_pointer, terminal=False)
    run, tube, _trace = execute(challenge)

    assert run.value(pointer) == GOOD_DYNAMIC_WORD
    artifact = run.payload("rebound artifact")
    run.close()

    assert artifact.bytes == CANARY.to_bytes(8, "little")
    assert artifact.bytes == bytes(tube.sent)
    assert GOOD_DYNAMIC_WORD.to_bytes(8, "little") != artifact.bytes


def test_reused_craft_records_distinct_send_time_artifacts(
    tmp_path: Path,
) -> None:
    challenge = target(tmp_path)
    pointer = challenge.fact("changing.pointer")
    challenge.assume(pointer, CANARY, reason="first send")
    payload = challenge.craft("reused symbolic craft").word(
        pointer, label="changing pointer"
    )
    challenge.send(payload, to=challenge.input.raw())

    @challenge.opaque(
        produces=pointer,
        consumes=[pointer],
        invalidates=[pointer],
        name="advance pointer",
    )
    def advance_pointer(_io, _facts):
        return GOOD_DYNAMIC_WORD

    challenge.want(advance_pointer, terminal=False)
    challenge.send(payload, to=challenge.input.raw())
    run, tube, _trace = execute(challenge)
    artifacts = tuple(
        item for item in run.payloads() if item.name == "reused symbolic craft"
    )
    run.close()

    assert bytes(tube.sent) == (
        CANARY.to_bytes(8, "little")
        + GOOD_DYNAMIC_WORD.to_bytes(8, "little")
    )
    assert [item.bytes for item in artifacts] == [
        CANARY.to_bytes(8, "little"),
        GOOD_DYNAMIC_WORD.to_bytes(8, "little"),
    ]
    assert len({item.send_id for item in artifacts}) == 2


@pytest.mark.parametrize("reverse", (False, True))
def test_chained_min_size_keeps_strongest_requirement(
    tmp_path: Path,
    reverse: bool,
) -> None:
    challenge = target(tmp_path)
    payload = challenge.craft(f"minimum {reverse}").raw(b"ABC", label="body")
    limits = (4, 2) if reverse else (2, 4)
    for limit in limits:
        payload = payload.require(min_size=limit)

    with pytest.raises(ConstraintError, match="minimum 4"):
        payload.build()


@pytest.mark.parametrize("reverse", (False, True))
def test_chained_max_size_keeps_strongest_requirement(
    tmp_path: Path,
    reverse: bool,
) -> None:
    challenge = target(tmp_path)
    payload = challenge.craft(f"maximum {reverse}").raw(b"ABCDE", label="body")
    limits = (4, 8) if reverse else (8, 4)
    for limit in limits:
        payload = payload.require(max_size=limit)

    with pytest.raises(ConstraintError, match="maximum 4"):
        payload.build()


@pytest.mark.parametrize("reverse", (False, True))
def test_chained_encoding_requirements_are_order_independent(
    tmp_path: Path,
    reverse: bool,
) -> None:
    challenge = target(tmp_path)
    payload = challenge.craft(f"encodings {reverse}").raw(
        "é".encode(), label="unicode"
    )
    encodings = ("ascii", "utf8") if reverse else ("utf8", "ascii")
    for encoding in encodings:
        payload = payload.require(encoding=encoding)

    with pytest.raises(ConstraintError, match="ascii"):
        payload.build()


def test_chained_predicates_preserve_each_explanation(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    payload = (
        challenge.craft("predicate chain")
        .raw(b"AZ", label="body")
        .require(
            predicate=lambda data: data.endswith(b"!"),
            explanation="payload must end with exclamation",
        )
        .require(
            predicate=lambda data: data.startswith(b"A"),
            explanation="payload must start with A",
        )
    )

    with pytest.raises(ConstraintError, match="payload must end with exclamation"):
        payload.build()


def test_chained_exact_size_combines_with_compatible_bounds(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    payload = (
        challenge.craft("compatible exact size")
        .raw(b"DATA", label="body")
        .require(min_size=2, max_size=8)
        .require(exact_size=4)
    )

    assert payload.build() == b"DATA"


def test_chained_exact_sizes_reject_conflict_at_declaration(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    payload = challenge.craft("conflicting exact size").raw(b"DATA", label="body")

    with pytest.raises(ValueError, match="exact_size|conflict"):
        payload.require(exact_size=4).require(exact_size=5)


def test_chained_min_and_max_reject_conflict_at_declaration(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    payload = challenge.craft("conflicting bounds").raw(b"DATA", label="body")

    with pytest.raises(
        ValueError,
        match="min_size|max_size|conflict|minimum size.*maximum size",
    ):
        payload.require(min_size=8).require(max_size=4)


def test_chained_exact_and_minimum_reject_conflict_at_declaration(
    tmp_path: Path,
) -> None:
    challenge = target(tmp_path)
    payload = challenge.craft("conflicting exact bound").raw(
        b"DATA", label="body"
    )

    with pytest.raises(ValueError, match="exact_size|min_size|conflict"):
        payload.require(exact_size=4).require(min_size=5)


def symbolic_line_plan(tmp_path: Path, value: int):
    challenge = target(tmp_path)
    pointer = challenge.fact("patch.pointer")
    challenge.assume(pointer, value, reason="fresh symbolic pointer")
    payload = challenge.craft("patchable symbolic line").word(
        pointer, label="symbolic pointer"
    )
    challenge.send(payload, to=challenge.input.line())
    return challenge.plan()


def test_plan_patch_rewrites_feasibility_guard_when_repairing_dynamic_newline(
    tmp_path: Path,
) -> None:
    plan = symbolic_line_plan(tmp_path, BAD_DYNAMIC_WORD)
    repaired = plan.patch_payload(
        "patchable symbolic line",
        offset=4,
        data=b"X",
        label="newline repair",
        reason="remote instance contains a newline byte",
    )
    tube = ScriptedTube()

    run = repaired.run(transport=tube)
    artifact = run.payload("patchable symbolic line")
    run.close()

    expected = bytearray(BAD_DYNAMIC_WORD.to_bytes(8, "little"))
    expected[4] = ord("X")
    assert bytes(tube.sent) == bytes(expected) + b"\n"
    assert artifact.bytes == bytes(expected)
    assert "newline repair" in repr(artifact.layout)


def test_static_plan_patch_over_dynamic_region_remains_nonretryable(
    tmp_path: Path,
) -> None:
    plan = symbolic_line_plan(tmp_path, GOOD_DYNAMIC_WORD)
    broken = plan.patch_payload(
        "patchable symbolic line",
        offset=4,
        data=b"\n",
        label="dynamic newline",
        reason="adversarial framing patch",
    )
    tube = ScriptedTube()

    with pytest.raises(ConstraintError) as raised:
        broken.run(transport=tube)

    assert not isinstance(raised.value, RetryableInstanceError)
    assert bytes(tube.sent) == b""


def test_static_plan_patch_framing_violation_remains_nonretryable(
    tmp_path: Path,
) -> None:
    challenge = target(tmp_path)
    payload = challenge.craft("static line patch").raw(b"STATIC", label="body")
    challenge.send(payload, to=challenge.input.line())
    broken = challenge.plan().patch_payload(
        "static line patch",
        offset=2,
        data=b"\n",
        label="static newline",
        reason="adversarial framing patch",
    )
    tube = ScriptedTube()

    with pytest.raises(ConstraintError) as raised:
        broken.run(transport=tube)

    assert not isinstance(raised.value, RetryableInstanceError)
    assert bytes(tube.sent) == b""


def test_plan_patch_correlates_guard_with_nested_menu_emit(tmp_path: Path) -> None:
    challenge = target(tmp_path)
    pointer = challenge.fact("nested.pointer")
    challenge.assume(pointer, BAD_DYNAMIC_WORD, reason="fresh nested pointer")
    payload = challenge.craft("nested symbolic line").word(
        pointer, label="nested pointer"
    )
    menu = challenge.menu(b"> ", upload=(1, b"data: ", bytes))
    challenge.send(payload, to=menu.upload)
    repaired = challenge.plan().patch_payload(
        "nested symbolic line",
        offset=4,
        data=b"X",
        label="nested repair",
        reason="repair nested menu payload",
    )
    tube = ScriptedTube(b"> data: ")

    run = repaired.run(transport=tube)
    run.close()

    expected = bytearray(BAD_DYNAMIC_WORD.to_bytes(8, "little"))
    expected[4] = ord("X")
    assert bytes(tube.sent) == b"1\n" + bytes(expected) + b"\n"


def branch_line_plan(tmp_path: Path, *, selected_then: bool):
    challenge = target(tmp_path)
    pointer = challenge.fact("branch.pointer")
    challenge.assume(pointer, GOOD_DYNAMIC_WORD, reason="fresh branch pointer")
    payload = challenge.craft("branch symbolic line").word(
        pointer, label="branch pointer"
    )
    branch = pwnx.Branch(
        pwnx.Expr.literal(selected_then),
        pwnx.sequence(pwnx.Emit(payload, pwnx.line()), name="then send"),
        pwnx.sequence(pwnx.Emit(payload, pwnx.line()), name="else send"),
    )
    challenge.send(payload, to=lambda _payload: branch)
    return challenge.plan()


def test_branch_patch_does_not_apply_else_guard_to_selected_then_send(
    tmp_path: Path,
) -> None:
    plan = branch_line_plan(tmp_path, selected_then=True)
    descriptors = plan.payloads()
    assert len(descriptors) == 2
    patched_else = plan.patch_payload(
        1,
        offset=4,
        data=b"\n",
        label="else newline",
        reason="patch only else branch",
    )
    tube = ScriptedTube()

    run = patched_else.run(transport=tube)
    run.close()

    assert bytes(tube.sent) == GOOD_DYNAMIC_WORD.to_bytes(8, "little") + b"\n"


def test_branch_static_patch_uses_nonretryable_guard_for_selected_else_send(
    tmp_path: Path,
) -> None:
    plan = branch_line_plan(tmp_path, selected_then=False)
    patched_else = plan.patch_payload(
        1,
        offset=4,
        data=b"\n",
        label="else newline",
        reason="patch only else branch",
    )
    tube = ScriptedTube()

    with pytest.raises(ConstraintError) as raised:
        patched_else.run(transport=tube)

    assert not isinstance(raised.value, RetryableInstanceError)
    assert bytes(tube.sent) == b""


def constrained_resize(tmp_path: Path):
    challenge = target(tmp_path)
    return (
        challenge.craft("constrained resize")
        .raw(b"MAGIC", label="original body")
        .require(no=b"\n")
        .require(encoding="ascii")
        .require(
            predicate=lambda data: data.startswith(b"MAGIC"),
            explanation="resized payload must retain MAGIC",
        )
        .require(max_size=8)
    )


def test_resize_preserves_semantic_identity_label_reason_and_provenance(
    tmp_path: Path,
) -> None:
    original = constrained_resize(tmp_path)
    resized = original.replace(
        5,
        0,
        b"!",
        label="appended marker",
        reason="protocol requires a marker",
        resize=True,
    )

    assert resized.semantic_id == original.semantic_id
    assert resized.build() == b"MAGIC!"
    assert any(
        row["label"] == "appended marker"
        and row.get("reason") == "protocol requires a marker"
        for row in resized.layout()
    )
    assert "protocol requires a marker" in resized.show()


@pytest.mark.parametrize(
    ("replacement", "match"),
    (
        (b"\n", "forbidden|0x0a"),
        (b"\xff", "ascii|encoding"),
        (b"XXXXXXXXX", "maximum|size"),
    ),
)
def test_resize_preserves_constraints_and_validates_changed_output(
    tmp_path: Path,
    replacement: bytes,
    match: str,
) -> None:
    original = constrained_resize(tmp_path)
    resized = original.replace(
        0,
        5,
        replacement,
        label="invalid resized body",
        reason="adversarial resize",
        resize=True,
    )

    with pytest.raises(ConstraintError, match=match):
        resized.build()


def test_resize_preserves_custom_predicate(tmp_path: Path) -> None:
    original = constrained_resize(tmp_path)
    resized = original.replace(
        0,
        5,
        b"OTHER",
        label="wrong prefix",
        reason="adversarial resize",
        resize=True,
    )

    with pytest.raises(ConstraintError, match="resized payload must retain MAGIC"):
        resized.build()


def test_resize_preserves_prior_patch_history_and_unaffected_region_ids(
    tmp_path: Path,
) -> None:
    challenge = target(tmp_path)
    original = (
        challenge.craft("iterated resize")
        .raw(b"HEAD", label="header")
        .raw(b"BODY", label="body")
    )
    original_ids = {
        row["label"]: row["id"]
        for row in original.layout()
    }
    patched = original.replace(
        0,
        4,
        b"EDIT",
        label="edited header",
        reason="first payload iteration",
    )
    resized = patched.replace(
        4,
        0,
        b"!",
        label="inserted separator",
        reason="second payload iteration",
        resize=True,
    )

    assert resized.build() == b"EDIT!BODY"
    assert {
        row["label"]: row["id"]
        for row in resized.layout()
        if row["label"] in {"header", "body"}
    } == original_ids
    rendered = resized.show()
    assert "first payload iteration" in rendered
    assert "second payload iteration" in rendered


def artifact_with_trace(tmp_path: Path):
    challenge = target(tmp_path)
    pointer = challenge.fact("immutable.pointer")
    challenge.assume(pointer, CANARY, reason="immutable fixture")
    payload = challenge.craft("immutable artifact").word(
        pointer, label="immutable pointer"
    )
    challenge.send(payload, to=challenge.input.raw())
    run, _tube, trace = execute(challenge)
    return run, run.payload("immutable artifact"), trace


def test_payload_artifact_layout_is_deeply_immutable(tmp_path: Path) -> None:
    run, artifact, trace = artifact_with_trace(tmp_path)
    trace_label = trace.metadata["payloads"][0]["layout"][0]["label"]

    with pytest.raises(TypeError):
        artifact.layout[0]["label"] = "tampered"
    with pytest.raises((AttributeError, TypeError)):
        artifact.layout[0]["dependencies"].append("tampered.fact")
    run.close()

    assert artifact.layout[0]["label"] == "immutable pointer"
    assert trace.metadata["payloads"][0]["layout"][0]["label"] == trace_label


def test_repeated_payload_artifact_serialization_returns_independent_data(
    tmp_path: Path,
) -> None:
    run, artifact, trace = artifact_with_trace(tmp_path)

    first = artifact.to_dict()
    second = artifact.to_dict()
    first["layout"][0]["label"] = "mutated serialization"
    first["layout"][0]["dependencies"].append("mutated.fact")
    run.close()

    assert second["layout"][0]["label"] == "immutable pointer"
    assert second["layout"][0]["dependencies"] == ["immutable.pointer"]
    assert artifact.layout[0]["label"] == "immutable pointer"
    assert trace.metadata["payloads"][0]["layout"][0]["label"] == "immutable pointer"


@pytest.mark.parametrize(
    "fixture_specific_text",
    (
        "captured stack cookie",
        "partial function pointer",
        "remote encoded tcache fd",
        "0x5555555592a0",
        "query> value=",
        "pivot stage",
    ),
)
def test_craft_implementation_contains_no_fixture_specific_logic(
    fixture_specific_text: str,
) -> None:
    source_root = Path(__file__).parents[1] / "src" / "pwnx"
    implementation = "\n".join(
        path.read_text().lower()
        for path in source_root.glob("*.py")
        if path.name in {
            "actions.py",
            "bytecraft.py",
            "challenge.py",
            "payload.py",
            "planner.py",
            "runtime.py",
            "trace.py",
        }
    )

    assert fixture_specific_text not in implementation
