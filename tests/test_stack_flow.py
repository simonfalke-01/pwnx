from __future__ import annotations

import ast
import os
from pathlib import Path
import subprocess

import pytest
import pwnx.runtime as runtime

from elf_factory import make_elf
from pwnx import Challenge, LifecyclePolicy, LocalProcessRecipe, Trace, tcp
from pwnx.codecs import Codec
from pwnx.errors import (
    EndOfStream,
    PlanningError,
    RetryableInstanceError,
    UnsupportedFeature,
)
from pwnx.transport import Tube


EXAMPLE = Path(__file__).parents[1] / "examples" / "cage.py"
CAGE_ENV = os.environ.get("PWNX_CAGE_CHALLENGE")
LOCAL_CAGE = Path("/Users/brandonli/Downloads/cage")
CAGE = Path(CAGE_ENV).expanduser().resolve() if CAGE_ENV else LOCAL_CAGE

PREFIX = b"The canary tilts its head: "
CANARY = 0x00A1A2A3A4A5A600
NEWLINE_CANARY = 0x00A1A20AA4A5A600
LIBC_LEAK = 0x7F1234529CA8
LIBC_BIAS = 0x29CA8


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


class PlainHexCodec(Codec[int]):
    """Intentionally not a dataclass; framing must use the Codec protocol."""

    def __init__(self, delimiter: bytes = b"original") -> None:
        self.delimiter = delimiter

    def parse(self, data: bytes | bytearray | memoryview) -> int:
        return int(bytes(data), 16)

    def build(self, value: int) -> bytes:
        return f"0x{value:x}".encode()


class TrackingRecipe:
    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.seeds: list[str] = []
        self.targets = []

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
        target = self.delegate.materialize(epoch_seed=epoch_seed)
        self.targets.append(target)
        return target


def cage_spec(tmp_path: Path):
    binary = make_elf(tmp_path / "cage", pie=False)
    libc = make_elf(tmp_path / "libc.so.6", pie=True)
    challenge = Challenge(binary, libc=libc)
    leaks = challenge.format_leak(
        challenge.input.line(b"sing> "),
        canary=9,
        libc=11,
        prefix=PREFIX,
        separator=b"|",
    )
    challenge.relate(challenge.libc.base, leaks.libc - LIBC_BIAS)
    control = challenge.control(
        challenge.input.line(b"sing> ").return_address(
            at=40,
            canary=(24, leaks.canary),
        )
    )
    challenge.want(challenge.call(challenge.exe.win), via=control, terminal=False)
    return challenge, leaks


def cage_input(canary: int = CANARY) -> bytes:
    return (
        b"sing> "
        + PREFIX
        + f"0x{canary:x}|0x{LIBC_LEAK:x}\n".encode()
        + b"sing> "
    )


def protected_word_spec(tmp_path: Path):
    binary = make_elf(tmp_path / "target", pie=False)
    challenge = Challenge(binary)
    leaks = challenge.input.line(b"token> ").format_leak(
        b"%17$p",
        after=b"guard=",
        separator=(b"#",),
        guard="hex",
    )
    control = challenge.control(
        challenge.input.line(b"data> ").return_address(
            at=40,
            protected=((24, leaks.guard, "session cookie"),),
        )
    )
    challenge.want(challenge.call(challenge.exe.win), via=control, terminal=False)
    return challenge, leaks


def protected_word_input(value: int) -> bytes:
    return b"token> guard=" + f"0x{value:x}".encode() + b"#data> "


def test_canonical_cage_example_has_no_manual_exploit_plumbing() -> None:
    source = EXAMPLE.read_text()
    tree = ast.parse(source)
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }

    assert not {"p64", "u64", "word", "Payload", "Action", "ROPCompiler"} & names
    assert not {"build", "to_bytes"} & attributes
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Lambda))
        for node in ast.walk(tree)
    )
    for feature in ("format_leak", "relate", "return_address", "shell"):
        assert feature in attributes


def test_format_leak_uses_named_hex_fields_prefix_and_separator(tmp_path: Path) -> None:
    challenge, leaks = cage_spec(tmp_path)

    assert leaks.canary.key.endswith("canary")
    assert leaks.libc.key.endswith("libc")
    rendered = challenge.plan().show().lower()
    assert "format leak" in rendered
    assert "canary" in rendered and "position 9" in rendered
    assert "libc" in rendered and "position 11" in rendered
    assert "the canary tilts its head" in rendered
    assert "separator" in rendered


def test_format_leak_frames_non_dataclass_custom_codecs_without_mutating_them(
    tmp_path: Path,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "target", pie=False))
    left_codec = PlainHexCodec()
    right_codec = PlainHexCodec(b"still-original")
    leaks = challenge.input.line(b"query> ").format_leak(
        b"%17$p::~%23$p",
        after=b"values=>",
        separator=(b"::~", b"!"),
        cookie=left_codec,
        token=right_codec,
    )
    control = challenge.control(
        challenge.input.line(b"payload> ").return_address(
            at=40,
            protected=(
                (8, leaks.cookie, "authentication cookie"),
                (24, leaks.token, "shadow token"),
            ),
        )
    )
    challenge.want(challenge.call(challenge.exe.win), via=control, terminal=False)
    tube = ScriptedTube(
        b"query> values=>0x1122334455667788::~0x8877665544332211!payload> "
    )

    with challenge.plan().run(transport=tube) as run:
        assert run.value(leaks.cookie) == 0x1122334455667788
        assert run.value(leaks.token) == 0x8877665544332211

    assert left_codec.delimiter == b"original"
    assert right_codec.delimiter == b"still-original"
    _probe, overflow, remainder = bytes(tube.sent).split(b"\n", 2)
    assert _probe == b"%17$p::~%23$p"
    assert overflow[8:16] == bytes.fromhex("8877665544332211")
    assert overflow[24:32] == bytes.fromhex("1122334455667788")
    assert remainder == b""


def test_stack_flow_executes_leak_relation_and_canary_payload(tmp_path: Path) -> None:
    challenge, leaks = cage_spec(tmp_path)
    plan = challenge.plan()
    tube = ScriptedTube(cage_input())

    with plan.run(transport=tube) as run:
        assert run.value(leaks.canary) == CANARY
        assert run.value(leaks.libc) == LIBC_LEAK
        assert run.value(challenge.libc.base) == LIBC_LEAK - LIBC_BIAS

    first, overflow, remainder = bytes(tube.sent).split(b"\n", 2)
    assert first == b"%9$p|%11$p"
    assert remainder == b""
    assert overflow[:24] == b"A" * 24
    assert int.from_bytes(overflow[24:32], "little") == CANARY
    assert overflow[32:40] == b"A" * 8
    assert len(overflow) > 40


def test_line_framing_rejects_newline_bearing_protected_word_before_overflow_send(
    tmp_path: Path,
) -> None:
    challenge, _leaks = protected_word_spec(tmp_path)
    tube = ScriptedTube(protected_word_input(NEWLINE_CANARY))

    with pytest.raises(RetryableInstanceError) as raised:
        challenge.plan().run(transport=tube)

    error = raised.value
    assert error.label == "session cookie"
    assert error.offset == 28
    assert error.byte == 0x0A
    assert "line channel" in error.channel
    assert "b'\\n'" in error.channel
    assert "session cookie" in str(error)
    assert "offset 28" in str(error)
    assert "0x0a" in str(error)
    assert bytes(tube.sent) == b"%17$p\n"


def test_raw_channel_accepts_newline_bearing_protected_word(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "target", pie=False))
    guard = challenge.fact("session.guard")
    challenge.assume(guard, NEWLINE_CANARY, reason="test fixture")
    control = challenge.control(
        challenge.input.raw(b"payload> ").return_address(
            at=40,
            protected=((24, guard, "session cookie"),),
        )
    )
    challenge.want(challenge.call(challenge.exe.win), via=control, terminal=False)
    tube = ScriptedTube(b"payload> ")

    with challenge.plan().run(transport=tube):
        pass

    assert bytes(tube.sent)[24:32] == NEWLINE_CANARY.to_bytes(8, "little")


def test_plan_explains_line_framing_as_retryable_instance_constraint(
    tmp_path: Path,
) -> None:
    challenge, _leaks = protected_word_spec(tmp_path)

    rendered = challenge.plan().show().lower()

    for phrase in ("session cookie", "line", "b'\\n'", "retryable"):
        assert phrase in rendered


def test_stack_flow_plan_is_semantic_and_expand_is_raw(tmp_path: Path) -> None:
    challenge, _leaks = cage_spec(tmp_path)
    plan = challenge.plan()
    rendered = plan.show().lower()

    for phrase in (
        "format leak",
        "canary",
        "libc.base",
        "return address",
        "offset 24",
        "offset 40",
    ):
        assert phrase in rendered
    assert "%9$p|%11$p" not in rendered
    assert "bytescodec(b'" not in rendered

    expanded = "\n".join(plan.expand(stage.name) for stage in plan.stages).lower()
    assert "%9$p|%11$p" in expanded
    assert "sing> " in expanded
    assert "bytescodec(b'" in expanded


def test_stack_flow_replays_without_live_effects(tmp_path: Path) -> None:
    challenge, _leaks = cage_spec(tmp_path)
    plan = challenge.plan()
    trace = Trace()

    with plan.run(transport=ScriptedTube(cage_input()), trace=trace):
        pass
    with plan.run(transport=FailingTube(), replay=trace):
        pass


@pytest.mark.parametrize(
    ("target_kind", "epoch_scope"),
    (("local", "process"), ("tcp", "connection")),
)
def test_run_retries_retryable_constraint_with_fresh_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_kind: str,
    epoch_scope: str,
) -> None:
    challenge, leaks = protected_word_spec(tmp_path)
    tubes = [
        ScriptedTube(protected_word_input(NEWLINE_CANARY)),
        ScriptedTube(protected_word_input(CANARY)),
    ]
    opened = []
    if target_kind == "local":
        delegate = LocalProcessRecipe(challenge.exe.path)
        adapter = "local-process"
    else:
        delegate = tcp("challenge.example", 31337)
        adapter = "tcp"
    recipe = TrackingRecipe(delegate)

    def open_target(target):
        opened.append(target)
        return tubes[len(opened) - 1]

    monkeypatch.setitem(runtime._ENVIRONMENT_OPENERS, adapter, open_target)
    trace = Trace()

    with challenge.run(on=recipe, attempts=2, trace=trace) as run:
        assert run.value(leaks.guard) == CANARY

    assert len(recipe.seeds) == 2
    assert len(set(recipe.seeds)) == 2
    assert len(opened) == 2
    assert len(
        {
            getattr(target.epochs, epoch_scope)
            for target in recipe.targets
        }
    ) == 2
    assert all(tube.closed for tube in tubes)
    retry = trace.metadata["retry"]
    assert retry["budget"] == 2
    assert retry["used"] == 2
    assert len(retry["failures"]) == 1
    assert "session cookie" in retry["failures"][0]
    assert "0x0a" in retry["failures"][0]


def test_run_stops_after_exact_retry_budget(tmp_path: Path, monkeypatch) -> None:
    challenge, _leaks = protected_word_spec(tmp_path)
    tubes = [
        ScriptedTube(protected_word_input(NEWLINE_CANARY))
        for _ in range(3)
    ]
    recipe = TrackingRecipe(tcp("challenge.example", 31337))
    opened = []

    def open_target(target):
        opened.append(target)
        return tubes[len(opened) - 1]

    monkeypatch.setitem(runtime._ENVIRONMENT_OPENERS, "tcp", open_target)
    trace = Trace()

    with pytest.raises(
        RetryableInstanceError,
        match=r"retry attempts exhausted: 3/3",
    ) as raised:
        challenge.run(on=recipe, attempts=3, trace=trace)

    assert raised.value.label == "session cookie"
    assert raised.value.offset == 28
    assert len(recipe.seeds) == 3
    assert len(set(recipe.seeds)) == 3
    assert len(opened) == 3
    assert all(tube.closed for tube in tubes)
    assert all(bytes(tube.sent) == b"%17$p\n" for tube in tubes)
    retry = trace.metadata["retry"]
    assert retry["budget"] == 3
    assert retry["used"] == 3
    assert len(retry["failures"]) == 3


def test_run_does_not_retry_nonretryable_runtime_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge, _leaks = protected_word_spec(tmp_path)
    tube = ScriptedTube(b"not-the-required-prompt")
    recipe = TrackingRecipe(tcp("challenge.example", 31337))
    opened = []

    def open_target(target):
        opened.append(target)
        return tube

    monkeypatch.setitem(runtime._ENVIRONMENT_OPENERS, "tcp", open_target)

    with pytest.raises(EndOfStream):
        challenge.run(on=recipe, attempts=4)

    assert len(recipe.seeds) == 1
    assert len(opened) == 1
    assert tube.closed


@pytest.mark.parametrize(
    "runtime_option",
    ("transport", "replay"),
)
def test_run_rejects_attempts_with_nonrefreshable_runtime_input(
    tmp_path: Path,
    runtime_option: str,
) -> None:
    challenge, _leaks = protected_word_spec(tmp_path)
    value = ScriptedTube(protected_word_input(CANARY))
    if runtime_option == "replay":
        value = Trace()

    with pytest.raises(
        (ValueError, UnsupportedFeature),
        match=rf"attempts.*{runtime_option}",
    ):
        challenge.run(attempts=2, **{runtime_option: value})


def test_run_rejects_retries_for_persistent_target_lifecycle(tmp_path: Path) -> None:
    challenge, _leaks = protected_word_spec(tmp_path)
    target = tcp(
        "challenge.example",
        31337,
        lifecycle=LifecyclePolicy("persistent", "persistent", "persistent"),
    )

    with pytest.raises(UnsupportedFeature, match="fresh process or connection"):
        challenge.run(on=target, attempts=2)


@pytest.mark.parametrize("attempts", (0, -1, "2"))
def test_run_rejects_nonpositive_or_noninteger_attempt_budget(
    tmp_path: Path,
    attempts,
) -> None:
    challenge, _leaks = protected_word_spec(tmp_path)

    with pytest.raises(ValueError, match="attempts must be a positive integer"):
        challenge.run(attempts=attempts)


@pytest.mark.parametrize("position", [0, -1])
def test_format_leak_rejects_nonpositive_positions(
    tmp_path: Path,
    position: int,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "cage", pie=False))
    with pytest.raises(PlanningError, match="position|positive|format"):
        challenge.format_leak(challenge.input.line(b"sing> "), value=position)


def test_format_leak_rejects_duplicate_positions(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "cage", pie=False))
    with pytest.raises(PlanningError, match="duplicate|position|format"):
        challenge.format_leak(
            challenge.input.line(b"sing> "),
            canary=9,
            libc=9,
        )


@pytest.mark.parametrize("separator", [b"", b"%"])
def test_format_leak_rejects_malformed_separator(
    tmp_path: Path,
    separator: bytes,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "cage", pie=False))
    with pytest.raises((PlanningError, ValueError), match="separator|format"):
        challenge.format_leak(
            challenge.input.line(b"sing> "),
            canary=9,
            libc=11,
            separator=separator,
        )


def test_return_control_rejects_nonaligned_canary_offset(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "cage", pie=False))
    canary = challenge.fact("stack.canary")
    with pytest.raises((PlanningError, ValueError), match="canary|align|offset"):
        challenge.input.line(b"sing> ").return_address(
            at=40,
            canary=(23, canary),
        )


@pytest.mark.parametrize("canary_at", [36, 40, 48])
def test_return_control_rejects_canary_and_return_overlap(
    tmp_path: Path,
    canary_at: int,
) -> None:
    challenge = Challenge(make_elf(tmp_path / "cage", pie=False))
    canary = challenge.fact("stack.canary")
    with pytest.raises((PlanningError, ValueError), match="canary|overlap|return"):
        challenge.input.line(b"sing> ").return_address(
            at=40,
            canary=(canary_at, canary),
        )


def test_old_return_address_control_remains_unchanged(tmp_path: Path) -> None:
    challenge = Challenge(make_elf(tmp_path / "cage", pie=False))
    control = challenge.control(
        challenge.input.line(b"payload: ").return_address(at=72)
    )
    challenge.want(challenge.call(challenge.exe.win), via=control, terminal=False)

    tube = ScriptedTube(b"payload: ")
    with challenge.plan().run(transport=tube):
        pass
    assert bytes(tube.sent).startswith(b"A" * 72)


@pytest.mark.skipif(
    not (CAGE / "solve_pwnx.py").is_file(),
    reason="set PWNX_CAGE_CHALLENGE=/path/to/cage-directory",
)
def test_actual_cage_solve_uses_canonical_stack_flow() -> None:
    source = (CAGE / "solve_pwnx.py").read_text()
    tree = ast.parse(source)
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }

    for feature in ("format_leak", "relate", "return_address", "shell"):
        assert feature in attributes
    assert "x.run(attempts=64)" in source
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Lambda))
        for node in ast.walk(tree)
    )


def test_canonical_cage_example_declares_bounded_fresh_instance_retries() -> None:
    assert "x.run(attempts=64)" in EXAMPLE.read_text()


@pytest.mark.parametrize(
    "challenge_specific_text",
    (
        "cage",
        "the canary tilts its head",
        "0x29ca8",
        "%9$p|%11$p",
    ),
)
def test_retry_and_framing_implementation_contains_no_cage_specific_logic(
    challenge_specific_text: str,
) -> None:
    source_root = Path(__file__).parents[1] / "src" / "pwnx"
    implementation = "\n".join(
        (source_root / name).read_text().lower()
        for name in ("challenge.py", "codecs.py", "errors.py", "planner.py", "runtime.py")
    )

    assert challenge_specific_text not in implementation


@pytest.mark.skipif(
    os.environ.get("PWNX_RUN_CTF_E2E") != "1"
    or not (CAGE / "cage").is_file(),
    reason=(
        "set PWNX_RUN_CTF_E2E=1 and PWNX_CAGE_CHALLENGE=/path/to/cage-directory"
    ),
)
def test_real_cage_solve_gets_shell_reliably_across_20_runs() -> None:
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
        f"{CAGE}:/chall:ro",
        "-w",
        "/tmp",
        "pwnx-test-linux:24.04",
        "bash",
        "-lc",
        (
            "cp -a /chall /tmp/cage && chmod +x /tmp/cage/cage "
            "/tmp/cage/ld-linux-x86-64.so.2 && cd /tmp/cage && "
            "for i in $(seq 1 20); do "
            "printf 'echo __CAGE_SHELL__\\nexit\\n' | python3 solve_pwnx.py || exit; "
            "done"
        ),
    ]
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stdout.decode(errors="replace")
    assert result.stdout.count(b"__CAGE_SHELL__") == 20
