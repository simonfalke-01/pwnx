from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from elf_factory import make_elf
from pwnx.cli import _collect_challenge, main
from pwnx.trace import Trace


def solve_file(tmp_path: Path, *, plans: int = 1) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    binary = make_elf(tmp_path / "chall", pie=False)
    script = tmp_path / "solve.py"
    challenges = "\n".join(
        f"c{index} = Challenge({str(binary)!r})"
        for index in range(plans)
    )
    run_block = """
c0.plan = lambda: FakePlan()
c0.run()
""" if plans else ""
    script.write_text(
        f"""
from pwnx.challenge import Challenge

class FakeRun:
    def interactive(self):
        print("INTERACTIVE")
    def close(self):
        print("CLOSE")

class FakePlan:
    def show(self):
        print("PLAN")
        return "PLAN"
    def run(self, **kwargs):
        print("RUN " + kwargs.get("profile", "") + " REPLAY=" + str(kwargs.get("replay") is not None))
        trace = kwargs.get("trace")
        if trace is not None:
            trace.append("receive", b"executed", operation="fake")
        return FakeRun()

{challenges}
{run_block}
""",
        encoding="utf-8",
    )
    return script


def test_collect_executes_main_guard_but_suppresses_run(tmp_path, capsys):
    script = solve_file(tmp_path)
    challenge = _collect_challenge(script)

    assert Path(challenge.exe.path).name == "chall"
    assert capsys.readouterr().out == ""


def test_collection_supports_with_run_idiom(tmp_path, capsys):
    script = solve_file(tmp_path)
    source = script.read_text(encoding="utf-8")
    script.write_text(
        source.replace(
            "c0.run()",
            "with c0.run() as run:\n    run.value(None)",
        ),
        encoding="utf-8",
    )

    challenge = _collect_challenge(script)
    assert Path(challenge.exe.path).name == "chall"
    assert capsys.readouterr().out == ""


def test_plan_prints_show_result_only_once(tmp_path, capsys):
    status = main(["plan", str(solve_file(tmp_path))])

    assert status == 0
    assert capsys.readouterr().out == "PLAN\n"


def test_checksec_and_cyclic_commands(tmp_path, capfd):
    binary = make_elf(tmp_path / "chall", pie=False)
    assert main(["checksec", str(binary)]) == 0
    output = capfd.readouterr().out
    assert "PIE" in output
    assert "NX" in output

    assert main(["cyclic", "12"]) == 0
    pattern = capfd.readouterr().out.strip().encode()
    assert len(pattern) == 12
    assert main(["cyclic", "--find", pattern[4:8].decode()]) == 0
    assert capfd.readouterr().out.strip() == "4"


def test_collection_requires_exactly_one_challenge(tmp_path, capsys):
    no_challenge = solve_file(tmp_path / "zero", plans=0)
    status = main(["plan", str(no_challenge)])
    assert status == 2
    assert "did not create a Challenge" in capsys.readouterr().err

    two_challenges = solve_file(tmp_path / "two", plans=2)
    status = main(["plan", str(two_challenges)])
    assert status == 2
    assert "created 2 Challenges" in capsys.readouterr().err


def test_run_configures_remote_interactive_and_saves_trace(tmp_path, capsys):
    script = solve_file(tmp_path)
    trace_path = tmp_path / "run.json"

    status = main(
        [
            "run",
            str(script),
            "--host",
            "127.0.0.1",
            "--port",
            "31337",
            "--trace",
            str(trace_path),
            "--interactive",
        ]
    )

    assert status == 0
    assert capsys.readouterr().out == "RUN remote REPLAY=False\nINTERACTIVE\nCLOSE\n"
    trace = Trace.load(trace_path)
    assert trace.metadata["profile"] == "remote"
    assert trace.metadata["script"] == str(script.resolve())
    assert trace.metadata["artifacts"]["exe"]["sha256"]
    assert trace.events[0].operation == "fake"


@pytest.mark.parametrize(
    "arguments, message",
    [
        (["--host", "localhost"], "--host and --port"),
        (["--port", "1234"], "--host and --port"),
        (["--tls"], "--tls requires"),
        (["--profile", "missing"], "unknown profile"),
    ],
)
def test_run_profile_errors_are_clean(tmp_path, capsys, arguments, message):
    status = main(["run", str(solve_file(tmp_path)), *arguments])
    captured = capsys.readouterr()
    assert status == 2
    assert message in captured.err
    assert "Traceback" not in captured.err


def test_replay_loads_trace_and_invokes_solve(tmp_path, capsys):
    script = solve_file(tmp_path)
    trace_path = tmp_path / "recording.json"
    trace = Trace(metadata={"profile": "remote"})
    trace.save(trace_path)

    status = main(["replay", str(script), str(trace_path), "--interactive"])

    assert status == 0
    assert capsys.readouterr().out == "RUN local REPLAY=True\nINTERACTIVE\nCLOSE\n"


def test_trace_diff_and_explain_commands(tmp_path, capsys):
    left_path = tmp_path / "left.json"
    right_path = tmp_path / "right.json"
    left = Trace(metadata={"profile": "remote", "nested": {"answer": 42}})
    left.append("send", b"hello", operation="stage1")
    left.save(left_path)
    right = Trace(metadata=dict(left.metadata), events=list(left.events))
    right.save(right_path)

    assert main(["trace", str(left_path)]) == 0
    trace_output = capsys.readouterr().out
    assert "Events: 1" in trace_output
    assert "event 0: send" in trace_output

    assert main(["explain", str(left_path), "event:0"]) == 0
    assert "5 byte(s)" in capsys.readouterr().out
    assert main(["explain", str(left_path), "metadata.nested.answer"]) == 0
    assert capsys.readouterr().out == "42\n"
    assert main(["explain", str(left_path), "stage1"]) == 0
    assert "event 0" in capsys.readouterr().out

    assert main(["diff", str(left_path), str(right_path)]) == 0
    assert capsys.readouterr().out == "traces match\n"

    right.append("close")
    right.save(right_path)
    assert main(["diff", str(left_path), str(right_path)]) == 1
    assert "event count differs" in capsys.readouterr().out


def test_unknown_explanation_is_a_clean_error(tmp_path, capsys):
    trace_path = tmp_path / "trace.json"
    Trace().save(trace_path)
    status = main(["explain", str(trace_path), "metadata.missing"])
    assert status == 2
    assert "has no path" in capsys.readouterr().err


def test_module_entrypoint_help():
    environment = os.environ.copy()
    source = str(Path(__file__).parents[1] / "src")
    environment["PYTHONPATH"] = source + os.pathsep + environment.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-m", "pwnx", "--help"],
        env=environment,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0
    assert "Plan, run, explain, and replay" in result.stdout
