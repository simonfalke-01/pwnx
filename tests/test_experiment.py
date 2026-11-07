import os
import sys

import pytest

from elf_factory import make_elf
from pwnx.actions import expect
from pwnx.architecture import LocalProcessRecipe
from pwnx.challenge import Challenge
from pwnx.domain import Evidence
from pwnx.errors import ReplayDivergence
from pwnx.experiment import Experiment
from pwnx.trace import Trace


class FakeRun:
    pass


class FakePlan:
    def __init__(self):
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(kwargs)
        trace = kwargs.get("trace")
        if trace is not None:
            trace.metadata["facts"] = [{"key": "libc.base", "value": 1}]
            trace.append("send", b"A")
        return FakeRun()

    def to_dict(self):
        return {
            "goal": ["shell"],
            "selected_tactic": "rop",
            "stages": [{"name": "stage1"}],
            "assumptions": ["libc matches"],
        }


def test_experiment_executes_reports_and_replays():
    plan = FakePlan()
    experiment = Experiment(plan)
    experiment.add_evidence(Evidence("artifact", "hash verified"))
    assert isinstance(experiment.execute(profile="local"), FakeRun)
    report = experiment.report()
    assert report.goal == ("shell",)
    assert report.selected_strategy == "rop"
    assert report.trace_events == 1
    assert "hash verified" in report.describe()

    experiment.replay()
    assert plan.calls[-1]["replay"] is experiment.trace


def test_experiment_diff_uses_semantic_and_trace_evidence():
    left = Experiment(FakePlan(), trace=Trace(metadata={"x": 1}))
    right = Experiment(FakePlan(), trace=Trace(metadata={"x": 2}))
    left.trace.append("send", b"A")
    right.trace.append("send", b"B")
    differences = left.diff(right)
    assert any("event" in item or "data" in item for item in differences)


def test_target_recipe_materializes_and_replays_as_experiment(tmp_path):
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    challenge.want(expect(b"READY\n"))
    target = LocalProcessRecipe(
        sys.executable,
        arguments=("-u", "-c", "print('READY')"),
    )
    challenge.on("python", target)
    experiment = challenge.plan().experiment(target=target)
    run = experiment.execute()
    run.close()
    assert experiment.trace.metadata["target"]["adapter"] == "local-process"
    with pytest.raises(ReplayDivergence, match="replay requires matching on="):
        challenge.plan().run(replay=experiment.trace)
    direct = challenge.plan().run(replay=experiment.trace, on=target)
    direct.close()
    replay = experiment.replay()
    replay.close()


@pytest.mark.skipif(os.name != "posix", reason="executable script fixture")
def test_experiment_replay_rejects_changed_target_recipe_artifact(tmp_path):
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    challenge.want(expect(b"READY\n"))
    executable = tmp_path / "target.sh"
    executable.write_text("#!/bin/sh\nprintf 'READY\\n'\n", encoding="utf-8")
    executable.chmod(0o755)
    target = LocalProcessRecipe(str(executable))
    experiment = challenge.plan().experiment(target=target)
    run = experiment.execute()
    run.close()

    executable.write_text("#!/bin/sh\nprintf 'READY\\n'\n# changed\n", encoding="utf-8")
    with pytest.raises(ReplayDivergence, match="target recipe identity changed"):
        experiment.replay()
