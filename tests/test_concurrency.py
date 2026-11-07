from __future__ import annotations

import subprocess
import sys
import time

import pytest

from pwnx.concurrency import (
    RaceAction,
    RaceLane,
    SearchAction,
)
from pwnx.errors import ProtocolError, ReplayDivergence
from pwnx.expressions import Expr
from pwnx.trace import RecordingTube, ReplayTube, Trace
from pwnx.transport import Tube


class NullTube(Tube):
    def _recv_raw(self, max_bytes, timeout):
        return b""

    def _send_raw(self, data, timeout):
        return len(data)

    def _close_raw(self):
        pass


class Context:
    def __init__(self):
        self.invalidated = []

    def invalidate(self, *values):
        self.invalidated.extend(values)


class Runtime:
    def __init__(self, tube, trace):
        self.tube = tube
        self.trace = trace
        self.context = Context()
        self.bound = []

    def bind(self, target, value, *, source):
        self.bound.append((target, value, source))


def test_search_is_bounded_resets_and_isolates_failed_attempt_facts():
    target = Expr.fact("search.result")

    def attempt(candidate, context):
        assert "previous" not in context.facts
        context.facts["previous"] = candidate
        return candidate * 2

    action = SearchAction(
        range(10),
        attempt,
        lambda result: result == 6,
        budget=5,
        reset=lambda _context: None,
        target=target,
        invalidates=("process",),
    )
    runtime = Runtime(NullTube(), None)
    result = action.execute(runtime)

    assert result.found and result.candidate == 3 and result.value == 6
    assert [item.candidate for item in result.attempts] == [0, 1, 2, 3]
    assert [item.status for item in result.attempts] == [
        "ok",
        "ok",
        "ok",
        "success",
    ]
    assert runtime.bound[0][0] is target
    assert runtime.bound[0][1] == 6
    assert runtime.context.invalidated == ["process"]
    assert "5 attempt" in action.describe()
    assert action.contract().writes == frozenset({"attempt"})


def test_search_deadline_and_exhaustion_are_evidence_not_hidden_hangs():
    def slow(_candidate, context):
        while not context.cancelled():
            time.sleep(0.001)
        return "cancelled"

    action = SearchAction(
        [1],
        slow,
        lambda _value: False,
        budget=1,
        attempt_deadline=0.02,
    )
    result = action.execute(Runtime(NullTube(), None))
    assert not result.found and result.exhausted
    assert result.attempts[0].status == "timeout"
    assert "deadline" in result.attempts[0].error


def test_search_live_trace_replays_without_repeating_attempts_and_detects_change():
    action = SearchAction(
        [1, 2, 3],
        lambda candidate, _context: candidate,
        lambda value: value == 2,
        budget=3,
    )
    trace = Trace()
    recording = RecordingTube(NullTube(), trace)
    live = action.execute(Runtime(recording, trace))
    assert live.candidate == 2
    assert [item.candidate for item in live.attempts] == [1, 2]
    assert [item.kind for item in trace.events] == ["opaque_start", "opaque"]

    replay = action.execute(Runtime(ReplayTube(trace), None))
    assert replay == live

    changed = SearchAction(
        [1, 3],
        action.attempt,
        action.success,
        budget=2,
    )
    with pytest.raises(ReplayDivergence):
        changed.execute(Runtime(ReplayTube(trace), None))

    malformed = Trace()
    malformed.append(
        "opaque_start",
        operation=action.identity,
        details={"inputs_sha256": action.input_digest},
    )
    malformed.append(
        "opaque",
        b"[]",
        operation=action.identity,
        details={"buffered_base64": ""},
    )
    with pytest.raises(ProtocolError, match="recorded search"):
        action.execute(Runtime(ReplayTube(malformed), None))


def test_race_has_explicit_lanes_barrier_and_winning_evidence():
    def writer(context):
        return f"written:{context.attempt}"

    def reader(context):
        return f"observed:{context.attempt}"

    action = RaceAction(
        (
            RaceLane("writer", writer),
            RaceLane("reader", reader),
        ),
        lambda attempt: any(
            lane.lane == "reader" and lane.value == "observed:1"
            for lane in attempt.lanes
        ),
        deadline=0.5,
        max_attempts=2,
    )
    result = action.execute(Runtime(NullTube(), None))
    assert result.won and result.attempt == 1
    assert {item.lane for item in result.attempts[0].lanes} == {
        "writer",
        "reader",
    }
    assert "barrier=simultaneous-start" in action.describe()


def test_race_restart_deadline_and_replay_do_not_repeat_effects():
    def loser(context):
        return False

    action = RaceAction(
        (RaceLane("a", loser), RaceLane("b", loser)),
        lambda _attempt: False,
        max_attempts=2,
        deadline=0.1,
        restart=lambda _context: None,
    )
    trace = Trace()
    live = action.execute(Runtime(RecordingTube(NullTube(), trace), trace))
    assert not live.won
    assert len(live.attempts) == 2
    assert sum(len(attempt.lanes) for attempt in live.attempts) == 4

    replay = action.execute(Runtime(ReplayTube(trace), None))
    assert replay == live

    malformed = Trace()
    malformed.append(
        "opaque_start",
        operation=action.identity,
        details={"inputs_sha256": action.input_digest},
    )
    malformed.append(
        "opaque",
        b"[]",
        operation=action.identity,
        details={"buffered_base64": ""},
    )
    with pytest.raises(ProtocolError, match="recorded race"):
        action.execute(Runtime(ReplayTube(malformed), None))

    def blocked(context):
        while not context.cancelled():
            time.sleep(0.001)

    timeout_action = RaceAction(
        (RaceLane("slow", blocked), RaceLane("fast", lambda _ctx: "done")),
        lambda attempt: False,
        deadline=0.02,
    )
    timed = timeout_action.execute(Runtime(NullTube(), None))
    statuses = {lane.lane: lane.status for lane in timed.attempts[0].lanes}
    assert statuses["slow"] == "timeout"


def test_race_validates_lane_and_scheduler_contracts():
    lane = RaceLane("one", lambda _context: None)
    with pytest.raises(ValueError, match="at least two"):
        RaceAction((lane,), lambda _attempt: True)
    with pytest.raises(ValueError, match="unique"):
        RaceAction((lane, lane), lambda _attempt: True)
    with pytest.raises(ValueError, match="processes"):
        RaceAction(
            (lane, RaceLane("two", lambda _context: None)),
            lambda _attempt: True,
            scheduler="implicit",
        )


def test_process_deadlines_kill_noncooperative_callbacks_before_late_effects(
    tmp_path,
):
    search_marker = tmp_path / "search-late"

    def late_search(_candidate, _context):
        time.sleep(0.15)
        search_marker.write_text("late", encoding="utf-8")

    search = SearchAction(
        [1],
        late_search,
        lambda _value: False,
        budget=1,
        attempt_deadline=0.02,
    )
    result = search.execute(Runtime(NullTube(), None))
    assert result.attempts[0].status == "timeout"
    time.sleep(0.2)
    assert not search_marker.exists()

    race_marker = tmp_path / "race-late"

    def late_lane(_context):
        time.sleep(0.15)
        race_marker.write_text("late", encoding="utf-8")

    race = RaceAction(
        (RaceLane("late", late_lane), RaceLane("fast", lambda _context: "done")),
        lambda _attempt: False,
        deadline=0.02,
    )
    race_result = race.execute(Runtime(NullTube(), None))
    assert any(lane.status == "timeout" for lane in race_result.attempts[0].lanes)
    time.sleep(0.2)
    assert not race_marker.exists()

    descendant_marker = tmp_path / "descendant-late"

    def spawn_descendant(_candidate, _context):
        subprocess.Popen(
            (
                sys.executable,
                "-c",
                "import pathlib,sys,time; time.sleep(.15); "
                "pathlib.Path(sys.argv[1]).write_text('late')",
                str(descendant_marker),
            )
        )
        return False

    descendant = SearchAction(
        [1],
        spawn_descendant,
        lambda _value: False,
        budget=1,
    )
    descendant.execute(Runtime(NullTube(), None))
    time.sleep(0.2)
    assert not descendant_marker.exists()

