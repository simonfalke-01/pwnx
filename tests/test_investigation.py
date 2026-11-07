from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time

import pytest

from elf_factory import make_elf
from pwnx.domain import Evidence
from pwnx.errors import ConstraintError, ProtocolError, ReplayDivergence
from pwnx.expressions import Expr
from pwnx.investigation import (
    AdapterSupport,
    CrashTriageAdapter,
    Hypothesis,
    Investigation,
    InvestigationAdapterRegistry,
    InvestigationArtifact,
    InvestigationBudget,
    InvestigationMetrics,
    InvestigationReport,
    InvestigationRequest,
    StaticTriageAdapter,
    SubprocessJSONAdapter,
)
from pwnx.trace import RecordingTube, ReplayTube, Trace
from pwnx.transport import Tube
from test_diagnostics import make_core


class NullTube(Tube):
    def _recv_raw(self, max_bytes, timeout):
        return b""

    def _send_raw(self, data, timeout):
        return len(data)

    def _close_raw(self):
        pass


class Context:
    def invalidate(self, *values):
        pass


class Runtime:
    def __init__(self, tube, trace):
        self.tube = tube
        self.trace = trace
        self.context = Context()
        self.bound = []

    def bind(self, target, value, *, source):
        self.bound.append((target, value, source))


def report_for(request, adapter="fake", claim="candidate"):
    return InvestigationReport(
        request.input_digest,
        (
            Hypothesis(
                "primitive",
                claim,
                0.75,
                (Evidence("test", "fixture"),),
                ("confirm dynamically",),
            ),
        ),
        (),
        InvestigationMetrics(adapter, 0.01, states=3, output_bytes=10),
    )


def test_budget_and_request_are_bounded_and_portable(tmp_path):
    with pytest.raises(ValueError):
        InvestigationBudget(timeout=0)
    target = make_elf(tmp_path / "chall", pie=False)
    request = InvestigationRequest(
        "static-triage",
        str(target),
        find=(0x401000,),
        avoid=(0x400000,),
        constraints={"max_depth": 10},
        inputs={"seed": 7},
    )
    assert request.target_sha256 == hashlib.sha256(target.read_bytes()).hexdigest()
    assert request.input_digest == request.input_digest
    assert request.to_dict()["budget"]["max_results"] == 64
    with pytest.raises((TypeError, ValueError)):
        InvestigationRequest("x", str(target), inputs={"bad": object()})


def test_registry_ranks_supported_adapters_and_keeps_rejections(tmp_path):
    request = InvestigationRequest("kind", str(tmp_path / "target"))

    class Adapter:
        def __init__(self, name, supported, reliability, cost, fail=False):
            self.name = name
            self.identity = name
            self.reliability = reliability
            self.cost = cost
            self.supported = supported
            self.fail = fail

        def supports(self, _request):
            return AdapterSupport(self.supported, "unsupported fixture")

        def investigate(self, request):
            if self.fail:
                raise ProtocolError("adapter failed")
            return report_for(request, self.name, self.name)

    registry = InvestigationAdapterRegistry(
        (
            Adapter("unsupported", False, "stable", 0),
            Adapter("broken", True, "stable", 1, fail=True),
            Adapter("working", True, "conditional", 2),
        )
    )
    report = registry.investigate(request)
    assert report.metrics.adapter == "working"
    assert report.candidates[0].claim == "working"
    assert [item.adapter for item in report.rejections] == [
        "unsupported",
        "broken",
    ]
    with pytest.raises(ConstraintError, match="no adapter supports"):
        InvestigationAdapterRegistry().investigate(request)


def test_static_triage_produces_hypotheses_not_facts(tmp_path):
    target = make_elf(tmp_path / "chall", pie=False)
    request = InvestigationRequest("static-triage", str(target))
    adapter = StaticTriageAdapter()
    assert adapter.supports(request).supported
    report = adapter.investigate(request)
    kinds = {item.kind for item in report.candidates}
    assert "fixed-code-addresses" in kinds
    assert "stack-control" in kinds
    assert report.artifacts[0].sha256 == hashlib.sha256(target.read_bytes()).hexdigest()
    assert all(isinstance(item, Hypothesis) for item in report.candidates)
    assert "candidate" in report.explain()


def test_crash_triage_recovers_control_offset(tmp_path):
    core = make_core(tmp_path / "core")
    request = InvestigationRequest("crash-triage", str(core))
    report = CrashTriageAdapter().investigate(request)
    control = next(
        item
        for item in report.candidates
        if item.kind == "instruction-pointer-control"
    )
    assert control.details["offset"] == 4
    assert control.confidence == 0.98
    assert report.metrics.states >= 1


def test_subprocess_json_adapter_validates_schema_bounds_and_artifacts(tmp_path):
    target = make_elf(tmp_path / "chall", pie=False)
    artifact = tmp_path / "analysis.json"
    artifact.write_text("evidence", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    response = {
        "candidates": [
            {
                "kind": "path",
                "claim": "find is reachable",
                "confidence": 0.8,
                "evidence": [],
                "requirements": ["validate"],
            }
        ],
        "metrics": {"states": 9},
        "artifacts": [
            {"path": str(artifact), "sha256": digest, "kind": "solver-log"}
        ],
    }
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(
            argv, 0, json.dumps(response).encode(), b""
        )

    adapter = SubprocessJSONAdapter(
        "solver",
        ("/tools/solver", "--json"),
        frozenset({"symbolic"}),
        runner=runner,
    )
    request = InvestigationRequest(
        "symbolic",
        str(target),
        find=(0x401000,),
        budget=InvestigationBudget(max_states=10),
    )
    report = adapter.investigate(request)
    assert report.candidates[0].claim == "find is reachable"
    assert report.artifacts == (
        InvestigationArtifact(str(artifact.resolve()), digest, 8, "solver-log"),
    )
    assert calls[0][0] == ["/tools/solver", "--json"]
    sent = json.loads(calls[0][1]["input"])
    assert sent["target_sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert calls[0][1]["timeout"] == request.budget.timeout

    too_many = dict(response)
    too_many["metrics"] = {"states": 11}
    adapter_states = SubprocessJSONAdapter(
        "states",
        ("tool",),
        frozenset({"symbolic"}),
        runner=lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 0, json.dumps(too_many).encode(), b""
        ),
    )
    with pytest.raises(ConstraintError, match="states"):
        adapter_states.investigate(request)


def test_subprocess_adapter_rejects_timeout_output_and_malformed_json(tmp_path):
    target = make_elf(tmp_path / "chall", pie=False)
    request = InvestigationRequest(
        "symbolic",
        str(target),
        budget=InvestigationBudget(timeout=0.1, max_output=16),
    )

    def timed(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    timeout = SubprocessJSONAdapter(
        "timeout", ("tool",), frozenset({"symbolic"}), runner=timed
    )
    with pytest.raises(ConstraintError, match="exceeded"):
        timeout.investigate(request)

    oversized = SubprocessJSONAdapter(
        "large",
        ("tool",),
        frozenset({"symbolic"}),
        runner=lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 0, b"X" * 17, b""
        ),
    )
    with pytest.raises(ConstraintError, match="output"):
        oversized.investigate(request)

    malformed = SubprocessJSONAdapter(
        "bad",
        ("tool",),
        frozenset({"symbolic"}),
        runner=lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 0, b"not json", b""
        ),
    )
    with pytest.raises(ProtocolError, match="malformed JSON"):
        malformed.investigate(request)


def test_subprocess_adapter_enforces_output_bound_during_capture(tmp_path):
    target = make_elf(tmp_path / "chall", pie=False)
    request = InvestigationRequest(
        "symbolic",
        str(target),
        budget=InvestigationBudget(
            timeout=1.0,
            memory_bytes=4 * 1024 * 1024 * 1024,
            max_output=1024,
        ),
    )
    adapter = SubprocessJSONAdapter(
        "noisy",
        (
            sys.executable,
            "-c",
            "import os,time\nwhile True:\n os.write(1, b'X' * 4096)\n time.sleep(.001)",
        ),
        frozenset({"symbolic"}),
    )
    started = time.monotonic()
    with pytest.raises(ConstraintError, match="output exceeds"):
        adapter.investigate(request)
    assert time.monotonic() - started < request.budget.timeout


def test_investigation_action_records_and_replays_without_rerun(tmp_path):
    target_path = make_elf(tmp_path / "chall", pie=False)
    request = InvestigationRequest("custom", str(target_path))
    calls = []

    class Adapter:
        name = "custom"
        identity = "custom-v1"
        reliability = "stable"
        cost = 1

        def supports(self, request):
            return AdapterSupport(request.kind == "custom")

        def investigate(self, request):
            calls.append(request.input_digest)
            return report_for(request, self.name)

    registry = InvestigationAdapterRegistry((Adapter(),))
    target = Expr.fact("investigation.report", scope="artifact")
    action = Investigation(request, registry, target)
    trace = Trace()
    live = RecordingTube(NullTube(), trace)
    live_runtime = Runtime(live, trace)
    report = action.execute(live_runtime)
    live.close()
    assert len(calls) == 1
    assert [event.kind for event in trace.events] == [
        "opaque_start",
        "opaque",
        "close",
    ]
    assert live_runtime.bound[0][0] is target
    assert report.candidates and not isinstance(report.candidates[0], Expr)
    assert len(trace.metadata["investigations"]) == 1

    replay = ReplayTube(trace)
    replay_runtime = Runtime(replay, None)
    assert action.execute(replay_runtime) == report
    replay.close()
    assert len(calls) == 1

    changed = Investigation(
        InvestigationRequest(
            "custom",
            str(target_path),
            constraints={"changed": True},
        ),
        registry,
        target,
    )
    replay = ReplayTube(trace)
    with pytest.raises(ReplayDivergence, match="opaque"):
        changed.execute(Runtime(replay, None))

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
    with pytest.raises(ProtocolError, match="recorded investigation"):
        action.execute(Runtime(ReplayTube(malformed), None))


def test_report_roundtrip_and_adapter_selection_are_deterministic(tmp_path):
    target = make_elf(tmp_path / "chall", pie=False)
    request = InvestigationRequest("static", str(target))
    registry = InvestigationAdapterRegistry(
        (CrashTriageAdapter(), StaticTriageAdapter())
    )
    candidates = registry.candidates(request)
    assert [item[0].name for item in candidates] == [
        "static-triage",
        "crash-triage",
    ]
    report = registry.investigate(request)
    assert InvestigationReport.from_dict(report.to_dict()) == report

