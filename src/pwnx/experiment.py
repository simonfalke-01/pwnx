"""A solve run as a reproducible, comparable experiment."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .domain import Environment, Evidence
from .trace import Trace


@dataclass(frozen=True, slots=True)
class ExperimentReport:
    goal: tuple[str, ...]
    selected_strategy: str
    stages: tuple[Mapping[str, Any], ...]
    facts: tuple[Mapping[str, Any], ...] = ()
    payloads: tuple[Mapping[str, Any], ...] = ()
    assumptions: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    trace_events: int = 0

    def describe(self) -> str:
        lines = [
            f"goal: {', '.join(self.goal) or '<none>'}",
            f"strategy: {self.selected_strategy or '<none>'}",
            f"stages: {len(self.stages)}, facts: {len(self.facts)}, "
            f"payloads: {len(self.payloads)}, events: {self.trace_events}",
        ]
        lines.extend(f"assumption: {item}" for item in self.assumptions)
        lines.extend(item.describe() for item in self.evidence)
        return "\n".join(lines)


@dataclass(slots=True)
class Experiment:
    plan: Any
    environment: Environment | None = None
    target: Any = None
    trace: Trace | None = None
    run: Any = None
    evidence: list[Evidence] = field(default_factory=list)

    def execute(self, **kwargs: Any):
        if self.run is not None:
            raise RuntimeError("experiment has already executed")
        if "on" in kwargs:
            self.target = kwargs["on"]
        elif self.target is not None:
            kwargs["on"] = self.target
        elif self.environment is not None and "profile" not in kwargs:
            kwargs["profile"] = str(
                self.environment.config.get("profile", self.environment.adapter)
            )
        trace = kwargs.get("trace")
        if trace is None:
            trace = Trace()
            kwargs["trace"] = trace
        self.trace = trace
        self.run = self.plan.run(**kwargs)
        return self.run

    def replay(self, trace: Trace | None = None):
        selected = trace or self.trace
        if selected is None:
            raise ValueError("experiment has no trace to replay")
        kwargs: dict[str, Any] = {"replay": selected}
        if self.target is not None:
            kwargs["on"] = self.target
        elif self.environment is not None:
            kwargs["profile"] = str(
                self.environment.config.get(
                    "profile", self.environment.adapter
                )
            )
        return self.plan.run(**kwargs)

    def add_evidence(self, evidence: Evidence) -> None:
        self.evidence.append(evidence)

    def report(self) -> ExperimentReport:
        plan = self.plan.to_dict()
        trace = self.trace
        metadata = trace.metadata if trace is not None else {}
        stages = tuple(MappingProxyType(dict(item)) for item in plan.get("stages", ()))
        facts = tuple(
            MappingProxyType(dict(item)) for item in metadata.get("facts", ())
        )
        payloads = tuple(
            MappingProxyType(dict(item)) for item in metadata.get("payloads", ())
        )
        return ExperimentReport(
            tuple(plan.get("goal", ())),
            plan.get("selected_tactic", ""),
            stages,
            facts,
            payloads,
            tuple(plan.get("assumptions", ())),
            tuple(self.evidence),
            len(trace.events) if trace is not None else 0,
        )

    def diff(self, other: "Experiment") -> tuple[str, ...]:
        differences: list[str] = []
        left = self.report()
        right = other.report()
        if left.goal != right.goal:
            differences.append(f"goal differs: {left.goal!r} != {right.goal!r}")
        if left.selected_strategy != right.selected_strategy:
            differences.append(
                "strategy differs: "
                f"{left.selected_strategy!r} != {right.selected_strategy!r}"
            )
        if self.trace is not None and other.trace is not None:
            differences.extend(self.trace.diff(other.trace))
        elif self.trace is not other.trace:
            differences.append("one experiment has no trace")
        return tuple(differences)
