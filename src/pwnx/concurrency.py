"""Bounded search and race actions with explicit attempt lifecycles.

These actions are opt-in concurrency. They never make ordinary plan actions
parallel. Callbacks execute behind one recorded opaque boundary, and replay
reuses the recorded result without repeating attempts or lane effects.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import itertools
import json
import multiprocessing
import os
import signal
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from .actions import Action
from .domain import EffectContract, Evidence, Scope
from .errors import ConstraintError, ProtocolError, UnsupportedFeature
from .expressions import Expr
from .trace import ReplayTube


def _callable_identity(function: Callable[..., Any] | None) -> str:
    if function is None:
        return ""
    target = getattr(function, "__call__", function)
    code = getattr(target, "__code__", None)
    material: tuple[Any, ...]
    if code is None:
        material = (
            getattr(target, "__module__", type(function).__module__),
            getattr(target, "__qualname__", type(function).__qualname__),
        )
    else:
        material = (
            getattr(target, "__module__", ""),
            getattr(target, "__qualname__", type(function).__qualname__),
            code.co_code,
            repr(code.co_consts),
        )
    return hashlib.sha256(repr(material).encode()).hexdigest()


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"__bytes__": base64.b64encode(value).decode("ascii")}
    if isinstance(value, tuple):
        return {"__tuple__": [_json_value(item) for item in value]}
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise ConstraintError(
        f"search/race results must be portable JSON values or bytes, got {type(value).__name__}"
    )


def _from_json(value: Any) -> Any:
    if isinstance(value, dict) and set(value) == {"__bytes__"}:
        return base64.b64decode(value["__bytes__"], validate=True)
    if isinstance(value, dict) and set(value) == {"__tuple__"}:
        return tuple(_from_json(item) for item in value["__tuple__"])
    if isinstance(value, dict):
        return {key: _from_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_from_json(item) for item in value]
    return value


def _encode(value: Any) -> bytes:
    return json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def _decode(data: bytes) -> Any:
    try:
        return _from_json(json.loads(data.decode()))
    except (UnicodeError, ValueError, TypeError) as error:
        raise ProtocolError("recorded search/race result is malformed") from error


def _process_context() -> Any:
    if "fork" not in multiprocessing.get_all_start_methods():
        raise UnsupportedFeature(
            "bounded search/race callbacks require a host with fork process isolation"
        )
    return multiprocessing.get_context("fork")


def _terminate_worker(process: Any) -> None:
    process.join(timeout=0)
    try:
        if os.name == "posix":
            # The callback may have spawned descendants and exited. Its process
            # group remains the owned effect boundary even after the leader dies.
            os.killpg(process.pid, signal.SIGKILL)
        elif process.is_alive():
            process.terminate()
    except (PermissionError, ProcessLookupError):
        if process.is_alive():
            process.terminate()
    process.join(timeout=1.0)
    if process.is_alive():
        process.kill()
        process.join(timeout=1.0)


def _isolated_call(
    function: Callable[[], Any],
    *,
    timeout: float,
    cancel: Any,
) -> tuple[str, Any, str]:
    """Run one opaque callback in a killable process boundary."""

    process_context = _process_context()
    receiver, sender = process_context.Pipe(duplex=False)

    def worker() -> None:
        if os.name == "posix":
            os.setsid()
        try:
            payload = _encode({"status": "ok", "value": function(), "error": ""})
        except Exception as error:
            payload = _encode(
                {
                    "status": "error",
                    "value": None,
                    "error": f"{type(error).__name__}: {error}",
                }
            )
        try:
            sender.send_bytes(payload)
        finally:
            sender.close()

    process = process_context.Process(target=worker)
    process.start()
    sender.close()
    try:
        if not receiver.poll(timeout):
            cancel.set()
            _terminate_worker(process)
            return "timeout", None, "attempt deadline exceeded"
        decoded = _decode(receiver.recv_bytes())
    except (EOFError, OSError) as error:
        _terminate_worker(process)
        return "error", None, f"isolated callback failed: {error}"
    finally:
        receiver.close()
    process.join(timeout=0.1)
    _terminate_worker(process)
    if not isinstance(decoded, dict):
        return "error", None, "isolated callback returned malformed evidence"
    return (
        str(decoded.get("status", "error")),
        decoded.get("value"),
        str(decoded.get("error", "")),
    )


def _invoke(function: Callable[..., Any], *args: Any) -> Any:
    """Call an ergonomic callback without masking callback TypeError values."""

    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return function(*args)
    positional = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind in {parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD}
    ]
    if any(
        parameter.kind is parameter.VAR_POSITIONAL for parameter in signature.parameters.values()
    ):
        return function(*args)
    return function(*args[: len(positional)])


@dataclass(slots=True)
class AttemptContext:
    index: int
    deadline: float
    cancel: Any
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def cancelled(self) -> bool:
        return self.cancel.is_set()


@dataclass(frozen=True, slots=True)
class AttemptEvidence:
    index: int
    candidate: Any
    status: str
    elapsed: float
    result: Any = None
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "candidate": _json_value(self.candidate),
            "status": self.status,
            "elapsed": self.elapsed,
            "result": _json_value(self.result),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AttemptEvidence":
        return cls(
            int(value["index"]),
            _from_json(value["candidate"]),
            str(value["status"]),
            float(value["elapsed"]),
            _from_json(value.get("result")),
            str(value.get("error", "")),
        )


@dataclass(frozen=True, slots=True)
class SearchResult:
    found: bool
    candidate: Any = None
    value: Any = None
    attempts: tuple[AttemptEvidence, ...] = ()
    exhausted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "found": self.found,
            "candidate": _json_value(self.candidate),
            "value": _json_value(self.value),
            "attempts": [item.to_dict() for item in self.attempts],
            "exhausted": self.exhausted,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SearchResult":
        return cls(
            bool(value["found"]),
            _from_json(value.get("candidate")),
            _from_json(value.get("value")),
            tuple(AttemptEvidence.from_dict(item) for item in value["attempts"]),
            bool(value.get("exhausted", False)),
        )

    def describe(self) -> str:
        state = f"found {self.candidate!r}" if self.found else "not found"
        return f"search {state} after {len(self.attempts)} attempt(s)"


CandidateSource = Iterable[Any] | Callable[[], Iterable[Any]]


@dataclass(frozen=True)
class SearchAction(Action):
    candidates: CandidateSource
    attempt: Callable[..., Any]
    success: Callable[..., bool]
    budget: int
    target: Expr | None = None
    reset: Callable[..., Any] | None = None
    attempt_deadline: float = 1.0
    restart_policy: str = "fresh-attempt"
    reads: tuple[str, ...] = ("target",)
    writes: tuple[str, ...] = ("attempt",)
    invalidates: tuple[Any, ...] = ()
    name: str = "bounded search"
    scheduler: str = "processes"

    def __post_init__(self) -> None:
        if self.budget <= 0:
            raise ValueError("search budget must be positive")
        if self.attempt_deadline <= 0:
            raise ValueError("attempt deadline must be positive")
        if not callable(self.attempt) or not callable(self.success):
            raise TypeError("attempt and success must be callable")
        if self.reset is not None and not callable(self.reset):
            raise TypeError("reset must be callable")
        if self.scheduler != "processes":
            raise ValueError("only the killable processes scheduler is implemented")
        if not callable(self.candidates):
            bounded = tuple(itertools.islice(iter(self.candidates), self.budget))
            object.__setattr__(self, "candidates", bounded)

    @property
    def output(self) -> Expr | None:
        return self.target

    @property
    def identity(self) -> str:
        source = (
            _callable_identity(self.candidates)
            if callable(self.candidates)
            else repr(self.candidates)
        )
        material = (
            self.name,
            source,
            _callable_identity(self.attempt),
            _callable_identity(self.success),
            _callable_identity(self.reset),
            self.budget,
            self.attempt_deadline,
            self.restart_policy,
            self.scheduler,
            getattr(self.target, "key", None),
        )
        return hashlib.sha256(repr(material).encode()).hexdigest()

    @property
    def input_digest(self) -> str:
        return hashlib.sha256(
            _encode(
                {
                    "identity": self.identity,
                    "candidates": None if callable(self.candidates) else list(self.candidates),
                }
            )
        ).hexdigest()

    def contract(self) -> EffectContract:
        return EffectContract(
            provides=(self.target,) if self.target is not None else (),
            reads=frozenset(self.reads),
            writes=frozenset(self.writes),
            invalidates=self.invalidates,
            scope=Scope.PROCESS,
            evidence=(
                Evidence(
                    "search-bound",
                    f"{self.budget} attempts, {self.attempt_deadline:g}s each",
                    self.name,
                ),
            ),
        )

    def describe(self) -> str:
        return (
            f"{self.name}: at most {self.budget} attempt(s), "
            f"{self.attempt_deadline:g}s each, reset={self.restart_policy}, "
            f"scheduler={self.scheduler}"
        )

    def _candidate_values(self) -> Iterable[Any]:
        values = self.candidates() if callable(self.candidates) else self.candidates
        return itertools.islice(values, self.budget)

    def _live(self) -> SearchResult:
        evidence: list[AttemptEvidence] = []
        process_context = _process_context()
        for index, candidate in enumerate(self._candidate_values(), 1):
            cancel = process_context.Event()
            context = AttemptContext(
                index,
                time.monotonic() + self.attempt_deadline,
                cancel,
            )

            def evaluate_attempt() -> tuple[bool, Any]:
                value = _invoke(self.attempt, candidate, context)
                return bool(_invoke(self.success, value, context)), value

            started = time.monotonic()
            status, outcome, error = _isolated_call(
                evaluate_attempt,
                timeout=self.attempt_deadline,
                cancel=cancel,
            )
            elapsed = time.monotonic() - started
            value = None
            if status == "ok":
                try:
                    matched, value = outcome
                    matched = bool(matched)
                except (TypeError, ValueError) as exception:
                    status = "error"
                    error = f"invalid isolated attempt result: {exception}"
                    matched = False
                if matched:
                    evidence.append(AttemptEvidence(index, candidate, "success", elapsed, value))
                    return SearchResult(True, candidate, value, tuple(evidence), exhausted=False)
            evidence.append(AttemptEvidence(index, candidate, status, elapsed, value, error))
            # Attempt-local facts die here. Reset gets a fresh context and cannot
            # observe context.facts from the failed attempt.
            if self.reset is not None:
                reset = self.reset
                reset_context = AttemptContext(
                    index,
                    time.monotonic() + self.attempt_deadline,
                    process_context.Event(),
                )
                reset_status, _reset_value, reset_error = _isolated_call(
                    lambda: _invoke(reset, reset_context),
                    timeout=self.attempt_deadline,
                    cancel=reset_context.cancel,
                )
                if reset_status != "ok":
                    raise ProtocolError(f"search reset failed after attempt {index}: {reset_error}")
        return SearchResult(False, attempts=tuple(evidence), exhausted=True)

    def execute(self, runtime: Any) -> SearchResult:
        tube = runtime.tube
        if isinstance(tube, ReplayTube):
            encoded = tube.consume_opaque(self.identity, self.input_digest)
            try:
                decoded = _decode(encoded)
                if not isinstance(decoded, dict):
                    raise TypeError("result must be an object")
                result = SearchResult.from_dict(decoded)
            except (ProtocolError, ValueError, TypeError, KeyError) as error:
                raise ProtocolError("recorded search result is malformed") from error
        else:
            trace = runtime.trace
            if trace is not None:
                trace.append(
                    "opaque_start",
                    operation=self.identity,
                    details={
                        "name": self.describe(),
                        "inputs_sha256": self.input_digest,
                    },
                )
            result = self._live()
            if trace is not None:
                buffered = getattr(tube, "buffered_bytes", b"")
                trace.append(
                    "opaque",
                    json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":")).encode(),
                    operation=self.identity,
                    details={
                        "name": self.describe(),
                        "inputs_sha256": self.input_digest,
                        "buffered_base64": base64.b64encode(buffered).decode("ascii"),
                    },
                )
        invalidator = getattr(runtime.context, "invalidate", None)
        if callable(invalidator) and self.invalidates:
            invalidator(*self.invalidates)
        if self.target is not None and result.found:
            runtime.bind(self.target, result.value, source=result.describe())
        return result


@dataclass(slots=True)
class RaceContext:
    attempt: int
    lane: str
    deadline: float
    cancel: Any
    barrier: Any
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def cancelled(self) -> bool:
        return self.cancel.is_set()

    def synchronize(self, timeout: float | None = None) -> None:
        self.barrier.wait(self.remaining if timeout is None else min(timeout, self.remaining))


@dataclass(frozen=True, slots=True)
class RaceLane:
    name: str
    action: Callable[[RaceContext], Any]

    def __post_init__(self) -> None:
        if not self.name or not callable(self.action):
            raise ValueError("race lanes require a name and callable")


@dataclass(frozen=True, slots=True)
class LaneResult:
    lane: str
    status: str
    elapsed: float
    value: Any = None
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "lane": self.lane,
            "status": self.status,
            "elapsed": self.elapsed,
            "value": _json_value(self.value),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LaneResult":
        return cls(
            str(value["lane"]),
            str(value["status"]),
            float(value["elapsed"]),
            _from_json(value.get("value")),
            str(value.get("error", "")),
        )


@dataclass(frozen=True, slots=True)
class RaceAttempt:
    index: int
    lanes: tuple[LaneResult, ...]
    won: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "lanes": [item.to_dict() for item in self.lanes],
            "won": self.won,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RaceAttempt":
        return cls(
            int(value["index"]),
            tuple(LaneResult.from_dict(item) for item in value["lanes"]),
            bool(value["won"]),
        )


@dataclass(frozen=True, slots=True)
class RaceResult:
    won: bool
    attempt: int | None
    attempts: tuple[RaceAttempt, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "won": self.won,
            "attempt": self.attempt,
            "attempts": [item.to_dict() for item in self.attempts],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RaceResult":
        attempt = value.get("attempt")
        return cls(
            bool(value["won"]),
            int(attempt) if attempt is not None else None,
            tuple(RaceAttempt.from_dict(item) for item in value["attempts"]),
        )

    def describe(self) -> str:
        return (
            f"race won on attempt {self.attempt}"
            if self.won
            else f"race exhausted {len(self.attempts)} attempt(s)"
        )


@dataclass(frozen=True)
class RaceAction(Action):
    lanes: tuple[RaceLane, ...]
    success: Callable[..., bool]
    max_attempts: int = 1
    deadline: float = 1.0
    restart: Callable[..., Any] | None = None
    target: Expr | None = None
    barrier: str = "simultaneous-start"
    scheduler: str = "processes"
    reads: tuple[str, ...] = ("target",)
    writes: tuple[str, ...] = ("target",)
    invalidates: tuple[Any, ...] = ()
    name: str = "explicit race"

    def __post_init__(self) -> None:
        if len(self.lanes) < 2:
            raise ValueError("a race requires at least two lanes")
        if len({lane.name for lane in self.lanes}) != len(self.lanes):
            raise ValueError("race lane names must be unique")
        if self.max_attempts <= 0 or self.deadline <= 0:
            raise ValueError("race attempts and deadline must be positive")
        if self.scheduler != "processes":
            raise ValueError("only the killable processes scheduler is implemented")
        if not callable(self.success):
            raise TypeError("race success predicate must be callable")
        if self.restart is not None and not callable(self.restart):
            raise TypeError("race restart must be callable")

    @property
    def output(self) -> Expr | None:
        return self.target

    @property
    def identity(self) -> str:
        material = (
            self.name,
            tuple((lane.name, _callable_identity(lane.action)) for lane in self.lanes),
            _callable_identity(self.success),
            _callable_identity(self.restart),
            self.max_attempts,
            self.deadline,
            self.barrier,
            self.scheduler,
            getattr(self.target, "key", None),
        )
        return hashlib.sha256(repr(material).encode()).hexdigest()

    @property
    def input_digest(self) -> str:
        return hashlib.sha256(
            _encode({"identity": self.identity, "lanes": [lane.name for lane in self.lanes]})
        ).hexdigest()

    def contract(self) -> EffectContract:
        return EffectContract(
            provides=(self.target,) if self.target is not None else (),
            reads=frozenset(self.reads),
            writes=frozenset(self.writes),
            invalidates=self.invalidates,
            scope=Scope.PROCESS,
            evidence=(
                Evidence(
                    "race-bound",
                    f"{self.max_attempts} attempts, {self.deadline:g}s each, "
                    f"{len(self.lanes)} lanes",
                    self.scheduler,
                ),
            ),
        )

    def describe(self) -> str:
        return (
            f"{self.name}: lanes={','.join(lane.name for lane in self.lanes)}, "
            f"barrier={self.barrier}, deadline={self.deadline:g}s, "
            f"attempts={self.max_attempts}"
        )

    def _attempt(self, index: int) -> RaceAttempt:
        process_context = _process_context()
        cancel = process_context.Event()
        barrier = process_context.Barrier(len(self.lanes))
        deadline = time.monotonic() + self.deadline
        channels = {lane.name: process_context.Pipe(duplex=False) for lane in self.lanes}

        def worker(lane: RaceLane, sender: Any) -> None:
            if os.name == "posix":
                os.setsid()
            context = RaceContext(index, lane.name, deadline, cancel, barrier)
            started = time.monotonic()
            try:
                context.synchronize()
                value = lane.action(context)
            except threading.BrokenBarrierError:
                result = {
                    "status": "timeout",
                    "value": None,
                    "error": "barrier deadline exceeded",
                    "elapsed": time.monotonic() - started,
                }
            except Exception as error:
                result = {
                    "status": "error",
                    "value": None,
                    "error": f"{type(error).__name__}: {error}",
                    "elapsed": time.monotonic() - started,
                }
            else:
                result = {
                    "status": "ok",
                    "value": value,
                    "error": "",
                    "elapsed": time.monotonic() - started,
                }
            try:
                sender.send_bytes(_encode(result))
            except Exception as error:
                sender.send_bytes(
                    _encode(
                        {
                            "status": "error",
                            "value": None,
                            "error": f"non-portable lane result: {error}",
                            "elapsed": time.monotonic() - started,
                        }
                    )
                )
            finally:
                sender.close()

        processes = [
            process_context.Process(
                target=worker,
                args=(lane, channels[lane.name][1]),
            )
            for lane in self.lanes
        ]
        for process in processes:
            process.start()
        for _receiver, sender in channels.values():
            sender.close()
        results: list[LaneResult] = []
        for lane in self.lanes:
            receiver = channels[lane.name][0]
            if not receiver.poll(max(0.0, deadline - time.monotonic())):
                results.append(
                    LaneResult(
                        lane.name,
                        "timeout",
                        self.deadline,
                        error="lane deadline exceeded",
                    )
                )
                receiver.close()
                continue
            try:
                decoded = _decode(receiver.recv_bytes())
                if not isinstance(decoded, dict):
                    raise TypeError("lane result must be an object")
                results.append(
                    LaneResult(
                        lane.name,
                        str(decoded["status"]),
                        float(decoded["elapsed"]),
                        decoded.get("value"),
                        str(decoded.get("error", "")),
                    )
                )
            except (EOFError, OSError, ProtocolError, KeyError, TypeError, ValueError):
                results.append(
                    LaneResult(lane.name, "error", self.deadline, error="no lane result")
                )
            finally:
                receiver.close()
        cancel.set()
        for process in processes:
            _terminate_worker(process)
        attempt = RaceAttempt(index, tuple(results), False)
        success_cancel = process_context.Event()
        status, won, error = _isolated_call(
            lambda: bool(_invoke(self.success, attempt)),
            timeout=self.deadline,
            cancel=success_cancel,
        )
        if status != "ok":
            raise ProtocolError(f"race success predicate failed: {error}")
        return RaceAttempt(index, tuple(results), won)

    def _live(self) -> RaceResult:
        attempts: list[RaceAttempt] = []
        for index in range(1, self.max_attempts + 1):
            result = self._attempt(index)
            attempts.append(result)
            if result.won:
                return RaceResult(True, index, tuple(attempts))
            if self.restart is not None and index < self.max_attempts:
                restart = self.restart
                context = AttemptContext(
                    index,
                    time.monotonic() + self.deadline,
                    _process_context().Event(),
                )
                status, _value, error = _isolated_call(
                    lambda: _invoke(restart, context),
                    timeout=self.deadline,
                    cancel=context.cancel,
                )
                if status != "ok":
                    raise ProtocolError(f"race restart failed after attempt {index}: {error}")
        return RaceResult(False, None, tuple(attempts))

    def execute(self, runtime: Any) -> RaceResult:
        tube = runtime.tube
        if isinstance(tube, ReplayTube):
            encoded = tube.consume_opaque(self.identity, self.input_digest)
            try:
                decoded = _decode(encoded)
                if not isinstance(decoded, dict):
                    raise TypeError("result must be an object")
                result = RaceResult.from_dict(decoded)
            except (ProtocolError, ValueError, TypeError, KeyError) as error:
                raise ProtocolError("recorded race result is malformed") from error
        else:
            trace = runtime.trace
            if trace is not None:
                trace.append(
                    "opaque_start",
                    operation=self.identity,
                    details={
                        "name": self.describe(),
                        "inputs_sha256": self.input_digest,
                    },
                )
            result = self._live()
            if trace is not None:
                buffered = getattr(tube, "buffered_bytes", b"")
                trace.append(
                    "opaque",
                    json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":")).encode(),
                    operation=self.identity,
                    details={
                        "name": self.describe(),
                        "inputs_sha256": self.input_digest,
                        "buffered_base64": base64.b64encode(buffered).decode("ascii"),
                    },
                )
        invalidator = getattr(runtime.context, "invalidate", None)
        if callable(invalidator) and self.invalidates:
            invalidator(*self.invalidates)
        if self.target is not None and result.won:
            runtime.bind(self.target, result.to_dict(), source=result.describe())
        return result
