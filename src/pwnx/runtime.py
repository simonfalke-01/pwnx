"""Interpreter for compiled plans with scoped facts and event recording."""

from __future__ import annotations

import asyncio
import base64
import builtins
import hashlib
import inspect
import json
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .actions import (
    Action,
    Bind,
    Branch,
    Capture,
    Check,
    Delay,
    Emit,
    Encoded,
    Expect,
    Sequence,
    action_executor,
)
from .challenge import Opaque
from .bytecraft import PayloadArtifact, artifact_from_emission
from .domain import (
    Capability,
    Constraint,
    Fact,
    Scope,
    canonical_invalidations,
    requirement_satisfied,
)
from .errors import (
    ConstraintError,
    PlanningError,
    ProtocolError,
    ReplayDivergence,
    StaleValueError,
    UnresolvedValueError,
    UnsupportedFeature,
)
from .expressions import BindingContext, Expr
from .formats import FormatOffsetDiscovery
from .memory import DynResolver, Resolution, ResolveMemorySymbol
from .payload import Payload
from .trace import RecordingTube, ReplayTube, Trace
from .transport import (
    DatagramTube,
    ListenerTube,
    ProcessTube,
    SerialTube,
    SocketTube,
)


_ENVIRONMENT_OPENERS: dict[str, Any] = {}


def register_environment_adapter(name: str, opener) -> None:
    if name in _ENVIRONMENT_OPENERS:
        raise ValueError(f"environment adapter {name!r} is already registered")
    _ENVIRONMENT_OPENERS[name] = opener


def _open_process_target(target):
    return ProcessTube(
        target.argv,
        env=target.env,
        cwd=target.cwd,
    )


def _open_supported_process_target(target):
    unsupported = tuple(item for item in target.evidence if item.startswith("unsupported:"))
    if unsupported:
        raise UnsupportedFeature("; ".join(unsupported))
    return _open_process_target(target)


def _open_tcp_target(target):
    if target.endpoint is None:
        raise PlanningError("TCP target has no endpoint")
    return SocketTube(
        target.endpoint[0],
        target.endpoint[1],
        tls=bool(target.options.get("tls", False)),
    )


def _open_serial_target(target):
    return SerialTube(
        target.options["device"],
        baud=int(target.options["baud"]),
    )


for _adapter in ("local-process", "qemu-user", "ssh-process"):
    _ENVIRONMENT_OPENERS[_adapter] = _open_process_target
for _adapter in (
    "adb-process",
    "wine-process",
    "windows-process",
    "cdb-debugger",
    "kernel-vm",
):
    _ENVIRONMENT_OPENERS[_adapter] = _open_supported_process_target
for _adapter in ("tcp", "tls"):
    _ENVIRONMENT_OPENERS[_adapter] = _open_tcp_target
_ENVIRONMENT_OPENERS["serial"] = _open_serial_target


def _value(data: Any, context: BindingContext) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, Payload):
        return data.build(context)
    if isinstance(data, Encoded):
        return data.build(context.resolve)
    build = getattr(data, "build", None)
    if callable(build):
        value = build(context)
        if isinstance(value, bytes):
            return value
    raise TypeError(f"cannot send {type(data).__name__}; expected bytes or compilable payload")


@dataclass
class Run:
    plan: Any
    tube: Any
    context: BindingContext
    trace: Trace | None = None
    trace_path: Path | None = None
    capabilities: list[Capability] = field(default_factory=list)
    _payload_artifacts: list[PayloadArtifact] = field(
        default_factory=list,
        repr=False,
    )
    _closed: bool = False

    def fact(self, expression: Expr):
        return self.context.resolved(expression)

    def value(self, expression):
        return self.context.resolve(expression)

    def bytes(self, payload):
        return _value(payload, self.context)

    def payload(self, name=-1):
        artifacts = self.payloads()
        if isinstance(name, int):
            return artifacts[name]
        for item in artifacts:
            if name in {item.name, item.id, item.stage}:
                return item
        raise PlanningError(f"run has no payload named {name!r}")

    def payloads(self) -> tuple[PayloadArtifact, ...]:
        return tuple(self._payload_artifacts)

    def explain(self, expression):
        return self.context.explain(expression)

    def interactive(self):
        self.tube.interactive()

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.tube.close()
        finally:
            listener = getattr(self.tube, "_pwnx_listener", None)
            if listener is not None:
                listener.close()
            if self.trace is not None and self.trace_path is not None:
                self.trace.save(self.trace_path)

    @property
    def maps(self):
        tube = getattr(self.tube, "tube", self.tube)
        method = getattr(tube, "maps", None)
        if method is None:
            raise UnsupportedFeature("memory maps are only available for local processes")
        return method()

    @property
    def libs(self):
        tube = getattr(self.tube, "tube", self.tube)
        method = getattr(tube, "libs", None)
        if method is None:
            raise UnsupportedFeature("loaded libraries are only available for local processes")
        return method()

    def read_memory(self, address: int, size: int) -> builtins.bytes:
        tube = getattr(self.tube, "tube", self.tube)
        method = getattr(tube, "read_memory", None)
        if method is None:
            raise UnsupportedFeature("memory reads are only available for local processes")
        return method(address, size)

    def write_memory(self, address: int, data: builtins.bytes) -> None:
        tube = getattr(self.tube, "tube", self.tube)
        method = getattr(tube, "write_memory", None)
        if method is None:
            raise UnsupportedFeature("memory writes are only available for local processes")
        method(address, data)

    def memory_oracle(self, *, max_read=0x1000, max_total=0x100000):
        from .memory import MemoryOracle

        return MemoryOracle(
            self.read_memory,
            instance_id=self.context.instance_id or "local-process",
            max_read=max_read,
            max_total=max_total,
            name="local process memory",
        )

    def attach_gdb(
        self,
        *,
        commands=(),
        debugger="gdb",
        wait=False,
    ):
        if isinstance(self.tube, ReplayTube):
            raise UnsupportedFeature("debugger attachment cannot run during replay")
        tube = getattr(self.tube, "tube", self.tube)
        pid = getattr(tube, "pid", None)
        if pid is None:
            raise UnsupportedFeature("GDB attachment requires a local process")
        executable = shutil.which(debugger)
        if executable is None:
            raise UnsupportedFeature(f"debugger {debugger!r} is not installed")
        argv = [executable, "-q", "-p", str(pid)]
        for command in commands:
            argv.extend(("-ex", str(command)))
        process = subprocess.Popen(argv)
        if self.trace is not None:
            self.trace.metadata.setdefault("debugger", []).append({"argv": argv, "pid": pid})
        if wait:
            process.wait()
        return process

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Interpreter:
    def __init__(self, run: Run):
        self.run = run
        self.challenge = run.plan.challenge

    def derive(self):
        pending = list(self.challenge._derivations)
        progress = True
        while pending and progress:
            progress = False
            for item in pending[:]:
                try:
                    values = [self.run.context.resolve(value) for value in item.inputs]
                except (UnresolvedValueError, StaleValueError):
                    continue
                value = item.function(*values)
                self.run.context.bind(item.target, value, source="pure derivation")
                self._record_fact(item.target, value, "pure derivation", kind="derive")
                pending.remove(item)
                progress = True

    def execute(self, action):
        if isinstance(action, (Sequence, Branch)):
            return self._execute_raw(action)
        if not isinstance(action, Action):
            raise UnsupportedAction(type(action).__name__)
        contract = action.contract()
        self._validate_contract(action, contract)
        checkpoint = self.run.context.checkpoint()
        capability_checkpoint = list(self.run.capabilities)
        invalidations = canonical_invalidations(contract.invalidates)
        replacement_names = self._replacement_names(
            contract.provides,
            invalidations,
        )
        self.run.context.allow_replacements(replacement_names)
        try:
            result = self._execute_raw(action)
            self._collect_capabilities(result)
        except BaseException as error:
            self._rollback_contract_state(checkpoint, capability_checkpoint)
            self._record_contract_failure(
                action,
                "execution",
                error,
                external_effect_status="unknown",
            )
            raise
        finally:
            self.run.context.finish_replacements()

        try:
            product_snapshot = self._capture_products(
                action,
                contract.provides,
                checkpoint=checkpoint,
                required_replacements=replacement_names,
            )
        except BaseException as error:
            self._rollback_contract_state(checkpoint, capability_checkpoint)
            self._record_contract_failure(
                action,
                "product-validation",
                error,
                external_effect_status="completed",
            )
            raise ConstraintError(
                f"{action.describe()} completed execution but did not satisfy its "
                "declared products; fact state was rolled back, external effects "
                "cannot be rolled back"
            ) from error

        try:
            self._apply_invalidations(invalidations)
            self.run.context.restore(product_snapshot)
            self._verify_products(action, contract.provides)
        except BaseException as error:
            self._rollback_contract_state(checkpoint, capability_checkpoint)
            self._record_contract_failure(
                action,
                "commit",
                error,
                external_effect_status="completed",
            )
            raise ConstraintError(
                f"{action.describe()} completed execution but its fact transaction "
                "could not commit; fact state was rolled back, external effects "
                "cannot be rolled back"
            ) from error
        return result

    def _rollback_contract_state(
        self,
        checkpoint: Any,
        capabilities: list[Capability],
    ) -> None:
        self.run.context.rollback(checkpoint)
        self.run.capabilities[:] = capabilities

    def _replacement_names(self, products, invalidations) -> tuple[str, ...]:
        names: set[str] = set()
        for product in products:
            expression = product.expr() if isinstance(product, Fact) else product
            if not isinstance(expression, Expr):
                continue
            for invalidation in invalidations:
                if isinstance(invalidation, Fact):
                    if expression.is_fact and expression.name == invalidation.name:
                        names.update(expression.dependencies)
                elif isinstance(invalidation, Expr):
                    names.update(expression.dependencies & invalidation.dependencies)
                elif isinstance(invalidation, Scope):
                    if expression.scope == invalidation.value:
                        names.update(expression.dependencies)
                elif isinstance(invalidation, str):
                    if invalidation in {"artifact", "service", "process", "connection"}:
                        if expression.scope == invalidation:
                            names.update(expression.dependencies)
                    else:
                        names.update(
                            name
                            for name in expression.dependencies
                            if name == invalidation or name.startswith(invalidation + ".")
                        )
        return tuple(sorted(names))

    def _capture_products(
        self,
        action: Action,
        products,
        *,
        checkpoint,
        required_replacements,
    ) -> dict[str, Any]:
        self._verify_products(action, products)
        expressions = tuple(
            product.expr() if isinstance(product, Fact) else product
            for product in products
            if isinstance(product, (Fact, Expr))
        )
        snapshot = self.run.context.snapshot_expressions(expressions)
        if required_replacements and not self.run.context.was_written_since(
            checkpoint,
            required_replacements,
        ):
            raise ConstraintError(
                f"{action.describe()} provides and invalidates the same fact but "
                "did not explicitly rebind it during this execution"
            )
        return snapshot

    def _record_contract_failure(
        self,
        action: Action,
        phase: str,
        error: BaseException,
        *,
        external_effect_status: str,
    ) -> None:
        if self.run.trace is None:
            return
        self.run.trace.metadata.setdefault("contract_failures", []).append(
            {
                "action": action.describe(),
                "phase": phase,
                "error": f"{type(error).__name__}: {error}",
                "external_effect_status": external_effect_status,
                "fact_state": "rolled-back",
            }
        )

    def _validate_contract(self, action: Action, contract) -> None:
        runtime = ActionRuntime(self)
        for requirement in contract.requires:
            if isinstance(requirement, Fact):
                self.run.context.resolve(requirement.expr())
            elif isinstance(requirement, Expr):
                self.run.context.resolve(requirement)
            elif isinstance(requirement, Capability):
                if not any(
                    requirement_satisfied(available, requirement)
                    for available in self.run.capabilities
                ):
                    raise ConstraintError(
                        f"{action.describe()} requires unsatisfied capability {requirement.name!r}"
                    )
            else:
                raise ConstraintError(
                    f"{action.describe()} declares unsupported requirement {requirement!r}"
                )
        values = {
            "action": action,
            "runtime": runtime,
            "challenge": self.challenge,
            "facts": self.run.context.bound_keys,
            "capabilities": tuple(self.run.capabilities),
            "reads": contract.reads,
            "writes": contract.writes,
        }
        for constraint in contract.constraints:
            if not isinstance(constraint, Constraint):
                raise ConstraintError(f"{action.describe()} has invalid constraint {constraint!r}")
            if not constraint.check(values):
                detail = f": {constraint.explanation}" if constraint.explanation else ""
                raise ConstraintError(
                    f"{action.describe()} violates constraint {constraint.name!r}{detail}"
                )

    def _apply_invalidations(self, invalidations) -> None:
        values: list[Expr | str] = []
        for value in invalidations:
            if isinstance(value, Fact):
                values.append(value.expr())
            elif isinstance(value, Scope):
                values.append(value.value)
            elif isinstance(value, (Expr, str)):
                values.append(value)
            else:
                raise ConstraintError(f"unsupported action invalidation {value!r}")
        if values:
            self.run.context.invalidate(*values)

    def _collect_capabilities(self, result: Any) -> None:
        values = result if isinstance(result, (tuple, list)) else (result,)
        for value in values:
            if not isinstance(value, Capability):
                continue
            if not any(
                requirement_satisfied(available, value) for available in self.run.capabilities
            ):
                self.run.capabilities.append(value)

    def _verify_products(self, action: Action, products) -> None:
        for product in products:
            if isinstance(product, Fact):
                if not self.run.context.has(product.expr()):
                    raise ConstraintError(
                        f"{action.describe()} did not bind declared fact {product.name!r}"
                    )
            elif isinstance(product, Expr):
                if not self.run.context.has(product):
                    raise ConstraintError(
                        f"{action.describe()} did not bind declared product {product.describe()}"
                    )
            elif isinstance(product, Capability):
                if not any(
                    requirement_satisfied(available, product) for available in self.run.capabilities
                ):
                    raise ConstraintError(
                        f"{action.describe()} did not provide declared capability {product.name!r}"
                    )
            else:
                raise ConstraintError(
                    f"{action.describe()} declares unsupported product {product!r}"
                )

    def _execute_raw(self, action):
        if isinstance(action, Sequence):
            result = None
            for child in action.actions:
                result = self.execute(child)
            return result
        if isinstance(action, Emit):
            if action.channel.prompt:
                if self._message_oriented():
                    received, _peer = self.run.tube.recv_datagram(
                        action.channel.max_receive,
                        timeout=action.channel.timeout,
                    )
                    if action.channel.prompt not in received:
                        raise ProtocolError(
                            f"datagram did not contain prompt {action.channel.prompt!r}"
                        )
                else:
                    self.run.tube.read_until(
                        action.channel.prompt,
                        timeout=action.channel.timeout,
                        max_bytes=action.channel.max_receive,
                    )
            payload_bytes = _value(action.data, self.run.context)
            raw = action.channel.encode(payload_bytes)
            descriptor = self.run.plan.payload_descriptor(action)
            artifact = (
                artifact_from_emission(
                    descriptor,
                    payload_bytes,
                    self.run.context,
                )
                if descriptor is not None
                else None
            )
            if self._message_oriented():
                self.run.tube.send_datagram(raw, timeout=action.channel.timeout)
            else:
                self.run.tube.send(raw, timeout=action.channel.timeout)
            if artifact is not None:
                self.run._payload_artifacts.append(artifact)
                if self.run.trace is not None:
                    metadata = artifact.to_dict()
                    metadata["description"] = action.describe()
                    self.run.trace.metadata.setdefault("payloads", []).append(
                        metadata
                    )
            return raw
        if isinstance(action, Expect):
            if self._message_oriented():
                received, _peer = self.run.tube.recv_datagram(
                    action.max_bytes, timeout=action.timeout
                )
                if action.delimiter not in received:
                    raise ProtocolError(f"datagram did not contain expected {action.delimiter!r}")
                return received
            return self.run.tube.read_until(
                action.delimiter, timeout=action.timeout, max_bytes=action.max_bytes
            )
        if isinstance(action, Delay):
            if not isinstance(self.run.tube, ReplayTube):
                time.sleep(action.seconds)
            return None
        if isinstance(action, FormatOffsetDiscovery):
            marker_value = int.from_bytes(action.marker, "little")
            expected = f"0x{marker_value:x}".encode()
            for position in range(action.start, action.stop):
                if action.channel.prompt:
                    self.run.tube.read_until(
                        action.channel.prompt,
                        timeout=action.channel.timeout,
                        max_bytes=action.channel.max_receive,
                    )
                probe = action.marker + f".%{position}$p".encode()
                self.run.tube.send(
                    action.channel.encode(probe),
                    timeout=action.channel.timeout,
                )
                response = action.response.read(self.run.tube, timeout=action.channel.timeout)
                if isinstance(response, str):
                    raw_response = response.encode()
                elif isinstance(response, (bytes, bytearray, memoryview)):
                    raw_response = bytes(response)
                else:
                    raise ProtocolError(
                        "format discovery response codec must return bytes or str, "
                        f"got {type(response).__name__}"
                    )
                if expected in raw_response.lower():
                    self.run.context.bind(
                        action.target,
                        position,
                        source=f"format discovery probe {position}",
                    )
                    self._record_fact(
                        action.target,
                        position,
                        f"format discovery probe {position}",
                        kind="discover",
                    )
                    return position
            raise ProtocolError(
                f"controlled format argument was not found in positions "
                f"{action.start}..{action.stop - 1}"
            )
        if isinstance(action, ResolveMemorySymbol):
            pointer = self.run.context.resolve(action.pointer)
            local_hash = getattr(action.local_image, "sha256", "")
            input_digest = hashlib.sha256(
                _opaque_encode(
                    {
                        "pointer": pointer,
                        "symbol": action.symbol,
                        "module": action.module,
                        "local_image": local_hash,
                        "oracle": action.oracle.identity,
                    }
                )
            ).hexdigest()
            if isinstance(self.run.tube, ReplayTube):
                recorded = _opaque_decode(
                    self.run.tube.consume_opaque(action.identity, input_digest)
                )
                resolution = Resolution(
                    recorded["module"],
                    recorded["base"],
                    recorded["symbol"],
                    recorded["address"],
                    recorded["hash_style"],
                    recorded["backend_reads"],
                    tuple(recorded["evidence"]),
                )
            else:
                if action.bind_runtime_instance:
                    action.oracle.rebind(self.run.context.instance_id or action.oracle.instance_id)
                if self.run.trace is not None:
                    self.run.trace.append(
                        "opaque_start",
                        operation=action.identity,
                        details={
                            "name": action.describe(),
                            "inputs_sha256": input_digest,
                        },
                    )
                resolution = DynResolver(
                    action.oracle,
                    pointer,
                    local_image=action.local_image,
                ).lookup(action.symbol, module=action.module)
                if self.run.trace is not None:
                    buffered = getattr(self.run.tube, "buffered_bytes", b"")
                    self.run.trace.append(
                        "opaque",
                        _opaque_encode(
                            {
                                "module": resolution.module,
                                "base": resolution.base,
                                "symbol": resolution.symbol,
                                "address": resolution.address,
                                "hash_style": resolution.hash_style,
                                "backend_reads": resolution.backend_reads,
                                "evidence": list(resolution.evidence),
                            }
                        ),
                        operation=action.identity,
                        details={
                            "name": action.describe(),
                            "inputs_sha256": input_digest,
                            "buffered_base64": base64.b64encode(buffered).decode("ascii"),
                        },
                    )
            self.run.context.bind(
                action.target,
                resolution.address,
                source=resolution.describe(),
            )
            self._record_fact(
                action.target,
                resolution.address,
                resolution.describe(),
                kind="dynelf",
            )
            if self.run.trace is not None:
                self.run.trace.metadata.setdefault("memory_resolutions", []).append(
                    {
                        "symbol": resolution.symbol,
                        "module": resolution.module,
                        "base": resolution.base,
                        "address": resolution.address,
                        "hash_style": resolution.hash_style,
                        "backend_reads": resolution.backend_reads,
                        "evidence": list(resolution.evidence),
                    }
                )
            return resolution
        if isinstance(action, Capture):
            if self._message_oriented():
                received, _peer = self.run.tube.recv_datagram()
                value = action.codec.parse(received)
            else:
                value = action.codec.read(self.run.tube)
            self.run.context.bind(action.output, value, source=action.name)
            self._record_fact(action.output, value, action.name, kind="capture")
            self.derive()
            return value
        if isinstance(action, Bind):
            value = self.run.context.resolve(action.value)
            self.run.context.bind(action.target, value, source="planned bind")
            self._record_fact(action.target, value, "planned bind", kind="bind")
            self.derive()
            return value
        if isinstance(action, Check):
            passed = bool(self.run.context.resolve(action.predicate))
            if self.run.trace is not None:
                self.run.trace.metadata.setdefault("validations", []).append(
                    {
                        "predicate": action.predicate.describe(),
                        "passed": passed,
                        "message": action.message,
                    }
                )
            if not passed:
                raise ConstraintError(action.message)
            return True
        if isinstance(action, Branch):
            selected = (
                action.then if self.run.context.resolve(action.predicate) else action.otherwise
            )
            return self.execute(selected)
        if isinstance(action, Opaque):
            values = {
                expression.key: self.run.context.resolve(expression)
                for expression in action.consumes
            }
            encoded_inputs = _opaque_encode(values)
            input_digest = hashlib.sha256(encoded_inputs).hexdigest()
            if isinstance(self.run.tube, ReplayTube):
                result = _opaque_decode(self.run.tube.consume_opaque(action.identity, input_digest))
            else:
                if self.run.trace is not None:
                    self.run.trace.append(
                        "opaque_start",
                        operation=action.identity,
                        details={
                            "name": action.name,
                            "inputs_sha256": input_digest,
                        },
                    )
                result = action.function(self.run.tube, values)
                if inspect.isawaitable(result):
                    result = asyncio.run(_await_value(result))
                if self.run.trace is not None:
                    buffered = getattr(self.run.tube, "buffered_bytes", b"")
                    self.run.trace.append(
                        "opaque",
                        _opaque_encode(result),
                        operation=action.identity,
                        details={
                            "name": action.name,
                            "inputs_sha256": input_digest,
                            "buffered_base64": base64.b64encode(buffered).decode("ascii"),
                        },
                    )
            values_out: tuple[Any, ...]
            if not action.produces:
                values_out = ()
            elif len(action.produces) == 1:
                values_out = (result,)
            elif isinstance(result, dict):
                values_out = tuple(result[target.key] for target in action.produces)
            else:
                values_out = tuple(result)
            if len(values_out) != len(action.produces):
                raise ConstraintError(
                    f"{action.name} returned {len(values_out)} values for "
                    f"{len(action.produces)} declared facts"
                )
            for target, value in zip(action.produces, values_out, strict=True):
                self.run.context.bind(target, value, source=action.name)
                self._record_fact(target, value, action.name, kind="opaque")
            self.derive()
            return result
        if isinstance(action, Action):
            result = action.execute(ActionRuntime(self))
            if result is not NotImplemented:
                return result
            executor = action_executor(action)
            if executor is not None:
                return executor(action, ActionRuntime(self))
        raise UnsupportedAction(type(action).__name__)

    def _message_oriented(self) -> bool:
        underlying = getattr(self.run.tube, "tube", self.run.tube)
        return bool(getattr(underlying, "message_oriented", False))

    def _record_fact(self, target, value, source, *, kind):
        if self.run.trace is None:
            return
        self.run.trace.metadata.setdefault("facts", []).append(
            {
                "kind": kind,
                "fact": target.describe(),
                "key": target.key,
                "value": _opaque_json(value),
                "source": source,
                "instance": self.run.context.instance_id,
            }
        )


class UnsupportedAction(PlanningError):
    pass


class ActionRuntime:
    """Stable runtime facade for plugin actions."""

    def __init__(self, interpreter: Interpreter) -> None:
        self._interpreter = interpreter

    @property
    def tube(self):
        return self._interpreter.run.tube

    @property
    def trace(self):
        return self._interpreter.run.trace

    @property
    def context(self):
        return self._interpreter.run.context

    def resolve(self, value):
        return self.context.resolve(value)

    def bind(self, target, value, *, source="plugin action", kind="plugin"):
        self.context.bind(target, value, source=source)
        self._interpreter._record_fact(target, value, source, kind=kind)
        self._interpreter.derive()
        return value

    def provide(self, capability: Capability) -> Capability:
        if not isinstance(capability, Capability):
            raise TypeError("provide() requires a Capability")
        self._interpreter._collect_capabilities(capability)
        return capability


def _opaque_json(value):
    if isinstance(value, bytes):
        return {"__pwnx_bytes__": base64.b64encode(value).decode("ascii")}
    if isinstance(value, tuple):
        return {"__pwnx_tuple__": [_opaque_json(item) for item in value]}
    if isinstance(value, list):
        return [_opaque_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _opaque_json(item) for key, item in value.items()}
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return {
            "__pwnx_type__": type(value).__qualname__,
            "value": _opaque_json(to_dict()),
        }
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise ConstraintError(
        f"opaque actions must return portable JSON values or bytes, got {type(value).__name__}"
    )


def _opaque_from_json(value):
    if isinstance(value, dict) and set(value) == {"__pwnx_bytes__"}:
        return base64.b64decode(value["__pwnx_bytes__"], validate=True)
    if isinstance(value, dict) and set(value) == {"__pwnx_tuple__"}:
        return tuple(_opaque_from_json(item) for item in value["__pwnx_tuple__"])
    if isinstance(value, dict):
        return {key: _opaque_from_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_opaque_from_json(item) for item in value]
    return value


def _opaque_encode(value) -> bytes:
    return json.dumps(
        _opaque_json(value), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _opaque_decode(data: bytes):
    try:
        return _opaque_from_json(json.loads(data.decode("utf-8")))
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        raise ConstraintError("recorded opaque result is malformed") from error


async def _await_value(awaitable):
    return await awaitable


def execute(
    plan,
    *,
    profile="local",
    trace=None,
    transport=None,
    replay=None,
    on=None,
) -> Run:
    challenge = plan.challenge
    if transport is not None and on is not None:
        raise ValueError("transport and target recipe are mutually exclusive")
    materialized = None
    if on is not None:
        recipe = challenge.target_recipes[on] if isinstance(on, str) else on
        materializer = getattr(recipe, "materialize", None)
        if not callable(materializer):
            raise TypeError("on= requires a TargetRecipe or registered recipe name")
        materialized = materializer(epoch_seed=uuid.uuid4().hex)
    tube: Any
    if replay is not None:
        ledger = replay if isinstance(replay, Trace) else Trace.load(replay)
        recorded_artifacts = ledger.metadata.get("artifacts", {})
        for image in challenge.images:
            recorded = recorded_artifacts.get(image.name)
            if recorded is None:
                raise ReplayDivergence(f"trace has no artifact identity for {image.name!r}")
            if recorded.get("sha256") != image.sha256:
                raise ReplayDivergence(
                    f"artifact {image.name!r} changed: recorded "
                    f"{recorded.get('sha256')}, current {image.sha256}"
                )
        if challenge.loader is not None:
            loader_path = Path(challenge.loader)
            loader_digest = hashlib.sha256(loader_path.read_bytes()).hexdigest()
            recorded = recorded_artifacts.get("loader")
            if recorded is None or recorded.get("sha256") != loader_digest:
                raise ReplayDivergence("loader artifact changed or is absent from the trace")
        recorded_target = ledger.metadata.get("target")
        if isinstance(recorded_target, dict) and recorded_target.get("identity"):
            if materialized is None:
                raise ReplayDivergence(
                    "trace was recorded with a target recipe; replay requires matching on="
                )
        if materialized is not None:
            recorded_target = recorded_target or {}
            if recorded_target.get("identity") != materialized.identity:
                raise ReplayDivergence("target recipe identity changed since the recording")
        tube = ReplayTube(ledger)
        run_trace = None
        instance = (
            materialized.epochs.process
            if materialized is not None
            else f"replay:{ledger.metadata.get('instance', 'recorded')}"
        )
    else:
        selected: Any = None
        if materialized is not None:
            try:
                opener = _ENVIRONMENT_OPENERS[materialized.adapter]
            except KeyError as error:
                raise UnsupportedFeature(
                    f"no runtime adapter is registered for {materialized.adapter!r}"
                ) from error
            tube = opener(materialized)
            selected = None
        elif profile not in challenge.profiles:
            raise PlanningError(f"unknown profile {profile!r}")
        else:
            selected = challenge.profiles[profile]
        if transport is not None:
            tube = transport
        elif materialized is not None:
            pass
        elif selected.kind in {"local", "debug"}:
            argv = selected.argv
            if selected.kind == "debug":
                argv = selected.debugger + selected.argv
            tube = ProcessTube(argv, env=selected.env, cwd=selected.cwd, timeout=selected.timeout)
        elif selected.kind == "remote":
            tube = SocketTube(
                selected.host, selected.port, timeout=selected.timeout, tls=selected.tls
            )
        elif selected.kind == "udp":
            tube = DatagramTube(
                selected.host,
                selected.port,
                timeout=selected.timeout,
            )
        elif selected.kind == "listen":
            listener = ListenerTube(
                selected.host or "127.0.0.1",
                selected.port or 0,
                backlog=selected.options.get("backlog", 1),
                timeout=selected.timeout,
            )
            tube = listener.accept(timeout=selected.timeout)
            setattr(tube, "_pwnx_listener", listener)
        elif selected.kind == "serial":
            tube = SerialTube(
                selected.options["device"],
                baud=selected.options["baud"],
                timeout=selected.timeout,
            )
        else:
            raise PlanningError(f"unsupported profile kind {selected.kind!r}")
        if trace is not None and not isinstance(trace, (Trace, str, Path)):
            raise TypeError("trace must be a Trace or filesystem path")
        trace_path = Path(trace) if isinstance(trace, (str, Path)) else None
        run_trace = trace if isinstance(trace, Trace) else Trace()
        run_trace.metadata.setdefault(
            "profile", materialized.adapter if materialized is not None else profile
        )
        run_trace.metadata.setdefault("instance", uuid.uuid4().hex)
        run_trace.metadata.setdefault("plan", plan.to_dict())
        if materialized is not None:
            run_trace.metadata.setdefault(
                "target",
                {
                    "identity": materialized.identity,
                    "adapter": materialized.adapter,
                    "architecture": materialized.architecture.as_dict(),
                    "argv": list(materialized.argv),
                    "endpoint": materialized.endpoint,
                    "lifecycle": {
                        "service": materialized.lifecycle.service,
                        "process": materialized.lifecycle.process,
                        "connection": materialized.lifecycle.connection,
                    },
                    "epochs": {
                        "service": materialized.epochs.service,
                        "process": materialized.epochs.process,
                        "connection": materialized.epochs.connection,
                    },
                    "artifacts": [
                        {
                            "role": item.role,
                            "path": item.path,
                            "sha256": item.sha256,
                            "size": item.size,
                        }
                        for item in materialized.artifacts
                    ],
                },
            )
        else:
            run_trace.metadata.setdefault(
                "launch",
                {
                    "kind": selected.kind,
                    "argv": list(selected.argv),
                    "host": selected.host,
                    "port": selected.port,
                    "tls": selected.tls,
                    "options": selected.options,
                },
            )
        for image in challenge.images:
            artifacts = run_trace.metadata.get("artifacts", {})
            if image.name not in artifacts:
                run_trace.add_artifact(image.name, image.path)
        if materialized is not None:
            for artifact in materialized.artifacts:
                artifacts = run_trace.metadata.get("artifacts", {})
                key = f"target:{artifact.role}"
                if key not in artifacts:
                    run_trace.add_artifact(key, artifact.path)
        if challenge.loader is not None:
            artifacts = run_trace.metadata.get("artifacts", {})
            if "loader" not in artifacts:
                run_trace.add_artifact("loader", challenge.loader)
        tube = RecordingTube(tube, run_trace)
        instance = (
            materialized.epochs.process
            if materialized is not None
            else f"{profile}:{run_trace.metadata['instance']}"
        )

    if materialized is not None:
        context = BindingContext(
            service_id=materialized.epochs.service,
            process_id=materialized.epochs.process,
            connection_id=materialized.epochs.connection,
        )
    else:
        context = BindingContext(instance_id=instance)
    for expression, value, reason in challenge._assumptions:
        context.bind(expression, value, source=reason)
    run = Run(
        plan,
        tube,
        context,
        run_trace,
        trace_path if replay is None else None,
        list(challenge.capabilities),
    )
    interpreter = Interpreter(run)
    if run.trace is not None:
        for expression, value, reason in challenge._assumptions:
            interpreter._record_fact(expression, value, reason, kind="assume")
    interpreter.derive()
    try:
        for action in plan.actions:
            interpreter.execute(action)
    except BaseException:
        try:
            run.close()
        except BaseException:
            pass
        raise
    return run
