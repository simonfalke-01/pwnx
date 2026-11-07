"""Public declarative authoring API; declaration methods never perform target I/O."""

from __future__ import annotations

import contextvars
import hashlib
import inspect
import json
import re
import shutil
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import CodeType
from typing import Any, Callable, Literal, Mapping, cast

from .actions import Action, Bind, Capture, Emit, Encoded, Expect
from .artifacts import Image
from .channels import Channel, line
from .domain import (
    Capability,
    EffectContract,
    Environment,
    Evidence,
    Fact,
    Scope,
    Sort,
)
from .domain import TargetRecipe as TargetManifest
from .errors import (
    ConstraintError,
    PlanningError,
    RetryableInstanceError,
    UnsupportedFeature,
)
from .expressions import Expr, as_expr
from .patterns import Pattern, template
from .providers import GoalRequest, ProviderRegistry


# The CLI collects a normal Python solve without allowing c.run() to connect.
_collect: contextvars.ContextVar[list | None] = contextvars.ContextVar("pwnx_collect", default=None)


def _stable_callable_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, Expr):
        return {
            "expr": value.key,
            "scope": value.scope,
            "kind": value.kind,
            "space": value.space,
        }
    if isinstance(value, Fact):
        return {
            "fact": value.name,
            "sort": _stable_callable_value(value.sort.semantic_identity),
            "scope": value.scope.value,
            "artifact": value.artifact,
        }
    if isinstance(value, Sort):
        return {
            "sort": value.name,
            "identity": _stable_callable_value(value.semantic_identity),
        }
    if isinstance(value, Scope):
        return {"scope": value.value}
    if isinstance(value, CodeType):
        return {
            "code": value.co_code.hex(),
            "constants": [_stable_callable_value(item) for item in value.co_consts],
            "names": list(value.co_names),
            "variables": list(value.co_varnames),
        }
    if isinstance(value, (tuple, list)):
        return [_stable_callable_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        encoded = [_stable_callable_value(item) for item in value]
        return sorted(encoded, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, Mapping):
        return {
            str(key): _stable_callable_value(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }
    raise TypeError(
        f"unsupported callable state {type(value).__name__}; pass semantic_id= "
        "to declare a stable boundary identity"
    )


def _callable_semantic_identity(function: Callable, semantic_id: str | None = None) -> str:
    if semantic_id is not None:
        if not semantic_id:
            raise ValueError("semantic_id cannot be empty")
        material: Any = {"explicit": semantic_id}
    else:
        closure = tuple(
            cell.cell_contents for cell in (function.__closure__ or ())
        )
        material = {
            "module": function.__module__,
            "qualname": function.__qualname__,
            "code": _stable_callable_value(function.__code__),
            "defaults": _stable_callable_value(function.__defaults__),
            "kwdefaults": _stable_callable_value(function.__kwdefaults__),
            "closure": _stable_callable_value(closure),
        }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class Control:
    channel: Channel
    return_at: int
    entry_sp_mod16: int = 0
    fill: bytes = b"A"
    name: str = "overflow"
    protected: tuple["ProtectedWord", ...] = ()

    def __post_init__(self):
        if self.return_at < 0 or not self.fill or len(self.fill) != 1:
            raise ValueError("return_at must be nonnegative and fill must be one byte")
        if self.entry_sp_mod16 not in {0, 8}:
            raise ValueError("AMD64 entry_sp_mod16 must be 0 or 8")
        occupied: list[tuple[int, int, str]] = []
        for item in self.protected:
            if item.offset % 8:
                raise ValueError(f"protected stack word {item.label!r} must be 8-byte aligned")
            if item.offset < 0 or item.offset + 8 > self.return_at:
                raise ValueError(
                    f"protected stack word {item.label!r} at {item.offset:#x} is "
                    f"outside the overflow prefix ending at {self.return_at:#x}"
                )
            for start, end, label in occupied:
                if item.offset < end and start < item.offset + 8:
                    raise ValueError(
                        f"protected stack word {item.label!r} overlaps {label!r}"
                    )
            occupied.append((item.offset, item.offset + 8, item.label))


@dataclass(frozen=True)
class ProtectedWord:
    offset: int
    value: Expr
    label: str = "protected stack word"


@dataclass(frozen=True)
class ControlDeclaration:
    capability: Capability
    implementation: Any

    def describe(self) -> str:
        return self.capability.describe()


@dataclass(frozen=True)
class InputSurface:
    challenge: Any
    channel: Channel
    name: str = "input"

    def return_address(
        self,
        *,
        at: int,
        entry_sp_mod16: int = 0,
        fill: bytes = b"A",
        canary: Any = None,
        canary_at: int | None = None,
        protected: Any = None,
    ) -> ControlDeclaration:
        words: list[ProtectedWord] = []
        if canary is not None:
            if isinstance(canary, tuple):
                if len(canary) != 2 or canary_at is not None:
                    raise TypeError(
                        "pass canary=(offset, expression) or canary=expression, "
                        "canary_at=offset"
                    )
                canary_at, canary = int(canary[0]), canary[1]
            if canary_at is None:
                raise TypeError("canary=expression requires canary_at=offset")
            words.append(ProtectedWord(int(canary_at), as_expr(canary), "stack canary"))
        if protected is not None:
            if isinstance(protected, Mapping):
                if "offset" in protected or "value" in protected:
                    try:
                        words.append(
                            ProtectedWord(
                                int(protected["offset"]),
                                as_expr(protected["value"]),
                                str(protected.get("label", "protected stack word")),
                            )
                        )
                    except KeyError as error:
                        raise TypeError("protected mapping requires offset and value") from error
                else:
                    words.extend(
                        ProtectedWord(int(offset), as_expr(value))
                        for offset, value in protected.items()
                    )
            else:
                for item in protected:
                    if not isinstance(item, tuple) or len(item) not in {2, 3}:
                        raise TypeError(
                            "protected entries require (offset, expression[, label])"
                        )
                    words.append(
                        ProtectedWord(
                            int(item[0]),
                            as_expr(item[1]),
                            str(item[2]) if len(item) == 3 else "protected stack word",
                        )
                    )
        for item in words:
            if item.offset % 8:
                raise PlanningError(
                    f"{item.label} offset {item.offset:#x} must be 8-byte aligned"
                )
            if item.offset < 0 or item.offset + 8 > at:
                raise PlanningError(
                    f"{item.label} at offset {item.offset:#x} overlaps or exceeds "
                    f"the return address at offset {at:#x}"
                )
        ordered = sorted(words, key=lambda item: item.offset)
        for left, right in zip(ordered, ordered[1:]):
            if left.offset + 8 > right.offset:
                raise PlanningError(
                    f"protected stack words {left.label!r} and {right.label!r} overlap"
                )
        implementation = Control(
            self.channel,
            at,
            entry_sp_mod16,
            fill,
            f"{self.name} return-address control",
            tuple(words),
        )
        capability = Capability(
            f"{self.name} controls the return address",
            EffectContract(
                writes=frozenset({"process.control-flow", "process.stack"}),
                scope=Scope.PROCESS,
                evidence=(
                    Evidence(
                        "declared-primitive",
                        f"saved return address at byte offset {at}",
                        self.name,
                    ),
                ),
            ),
            reliability="declared",
            evidence=(
                Evidence(
                    "control",
                    f"return address controlled at offset {at}",
                    self.name,
                ),
            ),
        )
        return ControlDeclaration(capability, implementation)

    def format_leak(
        self,
        payload: bytes | str,
        *,
        after: bytes | str = b"",
        separator: bytes | str | tuple[bytes | str, ...] | None = None,
        description: str | None = None,
        **named_codecs: Any,
    ) -> "LeakNamespace":
        from .actions import sequence
        from .codecs import Codec, bytes_, hex_pointer

        raw = payload.encode("ascii") if isinstance(payload, str) else bytes(payload)
        if not raw or not named_codecs:
            raise ValueError("format_leak requires a payload and at least one named capture")
        matches = tuple(re.finditer(rb"%[0-9]+\$p", raw))
        if len(matches) != len(named_codecs):
            raise PlanningError(
                f"format payload exposes {len(matches)} pointer field(s), but "
                f"{len(named_codecs)} named capture(s) were declared"
            )
        if separator is None:
            delimiters = []
            for index, match in enumerate(matches):
                next_start = matches[index + 1].start() if index + 1 < len(matches) else len(raw)
                literal = raw[match.end() : next_start]
                delimiters.append(literal or (b"\n" if index + 1 == len(matches) else b""))
            if any(not value for value in delimiters):
                raise PlanningError(
                    "cannot infer a delimiter between adjacent format fields; pass separator="
                )
        elif isinstance(separator, tuple):
            delimiters = [value.encode() if isinstance(value, str) else bytes(value) for value in separator]
            if len(delimiters) != len(matches):
                raise PlanningError("separator tuple must contain one delimiter per capture")
        else:
            between = separator.encode() if isinstance(separator, str) else bytes(separator)
            if not between:
                raise ValueError("format leak separator cannot be empty")
            delimiters = [between] * (len(matches) - 1) + [b"\n"]

        leak_id = self.challenge.input.next_leak_id()
        values: dict[str, Expr] = {}
        actions: list[Action] = [Emit(Encoded(bytes_(), raw), self.channel)]
        boundary = after.encode() if isinstance(after, str) else bytes(after)
        if boundary:
            actions.append(Expect(boundary))
        for (name, codec), delimiter in zip(named_codecs.items(), delimiters, strict=True):
            target = Expr.fact(
                f"input.leak.{leak_id}.{name}",
                scope="process",
                kind="address",
                label=name,
            )
            values[name] = target
            selected: Codec[Any]
            if codec == "hex":
                selected = hex_pointer(delimiter=None).until(delimiter)
            elif isinstance(codec, Codec):
                selected = codec.until(delimiter)
            else:
                raise TypeError(
                    f"format leak codec for {name!r} must be 'hex' or a Codec"
                )
            actions.append(Capture(selected, target, f"format leak {name}"))
        names = ", ".join(values)
        raw_exchange = sequence(*actions, name="raw format leak exchange")
        declaration = sequence(
            raw_exchange,
            name=description or f"format leak {names}",
        )
        self.challenge._sequences.append(declaration)
        return LeakNamespace(values, declaration)

    def format_string(self, *, offset, **options) -> ControlDeclaration:
        from .formats import format_string

        implementation = format_string(channel=self.channel, offset=offset, **options)
        capability = Capability(
            f"{self.name} controls a format string",
            EffectContract(
                reads=frozenset({"process.memory", "process.stack"}),
                writes=frozenset({"process.memory"}),
                scope=Scope.PROCESS,
                evidence=(
                    Evidence(
                        "declared-primitive",
                        f"controlled format string offset {offset!r}",
                        self.name,
                    ),
                ),
            ),
            reliability="declared",
        )
        return ControlDeclaration(capability, implementation)


@dataclass(frozen=True)
class LeakNamespace:
    values: Mapping[str, Expr]
    action: Action

    def __getattr__(self, name: str) -> Expr:
        try:
            return self.values[name]
        except KeyError as error:
            raise AttributeError(name) from error


class InputNamespace:
    def __init__(self, challenge: Any):
        self.challenge = challenge
        self._next_leak = 1

    def next_leak_id(self) -> int:
        selected = self._next_leak
        self._next_leak += 1
        return selected

    def line(self, prompt=b"", **options) -> InputSurface:
        return InputSurface(self.challenge, line(prompt, **options), "line input")

    def raw(self, prompt=b"", **options) -> InputSurface:
        from .channels import raw

        return InputSurface(self.challenge, raw(prompt, **options), "raw input")


@dataclass(frozen=True)
class Observation(Action):
    pattern: Pattern
    source: Any = None
    timeout: float = 3
    max_bytes: int = 1048576

    def __post_init__(self) -> None:
        if not isinstance(self.pattern, Pattern):
            raise TypeError("observation pattern must be a Pattern")
        if self.timeout <= 0:
            raise ValueError("observation timeout must be positive")
        if self.max_bytes <= 0:
            raise ValueError("observation max_bytes must be positive")

    def describe(self) -> str:
        return (
            f"observe {self.pattern.describe()} "
            f"(timeout {self.timeout:g}s, max {self.max_bytes} bytes)"
        )

    def contract(self) -> EffectContract:
        return EffectContract(
            provides=tuple(field.target for field in self.pattern.fields),
            reads=frozenset({"connection.stream"}),
            writes=frozenset({"connection.cursor", "process.facts"}),
            scope=Scope.CONNECTION,
        )

    def execute(self, runtime: Any):
        bindings, raw = self.pattern.read(
            runtime.tube,
            timeout=self.timeout,
            max_bytes=self.max_bytes,
        )
        for target, value in bindings:
            runtime.bind(
                target,
                value,
                source=f"observation {self.pattern.describe()}",
                kind="observe",
            )
        return raw


@dataclass(frozen=True)
class Learn:
    targets: tuple[Expr, ...]
    using: Any
    receive: Any = None
    resume: Expr | None = None
    via: Control | None = None
    name: str = ""
    cost: int = 0
    requires: tuple[Any, ...] = ()

    @property
    def provides(self):
        return set().union(*(target.dependencies for target in self.targets))


@dataclass(frozen=True)
class Goal:
    effect: Any
    using: Any = None
    via: Control | None = None
    terminal: bool = False


@dataclass(frozen=True)
class Profile:
    kind: str = "local"
    argv: tuple[str, ...] = ()
    host: str | None = None
    port: int | None = None
    tls: bool = False
    env: dict[str, str] | None = None
    cwd: str | None = None
    timeout: float = 3
    debugger: tuple[str, ...] = ("gdb", "-q", "-ex", "run", "--args")
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Derivation:
    target: Expr
    function: Callable
    inputs: tuple[Any, ...]


@dataclass(frozen=True)
class Opaque(Action):
    function: Callable
    consumes: tuple[Expr, ...]
    produces: tuple[Expr, ...]
    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    invalidates: tuple[Any, ...] = ()
    name: str = ""
    identity: str = ""

    def describe(self):
        return f"opaque {self.name} (internals not inspected)"

    def contract(self) -> EffectContract:
        return EffectContract(
            requires=self.consumes,
            provides=self.produces,
            reads=frozenset(self.reads),
            writes=frozenset(self.writes),
            invalidates=self.invalidates,
            scope=Scope.PROCESS,
            evidence=(
                Evidence(
                    "opaque-boundary",
                    f"{self.name} executes user code within its declared effects",
                    self.identity,
                ),
            ),
        )


class Facts:
    def __init__(self, prefix: str):
        self.prefix = prefix

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        return Expr.fact(f"{self.prefix}.{name}")


@dataclass(frozen=True)
class Tactic:
    name: str
    options: dict[str, Any] = field(default_factory=dict)

    def __call__(self, **options):
        return Tactic(self.name, {**self.options, **options})


class TechniqueNames:
    ret2libc = Tactic("rop")
    rop = Tactic("rop")
    dlresolve = Tactic("dlresolve")
    one_gadget = Tactic("one_gadget")


technique = TechniqueNames()


class Challenge:
    def __init__(self, binary: str | Path, *, libc=None, loader=None, timeout=3):
        self.exe = Image(binary, name="exe")
        self.libc = Image(libc, name="libc") if libc is not None else None
        self.loader = str(Path(loader).resolve()) if loader is not None else None
        self.target = self.exe
        from .exploit import HeapNamespace
        from .control_flow import RopNamespace

        self.heap = HeapNamespace(self)
        self.rop = RopNamespace(self)
        self.stack = Facts("stack")
        self.stdout = type("Stdout", (), {"startup": "startup"})()
        self.input = InputNamespace(self)
        self._controls: list[Any] = []
        self._observations: list[Observation] = []
        self._learns: list[Learn] = []
        self._goals: list[Goal] = []
        self._sequences: list[Any] = []
        self._assumptions: list[tuple[Expr, Any, str]] = []
        self._narrative_assumptions: list[str] = []
        self._derivations: list[Derivation] = []
        self._opaque: list[Opaque] = []
        self._plugins: dict[str, Any] = {}
        self._craft_names: set[str] = set()
        self._preferred: list[str] = []
        self._forbidden: set[str] = set()
        self._requirements: dict[str, Any] = {}
        self._attempt_budget = 1
        self.capabilities: list[Capability] = []
        self.providers = ProviderRegistry()
        self.environments: dict[str, Environment] = {}
        self.target_manifests: dict[str, TargetManifest] = {}
        self.target_recipes: dict[str, Any] = {}
        self._default_target_recipe: Any = None
        binary_path = str(Path(binary).resolve())
        if self.loader is not None:
            local_argv = [self.loader]
            if self.libc is not None:
                local_argv.extend(("--library-path", str(Path(self.libc.path).parent)))
            local_argv.append(binary_path)
        else:
            local_argv = [binary_path]
        self._default_argv = tuple(local_argv)
        self.profiles = {"local": Profile(argv=self._default_argv, timeout=timeout)}
        from .protocols import Protocols
        self.protocol = Protocols()
        collected = _collect.get()
        if collected is not None:
            collected.append(self)

    @property
    def images(self):
        return [self.exe] + ([self.libc] if self.libc is not None else [])

    def _lookup(self, path: str) -> Expr:
        parts = path.split(".")
        root = {"exe": self.exe, "libc": self.libc, "heap": self.heap, "stack": self.stack}.get(parts[0])
        if root is None or len(parts) < 2:
            raise PlanningError(f"unknown observation target {path!r}")
        for part in parts[1:]:
            root = getattr(root, part)
        if not isinstance(root, Expr):
            raise PlanningError(f"{path!r} is not a symbolic fact")
        return root

    def observe(self, observation: str | Pattern, *, from_=None, timeout=3, max_bytes=1048576):
        parsed = template(observation, self._lookup) if isinstance(observation, str) else observation
        if not isinstance(parsed, Pattern):
            raise TypeError("observe requires a pattern or pattern string")
        obj = Observation(parsed, from_, timeout, max_bytes)
        self._observations.append(obj)
        return obj

    def format_leak(
        self,
        surface: InputSurface,
        *,
        prefix: bytes | str = b"",
        separator: bytes | str = b"|",
        **positions: int,
    ) -> LeakNamespace:
        if not isinstance(surface, InputSurface) or surface.challenge is not self:
            raise PlanningError("format_leak input surface belongs to another challenge")
        if not positions:
            raise PlanningError("format_leak requires at least one named stack position")
        selected = tuple(int(value) for value in positions.values())
        if any(value <= 0 for value in selected):
            raise PlanningError("format leak positions must be positive")
        if len(set(selected)) != len(selected):
            raise PlanningError("format leak positions must be unique")
        delimiter = separator.encode() if isinstance(separator, str) else bytes(separator)
        if not delimiter or b"%" in delimiter:
            raise PlanningError("format leak separator must be non-empty and contain no '%'")
        payload = delimiter.join(f"%{value}$p".encode() for value in selected)
        boundary = prefix.encode() if isinstance(prefix, str) else bytes(prefix)
        relationships = ", ".join(
            f"{name} at position {position}" for name, position in positions.items()
        )
        prefix_description = (
            f" after {boundary.decode('ascii', 'backslashreplace')!r}"
            if boundary
            else ""
        )
        description = (
            f"format leak {relationships}{prefix_description}; "
            f"separator {delimiter!r}"
        )
        return surface.format_leak(
            payload,
            after=boundary,
            separator=delimiter,
            description=description,
            **{name: "hex" for name in positions},
        )

    def control(self, channel=None, *, return_at=None, entry_sp_mod16=0,
                fill=b"A", name="overflow", stack_alignment=None, **kwargs):
        from .formats import FormatControl
        if isinstance(channel, ControlDeclaration):
            self.capabilities.append(channel.capability)
            self._controls.append(channel.implementation)
            return channel
        if isinstance(channel, Capability):
            self.capabilities.append(channel)
            return channel
        if isinstance(channel, FormatControl):
            self._controls.append(channel)
            return channel
        declared_capability = getattr(channel, "capability", None)
        if isinstance(declared_capability, Capability):
            self.capabilities.append(declared_capability)
            return channel
        if kwargs:
            raise TypeError(f"unknown control options: {', '.join(kwargs)}")
        if return_at is None:
            raise TypeError("return-address control requires return_at")
        if stack_alignment not in {None, 16}:
            raise ValueError("only the AMD64 16-byte stack ABI is supported")
        control = Control(channel if channel is not None else line(), return_at,
                          entry_sp_mod16, fill, name)
        self._controls.append(control)
        return control

    def learn(
        self, fact, *, using, receive=None, resume=None, via=None, name=None,
        cost=0, requires=(),
    ):
        if isinstance(via, ControlDeclaration):
            via = via.implementation
        targets = tuple(fact) if isinstance(fact, (list, tuple)) else (fact,)
        if not targets or not all(isinstance(t, Expr) for t in targets):
            raise TypeError("learn targets must be symbolic expressions")
        recipe = Learn(
            targets, using, receive, resume, via,
            name or "learn " + ", ".join(t.describe() for t in targets),
            cost, tuple(requires),
        )
        self._learns.append(recipe)
        return recipe

    def want(self, effect, *, using=None, via=None, terminal=None):
        if isinstance(via, ControlDeclaration):
            via = via.implementation
        if using is not None and isinstance(effect, GoalRequest):
            from .control_flow import attach_using

            attached = attach_using(effect, using)
            if attached is not effect:
                effect = attached
                using = None
        if via is not None and isinstance(effect, GoalRequest):
            from .exploit import attach_goal_control

            attached = attach_goal_control(effect, via)
            if attached is not effect:
                effect = attached
                via = None
        if terminal is None:
            terminal = _is_terminal_effect(effect)
        goal = Goal(effect, using, via, bool(terminal))
        self._goals.append(goal)
        return goal

    def assume(self, fact, value, *, reason="user supplied"):
        self._assumptions.append((as_expr(fact), value, reason))
        return fact

    def derive(self, function, *inputs, name=None):
        label = name or function.__qualname__
        identity = hashlib.sha256((label + repr(tuple(getattr(v, 'key', v) for v in inputs))).encode()).hexdigest()[:12]
        result = Expr.fact(f"derived.{identity}", label=label)
        self._derivations.append(Derivation(result, function, inputs))
        return result

    def relate(self, target, expression, *, reason=None):
        """Bind a symbolic relationship without a user-authored lambda."""

        from .actions import sequence

        selected = as_expr(target)
        value = as_expr(expression)
        explanation = reason or f"{selected.describe()} = {value.describe()}"
        self._sequences.append(
            sequence(
                Bind(selected, value),
                name=f"relate {explanation}",
            )
        )
        return selected

    def fact(self, name: str, *, scope="process"):
        return Expr.fact(name, scope=scope)

    def typed_fact(
        self,
        name: str,
        sort: Sort,
        *,
        scope="process",
        artifact=None,
        description="",
    ) -> Fact:
        from .domain import Scope

        return Fact(name, sort, Scope(scope), artifact, description)

    def capability(self, capability: Capability) -> Capability:
        self.capabilities.append(capability)
        return capability

    def provider(self, **contract):
        return self.providers.provider(**contract)

    def strategy(self, **contract):
        return self.providers.strategy(**contract)

    def goal(self, name: str, *, requires=(), constraints=()):
        return GoalRequest(name, tuple(requires), tuple(constraints))

    def environment(self, name: str, environment: Environment) -> Environment:
        if name in self.environments:
            raise ValueError(f"environment {name!r} is already registered")
        self.environments[name] = environment
        return environment

    def target_recipe(
        self,
        name: str,
        environment: Environment,
        *,
        images=None,
        argv=(),
        env=None,
        cwd=None,
    ) -> TargetManifest:
        recipe = TargetManifest(
            name,
            environment,
            tuple(images or (image.path for image in self.images)),
            tuple(str(item) for item in argv),
            env or {},
            cwd,
        )
        self.target_manifests[name] = recipe
        return recipe

    def on(self, name: str | Any, recipe: Any = None):
        if recipe is None:
            recipe = name
            if not callable(getattr(recipe, "materialize", None)):
                raise TypeError("target recipe must provide materialize(epoch_seed=...)")
            self._default_target_recipe = recipe
            return self
        if not isinstance(name, str) or not name:
            raise TypeError("registered target recipe names must be non-empty strings")
        if name in self.target_recipes:
            raise ValueError(f"target recipe {name!r} is already registered")
        if not callable(getattr(recipe, "materialize", None)):
            raise TypeError("target recipe must provide materialize(epoch_seed=...)")
        self.target_recipes[name] = recipe
        return recipe

    def sequence(self, *actions, name="sequence"):
        from .actions import sequence
        obj = sequence(*actions, name=name)
        self._sequences.append(obj)
        return obj

    def craft(
        self,
        name,
        *,
        endian: Literal["little", "big"] | None = None,
        pointer_size: int | None = None,
        fill=b"\x00",
    ):
        from .bytecraft import Craft

        if name in self._craft_names:
            raise ValueError(f"craft name {name!r} is already declared")
        self._craft_names.add(name)
        selected_endian = endian or self.target.endian
        if selected_endian not in {"little", "big"}:
            raise ValueError("craft endian must be 'little' or 'big'")
        return Craft.create(
            str(name),
            endian=cast(Literal["little", "big"], selected_endian),
            pointer_size=pointer_size or self.target.pointer_size,
            fill=fill,
        )

    def send(self, craft, *, to):
        from .actions import Branch, Encoded, PayloadFeasibility, Sequence, sequence

        from .bytecraft import Craft

        if not isinstance(craft, Craft):
            raise TypeError("x.send requires a Craft")
        if isinstance(to, InputSurface):
            action = Emit(craft, to.channel)
        elif isinstance(to, Channel):
            action = Emit(craft, to)
        elif callable(to):
            action = to(craft)
            if not isinstance(action, Action):
                raise PlanningError("craft destination did not produce an Action")
        else:
            raise TypeError("craft destination must be an InputSurface, Channel, or operation")

        guarded = False

        def correlate(item):
            nonlocal guarded
            if isinstance(item, Emit):
                value = item.data.value if isinstance(item.data, Encoded) else item.data
                if value is not craft:
                    return item
                correlation = object()
                correlated = replace(item, correlation=correlation)
                if not (
                    craft.dependencies
                    and (
                        item.channel.terminator is not None
                        or item.channel.forbidden
                        or item.channel.max_size is not None
                    )
                ):
                    return correlated
                guarded = True
                return Sequence(
                    (
                        PayloadFeasibility(
                            craft,
                            item.channel,
                            correlation=correlation,
                        ),
                        correlated,
                    ),
                    f"guarded send {craft.name}",
                )
            if isinstance(item, Sequence):
                return Sequence(tuple(correlate(child) for child in item.actions), item.name)
            if isinstance(item, Branch):
                return Branch(
                    item.predicate,
                    correlate(item.then),
                    correlate(item.otherwise),
                )
            return item

        action = correlate(action)
        if guarded:
            self._narrative_assumptions.append(
                f"retryable prerequisite: symbolic craft {craft.name!r} must satisfy "
                "its destination framing within the run attempt budget"
            )
        declaration = sequence(action, name=f"send craft {craft.name}")
        self.want(declaration, terminal=False)
        return declaration

    def menu(self, prompt, *, name="store", **operations):
        from .sugar import quick_menu

        return quick_menu(self, prompt, name=name, **operations)

    def recipe(self, *, produces, requires=(), name=None):
        """Register a builder returning declarative actions, evaluated at plan time."""
        targets = (produces,) if isinstance(produces, Expr) else tuple(produces)
        def decorate(function):
            self.learn(
                targets,
                using=function,
                name=name or function.__name__,
                requires=requires,
            )
            function.__pwnx_requires__ = tuple(requires)
            return function
        return decorate

    def opaque(
        self,
        *,
        produces=(),
        consumes=(),
        reads=(),
        writes=(),
        invalidates=(),
        name=None,
        semantic_id=None,
        register_learn=True,
    ):
        targets = (produces,) if isinstance(produces, Expr) else tuple(produces)
        def decorate(function):
            try:
                source = inspect.getsource(function)
            except (OSError, TypeError):
                source = repr(function.__code__.co_code) + repr(function.__code__.co_consts)
            identity = (
                hashlib.sha256(f"semantic:{semantic_id}".encode()).hexdigest()
                if semantic_id is not None
                else hashlib.sha256(source.encode()).hexdigest()
            )
            obj = Opaque(function, tuple(consumes), targets, tuple(reads), tuple(writes),
                         tuple(invalidates), name or function.__qualname__, identity)
            self._opaque.append(obj)
            if targets and register_learn:
                self.learn(targets, using=obj, name=obj.name)
            return obj
        return decorate

    def boundary(
        self,
        name: str,
        *,
        needs=(),
        gives=(),
        reads=(),
        writes=(),
        invalidates=(),
        semantic_id=None,
    ):
        """Declare a concise, explicitly opaque custom operation boundary."""

        targets = tuple(gives)

        def decorate(function):
            identity = _callable_semantic_identity(function, semantic_id)

            def normalize_result(result):
                if not isinstance(result, Mapping):
                    if len(targets) > 1:
                        raise ConstraintError(
                            f"boundary {name!r} declares {len(targets)} outputs and "
                            "must return a mapping keyed by those output facts"
                        )
                    return result
                expected = {target.key for target in targets}
                actual = set(result)
                missing = sorted(expected - actual)
                extra = sorted(str(key) for key in actual - expected)
                if missing:
                    raise ConstraintError(
                        f"boundary {name!r} returned a mapping missing declared "
                        f"output(s): {', '.join(missing)}"
                    )
                if extra:
                    raise ConstraintError(
                        f"boundary {name!r} returned undeclared mapping output(s): "
                        f"{', '.join(extra)}"
                    )
                if len(targets) == 1:
                    return result[targets[0].key]
                return dict(result)

            def normalized(io, facts):
                result = function(io, facts)
                if inspect.isawaitable(result):
                    async def finish():
                        return normalize_result(await result)

                    return finish()
                return normalize_result(result)

            normalized.__name__ = function.__name__
            normalized.__qualname__ = function.__qualname__
            return self.opaque(
                produces=targets,
                consumes=tuple(needs),
                reads=tuple(reads),
                writes=tuple(writes),
                invalidates=tuple(invalidates),
                name=name,
                semantic_id=identity,
                register_learn=False,
            )(normalized)

        return decorate

    def technique(self, *, name=None, requires=(), provides=(), reliability="conditional", cost=0):
        def decorate(function):
            key = name or function.__name__
            self._plugins[key] = dict(lower=function, requires=tuple(requires),
                                     provides=tuple(provides), reliability=reliability, cost=cost)
            return Tactic(key)
        return decorate

    def prefer(self, tactic):
        self._preferred.append(tactic.name if isinstance(tactic, Tactic) else str(tactic))
        return self

    def forbid(self, tactic):
        self._forbidden.add(tactic.name if isinstance(tactic, Tactic) else str(tactic))
        return self

    def require(self, **constraints):
        if set(constraints) - {"no_bruteforce"}:
            raise UnsupportedFeature("unknown planner requirements: " + ", ".join(constraints))
        self._requirements.update(constraints)
        return self

    def local(self, argv=None, *, env=None, cwd=None, timeout=3, name="local"):
        args = self._default_argv if argv is None else tuple(str(v) for v in argv)
        self.profiles[name] = Profile(argv=args, env=env, cwd=cwd, timeout=timeout)
        return self

    def remote(self, host, port, *, tls=False, timeout=3, name="remote",
               process="fresh-per-connection", service="persistent",
               protocol="tcp"):
        if process != "fresh-per-connection":
            raise UnsupportedFeature("this release creates a fresh runtime scope for each connection")
        if protocol not in {"tcp", "udp"}:
            raise ValueError("remote protocol must be 'tcp' or 'udp'")
        if tls and protocol != "tcp":
            raise ValueError("TLS is only available for TCP profiles")
        self.profiles[name] = Profile(
            "remote" if protocol == "tcp" else "udp",
            host=host,
            port=int(port),
            tls=tls,
            timeout=timeout,
        )
        return self

    def listen(
        self,
        host="127.0.0.1",
        port=0,
        *,
        backlog=1,
        timeout=30,
        name="listen",
    ):
        if not 0 < int(port) < 65536:
            raise ValueError(
                "declarative listeners require an explicit port in 1..65535; "
                "use ListenerTube directly when the caller can publish an ephemeral address"
            )
        self.profiles[name] = Profile(
            "listen",
            host=str(host),
            port=int(port),
            timeout=timeout,
            options={"backlog": int(backlog)},
        )
        return self

    def serial(
        self,
        device,
        *,
        baud=115200,
        timeout=3,
        name="serial",
    ):
        self.profiles[name] = Profile(
            "serial",
            timeout=timeout,
            options={
                "device": str(Path(device).expanduser()),
                "baud": int(baud),
            },
        )
        return self

    def debug(self, *, debugger=("gdb", "-q", "-ex", "run", "--args"), name="debug"):
        self.profiles[name] = replace(
            self.profiles["local"], kind="debug", debugger=tuple(debugger)
        )
        return self

    def gdb(
        self,
        *,
        breakpoints=(),
        commands=(),
        debugger="gdb",
        name="debug",
    ):
        executable = shutil.which(debugger)
        if executable is None:
            raise UnsupportedFeature(f"debugger {debugger!r} is not installed")
        arguments: list[str] = [executable, "-q"]
        for breakpoint in breakpoints:
            if isinstance(breakpoint, Expr):
                if not breakpoint.is_literal:
                    raise PlanningError(
                        "GDB breakpoints must be static; use a symbol name for PIE targets"
                    )
                breakpoint = f"*{int(breakpoint.value):#x}"
            elif isinstance(breakpoint, int):
                breakpoint = f"*{breakpoint:#x}"
            arguments.extend(("-ex", f"break {breakpoint}"))
        for command in commands:
            arguments.extend(("-ex", str(command)))
        arguments.extend(("-ex", "run", "--args"))
        return self.debug(debugger=tuple(arguments), name=name)

    def qemu(
        self,
        *,
        arch="x86_64",
        sysroot=None,
        arguments=(),
        gdb_port=None,
        emulator=None,
        name="qemu",
        timeout=3,
    ):
        aliases = {"amd64": "x86_64", "x64": "x86_64"}
        architecture = aliases.get(arch, arch)
        executable = emulator or shutil.which(f"qemu-{architecture}")
        if executable is None:
            raise UnsupportedFeature(
                f"qemu-{architecture} is not installed; pass emulator= explicitly"
            )
        argv = [str(executable)]
        if sysroot is not None:
            argv.extend(("-L", str(Path(sysroot).resolve())))
        if gdb_port is not None:
            argv.extend(("-g", str(int(gdb_port))))
        argv.append(str(Path(self.exe.path).resolve()))
        argv.extend(str(value) for value in arguments)
        self.profiles[name] = Profile(
            "local", argv=tuple(argv), timeout=timeout
        )
        return self

    def ssh(
        self,
        host,
        command,
        *,
        user=None,
        port=22,
        identity=None,
        options=(),
        name="ssh",
        timeout=10,
    ):
        executable = shutil.which("ssh")
        if executable is None:
            raise UnsupportedFeature("OpenSSH client is not installed")
        destination = f"{user}@{host}" if user else str(host)
        argv = [executable, "-T", "-p", str(int(port))]
        if identity is not None:
            argv.extend(("-i", str(Path(identity).expanduser().resolve())))
        for option in options:
            argv.extend(("-o", str(option)))
        argv.extend((destination, "--"))
        if isinstance(command, str):
            argv.append(command)
        else:
            argv.extend(str(value) for value in command)
        self.profiles[name] = Profile(
            "local", argv=tuple(argv), timeout=timeout
        )
        return self

    def shell(self):
        if self.libc is not None:
            return self.libc.call("system", "/bin/sh")
        return DynamicCall("system", ("/bin/sh",))

    def read_file(
        self,
        path,
        *,
        size=0x100,
        scratch,
        path_size=None,
        scratch_size=None,
    ):
        from .exploit import read_file_goal

        return read_file_goal(
            self,
            path,
            size=size,
            scratch=scratch,
            path_size=path_size,
            scratch_size=scratch_size,
        )

    def buffer(
        self,
        name=None,
        *,
        at,
        size,
        encoding=None,
        **removed,
    ):
        from .control_flow import buffer, utf8

        if removed:
            spellings = ", ".join(sorted(removed))
            raise PlanningError(
                f"primary buffer composition aliases were removed ({spellings}); "
                "use x.buffer(at=..., size=..., encoding=...).written_by(op), "
                "or pwnx.advanced.controlled_buffer(...)"
            )
        declared: tuple[Any, ...] = ()
        if encoding is not None:
            normalized = str(encoding).lower().replace("-", "")
            if normalized != "utf8":
                raise ValueError("natural buffer encoding currently supports only 'utf8'")
            declared = (*declared, utf8())
        return buffer(
            self,
            name or "buffer",
            at=at,
            size=size,
            writer=None,
            constraints=declared,
        )

    def indirect_call(self, **declaration):
        from .control_flow import indirect_call

        return indirect_call(self, **declaration)

    def execve(self, path):
        from .control_flow import execve_goal

        return execve_goal(self, path)

    def call(self, target, *args):
        if not isinstance(target, Expr):
            raise TypeError("call target must be a symbolic address")
        return target(*args)

    def plan(self):
        from .planner import build_plan
        return build_plan(self)

    def experiment(self):
        from .experiment import Experiment

        return Experiment(self.plan())

    def run(
        self,
        *,
        profile="local",
        trace=None,
        transport=None,
        replay=None,
        on=None,
        attempts=1,
    ):
        if _collect.get() is not None:
            return _CollectionRun()
        if not isinstance(attempts, int) or attempts <= 0:
            raise ValueError("attempts must be a positive integer")
        if attempts > 1 and replay is not None:
            raise UnsupportedFeature("attempts>1 is incompatible with replay")
        if attempts > 1 and transport is not None:
            raise UnsupportedFeature(
                "attempts>1 requires pwnx to open a fresh target; explicit transport "
                "cannot be refreshed"
            )
        selected_target = self._default_target_recipe if on is None else on
        if attempts > 1 and selected_target is not None:
            lifecycle = getattr(selected_target, "lifecycle", None)
            if lifecycle is not None and not (
                str(lifecycle.process).startswith("fresh-")
                or str(lifecycle.connection).startswith("fresh-")
            ):
                raise UnsupportedFeature(
                    "attempts>1 requires a target recipe with a fresh process or connection"
                )
        self._attempt_budget = attempts
        plan = self.plan()
        if attempts == 1:
            return plan.run(
                profile=profile,
                trace=trace,
                transport=transport,
                replay=replay,
                on=selected_target,
            )

        from .trace import Trace

        failures: list[str] = []
        last_error: RetryableInstanceError | None = None
        for attempt in range(1, attempts + 1):
            attempt_trace = Trace()
            try:
                run = plan.run(
                    profile=profile,
                    trace=attempt_trace,
                    on=selected_target,
                )
            except RetryableInstanceError as error:
                failures.append(str(error))
                last_error = error
                if isinstance(trace, Trace):
                    trace.metadata.clear()
                    trace.metadata.update(attempt_trace.metadata)
                    trace.metadata["retry"] = {
                        "budget": attempts,
                        "used": attempt,
                        "failures": list(failures),
                    }
                    trace.events[:] = attempt_trace.events
                continue
            if run.trace is not None:
                run.trace.metadata["retry"] = {
                    "budget": attempts,
                    "used": attempt,
                    "failures": list(failures),
                }
            if trace is not None:
                if isinstance(trace, Trace):
                    trace.metadata.clear()
                    trace.metadata.update(attempt_trace.metadata)
                    trace.events[:] = attempt_trace.events
                    run.trace = trace
                elif isinstance(trace, (str, Path)):
                    run.trace_path = Path(trace)
                else:
                    raise TypeError("trace must be a Trace or filesystem path")
            return run

        assert last_error is not None
        raise RetryableInstanceError(
            f"retry attempts exhausted: {attempts}/{attempts}; last failure: {last_error}",
            label=last_error.label,
            offset=last_error.offset,
            byte=last_error.byte,
            channel=last_error.channel,
        ) from last_error


@dataclass(frozen=True)
class DynamicCall:
    symbol: str
    args: tuple[Any, ...] = ()

    @property
    def dependencies(self) -> set[str]:
        return set().union(
            *(getattr(value, "dependencies", set()) for value in self.args)
        )

    def describe(self):
        return f"dynamic {self.symbol}({', '.join(map(repr, self.args))})"


def dynamic_call(symbol: str, *args):
    return DynamicCall(symbol, args)


def _is_terminal_effect(effect: Any) -> bool:
    if bool(getattr(getattr(effect, "intent", None), "terminal", False)):
        return True
    name = getattr(effect, "name", "") or getattr(effect, "symbol", "")
    args = getattr(effect, "args", ())
    if not str(name).endswith("system") or not args:
        return False
    value = getattr(args[0], "value", args[0])
    return value in {"/bin/sh", b"/bin/sh", "/bin/bash", b"/bin/bash"}


class _CollectionRun:
    """Harmless value returned while the CLI evaluates a solve for declarations."""

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def value(self, _expression):
        return 0

    def fact(self, _expression):
        return 0

    def bytes(self, _payload):
        return b""

    def explain(self, _subject):
        return "collection mode"

    def interactive(self):
        return None

    def close(self):
        return None
