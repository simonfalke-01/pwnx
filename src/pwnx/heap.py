"""Versioned allocator state and capability proofs.

The public model describes what an exploit can do. Named allocator techniques
remain implementation evidence inside a TechniqueProof.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .actions import Action
from .domain import Capability, EffectContract, Evidence, Scope, TechniqueProof
from .errors import ConstraintError, PlanningError


def _version(value: str | tuple[int, int]) -> tuple[int, int]:
    if isinstance(value, tuple):
        if len(value) != 2:
            raise ValueError("allocator version must be major.minor")
        return int(value[0]), int(value[1])
    parts = value.split(".", 2)
    if len(parts) < 2:
        raise ValueError("allocator version must be major.minor")
    return int(parts[0]), int(parts[1])


@dataclass(frozen=True, slots=True)
class AllocatorModel:
    implementation: str
    version: tuple[int, int]
    word_size: int = 8
    alignment: int = 16
    tcache: bool = True
    safe_linking: bool = False
    tcache_count: int = 7
    tcache_max: int | None = None
    hooks: bool = False
    assumptions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.word_size <= 0 or self.alignment <= 0:
            raise ValueError("allocator word size and alignment must be positive")
        if self.alignment & (self.alignment - 1):
            raise ValueError("allocator alignment must be a power of two")
        if self.tcache_count < 0:
            raise ValueError("tcache count cannot be negative")
        if self.tcache_max is not None:
            if not self.tcache:
                raise ValueError("tcache_max requires tcache=True")
            if self.tcache_max <= 0 or self.tcache_max % self.alignment:
                raise ValueError("tcache_max must be a positive aligned chunk size")

    @classmethod
    def glibc(cls, version: str | tuple[int, int]) -> "AllocatorModel":
        selected = _version(version)
        if selected not in {(2, 27), (2, 31), (2, 35), (2, 39)}:
            raise ValueError(
                "reference glibc model requires explicit version 2.27, 2.31, 2.35, or 2.39"
            )
        return cls(
            "glibc",
            selected,
            tcache=True,
            safe_linking=selected >= (2, 32),
            tcache_max=0x410,
            hooks=selected < (2, 34),
            assumptions=(
                f"glibc {selected[0]}.{selected[1]} allocator semantics",
                "single-threaded arena unless declared otherwise",
            ),
        )

    @property
    def name(self) -> str:
        return f"{self.implementation}-{self.version[0]}.{self.version[1]}"

    def normalize_size(self, requested: int) -> int:
        if requested <= 0:
            raise ValueError("allocation size must be positive")
        minimum = self.word_size * 4
        # glibc request2size accounts for SIZE_SZ because prev_size overlaps
        # user storage while the preceding chunk is allocated.
        with_header = requested + self.word_size
        return max(minimum, (with_header + self.alignment - 1) & -self.alignment)

    def tcache_eligible(self, size: int, *, normalized: bool = False) -> bool:
        """Return whether a request/chunk belongs to the declared tcache classes."""

        if not self.tcache or self.tcache_max is None:
            return False
        chunk_size = int(size) if normalized else self.normalize_size(int(size))
        if chunk_size <= 0 or chunk_size % self.alignment:
            raise ValueError("normalized chunk size must be positive and aligned")
        return chunk_size <= self.tcache_max

    def encode_link(self, field_address: int, target: int) -> int:
        if min(field_address, target) < 0:
            raise ValueError("heap addresses must be non-negative")
        return target ^ (field_address >> 12) if self.safe_linking else target

    def decode_link(self, field_address: int, encoded: int) -> int:
        return self.encode_link(field_address, encoded)


@dataclass(frozen=True, slots=True)
class HeapChunk:
    name: str
    requested: int
    size: int
    address: int
    allocated: bool = True
    data: bytes = b""
    bin_name: str | None = None
    free_count: int = 0


@dataclass(frozen=True, slots=True)
class HeapEvent:
    operation: str
    chunk: str
    summary: str
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class HeapPrimitive:
    name: str
    chunk: str | None = None
    address: int | None = None
    size: int | None = None
    evidence: tuple[Evidence, ...] = ()

    def capability(self) -> Capability:
        return Capability(
            self.name,
            EffectContract(
                reads=frozenset({"process.heap"}),
                writes=frozenset({"process.heap"}),
                scope=Scope.PROCESS,
                evidence=self.evidence,
            ),
            evidence=self.evidence,
        )


class DanglingRead(HeapPrimitive):
    pass


class UseAfterFree(HeapPrimitive):
    pass


class DoubleFree(HeapPrimitive):
    pass


class Overlap(HeapPrimitive):
    pass


class ArbitraryRead(HeapPrimitive):
    pass


class ArbitraryWrite(HeapPrimitive):
    pass


class HeapAddressKnowledge(HeapPrimitive):
    pass


@dataclass(frozen=True, slots=True)
class HeapState:
    model: AllocatorModel
    chunks: Mapping[str, HeapChunk] = field(default_factory=dict)
    bins: Mapping[int, tuple[str, ...]] = field(default_factory=dict)
    history: tuple[HeapEvent, ...] = ()
    next_address: int = 0x10000

    def __post_init__(self) -> None:
        object.__setattr__(self, "chunks", MappingProxyType(dict(self.chunks)))
        object.__setattr__(
            self,
            "bins",
            MappingProxyType({size: tuple(items) for size, items in self.bins.items()}),
        )

    def _replace(
        self,
        *,
        chunks: Mapping[str, HeapChunk] | None = None,
        bins: Mapping[int, tuple[str, ...]] | None = None,
        event: HeapEvent | None = None,
        next_address: int | None = None,
    ) -> "HeapState":
        history = self.history + ((event,) if event else ())
        return HeapState(
            self.model,
            chunks if chunks is not None else self.chunks,
            bins if bins is not None else self.bins,
            history,
            self.next_address if next_address is None else next_address,
        )

    def allocate(
        self,
        name: str,
        requested: int,
        data: bytes = b"",
        *,
        address: int | None = None,
    ) -> "HeapState":
        if not name or name in self.chunks:
            raise ConstraintError(f"heap chunk name {name!r} is empty or already used")
        size = self.model.normalize_size(requested)
        bins = dict(self.bins)
        available = list(bins.get(size, ()))
        reused = available.pop(0) if available else None
        if reused is not None:
            chosen_address = self.chunks[reused].address
            bins[size] = tuple(available)
        else:
            chosen_address = (
                self.next_address if address is None else int(address)
            )
        if chosen_address % self.model.alignment:
            raise ConstraintError("chunk address violates allocator alignment")
        chunk = HeapChunk(
            name,
            requested,
            size,
            chosen_address,
            True,
            bytes(data),
        )
        chunks = dict(self.chunks)
        chunks[name] = chunk
        next_address = max(self.next_address, chosen_address + size)
        detail = f"{name} at {chosen_address:#x}, chunk size {size:#x}"
        if reused:
            detail += f", reused storage from {reused}"
        return self._replace(
            chunks=chunks,
            bins=bins,
            event=HeapEvent("allocate", name, detail),
            next_address=next_address,
        )

    def free(
        self,
        name: str,
        *,
        capability: DoubleFree | None = None,
    ) -> "HeapState":
        chunk = self._chunk(name)
        if not chunk.allocated and capability is None:
            raise ConstraintError(
                f"{name} is already free; declare a DoubleFree capability"
            )
        if not chunk.allocated and capability is not None and capability.chunk not in {
            None,
            name,
        }:
            raise ConstraintError("double-free capability applies to another chunk")
        bins = dict(self.bins)
        members = list(bins.get(chunk.size, ()))
        eligible = self.model.tcache_eligible(chunk.size, normalized=True)
        if self.model.tcache:
            if eligible and len(members) < self.model.tcache_count:
                bin_name = "tcache"
                members.insert(0, name)
                bins[chunk.size] = tuple(members)
            else:
                bin_name = "unsorted"
        else:
            bin_name = "fastbin"
            members.insert(0, name)
            bins[chunk.size] = tuple(members)
        chunks = dict(self.chunks)
        chunks[name] = replace(
            chunk,
            allocated=False,
            bin_name=bin_name,
            free_count=chunk.free_count + 1,
        )
        evidence = capability.evidence if capability else ()
        return self._replace(
            chunks=chunks,
            bins=bins,
            event=HeapEvent("free", name, f"{name} -> {bin_name}", evidence),
        )

    def edit(
        self,
        name: str,
        data: bytes,
        *,
        capability: UseAfterFree | ArbitraryWrite | None = None,
    ) -> "HeapState":
        chunk = self._chunk(name)
        if not chunk.allocated and capability is None:
            raise ConstraintError(
                f"{name} is free; declare UseAfterFree or ArbitraryWrite"
            )
        if (
            not chunk.allocated
            and capability is not None
            and capability.chunk not in {None, name}
        ):
            raise ConstraintError("write capability applies to another chunk")
        chunks = dict(self.chunks)
        for key, item in chunks.items():
            if item.address == chunk.address:
                chunks[key] = replace(item, data=bytes(data))
        return self._replace(
            chunks=chunks,
            event=HeapEvent(
                "edit",
                name,
                f"wrote {len(data)} byte(s) at {chunk.address:#x}",
                capability.evidence if capability else (),
            ),
        )

    def show(
        self,
        name: str,
        *,
        capability: DanglingRead | ArbitraryRead | None = None,
    ) -> tuple[bytes, Evidence]:
        chunk = self._chunk(name)
        if not chunk.allocated and capability is None:
            raise ConstraintError(
                f"{name} is free; declare DanglingRead or ArbitraryRead"
            )
        if (
            not chunk.allocated
            and capability is not None
            and capability.chunk not in {None, name}
        ):
            raise ConstraintError("read capability applies to another chunk")
        evidence = Evidence(
            "heap-read",
            f"{len(chunk.data)} byte(s) from {name} at {chunk.address:#x}",
            self.model.name,
            {"allocated": chunk.allocated, "bin": chunk.bin_name},
        )
        return chunk.data, evidence

    def consolidate(
        self,
        first: str,
        second: str,
    ) -> tuple["HeapState", Overlap]:
        left, right = self._chunk(first), self._chunk(second)
        if left.allocated or right.allocated:
            raise ConstraintError("consolidation requires two free chunks")
        if left.address + left.size != right.address:
            raise ConstraintError("chunks are not physically adjacent")
        overlap = Overlap(
            "overlapping heap storage",
            first,
            left.address,
            left.size + right.size,
            (
                Evidence(
                    "heap-transition",
                    f"{first} and {second} consolidated",
                    self.model.name,
                ),
            ),
        )
        state = self._replace(
            event=HeapEvent(
                "consolidate",
                first,
                f"{first}+{second} -> overlap {left.size + right.size:#x}",
                overlap.evidence,
            )
        )
        return state, overlap

    def overlap(self, first: str, second: str) -> Overlap | None:
        left, right = self._chunk(first), self._chunk(second)
        start = max(left.address, right.address)
        end = min(left.address + left.size, right.address + right.size)
        if start >= end:
            return None
        return Overlap(
            "overlapping heap storage",
            first,
            start,
            end - start,
            (Evidence("heap-alias", f"{first} overlaps {second}", self.model.name),),
        )

    def action(self, operation: str, *args: Any, **kwargs: Any) -> "HeapAction":
        return HeapAction(self, operation, args, kwargs)

    def _chunk(self, name: str) -> HeapChunk:
        try:
            return self.chunks[name]
        except KeyError as error:
            raise ConstraintError(f"unknown heap chunk {name!r}") from error


@dataclass(frozen=True, slots=True)
class HeapAction(Action):
    state: HeapState
    operation: str
    args: tuple[Any, ...]
    kwargs: Mapping[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        return f"heap {self.operation}({', '.join(map(repr, self.args))})"

    def contract(self) -> EffectContract:
        return EffectContract(
            reads=frozenset({"process.heap"}),
            writes=frozenset({"process.heap"}),
            invalidates=("heap.derived",),
            scope=Scope.PROCESS,
            evidence=(
                Evidence("allocator", self.state.model.name, "declared model"),
            ),
        )

    def apply(self) -> HeapState:
        method = getattr(self.state, self.operation, None)
        if method is None or self.operation.startswith("_"):
            raise ConstraintError(f"unknown heap operation {self.operation!r}")
        result = method(*self.args, **dict(self.kwargs))
        return result[0] if isinstance(result, tuple) else result

    def execute(self, _runtime: Any) -> HeapState:
        return self.apply()


@dataclass(frozen=True, slots=True)
class HeapGoal:
    kind: str
    target: int | None = None
    size: int = 8
    description: str = ""

    def __post_init__(self) -> None:
        if self.kind not in {
            "read-memory",
            "write-memory",
            "control-flow",
            "file-contents",
            "overlap-storage",
        }:
            raise ValueError(f"unknown heap goal {self.kind!r}")
        if self.size <= 0:
            raise ValueError("heap goal size must be positive")


@dataclass(frozen=True, slots=True)
class HeapProofStep:
    operation: str
    explanation: str

    def describe(self) -> str:
        return f"{self.operation}: {self.explanation}"


class HeapTechniqueRegistry:
    """Select capability proofs without exposing technique names as goals."""

    def candidates(
        self,
        goal: HeapGoal,
        state: HeapState,
        capabilities: Iterable[HeapPrimitive],
    ) -> tuple[TechniqueProof, ...]:
        available = tuple(capabilities)
        proofs: list[TechniqueProof] = []
        rejected: list[str] = []

        if goal.kind == "read-memory":
            primitive = next(
                (item for item in available if isinstance(item, ArbitraryRead)),
                None,
            )
            if primitive:
                proofs.append(
                    TechniqueProof(
                        "direct arbitrary-read capability",
                        goal.kind,
                        (HeapProofStep("read", f"{goal.size} bytes at {goal.target:#x}"),),
                        prerequisites=(primitive.capability(),),
                        reliability="stable",
                        cost=1,
                        evidence=primitive.evidence,
                    )
                )

        if goal.kind in {"write-memory", "control-flow", "file-contents"}:
            direct = next(
                (item for item in available if isinstance(item, ArbitraryWrite)),
                None,
            )
            if direct:
                proofs.append(
                    TechniqueProof(
                        "direct arbitrary-write capability",
                        goal.kind,
                        (HeapProofStep("write", f"{goal.size} bytes at {goal.target:#x}"),),
                        prerequisites=(direct.capability(),),
                        reliability="stable",
                        cost=1,
                        evidence=direct.evidence,
                    )
                )
            uaf = next(
                (item for item in available if isinstance(item, UseAfterFree)),
                None,
            )
            double = next(
                (item for item in available if isinstance(item, DoubleFree)),
                None,
            )
            heap_base = next(
                (
                    item
                    for item in available
                    if isinstance(item, HeapAddressKnowledge)
                ),
                None,
            )
            if state.model.tcache and (uaf or double):
                if state.model.safe_linking and heap_base is None:
                    rejected.append(
                        "tcache forward-pointer control requires heap-address evidence"
                    )
                else:
                    prerequisites = tuple(
                        item.capability()
                        for item in (uaf or double, heap_base)
                        if item is not None
                    )
                    proofs.append(
                        TechniqueProof(
                            "glibc tcache forward-pointer control",
                            goal.kind,
                            (
                                HeapProofStep(
                                    "prepare-bin",
                                    "place a controllable free chunk in the target size class",
                                ),
                                HeapProofStep(
                                    "encode-link",
                                    "encode target with declared allocator safe-linking policy",
                                ),
                                HeapProofStep(
                                    "allocate-target",
                                    f"obtain a chunk at {goal.target:#x}",
                                ),
                            ),
                            prerequisites=prerequisites,
                            assumptions=state.model.assumptions,
                            rejected_alternatives=tuple(rejected),
                            reliability="conditional",
                            cost=4,
                        )
                    )

        if goal.kind == "overlap-storage":
            double = next(
                (item for item in available if isinstance(item, DoubleFree)),
                None,
            )
            if state.model.tcache and double and state.model.version >= (2, 29):
                proofs.append(
                    TechniqueProof(
                        "glibc tcache/unsorted consolidation overlap",
                        goal.kind,
                        (
                            HeapProofStep("fill-cache", "fill the declared size class"),
                            HeapProofStep("consolidate", "merge adjacent free chunks"),
                            HeapProofStep("reinsert", "reinsert an aliased chunk"),
                        ),
                        prerequisites=(double.capability(),),
                        assumptions=state.model.assumptions,
                        reliability="conditional",
                        cost=7,
                    )
                )
        return tuple(sorted(proofs, key=lambda item: (item.cost, item.strategy)))

    def prove(
        self,
        goal: HeapGoal,
        state: HeapState,
        capabilities: Iterable[HeapPrimitive],
    ) -> TechniqueProof:
        candidates = self.candidates(goal, state, capabilities)
        if not candidates:
            supplied = ", ".join(sorted(item.name for item in capabilities)) or "none"
            raise PlanningError(
                f"no heap capability proof satisfies {goal.kind}; supplied: {supplied}"
            )
        return candidates[0]


def safe_link_pointer(model: AllocatorModel, field_address: int, target: int) -> int:
    return model.encode_link(field_address, target)

