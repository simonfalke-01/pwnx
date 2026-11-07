from dataclasses import replace

import pytest

from pwnx.domain import Evidence
from pwnx.errors import ConstraintError, PlanningError
from pwnx.heap import (
    AllocatorModel,
    ArbitraryWrite,
    DanglingRead,
    DoubleFree,
    HeapAddressKnowledge,
    HeapGoal,
    HeapState,
    HeapTechniqueRegistry,
    UseAfterFree,
    safe_link_pointer,
)


def evidence(summary):
    return (Evidence("primitive", summary, "test"),)


def test_versioned_models_and_safe_linking_are_explicit():
    old = AllocatorModel.glibc("2.31")
    new = AllocatorModel.glibc("2.35")
    assert old.safe_linking is False and old.hooks is True
    assert new.safe_linking is True and new.hooks is False
    assert safe_link_pointer(old, 0x55555000, 0x404040) == 0x404040
    encoded = safe_link_pointer(new, 0x55555000, 0x404040)
    assert new.decode_link(0x55555000, encoded) == 0x404040
    with pytest.raises(ValueError):
        AllocatorModel.glibc("2.33")


def test_glibc_tcache_boundary_is_versioned_and_consistent():
    model = AllocatorModel.glibc("2.35")
    assert model.tcache_max == 0x410
    assert model.normalize_size(0x408) == 0x410
    assert model.tcache_eligible(0x408)
    assert not model.tcache_eligible(0x409)
    assert model.tcache_eligible(0x410, normalized=True)
    assert not model.tcache_eligible(0x420, normalized=True)


def test_heap_free_uses_model_tcache_eligibility_and_capacity():
    model = AllocatorModel.glibc("2.35")
    eligible = HeapState(model).allocate("eligible", 0x408).free("eligible")
    assert eligible.chunks["eligible"].bin_name == "tcache"

    ineligible = HeapState(model).allocate("large", 0x409).free("large")
    assert ineligible.chunks["large"].size == 0x420
    assert ineligible.chunks["large"].bin_name == "unsorted"

    full = HeapState(model)
    for index in range(model.tcache_count + 1):
        full = full.allocate(f"chunk{index}", 0x100)
    for index in range(model.tcache_count + 1):
        full = full.free(f"chunk{index}")
    assert full.chunks[f"chunk{model.tcache_count}"].bin_name == "unsorted"

    no_tcache = replace(model, tcache=False, tcache_max=None)
    fast = HeapState(no_tcache).allocate("fast", 0x409).free("fast")
    assert fast.chunks["fast"].bin_name == "fastbin"


def test_immutable_transitions_reject_undeclared_uaf_and_double_free():
    state = HeapState(AllocatorModel.glibc("2.35"))
    allocated = state.allocate("a", 0x30, b"secret")
    assert not state.chunks and allocated.chunks["a"].allocated
    freed = allocated.free("a")
    with pytest.raises(ConstraintError, match="already free"):
        freed.free("a")
    with pytest.raises(ConstraintError, match="declare DanglingRead"):
        freed.show("a")
    with pytest.raises(ConstraintError, match="declare UseAfterFree"):
        freed.edit("a", b"x")

    read = DanglingRead("dangling read", "a", evidence=evidence("show-after-free"))
    assert freed.show("a", capability=read)[0] == b"secret"
    uaf = UseAfterFree("use-after-free write", "a", evidence=evidence("edit-after-free"))
    edited = freed.edit("a", b"controlled", capability=uaf)
    assert edited.chunks["a"].data == b"controlled"
    double = DoubleFree("repeat free", "a", evidence=evidence("free-after-free"))
    repeated = freed.free("a", capability=double)
    assert repeated.chunks["a"].free_count == 2


def test_reuse_creates_alias_and_consolidation_requires_adjacency():
    state = HeapState(AllocatorModel.glibc("2.31"))
    state = state.allocate("a", 0x30).allocate("b", 0x30)
    state = state.free("a")
    state = state.allocate("alias", 0x30)
    overlap = state.overlap("a", "alias")
    assert overlap is not None and overlap.size == state.chunks["a"].size
    state = state.free("alias").free("b")
    consolidated, proof = state.consolidate("alias", "b")
    assert proof.size == state.chunks["alias"].size + state.chunks["b"].size
    assert consolidated.history[-1].operation == "consolidate"


def test_technique_selection_checks_safe_linking_and_capabilities():
    state = HeapState(AllocatorModel.glibc("2.35"))
    uaf = UseAfterFree("uaf", "a", evidence=evidence("dangling edit"))
    goal = HeapGoal("write-memory", target=0x404040)
    registry = HeapTechniqueRegistry()
    with pytest.raises(PlanningError, match="no heap capability proof"):
        registry.prove(goal, state, [uaf])

    address = HeapAddressKnowledge(
        "heap address known", address=0x55555000, evidence=evidence("heap leak")
    )
    proof = registry.prove(goal, state, [uaf, address])
    assert proof.strategy == "glibc tcache forward-pointer control"
    assert any(step.operation == "encode-link" for step in proof.actions)
    assert proof.assumptions

    direct = ArbitraryWrite(
        "arbitrary write", address=0x404040, size=8, evidence=evidence("primitive")
    )
    assert registry.prove(goal, state, [direct]).strategy.startswith("direct")


def test_overlap_goal_exposes_internal_technique_only_in_proof():
    state = HeapState(AllocatorModel.glibc("2.39"))
    double = DoubleFree("double-free", "a", evidence=evidence("repeat free"))
    proof = HeapTechniqueRegistry().prove(
        HeapGoal("overlap-storage"), state, [double]
    )
    assert "consolidation overlap" in proof.strategy
    assert proof.goal == "overlap-storage"

