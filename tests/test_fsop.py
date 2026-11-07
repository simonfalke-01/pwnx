import pytest

from pwnx.domain import Capability, EffectContract, Evidence, Scope
from pwnx.errors import ConstraintError, PlanningError
from pwnx.expressions import BindingContext
from pwnx.fsop import (
    FILELayout,
    FSOPAction,
    FSOPContext,
    FSOPProvider,
    FileObject,
    StreamCapability,
    glibc_file_layout,
)


def write_capability():
    return Capability(
        "arbitrary write",
        EffectContract(writes=frozenset({"process.memory"})),
        reliability="stable",
    )


def test_versioned_file_layout_and_labelled_payload():
    layout = glibc_file_layout("2.35")
    assert layout.field("_IO_write_ptr").offset == 0x28
    assert layout.wide_data_vtable_offset == 0xE0
    assert layout.wide_vtable_call_offset == 0x68
    file = FileObject(layout, {"_flags": 0xFBAD1800, "_lock": 0x404800})
    payload = file.payload()
    raw = payload.build(BindingContext())
    assert int.from_bytes(raw[:8], "little") == 0xFBAD1800
    labels = {row["label"] for row in payload.layout()}
    assert "FILE._flags" in labels and "FILE._lock" in labels
    with pytest.raises(ConstraintError, match="no field"):
        FileObject(layout, {"made_up": 1})
    with pytest.raises(ValueError):
        glibc_file_layout("2.33")


def test_fsop_leak_and_write_are_capability_proofs():
    provider = FSOPProvider(glibc_file_layout("2.35"))
    context = FSOPContext(
        file_address=0x505000,
        lock=0x7F001000,
        vtable=0x7F002000,
        target=0x7FFF0000,
        size=8,
    )
    leak = provider.prove(
        StreamCapability(
            "leak stack", "leak-range", target=0x7FFF0000, size=8,
            evidence=(Evidence("goal", "read environ"),),
        ),
        arbitrary_write=write_capability(),
        context=context,
    )
    raw = leak.payload.build(BindingContext())
    assert int.from_bytes(raw[0x20:0x28], "little") == 0x7FFF0000
    assert int.from_bytes(raw[0x28:0x30], "little") == 0x7FFF0008
    assert leak.proof.strategy == "glibc stdout buffer disclosure"
    action = FSOPAction(leak)
    assert "stdout" in action.describe()
    assert action.execute(None) == leak.writes
    assert action.execute(None)[0].payload is leak.payload

    write = provider.prove(
        StreamCapability("write memory", "write-range", target=0x404000, size=0x20),
        arbitrary_write=write_capability(),
        context=context,
    )
    assert write.proof.strategy == "glibc stdin buffer redirection"


def test_fsop_rejects_capabilities_without_process_memory_write_semantics():
    provider = FSOPProvider(glibc_file_layout("2.35"))
    goal = StreamCapability("leak", "leak-range", target=0x404000, size=8)
    context = FSOPContext(0x500000, 0x600000, 0x700000)

    read_only = Capability(
        "arbitrary read",
        EffectContract(reads=frozenset({"process.memory"})),
    )
    with pytest.raises(PlanningError, match="writes process.memory"):
        provider.prove(goal, arbitrary_write=read_only, context=context)

    unrelated = Capability(
        "heap edit",
        EffectContract(writes=frozenset({"process.heap"})),
    )
    with pytest.raises(PlanningError, match="writes process.memory"):
        provider.prove(goal, arbitrary_write=unrelated, context=context)

    wrong_scope = Capability(
        "service memory write",
        EffectContract(
            writes=frozenset({"process.memory"}),
            scope=Scope.SERVICE,
        ),
    )
    with pytest.raises(PlanningError, match="process-scoped"):
        provider.prove(goal, arbitrary_write=wrong_scope, context=context)


def test_controlled_call_rejects_missing_or_validated_wide_state():
    capability = write_capability()
    legacy = FSOPProvider(glibc_file_layout("2.35"))
    with pytest.raises(PlanningError, match="wide-data"):
        legacy.prove(
            StreamCapability("call", "controlled-call", call_target=0x401000),
            arbitrary_write=capability,
            context=FSOPContext(0x500000, 0x600000, 0x700000),
        )
    with pytest.raises(PlanningError, match="wide-vtable"):
        legacy.prove(
            StreamCapability("call", "controlled-call", call_target=0x401000),
            arbitrary_write=capability,
            context=FSOPContext(
                0x500000,
                0x600000,
                0x700000,
                wide_data=0x800000,
            ),
        )

    controlled = legacy.prove(
        StreamCapability("call", "controlled-call", call_target=0x401000),
        arbitrary_write=capability,
        context=FSOPContext(
            0x500000,
            0x600000,
            0x700000,
            wide_data=0x800000,
            wide_vtable=0x810000,
        ),
    )
    assert [item.role for item in controlled.writes] == [
        "FILE",
        "wide-data",
        "wide-vtable",
    ]
    assert [item.address for item in controlled.writes] == [
        0x500000,
        0x800000,
        0x810000,
    ]
    file_raw, wide_data_raw, wide_vtable_raw = (
        item.payload.build(BindingContext()) for item in controlled.writes
    )
    assert int.from_bytes(file_raw[0xA0:0xA8], "little") == 0x800000
    assert int.from_bytes(file_raw[0x28:0x30], "little") == 1
    assert int.from_bytes(wide_data_raw[0xE0:0xE8], "little") == 0x810000
    assert int.from_bytes(wide_vtable_raw[0x68:0x70], "little") == 0x401000
    labels = {
        row["label"]
        for item in controlled.writes
        for row in item.payload.layout()
    }
    assert "wide_data._wide_vtable" in labels
    assert "wide_vtable.__doallocate" in labels

    modern = FSOPProvider(glibc_file_layout("2.39"))
    with pytest.raises(PlanningError, match="validates wide vtables"):
        modern.prove(
            StreamCapability("call", "controlled-call", call_target=0x401000),
            arbitrary_write=capability,
            context=FSOPContext(
                0x500000,
                0x600000,
                0x700000,
                wide_data=0x800000,
                wide_vtable=0x810000,
            ),
        )


def test_layout_rejects_out_of_range_fields():
    with pytest.raises(ValueError, match="outside"):
        FILELayout(
            "x",
            (1, 0),
            8,
            {"bad": __import__("pwnx.fsop", fromlist=["FILEField"]).FILEField("bad", 8)},
            False,
            False,
        )
