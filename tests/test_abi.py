from __future__ import annotations

import pytest

from pwnx.abi import (
    ABIField,
    LINUX_AMD64,
    LINUX_I386,
    LINUX_MIPS,
    LINUX_MIPSEL,
    WINDOWS_X64,
    StructSchema,
    target_abi,
)
from pwnx.architecture import AMD64
from pwnx.codecs import word
from pwnx.errors import ConstraintError, UnsupportedFeature


def test_abi_resolution_is_explicit_and_has_no_ambient_context() -> None:
    assert target_abi("linux-amd64") is LINUX_AMD64
    assert target_abi("amd64") is LINUX_AMD64
    assert target_abi(AMD64) is LINUX_AMD64
    assert target_abi(WINDOWS_X64) is WINDOWS_X64
    with pytest.raises(UnsupportedFeature, match="unsupported ABI"):
        target_abi("plan9-sparc")
    assert LINUX_AMD64.version == "1"
    assert len(LINUX_AMD64.identity) == 64
    assert LINUX_AMD64.identity != WINDOWS_X64.identity


def test_call_layout_expresses_target_side_placement() -> None:
    call = LINUX_AMD64.call((1, 2, 3, 4, 5, 6, 7))
    assert dict(call.registers) == {
        "rdi": 1,
        "rsi": 2,
        "rdx": 3,
        "rcx": 4,
        "r8": 5,
        "r9": 6,
    }
    assert call.stack == (7,)
    assert call.stack_alignment == 16

    stack_call = LINUX_I386.call(("first", "second"))
    assert dict(stack_call.registers) == {}
    assert stack_call.stack == ("first", "second")

    windows_call = WINDOWS_X64.call((1, 2, 3, 4, 5))
    assert dict(windows_call.registers) == {"rcx": 1, "rdx": 2, "r8": 3, "r9": 4}
    assert windows_call.stack == (5,)
    assert windows_call.shadow_space == 32


def test_syscall_layout_resolves_names_and_validates_capacity() -> None:
    invocation = LINUX_AMD64.syscall("SYS_write", (1, 0x404000, 8))
    assert dict(invocation.registers) == {
        "rax": 1,
        "rdi": 1,
        "rsi": 0x404000,
        "rdx": 8,
    }
    with pytest.raises(ConstraintError, match="at most"):
        LINUX_AMD64.syscall(1, tuple(range(7)))
    with pytest.raises(UnsupportedFeature, match="syscall ABI"):
        WINDOWS_X64.syscall(1)
    with pytest.raises(UnsupportedFeature, match="does not declare constant"):
        LINUX_AMD64.syscall("SYS_not_real")


def test_struct_schemas_pack_sparse_fields_and_unpack_immutably() -> None:
    schema = LINUX_AMD64.schema("sigaction")
    assert schema.version == "1"
    assert len(schema.identity) == 64
    encoded = schema.pack({"handler": 0x401000, "flags": 4})
    decoded = schema.unpack(encoded)
    assert decoded["handler"] == 0x401000
    assert decoded["flags"] == 4
    assert decoded["mask"] == 0
    with pytest.raises(TypeError):
        decoded["mask"] = 1
    with pytest.raises(ConstraintError, match="no field"):
        schema.pack({"unknown": 1})
    with pytest.raises(ConstraintError, match="requires"):
        schema.unpack(b"short")


def test_schema_definition_rejects_overlap_duplicate_and_overflow() -> None:
    with pytest.raises(ValueError, match="overlaps"):
        StructSchema(
            "bad",
            8,
            (ABIField("a", 0, word(32)), ABIField("b", 2, word(32))),
        )
    with pytest.raises(ValueError, match="duplicate"):
        StructSchema(
            "bad",
            8,
            (ABIField("a", 0, word(32)), ABIField("a", 4, word(32))),
        )
    with pytest.raises(ValueError, match="exceeds"):
        StructSchema("bad", 4, (ABIField("a", 1, word(32)),))


def test_endianness_and_pointer_width_are_properties_of_the_selected_abi() -> None:
    value = 0x01020304
    assert LINUX_MIPS.pointer().build(value) == b"\x01\x02\x03\x04"
    assert LINUX_MIPSEL.pointer().build(value) == b"\x04\x03\x02\x01"
    assert LINUX_AMD64.pointer_size == 8
    assert LINUX_I386.pointer_size == 4
    assert LINUX_AMD64.constant("SYS_execve") == 59


def test_os_specific_schemas_do_not_claim_false_portability() -> None:
    sigreturn = LINUX_AMD64.schema("rt_sigreturn")
    assert sigreturn.size == 248
    assert sigreturn.version == "linux-amd64-rt-sigframe-v1"
    assert sigreturn.field("rdi").offset == 104
    assert sigreturn.field("rip").offset == 168
    with pytest.raises(UnsupportedFeature, match="rt_sigreturn"):
        LINUX_I386.schema("rt_sigreturn")
    assert WINDOWS_X64.schema("unicode_string").size == 16
    with pytest.raises(UnsupportedFeature, match="does not declare schema"):
        WINDOWS_X64.schema("dirent64")
    with pytest.raises(UnsupportedFeature, match="does not declare constant"):
        WINDOWS_X64.constant("SYS_read")
