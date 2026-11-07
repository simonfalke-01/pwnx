from __future__ import annotations

import platform
import subprocess
import sys

import pytest

from pwnx.errors import ConstraintError
from pwnx.shellcode import AMD64LinuxShellcode, shellcode


def labels(payload) -> list[str]:
    return [row["label"] for row in payload.layout()]


def test_generic_syscall_is_explicit_and_labelled() -> None:
    payload = shellcode.syscall(1, 2, 0x404000, 7)
    raw = payload.build()

    assert raw.startswith(b"\x48\xb8" + (1).to_bytes(8, "little"))
    assert raw.endswith(b"\x0f\x05")
    assert labels(payload) == [
        "rax = syscall 1",
        "rdi = argument 0",
        "rsi = argument 1",
        "rdx = argument 2",
        "syscall",
    ]
    with pytest.raises(ValueError, match="at most six"):
        shellcode.syscall(1, *range(7))
    with pytest.raises(ConstraintError, match="64 bits"):
        shellcode.syscall(1 << 65)


def test_sh_is_null_free_and_execve_is_inspectable() -> None:
    sh = shellcode.sh()
    assert b"\0" not in sh.build()
    assert sh.build().endswith(b"\x0f\x05")
    assert "push /bin//sh" in labels(sh)
    assert "SYS_execve is permitted" in sh.assumptions

    custom = shellcode.execve("/tmp/tool")
    assert b"/tmp/too" in custom.build()
    assert labels(custom)[-1] == "execve syscall"


def test_read_write_open_and_orw_have_correct_syscall_flow() -> None:
    assert shellcode.read(0, 0x404000, 0x80).build().endswith(b"\x0f\x05")
    assert shellcode.write(1, 0x404000, 0x80).build().endswith(b"\x0f\x05")

    opened = shellcode.openat("/flag")
    assert "rax = SYS_openat" in labels(opened)
    assert opened.build().count(b"\x0f\x05") == 1

    cat = shellcode.cat("/flag", buffer=0x404000, count=0x100)
    assert cat.build().count(b"\x0f\x05") == 3
    assert labels(cat)[-1] == "write file"
    assert "memory at 0x404000 is writable for 0x100 bytes" in cat.assumptions
    assert shellcode.orw("/flag", buffer=0x404000).build() == cat.build()


def test_negative_immediates_are_twos_complement() -> None:
    payload = shellcode.openat("/x", dirfd=-100)
    encoded = (-100 & ((1 << 64) - 1)).to_bytes(8, "little")
    assert encoded in payload.build()


def test_constructor_is_stateless() -> None:
    other = AMD64LinuxShellcode()
    assert other.exit(3).build() == shellcode.exit(3).build()


@pytest.mark.skipif(
    platform.system() != "Linux" or platform.machine() != "x86_64",
    reason="executes Linux AMD64 machine code",
)
def test_exit_shellcode_executes_with_requested_status() -> None:
    code = shellcode.exit(37).build().hex()
    program = f"""
import ctypes
import mmap
code = bytes.fromhex({code!r})
memory = mmap.mmap(
    -1, len(code),
    prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
)
memory.write(code)
address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
ctypes.CFUNCTYPE(None)(address)()
"""
    result = subprocess.run([sys.executable, "-c", program], check=False)
    assert result.returncode == 37

