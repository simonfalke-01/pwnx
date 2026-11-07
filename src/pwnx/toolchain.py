"""Explicit, optional native toolchain integration.

The compiler backend is intentionally outside Challenge context.  Every call
names its architecture and the resulting bytes can be retained as a labelled
Payload, so assembly never depends on mutable ambient configuration.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import Mapping

from .errors import UnsupportedFeature
from .payload import Payload


_ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
_SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")


def _default_cache() -> Path:
    root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return root / "pwnx" / "toolchain"


def _resolve_tool(value: str | os.PathLike[str] | None, default: str) -> str:
    requested = os.fspath(value) if value is not None else default
    resolved = shutil.which(requested)
    if resolved is None:
        raise UnsupportedFeature(
            f"required tool {requested!r} was not found; install a Clang/GNU toolchain "
            "or pass its executable path explicitly"
        )
    return resolved


def _run(
    argv: list[str],
    *,
    input_: bytes | None = None,
    operation: str,
) -> bytes:
    try:
        result = subprocess.run(
            argv,
            input=input_,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise UnsupportedFeature(f"{operation} could not start {argv[0]!r}: {error}") from error
    if result.returncode:
        diagnostic = result.stderr.decode("utf-8", "replace").strip()
        raise UnsupportedFeature(
            f"{operation} failed with status {result.returncode}: "
            f"{diagnostic or '<no diagnostic>'}"
        )
    return result.stdout


def _cstring(data: bytes, offset: int) -> str:
    if not 0 <= offset < len(data):
        raise UnsupportedFeature("toolchain produced a malformed ELF string table")
    end = data.find(b"\0", offset)
    if end < 0:
        raise UnsupportedFeature("toolchain produced an unterminated ELF section name")
    return data[offset:end].decode("ascii", "replace")


def _elf_text(data: bytes) -> bytes:
    if len(data) < _ELF_HEADER.size:
        raise UnsupportedFeature("assembler output is not a complete ELF object")
    header = _ELF_HEADER.unpack_from(data)
    ident = header[0]
    if ident[:6] != b"\x7fELF\x02\x01":
        raise UnsupportedFeature("assembler did not produce ELF64 little-endian output")
    shoff = header[6]
    shentsize, shnum, shstrndx = header[11:14]
    if shentsize < _SECTION_HEADER.size or not shnum or shstrndx >= shnum:
        raise UnsupportedFeature("assembler output has malformed ELF section metadata")

    sections: list[tuple[int, ...]] = []
    for index in range(shnum):
        offset = shoff + index * shentsize
        if offset + _SECTION_HEADER.size > len(data):
            raise UnsupportedFeature("assembler output has a truncated section table")
        sections.append(_SECTION_HEADER.unpack_from(data, offset))

    strings = sections[shstrndx]
    string_offset, string_size = strings[4], strings[5]
    if string_offset + string_size > len(data):
        raise UnsupportedFeature("assembler output has a truncated section-name table")
    names = data[string_offset : string_offset + string_size]

    text: bytes | None = None
    relocations = False
    for section in sections:
        name = _cstring(names, section[0]) if section[0] else ""
        offset, size = section[4], section[5]
        if offset + size > len(data):
            raise UnsupportedFeature(f"assembler output section {name!r} is truncated")
        if name == ".text":
            text = data[offset : offset + size]
        elif name in {".rel.text", ".rela.text"} and size:
            relocations = True
    if text is None:
        raise UnsupportedFeature("assembler output contains no .text section")
    if relocations:
        raise UnsupportedFeature(
            "assembly contains unresolved relocations; use position-independent local "
            "labels or provide fully resolved instruction operands"
        )
    return text


def _store(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


@dataclass(frozen=True)
class Toolchain:
    """A target-explicit assembler, disassembler, and preprocessor."""

    arch: str = "amd64"
    os: str = "linux"
    endian: str = "little"
    clang: str | PathLike[str] | None = None
    objdump: str | PathLike[str] | None = None
    cache_dir: str | PathLike[str] | None = None

    def __post_init__(self) -> None:
        normalized = {"amd64": "amd64", "x86_64": "amd64"}.get(self.arch)
        if normalized is None:
            raise UnsupportedFeature(
                f"toolchain architecture {self.arch!r} is unsupported; current backend is amd64"
            )
        if self.os != "linux":
            raise UnsupportedFeature(
                f"toolchain OS {self.os!r} is unsupported; current backend is linux"
            )
        if self.endian != "little":
            raise UnsupportedFeature("AMD64 toolchain supports little-endian output only")
        object.__setattr__(self, "arch", normalized)

    @property
    def target(self) -> str:
        return "x86_64-unknown-linux-gnu"

    @property
    def cache_path(self) -> Path:
        return Path(self.cache_dir) if self.cache_dir is not None else _default_cache()

    def _clang(self) -> str:
        if self.clang is not None:
            return _resolve_tool(self.clang, "clang")
        for candidate in ("clang", "gcc", "cc"):
            resolved = shutil.which(candidate)
            if resolved is not None:
                return resolved
        raise UnsupportedFeature(
            "no assembler compiler was found; install clang or gcc, or pass clang=..."
        )

    def _objdump(self) -> str:
        return _resolve_tool(self.objdump, "objdump")

    def _version(self, executable: str) -> str:
        output = _run([executable, "--version"], operation="tool version")
        return output.decode("utf-8", "replace").splitlines()[0]

    def _compiler_target_flags(self, compiler: str) -> list[str]:
        version = self._version(compiler).lower()
        if "clang" in version:
            return [f"--target={self.target}"]
        machine = _run([compiler, "-dumpmachine"], operation="compiler target").decode(
            "ascii", "replace"
        ).strip()
        if not (machine.startswith("x86_64") or machine.startswith("amd64")):
            raise UnsupportedFeature(
                f"GNU compiler targets {machine!r}; install Clang for AMD64 cross assembly"
            )
        return ["-m64"]

    def _key(self, operation: str, source: bytes, options: tuple[object, ...]) -> str:
        clang = self._clang()
        material = repr(
            (
                operation,
                self.arch,
                self.os,
                self.endian,
                options,
                self._version(clang),
            )
        ).encode() + b"\0" + source
        return hashlib.sha256(material).hexdigest()

    def asm(
        self,
        source: str | bytes,
        *,
        vma: int = 0,
        syntax: str = "intel",
        extract: bool = True,
    ) -> bytes:
        """Assemble AMD64 Linux source.

        VMA is provenance for raw extraction. Local relative labels are
        supported; unresolved absolute relocations are rejected rather than
        silently encoded with zeroes.
        """

        if not isinstance(vma, int) or vma < 0:
            raise ValueError("assembly VMA must be a non-negative integer")
        if syntax not in {"intel", "att"}:
            raise ValueError("assembly syntax must be 'intel' or 'att'")
        raw_source = source.encode() if isinstance(source, str) else bytes(source)
        preamble = (
            b".text\n.globl _pwnx_entry\n.type _pwnx_entry,@function\n"
            + (b".intel_syntax noprefix\n" if syntax == "intel" else b".att_syntax\n")
            + b"_pwnx_entry:\n"
        )
        complete = preamble + raw_source + b"\n"
        key = self._key("asm", complete, (vma, syntax, extract))
        cache = self.cache_path
        cached = cache / f"{key}.{'bin' if extract else 'o'}"
        if cached.is_file():
            return cached.read_bytes()

        compiler = self._clang()
        with tempfile.TemporaryDirectory(prefix="pwnx-asm-") as temporary:
            output = Path(temporary) / "shellcode.o"
            _run(
                [
                    compiler,
                    *self._compiler_target_flags(compiler),
                    "-c",
                    "-x",
                    "assembler",
                    "-o",
                    os.fspath(output),
                    "-",
                ],
                input_=complete,
                operation="assembly",
            )
            object_data = output.read_bytes()
        result = _elf_text(object_data) if extract else object_data
        _store(cached, result)
        return result

    def payload(
        self,
        source: str | bytes,
        *,
        vma: int = 0,
        syntax: str = "intel",
        label: str = "assembled amd64 shellcode",
    ) -> Payload:
        return Payload().append(
            self.asm(source, vma=vma, syntax=syntax),
            label=label,
        )

    def disasm(self, data: bytes, *, vma: int = 0, syntax: str = "intel") -> str:
        if not isinstance(vma, int) or vma < 0:
            raise ValueError("disassembly VMA must be a non-negative integer")
        raw = bytes(data)
        if not raw:
            return ""
        byte_source = ".byte " + ", ".join(f"0x{byte:02x}" for byte in raw)
        compiler = self._clang()
        disassembler = self._objdump()
        key = self._key(
            "disasm",
            raw,
            (vma, syntax, self._version(disassembler)),
        )
        cached = self.cache_path / f"{key}.txt"
        if cached.is_file():
            return cached.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="pwnx-disasm-") as temporary:
            output = Path(temporary) / "bytes.o"
            complete = (
                ".text\n.globl _pwnx_entry\n.type _pwnx_entry,@function\n"
                "_pwnx_entry:\n" + byte_source + "\n"
            ).encode()
            _run(
                [
                    compiler,
                    *self._compiler_target_flags(compiler),
                    "-c",
                    "-x",
                    "assembler",
                    "-o",
                    os.fspath(output),
                    "-",
                ],
                input_=complete,
                operation="disassembly preparation",
            )
            argv = [
                disassembler,
                "-d",
                f"--adjust-vma={vma}",
            ]
            if syntax == "intel":
                argv.extend(["-M", "intel"])
            elif syntax != "att":
                raise ValueError("disassembly syntax must be 'intel' or 'att'")
            argv.append(os.fspath(output))
            rendered = _run(argv, operation="disassembly").decode("utf-8", "replace")
        lines = [
            line.rstrip()
            for line in rendered.splitlines()
            if re.match(r"^\s*[0-9a-fA-F]+:\s+", line)
        ]
        result = "\n".join(lines)
        _store(cached, result.encode())
        return result

    def cpp(
        self,
        source: str | bytes,
        *,
        defines: Mapping[str, str | int | None] | None = None,
    ) -> str:
        raw = source.encode() if isinstance(source, str) else bytes(source)
        definitions = tuple(sorted((defines or {}).items()))
        key = self._key("cpp", raw, definitions)
        cached = self.cache_path / f"{key}.txt"
        if cached.is_file():
            return cached.read_text(encoding="utf-8")
        compiler = self._clang()
        argv = [
            compiler,
            *self._compiler_target_flags(compiler),
            "-E",
            "-P",
            "-x",
            "c",
        ]
        for name, value in definitions:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ValueError(f"invalid preprocessor name {name!r}")
            argv.append(f"-D{name}" if value is None else f"-D{name}={value}")
        argv.append("-")
        result = _run(argv, input_=raw, operation="preprocessing").decode(
            "utf-8", "replace"
        )
        _store(cached, result.encode())
        return result


def asm(
    source: str | bytes,
    *,
    arch: str = "amd64",
    os: str = "linux",
    endian: str = "little",
    vma: int = 0,
    syntax: str = "intel",
    cache_dir: str | PathLike[str] | None = None,
) -> bytes:
    return Toolchain(arch, os, endian, cache_dir=cache_dir).asm(
        source, vma=vma, syntax=syntax
    )


def disasm(
    data: bytes,
    *,
    arch: str = "amd64",
    os: str = "linux",
    endian: str = "little",
    vma: int = 0,
    syntax: str = "intel",
) -> str:
    return Toolchain(arch, os, endian).disasm(data, vma=vma, syntax=syntax)


def cpp(
    source: str | bytes,
    *,
    arch: str = "amd64",
    os: str = "linux",
    endian: str = "little",
    defines: Mapping[str, str | int | None] | None = None,
) -> str:
    return Toolchain(arch, os, endian).cpp(source, defines=defines)

