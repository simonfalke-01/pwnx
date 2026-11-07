#!/usr/bin/env python3
"""Inventory, validate, query, and safely run the pwn challenge corpus."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
from typing import Any, Iterable, Literal, Mapping, Sequence


DEFAULT_ROOT = Path(
    os.environ.get("PWNX_CHALLENGE_ROOT", "/Users/brandonli/Downloads/pwn-challenges")
)
REPOSITORY = Path(__file__).resolve().parents[1]
DEFAULT_MATRIX = REPOSITORY / "corpus" / "coverage.csv"
DEFAULT_OVERRIDES = REPOSITORY / "corpus" / "overrides.json"

FIELDS = (
    "id",
    "event",
    "name",
    "path",
    "architecture",
    "format",
    "artifacts",
    "binary",
    "libc",
    "loader",
    "source",
    "docker",
    "existing_solve",
    "writeup",
    "purpose_families",
    "pwnx_solve",
    "pwnx_status",
    "native_status",
    "native_evidence",
    "missing_primitive",
    "priority",
    "environment",
    "workdir",
    "run_command",
    "notes",
)

STATUS_VALUES = frozenset({"not_started", "implemented", "verified", "artifact_missing"})
NATIVE_VALUES = frozenset({"not_run", "verified", "unavailable", "failed"})
PRIORITY_VALUES = frozenset({"low", "medium", "high", "critical"})

TEXT_SUFFIXES = frozenset(
    {
        ".c", ".cc", ".cpp", ".cxx", ".rs", ".s", ".asm", ".sh",
        ".py", ".js", ".md", ".txt",
    }
)
SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".rs", ".s", ".asm", ".js"})

ARCHITECTURES = {
    3: "i386",
    8: "mips",
    40: "arm",
    62: "amd64",
    183: "aarch64",
    243: "riscv64",
}


class CorpusError(RuntimeError):
    pass


def _relative_path(value: str, *, what: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not value or any(part == ".." for part in path.parts):
        raise CorpusError(f"{what} must be a non-empty relative path without '..': {value!r}")
    return path


def _contained(root: Path, value: Path) -> Path:
    resolved_root = root.resolve()
    resolved = value.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise CorpusError(f"path escapes corpus root: {value}")
    return resolved


def _split(value: str) -> list[str]:
    return [item for item in value.split(";") if item]


def _json_list(value: str) -> list[str]:
    try:
        result = json.loads(value or "[]")
    except json.JSONDecodeError as error:
        raise CorpusError(f"invalid run_command JSON: {value!r}") from error
    if not isinstance(result, list) or not all(isinstance(item, str) for item in result):
        raise CorpusError("run_command must be a JSON array of strings")
    return result


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _validate_manifest(root: Path, rows: Sequence[Mapping[str, str]]) -> None:
    required = {"path", "bytes", "sha256", "mode", "type", "link_target"}
    for index, row in enumerate(rows, start=2):
        missing = sorted(required - set(row))
        if missing:
            raise CorpusError(f"manifest row {index} missing fields: {missing}")
        relative = _relative_path(row["path"], what=f"manifest row {index} path")
        try:
            size = int(row["bytes"])
            mode = int(row["mode"], 0)
        except ValueError as error:
            raise CorpusError(f"manifest row {index} has invalid bytes/mode") from error
        if size < 0 or mode < 0:
            raise CorpusError(f"manifest row {index} has negative bytes/mode")
        if row["type"] not in {"file", "symlink"}:
            raise CorpusError(f"manifest row {index} has unsupported type {row['type']!r}")
        candidate = root / relative
        if row["type"] == "file":
            _contained(root, candidate)
        elif not row["link_target"]:
            raise CorpusError(f"manifest row {index} symlink is missing link_target")


def _write_csv(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in FIELDS})


def _load_overrides(path: Path) -> Mapping[str, Mapping[str, Any]]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise CorpusError("corpus overrides must be an object keyed by challenge path")
    return data


def _artifact_kind(path: Path) -> tuple[str, str]:
    try:
        data = path.read_bytes()[:0x1000]
    except OSError:
        return "unknown", "unknown"
    if data.startswith(b"\x7fELF") and len(data) >= 20:
        bits = "ELF64" if data[4] == 2 else "ELF32" if data[4] == 1 else "ELF"
        endian: Literal["little", "big"] = "little" if data[5] == 1 else "big"
        machine = int.from_bytes(data[18:20], endian)
        architecture = ARCHITECTURES.get(machine, f"elf-machine-{machine}")
        return bits, architecture
    if data.startswith(b"MZ") and len(data) >= 0x40:
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if pe_offset + 6 <= len(data) and data[pe_offset : pe_offset + 4] == b"PE\0\0":
            machine = int.from_bytes(data[pe_offset + 4 : pe_offset + 6], "little")
            architecture = {
                0x14C: "i386-pe",
                0x8664: "amd64-pe",
                0xAA64: "aarch64-pe",
            }.get(machine, f"pe-machine-{machine}")
            return "PE", architecture
    if data[:4] in {
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
    }:
        return "Mach-O", "macos"
    return "other", "unknown"


def _is_loader(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith("ld-") or "ld-linux" in lowered or lowered == "ld"


def _is_libc(name: str) -> bool:
    lowered = name.lower()
    return "libc" in lowered and (lowered.endswith(".so") or ".so." in lowered)


def _dedupe_manifest(rows: Sequence[Mapping[str, str]]) -> list[Mapping[str, str]]:
    """Keep the shortest source path for identical nested artifacts."""

    selected: dict[tuple[str, str], Mapping[str, str]] = {}
    for row in rows:
        key = (row.get("sha256", ""), row.get("type", ""))
        current = selected.get(key)
        if current is None or (len(row["path"]), row["path"]) < (
            len(current["path"]),
            current["path"],
        ):
            selected[key] = row
    return sorted(selected.values(), key=lambda row: row["path"])


def _challenge_manifest(
    manifest: Sequence[Mapping[str, str]], challenge_path: str, root: Path
) -> list[Mapping[str, str]]:
    prefix = challenge_path.rstrip("/") + "/"
    rows: list[Mapping[str, str]] = [
        row for row in manifest if row["path"].startswith(prefix)
    ]
    known = {row["path"] for row in rows}
    directory = root / challenge_path
    if directory.is_dir():
        for path in sorted(directory.rglob("*")):
            if not path.is_file() and not path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if relative in known or "__pycache__" in path.parts or path.name == ".DS_Store":
                continue
            if path.is_symlink():
                rows.append(
                    {
                        "path": relative,
                        "bytes": "0",
                        "sha256": f"symlink:{os.readlink(path)}",
                        "mode": oct(path.lstat().st_mode & 0o777),
                        "type": "symlink",
                        "link_target": os.readlink(path),
                    }
                )
                continue
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            rows.append(
                {
                    "path": relative,
                    "bytes": str(path.stat().st_size),
                    "sha256": digest.hexdigest(),
                    "mode": oct(path.stat().st_mode & 0o777),
                    "type": "file",
                    "link_target": "",
                }
            )
    return _dedupe_manifest(rows)


def _relative_items(rows: Sequence[Mapping[str, str]], challenge_path: str) -> list[str]:
    prefix = challenge_path.rstrip("/") + "/"
    return [row["path"][len(prefix) :] for row in rows]


def _text_corpus(root: Path, challenge_path: str, items: Sequence[str]) -> str:
    chunks: list[str] = [challenge_path.lower(), *(item.lower() for item in items)]
    budget = 2 * 1024 * 1024
    for relative in items:
        path = root / challenge_path / relative
        if path.suffix.lower() not in TEXT_SUFFIXES or not path.is_file():
            continue
        try:
            data = path.read_bytes()[: min(budget, 256 * 1024)]
        except OSError:
            continue
        budget -= len(data)
        chunks.append(data.decode("utf-8", errors="ignore").lower())
        if budget <= 0:
            break
    return "\n".join(chunks)


def _families(path: str, text: str, formats: set[str]) -> list[str]:
    haystack = f"{path.lower()}\n{text}"
    result: list[str] = []

    def add(name: str, *needles: str) -> None:
        if any(needle in haystack for needle in needles):
            result.append(name)

    add(
        "kernel",
        "vmlinux",
        "bzimage",
        "rootfs.cpio",
        "qemu-system",
        "kaslr",
        "kpti",
        "kernel module",
        "commit_creds",
    )
    if re.search(r"(?:^|[/_\s-])v8(?:[/_\s-]|$)", haystack) or any(
        needle in haystack for needle in ("turbofan", "javascriptcore", "v8::")
    ):
        result.append("v8")
    add("windows", "win32", "windows", "windbg", "pe32")
    add("vm", "dreamvm", "bytecode", "virtual machine", "interpreter")
    add("heap", "heap", "tcache", "malloc", "free(", "__free_hook", "fastbin")
    add("format", "format-string", "format string", "fmtstr", "%n", "%p")
    add("shellcode", "shellcode", "mprotect", "seccomp", " orw", "open read write")
    add("rop", "rop", "gadget", "pop rdi", "ret2libc", "sigreturn", "srop")
    add("race", "race condition", "pthread_create", "threading.thread", "raceaction")
    add("signal", "sigreturn", "sigframe", "sigaction", "signal(")
    add("musl", "musl")
    add("rust", "rust", "cargo", "from_utf8")
    add("custom-protocol", "menu", "sendlineafter", "recvuntil", "protocol")
    add("stack", "gets(", "strcpy", "buffer overflow", "canary", "cyclic", "stack")
    if "PE" in formats and "windows" not in result and "kernel" not in result:
        result.append("windows")
    if not result:
        result.append("unclassified")
    return list(dict.fromkeys(result))


def _surface(families: Sequence[str]) -> str:
    mapping = {
        "kernel": "kernel VM / advanced boundary",
        "v8": "engine adapter / advanced boundary",
        "windows": "PE platform adapter / advanced boundary",
        "heap": "heap recipes / HeapFlow / craft",
        "format": "format leak-write / relate / craft",
        "shellcode": "shellcode effect / craft",
        "rop": "control / ROP strategy / craft",
        "stack": "stack control / protected layout / craft",
        "race": "RaceAction / boundary",
        "signal": "SROP backend / craft",
        "custom-protocol": "menu or protocol flow",
        "vm": "custom protocol / boundary / craft",
        "musl": "advanced libc model / craft",
        "rust": "controlled buffer / protocol flow",
    }
    return "; ".join(dict.fromkeys(mapping[item] for item in families if item in mapping))


def _missing_primitive(families: Sequence[str], pwnx_status: str) -> str:
    if pwnx_status == "verified":
        return ""
    for family, missing in (
        ("kernel", "kernel VM and kernel-ROP realization"),
        ("v8", "V8/JIT engine adapter and exploit primitives"),
        ("windows", "Windows execution/debug reference solve"),
        ("vm", "custom VM bytecraft/protocol realization"),
        ("musl", "versioned musl allocator/libc realization"),
        ("race", "challenge-specific race lifecycle realization"),
    ):
        if family in families:
            return missing
    return "pwnx solve conversion and native execution proof"


def inventory(
    root: Path,
    challenges_path: Path,
    manifest_path: Path,
    *,
    overrides_path: Path = DEFAULT_OVERRIDES,
) -> list[dict[str, str]]:
    challenges = _read_csv(challenges_path)
    manifest = _read_csv(manifest_path)
    _validate_manifest(root, manifest)
    overrides = _load_overrides(overrides_path)
    output: list[dict[str, str]] = []
    seen: set[str] = set()

    for index, challenge in enumerate(challenges, start=1):
        challenge_path = challenge["path"].strip("/")
        if not challenge_path or challenge_path in seen:
            raise CorpusError(f"duplicate or empty curated challenge path: {challenge_path!r}")
        _relative_path(challenge_path, what=f"curated challenge row {index} path")
        _contained(root, root / challenge_path)
        seen.add(challenge_path)
        rows = _challenge_manifest(manifest, challenge_path, root)
        items = _relative_items(rows, challenge_path)
        directory = root / challenge_path
        item_types = {
            row["path"][len(challenge_path.rstrip("/") + "/") :]: row.get("type", "file")
            for row in rows
        }
        format_arch = [
            (relative, *_artifact_kind(directory / relative))
            for relative in items
            if item_types.get(relative) != "symlink" and (directory / relative).is_file()
        ]
        formats = {fmt for _item, fmt, _arch in format_arch if fmt != "other"}
        architectures = {
            arch
            for _item, fmt, arch in format_arch
            if fmt != "other" and arch != "unknown"
        }
        executables = [
            relative
            for relative, fmt, _arch in format_arch
            if fmt in {"ELF64", "ELF32", "PE", "Mach-O"}
            and not _is_loader(Path(relative).name)
            and not _is_libc(Path(relative).name)
        ]
        libc = [relative for relative in items if _is_libc(Path(relative).name)]
        loader = [relative for relative in items if _is_loader(Path(relative).name)]
        source = [relative for relative in items if Path(relative).suffix.lower() in SOURCE_SUFFIXES]
        docker = [
            relative
            for relative in items
            if Path(relative).name.lower().startswith("dockerfile")
            or "docker-compose" in Path(relative).name.lower()
            or Path(relative).name.lower().startswith("compose.")
        ]
        solves = sorted(
            relative
            for relative in items
            if Path(relative).suffix == ".py"
            and (
                Path(relative).name.startswith("solve")
                or Path(relative).name.startswith("exploit")
            )
        )
        writeups = sorted(
            relative
            for relative in items
            if Path(relative).name.lower().startswith(("writeup", "readme"))
        )
        pwnx_solves = [relative for relative in solves if "pwnx" in Path(relative).stem]
        text = _text_corpus(root, challenge_path, items)
        families = _families(challenge_path, text, formats)

        if not directory.is_dir() or not rows:
            pwnx_status = "artifact_missing"
            native_status = "unavailable"
        elif pwnx_solves:
            pwnx_status = "implemented"
            native_status = "not_run"
        else:
            pwnx_status = "not_started"
            native_status = "not_run" if executables else "unavailable"

        if "kernel" in families:
            environment = "kernel-vm"
        elif "v8" in families:
            environment = "v8"
        elif "windows" in families:
            environment = "windows"
        elif docker:
            environment = "docker"
        elif executables:
            environment = "local"
        else:
            environment = "unavailable"

        priority = (
            "critical"
            if any(item in families for item in ("kernel", "v8", "windows"))
            else "high"
            if not solves or native_status == "unavailable"
            else "medium"
        )
        command = ["python3", pwnx_solves[0]] if pwnx_solves else []
        notes = challenge.get("note", "")
        duplicate_count = len([row for row in manifest if row["path"].startswith(challenge_path + "/")]) - len(rows)
        if duplicate_count:
            notes = "; ".join(filter(None, (notes, f"deduplicated {duplicate_count} nested artifact(s)")))

        row: dict[str, str] = {
            "id": f"C{index:03d}",
            "event": challenge_path.split("/", 1)[0],
            "name": Path(challenge_path).name,
            "path": challenge_path,
            "architecture": ";".join(sorted(architectures)) or "unknown",
            "format": ";".join(sorted(formats)) or "unknown",
            "artifacts": ";".join(items),
            "binary": ";".join(executables),
            "libc": ";".join(libc),
            "loader": ";".join(loader),
            "source": ";".join(source),
            "docker": ";".join(docker),
            "existing_solve": ";".join(solves),
            "writeup": ";".join(writeups),
            "purpose_families": ";".join(families),
            "pwnx_solve": ";".join(pwnx_solves),
            "pwnx_status": pwnx_status,
            "native_status": native_status,
            "native_evidence": "",
            "missing_primitive": _missing_primitive(families, pwnx_status),
            "priority": priority,
            "environment": environment,
            "workdir": challenge_path,
            "run_command": json.dumps(command, separators=(",", ":")),
            "notes": notes,
        }
        override = overrides.get(challenge_path, {})
        for key, value in override.items():
            if key not in FIELDS:
                raise CorpusError(f"unknown override field {key!r} for {challenge_path}")
            row[key] = str(value)
        row["missing_primitive"] = _missing_primitive(families, row["pwnx_status"])
        output.append(row)
    return output


def validate(rows: Sequence[Mapping[str, str]], *, expected_paths: Sequence[str] | None = None) -> list[str]:
    errors: list[str] = []
    ids = [row.get("id", "") for row in rows]
    paths = [row.get("path", "") for row in rows]
    if len(ids) != len(set(ids)):
        errors.append("duplicate matrix ids")
    if len(paths) != len(set(paths)):
        errors.append("duplicate matrix paths")
    if expected_paths is not None and list(paths) != list(expected_paths):
        missing = sorted(set(expected_paths) - set(paths))
        extra = sorted(set(paths) - set(expected_paths))
        errors.append(f"matrix paths differ from curated manifest; missing={missing}, extra={extra}")
    for index, row in enumerate(rows, start=1):
        missing_fields = [field for field in FIELDS if field not in row]
        if missing_fields:
            errors.append(f"row {index} missing fields: {missing_fields}")
        if row.get("pwnx_status") not in STATUS_VALUES:
            errors.append(f"row {index} invalid pwnx_status {row.get('pwnx_status')!r}")
        if row.get("native_status") not in NATIVE_VALUES:
            errors.append(f"row {index} invalid native_status {row.get('native_status')!r}")
        if row.get("priority") not in PRIORITY_VALUES:
            errors.append(f"row {index} invalid priority {row.get('priority')!r}")
        try:
            _json_list(row.get("run_command", ""))
        except CorpusError as error:
            errors.append(f"row {index}: {error}")
    return errors


def _load_matrix(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise CorpusError(f"coverage matrix does not exist: {path}")
    return _read_csv(path)


def _summary(rows: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    def counts(field: str) -> dict[str, int]:
        output: dict[str, int] = {}
        for row in rows:
            for value in _split(row.get(field, "")) or [row.get(field, "")]:
                if value:
                    output[value] = output.get(value, 0) + 1
        return dict(sorted(output.items()))

    return {
        "total": len(rows),
        "pwnx_status": counts("pwnx_status"),
        "native_status": counts("native_status"),
        "priority": counts("priority"),
        "environment": counts("environment"),
        "purpose_families": counts("purpose_families"),
    }


def _emit(value: Any, *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(value, sort_keys=True, indent=2))
        return
    if isinstance(value, list):
        for row in value:
            print(
                f"{row['id']} {row['pwnx_status']:>16} {row['priority']:>8} "
                f"{row['purpose_families']:<32} {row['path']}"
            )
    elif isinstance(value, dict):
        print(json.dumps(value, sort_keys=True, indent=2))
    else:
        print(value)


def _row_by_id(rows: Sequence[Mapping[str, str]], identifier: str) -> Mapping[str, str]:
    matches = [row for row in rows if row["id"] == identifier or row["path"] == identifier]
    if len(matches) != 1:
        raise CorpusError(f"expected one matrix row for {identifier!r}, found {len(matches)}")
    return matches[0]


def _run(
    row: Mapping[str, str],
    *,
    root: Path,
    timeout: float,
    max_output: int,
    dry_run: bool,
    docker: bool,
) -> dict[str, Any]:
    if timeout <= 0 or timeout > 600:
        raise CorpusError("timeout must be in (0, 600]")
    if max_output <= 0 or max_output > 64 * 1024 * 1024:
        raise CorpusError("max-output must be in (0, 67108864]")
    command = _json_list(row["run_command"])
    if not command:
        raise CorpusError(f"{row['id']} has no declared pwnx run command")
    workdir = _contained(root, root / row["workdir"])
    if not workdir.is_dir():
        raise CorpusError(f"challenge workdir does not exist: {workdir}")
    solve = _contained(root, workdir / command[-1]) if command[-1].endswith(".py") else None
    if solve is not None and not solve.is_file():
        raise CorpusError(f"declared solve does not exist: {solve}")

    environment = os.environ.copy()
    environment["PWNX_OFFLINE"] = "1"
    environment["PYTHONPATH"] = str(REPOSITORY / "src")
    for key in tuple(environment):
        if key.lower().endswith("_proxy") or key.lower() == "all_proxy":
            environment.pop(key, None)

    argv = list(command)
    execution_cwd = workdir
    if docker:
        image = "pwnx-test-linux:24.04"
        argv = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--volume",
            f"{root.resolve()}:/corpus:ro",
            "--volume",
            f"{REPOSITORY.resolve()}:/pwnx:ro",
            "--workdir",
            f"/corpus/{row['workdir']}",
            "--env",
            "PYTHONPATH=/pwnx/src",
            image,
            *command,
        ]
        execution_cwd = REPOSITORY
    result: dict[str, Any] = {
        "id": row["id"],
        "path": row["path"],
        "argv": argv,
        "cwd": str(execution_cwd),
        "network": "docker-none" if docker else "offline-environment-only",
        "timeout": timeout,
        "max_output": max_output,
        "dry_run": dry_run,
    }
    if dry_run:
        return result

    timed_out = False
    captured = bytearray()
    truncated = False
    process = subprocess.Popen(
        argv,
        cwd=execution_cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    stdout = process.stdout
    assert stdout is not None

    def drain_output() -> None:
        nonlocal truncated
        while True:
            chunk = stdout.read(64 * 1024)
            if not chunk:
                return
            remaining = max_output - len(captured)
            if remaining > 0:
                captured.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True

    reader = threading.Thread(target=drain_output, daemon=True)
    reader.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    reader.join(timeout=5)
    if reader.is_alive():
        stdout.close()
        reader.join(timeout=1)
    output = bytes(captured)
    result.update(
        {
            "exit_code": process.returncode,
            "timed_out": timed_out,
            "output_truncated": truncated,
            "output": output.decode("utf-8", errors="replace"),
        }
    )
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory_parser = subparsers.add_parser("inventory", help="regenerate the coverage matrix")
    inventory_parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    inventory_parser.add_argument("--challenges", type=Path)
    inventory_parser.add_argument("--manifest", type=Path)
    inventory_parser.add_argument("--overrides", type=Path, default=DEFAULT_OVERRIDES)
    inventory_parser.add_argument("--output", type=Path, default=DEFAULT_MATRIX)
    inventory_parser.add_argument("--json", action="store_true")

    check_parser = subparsers.add_parser("check", help="validate matrix completeness")
    check_parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    check_parser.add_argument("--challenges", type=Path)
    check_parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    check_parser.add_argument("--json", action="store_true")

    list_parser = subparsers.add_parser("list", help="filter coverage rows")
    list_parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    list_parser.add_argument("--family")
    list_parser.add_argument("--status")
    list_parser.add_argument("--priority")
    list_parser.add_argument("--json", action="store_true")

    status_parser = subparsers.add_parser("status", help="summarize coverage")
    status_parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    status_parser.add_argument("--json", action="store_true")

    run_parser = subparsers.add_parser("run", help="run a declared pwnx solve")
    run_parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    run_parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    run_parser.add_argument("--id", required=True)
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.add_argument("--docker", action="store_true")
    run_parser.add_argument("--timeout", type=float, default=30.0)
    run_parser.add_argument("--max-output", type=int, default=1024 * 1024)
    run_parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "inventory":
            root = arguments.root.resolve()
            challenges = arguments.challenges or root / "CHALLENGES.csv"
            manifest = arguments.manifest or root / "MANIFEST.csv"
            rows = inventory(
                root,
                challenges,
                manifest,
                overrides_path=arguments.overrides,
            )
            _write_csv(arguments.output, rows)
            _emit({"matrix": str(arguments.output), **_summary(rows)}, json_output=arguments.json)
            return 0
        if arguments.command == "check":
            root = arguments.root.resolve()
            challenges = arguments.challenges or root / "CHALLENGES.csv"
            curated = [row["path"] for row in _read_csv(challenges)]
            rows = _load_matrix(arguments.matrix)
            errors = validate(rows, expected_paths=curated)
            result = {"ok": not errors, "rows": len(rows), "errors": errors}
            _emit(result, json_output=arguments.json)
            return 0 if not errors else 1
        if arguments.command == "list":
            rows = _load_matrix(arguments.matrix)
            if arguments.family:
                rows = [row for row in rows if arguments.family in _split(row["purpose_families"])]
            if arguments.status:
                rows = [row for row in rows if row["pwnx_status"] == arguments.status]
            if arguments.priority:
                rows = [row for row in rows if row["priority"] == arguments.priority]
            _emit(rows, json_output=arguments.json)
            return 0
        if arguments.command == "status":
            _emit(_summary(_load_matrix(arguments.matrix)), json_output=arguments.json)
            return 0
        if arguments.command == "run":
            row = _row_by_id(_load_matrix(arguments.matrix), arguments.id)
            result = _run(
                row,
                root=arguments.root.resolve(),
                timeout=arguments.timeout,
                max_output=arguments.max_output,
                dry_run=arguments.dry_run,
                docker=arguments.docker,
            )
            _emit(result, json_output=arguments.json)
            if arguments.dry_run:
                return 0
            return 124 if result["timed_out"] else int(result["exit_code"] != 0)
    except (CorpusError, OSError, ValueError) as error:
        if getattr(arguments, "json", False):
            print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True, indent=2))
        else:
            print(f"corpus: {error}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
