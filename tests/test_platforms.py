from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pwnx.architecture import CredentialReference
from pwnx.errors import ArtifactError, ConstraintError, UnsupportedFeature
from pwnx.expressions import Expr
from pwnx.platforms import (
    ADBRecipe,
    CDBRecipe,
    DebuggerScript,
    KernelVMRecipe,
    PlatformAction,
    SubprocessPlatformBackend,
    WindowsProcessRecipe,
    parse_pe,
)
from pwnx.trace import RecordingTube, ReplayTube, Trace
from pwnx.transport import Tube


def completed(argv, *, stdout=b"", stderr=b"", returncode=0):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


class NullTube(Tube):
    def _recv_raw(self, max_bytes, timeout):
        return b""

    def _send_raw(self, data, timeout):
        return len(data)

    def _close_raw(self):
        pass


class Runtime:
    def __init__(self, tube, trace):
        self.tube = tube
        self.trace = trace
        self.bound = []

    def bind(self, target, value, *, source):
        self.bound.append((target, value, source))


def _pe64(path: Path) -> None:
    data = bytearray(0x700)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1010)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 60, 0x400)
    struct.pack_into("<H", data, optional + 70, 0x40 | 0x100 | 0x4000 | 0x20)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 112 + 8, 0x1100, 0x80)

    section = optional + 0xF0
    data[section : section + 8] = b".rdata\0\0"
    struct.pack_into(
        "<IIIIIIHHI",
        data,
        section + 8,
        0x300,
        0x1000,
        0x300,
        0x400,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    descriptor = 0x500
    struct.pack_into("<IIIII", data, descriptor, 0x1160, 0, 0, 0x1140, 0x1170)
    data[0x540 : 0x540 + len(b"KERNEL32.dll\0")] = b"KERNEL32.dll\0"
    struct.pack_into("<QQ", data, 0x560, 0x1180, 0)
    data[0x580:0x582] = b"\0\0"
    data[0x582 : 0x582 + len(b"ExitProcess\0")] = b"ExitProcess\0"
    path.write_bytes(data)


def test_pe_parser_reports_identity_sections_imports_and_mitigations(tmp_path) -> None:
    executable = tmp_path / "chall.exe"
    _pe64(executable)
    image = parse_pe(executable)
    assert image.machine_name == "amd64"
    assert image.bits == 64
    assert image.image_base == 0x140000000
    assert image.sha256 == hashlib.sha256(executable.read_bytes()).hexdigest()
    assert image.section(".rdata").virtual_address == 0x1000
    assert image.imports[0].library == "KERNEL32.dll"
    assert image.imports[0].symbols == ("ExitProcess",)
    assert image.mitigations.aslr
    assert image.mitigations.nx
    assert image.mitigations.cfg
    assert image.mitigations.high_entropy_va


def test_pe_parser_rejects_truncated_and_non_pe_inputs(tmp_path) -> None:
    bad = tmp_path / "bad.exe"
    bad.write_bytes(b"not a pe")
    with pytest.raises(ArtifactError, match="MZ|truncated"):
        parse_pe(bad)
    with pytest.raises(ConstraintError, match="maximum"):
        parse_pe(bad, max_size=2)


def test_adb_recipe_keeps_device_and_untrusted_values_in_argv(tmp_path) -> None:
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return completed(argv, stdout=b"uid=2000\n")

    recipe = ADBRecipe(
        "device;not-a-shell",
        ("/data/local/tmp/chall", "argument with spaces", ";reboot"),
        adb="adb-custom",
        credential=CredentialReference("android-debug-key"),
        runner=runner,
    )
    target = recipe.materialize(epoch_seed="one")
    assert target.argv == (
        "adb-custom",
        "-s",
        "device;not-a-shell",
        "shell",
        "--",
        "/data/local/tmp/chall 'argument with spaces' ';reboot'",
    )
    assert "android-debug-key" in " ".join(target.evidence)
    result = recipe.process("/system/bin/id", "$(reboot)").perform()
    assert result.stdout == b"uid=2000\n"
    assert calls[0][0][-1] == "/system/bin/id '$(reboot)'"
    assert calls[0][0] == [
        "adb-custom",
        "-s",
        "device;not-a-shell",
        "shell",
        "--",
        "/system/bin/id '$(reboot)'",
    ]


def test_adb_transfer_hashes_and_atomic_pull(tmp_path) -> None:
    source = tmp_path / "payload"
    source.write_bytes(b"PAYLOAD")
    destination = tmp_path / "download"
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        if "pull" in argv:
            Path(argv[-1]).write_bytes(b"REMOTE")
        return completed(argv)

    recipe = ADBRecipe("serial", adb="adb", runner=runner)
    pushed = recipe.push(source, "/data/local/tmp/payload").perform()
    assert pushed.artifacts[0].sha256 == hashlib.sha256(b"PAYLOAD").hexdigest()
    pulled = recipe.pull(
        "/data/local/tmp/result",
        destination,
        expected_sha256=hashlib.sha256(b"REMOTE").hexdigest(),
    ).perform()
    assert destination.read_bytes() == b"REMOTE"
    assert pulled.artifacts[0].path == str(destination.resolve())
    assert calls[1][-1] != str(destination.resolve())
    assert not list(tmp_path.glob("*.pwnx-pull"))


def test_platform_action_trace_replay_does_not_repeat_device_effect() -> None:
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return completed(argv, stdout=b"log line\n")

    target = Expr.fact("android.logs", scope="service")
    action = ADBRecipe("serial", runner=runner).logcat("ActivityManager:I", lines=5, target=target)
    trace = Trace()
    recording = RecordingTube(NullTube(), trace)
    live_runtime = Runtime(recording, trace)
    result = action.execute(live_runtime)
    recording.close()
    assert len(calls) == 1
    assert live_runtime.bound[0][0] is target

    replay = ReplayTube(trace)
    replay_runtime = Runtime(replay, None)
    replayed = action.execute(replay_runtime)
    replay.close()
    assert replayed == result
    assert len(calls) == 1


def test_windows_native_wine_and_cdb_recipes_are_pure_manifests(tmp_path) -> None:
    executable = tmp_path / "chall.exe"
    wine = tmp_path / "wine64"
    cdb = tmp_path / "cdb"
    executable.write_bytes(b"PE")
    wine.write_bytes(b"WINE")
    cdb.write_bytes(b"CDB")

    native = WindowsProcessRecipe.native(str(executable), "argument with spaces")
    native_target = native.materialize()
    assert native_target.argv[-1] == "argument with spaces"
    if os.name != "nt":
        assert "unsupported" in " ".join(native_target.evidence)

    via_wine = WindowsProcessRecipe.through_wine(str(executable), ";not-shell", wine=str(wine))
    wine_target = via_wine.materialize()
    assert wine_target.argv == (str(wine), str(executable.resolve()), ";not-shell")
    assert {item.role for item in wine_target.artifacts} == {"executable", "wine"}

    debug = CDBRecipe(
        native,
        DebuggerScript(("sxe av", "bp chall!main"), continue_after_load=True),
        debugger=str(cdb),
    ).materialize()
    assert debug.argv[1:3] == ("-c", "sxe av;bp chall!main;g")
    assert debug.argv[3] == str(executable.resolve())


def test_kernel_vm_recipe_has_strict_argv_artifacts_and_lifecycle(tmp_path) -> None:
    emulator = tmp_path / "qemu-system-x86_64"
    kernel = tmp_path / "bzImage"
    initrd = tmp_path / "initramfs.cpio"
    disk = tmp_path / "disk,unsafe=on.img"
    emulator.write_bytes(b"QEMU")
    kernel.write_bytes(b"KERNEL")
    initrd.write_bytes(b"INITRD")
    disk.write_bytes(b"DISK")
    recipe = KernelVMRecipe(
        str(kernel),
        emulator=str(emulator),
        initrd=str(initrd),
        disk=str(disk),
        append=("console=ttyS0", "kaslr"),
        network="user",
        gdb_port=1234,
        paused=True,
    )
    first = recipe.materialize(epoch_seed="one")
    second = recipe.materialize(epoch_seed="two")
    assert first.argv[0] == str(emulator)
    block = first.argv[first.argv.index("-blockdev") + 1]
    assert '"filename":"' in block
    assert str(disk.resolve()) in block
    assert "-S" in first.argv
    assert first.options["gdb_port"] == 1234
    assert first.argv[first.argv.index("-gdb") + 1] == "tcp:127.0.0.1:1234"
    assert {item.role for item in first.artifacts} == {
        "kernel",
        "initrd",
        "disk",
        "emulator",
    }
    assert first.epochs.service == second.epochs.service
    assert first.epochs.process != second.epochs.process


def test_platform_recipes_use_registered_runtime_adapters_with_support_gates(
    tmp_path,
) -> None:
    from pwnx.runtime import _ENVIRONMENT_OPENERS

    assert {
        "adb-process",
        "wine-process",
        "windows-process",
        "cdb-debugger",
        "kernel-vm",
    } <= set(_ENVIRONMENT_OPENERS)

    if os.name != "nt":
        executable = tmp_path / "chall.exe"
        executable.write_bytes(b"PE")
        target = WindowsProcessRecipe.native(str(executable)).materialize()
        with pytest.raises(UnsupportedFeature, match="requires Windows"):
            _ENVIRONMENT_OPENERS["windows-process"](target)


def test_platform_bounds_and_unsupported_tool_evidence(tmp_path) -> None:
    recipe = ADBRecipe(
        "serial",
        adb="definitely-not-a-real-adb-binary",
        runner=lambda argv, **kwargs: completed(argv, stdout=b"too much"),
    )
    assert not recipe.support().supported
    with pytest.raises(ConstraintError, match="maximum"):
        recipe.logcat(max_output=2).perform()
    with pytest.raises(ValueError, match="tokens"):
        KernelVMRecipe(str(tmp_path / "kernel"), append=("console=x y",))
    with pytest.raises(ValueError, match="unsafe_remote_gdb"):
        KernelVMRecipe(
            str(tmp_path / "kernel"),
            gdb_port=1234,
            gdb_host="0.0.0.0",
        )


def test_platform_backend_enforces_output_bound_during_capture() -> None:
    backend = SubprocessPlatformBackend(
        "noisy",
        sys.executable,
        (
            "-c",
            "import os,time\nwhile True:\n os.write(1, b'X' * 4096)\n time.sleep(.001)",
        ),
    )
    action = PlatformAction(
        "shell",
        ("ignored",),
        backend,
        deadline=1.0,
        max_output=1024,
    )
    started = time.monotonic()
    with pytest.raises(ConstraintError, match="output exceeds"):
        action.perform()
    assert time.monotonic() - started < action.deadline
