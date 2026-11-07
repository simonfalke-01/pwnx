"""Command-line entry point for declarative solve files and run traces."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import runpy
import sys
from pathlib import Path
from typing import Any, Sequence

from .challenge import Challenge, _collect
from .errors import PlanningError, PwnxError
from .trace import Trace


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwnx",
        description="Plan, run, explain, and replay declarative pwnx solves.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan", help="compile a solve without target I/O")
    plan.add_argument("script", type=Path)
    plan.set_defaults(handler=_command_plan)

    run = commands.add_parser("run", help="compile and execute a solve")
    run.add_argument("script", type=Path)
    run.add_argument("--profile", help="profile name (default: local, or remote with --host)")
    run.add_argument("--host", help="register and select a remote TCP profile")
    run.add_argument("--port", type=int, help="remote TCP port")
    run.add_argument("--tls", action="store_true", help="use TLS for --host")
    run.add_argument("--udp", action="store_true", help="use UDP for --host")
    run.add_argument("--trace", type=Path, help="save the run event ledger")
    run.add_argument("--interactive", action="store_true", help="enter interactive mode after actions")
    run.set_defaults(handler=_command_run)

    replay = commands.add_parser("replay", help="run a solve against a recorded trace")
    replay.add_argument("script", type=Path)
    replay.add_argument("trace", type=Path)
    replay.add_argument("--interactive", action="store_true")
    replay.set_defaults(handler=_command_replay)

    trace = commands.add_parser("trace", help="display a recorded event ledger")
    trace.add_argument("trace", type=Path)
    trace.set_defaults(handler=_command_trace)

    diff = commands.add_parser("diff", help="compare two recorded event ledgers")
    diff.add_argument("left", type=Path)
    diff.add_argument("right", type=Path)
    diff.set_defaults(handler=_command_diff)

    explain = commands.add_parser("explain", help="explain one event or metadata value")
    explain.add_argument("trace", type=Path)
    explain.add_argument("subject", help="event:N, N, events, metadata, or metadata.path")
    explain.set_defaults(handler=_command_explain)

    checksec = commands.add_parser("checksec", help="report static ELF mitigations")
    checksec.add_argument("binary", type=Path, nargs="+")
    checksec.set_defaults(handler=_command_checksec)

    cyclic = commands.add_parser("cyclic", help="generate or search a cyclic pattern")
    cyclic.add_argument("length", type=int, nargs="?", default=128)
    cyclic.add_argument("--find", dest="needle")
    cyclic.add_argument("--n", type=int, default=4)
    cyclic.add_argument("--alphabet", default=None)
    cyclic.add_argument("--max-work", type=int, default=16 * 1024 * 1024)
    cyclic.set_defaults(handler=_command_cyclic)

    assemble = commands.add_parser("asm", help="assemble explicit target code")
    assemble.add_argument("source", nargs="?")
    assemble.add_argument("--arch", default="amd64")
    assemble.add_argument("--raw", action="store_true")
    assemble.set_defaults(handler=_command_asm)

    disassemble = commands.add_parser("disasm", help="disassemble hexadecimal bytes")
    disassemble.add_argument("data", nargs="?")
    disassemble.add_argument("--arch", default="amd64")
    disassemble.add_argument("--vma", type=lambda value: int(value, 0), default=0)
    disassemble.set_defaults(handler=_command_disasm)
    return parser


def _collect_challenge(script: Path) -> Challenge:
    script = script.expanduser().resolve()
    if not script.is_file():
        raise PlanningError(f"solve file does not exist: {script}")
    challenges: list[Challenge] = []
    token = _collect.set(challenges)
    try:
        try:
            runpy.run_path(str(script), run_name="__main__")
        except SystemExit as exc:
            if exc.code not in (None, 0):
                raise PlanningError(
                    f"solve file exited while being collected (status {exc.code})"
                ) from exc
    finally:
        _collect.reset(token)
    if not challenges:
        raise PlanningError(f"{script.name} did not create a Challenge")
    if len(challenges) != 1:
        raise PlanningError(
            f"{script.name} created {len(challenges)} Challenges; "
            "a CLI solve file must create exactly one"
        )
    return challenges[0]


def _command_plan(args: argparse.Namespace) -> int:
    challenge = _collect_challenge(args.script)
    _show(challenge.plan())
    return 0


def _command_run(args: argparse.Namespace) -> int:
    challenge = _collect_challenge(args.script)
    profile = _configure_profile(challenge, args)
    trace = _new_run_trace(challenge, args.script, profile) if args.trace else None
    run = None
    error: BaseException | None = None
    try:
        run = challenge.run(profile=profile, trace=trace)
        if args.interactive and not getattr(getattr(run, "plan", None), "auto_interactive", False):
            run.interactive()
    except BaseException as exc:
        error = exc
        raise
    finally:
        if run is not None:
            try:
                run.close()
            except BaseException:
                if error is None:
                    raise
        if trace is not None:
            trace.save(args.trace)
    return 0


def _command_replay(args: argparse.Namespace) -> int:
    challenge = _collect_challenge(args.script)
    recorded = Trace.load(args.trace)
    run = None
    error: BaseException | None = None
    try:
        run = challenge.run(replay=recorded)
        if args.interactive and not getattr(getattr(run, "plan", None), "auto_interactive", False):
            run.interactive()
    except BaseException as exc:
        error = exc
        raise
    finally:
        if run is not None:
            try:
                run.close()
            except BaseException:
                if error is None:
                    raise
    return 0


def _command_trace(args: argparse.Namespace) -> int:
    trace = Trace.load(args.trace)
    describe = getattr(trace, "describe", None)
    if callable(describe):
        _emit_text(describe())
        return 0
    print(f"Trace: {args.trace}")
    print(f"Events: {len(trace.events)}")
    if trace.metadata:
        print("Metadata:")
        print(json.dumps(trace.metadata, indent=2, sort_keys=True))
    for event in trace.events:
        print(trace.explain(event.sequence))
    return 0


def _command_diff(args: argparse.Namespace) -> int:
    left = Trace.load(args.left)
    right = Trace.load(args.right)
    differences = left.diff(right)
    if not differences:
        print("traces match")
        return 0
    for difference in differences:
        print(difference)
    return 1


def _command_explain(args: argparse.Namespace) -> int:
    trace = Trace.load(args.trace)
    subject = args.subject
    if subject.isdecimal():
        _explain_event(trace, int(subject))
        return 0
    if subject.startswith("event:") and subject[6:].isdecimal():
        _explain_event(trace, int(subject[6:]))
        return 0
    if subject == "events":
        for event in trace.events:
            print(trace.explain(event.sequence))
        return 0
    if subject == "metadata":
        print(json.dumps(trace.metadata, indent=2, sort_keys=True))
        return 0
    if subject.startswith("metadata."):
        value: Any = trace.metadata
        for part in subject.split(".")[1:]:
            if not isinstance(value, dict) or part not in value:
                raise PlanningError(f"trace metadata has no path {subject!r}")
            value = value[part]
        if isinstance(value, (dict, list)):
            print(json.dumps(value, indent=2, sort_keys=True))
        else:
            print(value)
        return 0
    matches = [event for event in trace.events if event.operation == subject]
    if matches:
        for event in matches:
            print(trace.explain(event.sequence))
        return 0
    raise PlanningError(
        f"unknown trace subject {subject!r}; use an event number, events, or metadata"
    )


def _command_checksec(args: argparse.Namespace) -> int:
    from .artifacts import Image

    for index, path in enumerate(args.binary):
        image = Image(path)
        if len(args.binary) > 1:
            if index:
                print()
            print(f"{path}:")
        print(image.checksec())
    return 0


def _command_cyclic(args: argparse.Namespace) -> int:
    from .packing import cyclic, cyclic_find

    alphabet = args.alphabet.encode() if args.alphabet is not None else None
    keyword: dict[str, Any] = {"n": args.n}
    if alphabet is not None:
        keyword["alphabet"] = alphabet
    if args.needle is None:
        sys.stdout.buffer.write(cyclic(args.length, **keyword))
        sys.stdout.buffer.write(b"\n")
        return 0
    needle: bytes | int
    if args.needle.lower().startswith("0x"):
        needle = int(args.needle, 16)
    else:
        needle = args.needle.encode()
    print(cyclic_find(needle, max_work=args.max_work, **keyword))
    return 0


def _command_asm(args: argparse.Namespace) -> int:
    from .toolchain import asm

    source = args.source if args.source is not None else sys.stdin.read()
    result = asm(source, arch=args.arch)
    if args.raw:
        sys.stdout.buffer.write(result)
    else:
        print(result.hex())
    return 0


def _command_disasm(args: argparse.Namespace) -> int:
    from .packing import unhex
    from .toolchain import disasm

    encoded = args.data if args.data is not None else sys.stdin.read()
    print(disasm(unhex(encoded.strip()), arch=args.arch, vma=args.vma))
    return 0


def _explain_event(trace: Trace, sequence: int) -> None:
    try:
        print(trace.explain(sequence))
    except IndexError as exc:
        raise PlanningError(str(exc)) from exc


def _configure_profile(challenge: Challenge, args: argparse.Namespace) -> str:
    if (args.host is None) != (args.port is None):
        raise PlanningError("--host and --port must be provided together")
    profile = args.profile
    if args.host is not None:
        challenge.remote(
            args.host,
            args.port,
            tls=args.tls,
            protocol="udp" if args.udp else "tcp",
            name="remote",
        )
        if profile is None:
            profile = "remote"
    elif args.tls:
        raise PlanningError("--tls requires --host and --port")
    elif args.udp:
        raise PlanningError("--udp requires --host and --port")
    profile = profile or "local"
    if profile == "debug" and profile not in challenge.profiles:
        challenge.debug()
    if profile not in challenge.profiles:
        available = ", ".join(sorted(challenge.profiles))
        raise PlanningError(
            f"unknown profile {profile!r}; available profiles: {available or '<none>'}"
        )
    return profile


def _new_run_trace(challenge: Challenge, script: Path, profile: str) -> Trace:
    trace = Trace(
        metadata={
            "script": str(script.expanduser().resolve()),
            "profile": profile,
        }
    )
    for index, image in enumerate(challenge.images):
        if image is None:
            continue
        name = getattr(image, "name", None) or f"image{index}"
        trace.add_artifact(name, image.path)
    return trace


def _show(value: Any) -> None:
    show = getattr(value, "show", None)
    if not callable(show):
        _emit_text(str(value))
        return
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        result = show()
    emitted = captured.getvalue()
    if emitted:
        sys.stdout.write(emitted)
        if not emitted.endswith("\n"):
            sys.stdout.write("\n")
    if isinstance(result, str) and result.strip() != emitted.strip():
        _emit_text(result)


def _emit_text(value: Any) -> None:
    if value is None:
        return
    text = str(value)
    sys.stdout.write(text)
    if text and not text.endswith("\n"):
        sys.stdout.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
        return int(args.handler(args))
    except PwnxError as exc:
        print(f"pwnx: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

