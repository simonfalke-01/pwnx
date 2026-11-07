# Migrating pwnx solves through 0.5

Pwnx 0.3 preserves solve behavior through explicit compatibility and backend
namespaces. The primary package no longer exposes pwntools-shaped helpers or
mechanism compilers as attributes; migration makes that boundary explicit.

## Migrating constrained-control solves from 0.4 to 0.5

Version 0.5 makes one autocomplete-friendly surface canonical and moves
map-based construction plus implementation types to `pwnx.advanced`.

| Removed 0.4 primary spelling | Canonical 0.5 spelling | Explicit flexibility path |
| --- | --- | --- |
| `x.buffer(..., writer=op)` or `write=op` | `x.buffer(...).written_by(op)` | `controlled_buffer(x, ..., writer=op)` |
| `x.buffer(..., constraint=utf8())` or `constraints=[...]` | `x.buffer(..., encoding="utf8")` | `controlled_buffer(..., constraints=[...])` |
| `message[80]` | `message.qword(80)` | `BufferSlice` is available from `pwnx.advanced` |
| `call.pivot(eax=message, gadget=...)` | `call.pivot(register="eax", stack=message, gadget=...)` | `pivot(call, stack=message, pointer_register="eax", gadget=...)` |
| `call.pivot(pointer_register="eax", stack=message, ...)` | `call.pivot(register="eax", stack=message, ...)` | `pwnx.advanced.pivot(...)` |
| `x.rop(pop_rdi=..., zero_rax=..., move_rdx_rax=..., syscall=...)` | `x.rop(utf8()).pop("rdi", ...).zero("rax", ...).move("rdx", "rax", ...).syscall(...)` | `rop_palette(x, pop=..., zero=..., move=..., syscall=...)` |
| `x.rop(encoding="utf8")` or `x.rop(constraints=[...])` | `x.rop(utf8())` | `rop_palette(..., constraints=[...])` |
| `x.rop.palette(...)` | Fluent `x.rop(constraint)` builder | `pwnx.advanced.rop_palette(...)` |
| `pinned={"pop rdi": ..., ...}` | Fluent `.pop()`, `.zero()`, `.move()`, `.syscall()` calls | `rop_palette(..., pinned=...)` |
| Primary imports of `ControlledBuffer`, `BufferSlice`, `RopBuilder`, `RopPalette`, `Action`, `EffectContract`, or `Payload` | Use `Challenge`, `utf8`, and the fluent methods | Import implementation types from `pwnx.advanced` only when extending the framework |

The explicit flexibility module is intentionally noisy:

~~~python
from pwnx.advanced import controlled_buffer, pivot, rop_palette
~~~

Both paths lower to the same Actions, contracts, channels, codecs, payload,
computed index, trace, and replay result. The migration changes spelling and
namespace position, not exploit semantics.

## Return-address control

0.2:

~~~python
c.control(line("payload: "), return_at=72)
c.want(c.exe.win())
~~~

0.3:

~~~python
c.control(c.input.line("payload: ").return_address(at=72))
c.want(c.call(c.exe.win))
~~~

The 0.3 declaration creates a general Capability and retains an implementation
adapter for the current AMD64 planner.

## Environments

0.2 mutates Challenge profile state:

~~~python
c.remote("host", 31337)
c.run(profile="remote")
~~~

0.3 uses immutable target recipes:

~~~python
from pwnx import tcp

c.on(tcp("host", 31337))
c.run()
~~~

Use LocalProcessRecipe, QemuUserRecipe, SSHProcessRecipe, SerialRecipe, or
TcpRecipe when the full manifest must be explicit; `tcp()` is its compact
competition shorthand. Materialization records architecture, lifecycle, epochs,
adapter identity, and artifact hashes.

## Packing and tubes

0.2 primary-package mechanism imports:

~~~python
from pwnx import p64  # removed from the 0.3 primary surface
~~~

Migration makes compatibility intent visible:

~~~python
from pwnx.compat import pwntools

raw = pwntools.p64(value)
~~~

Technique authors should use pwnx codecs and Payload. Direct transport and
compiler mechanisms live under pwnx.backends. For example, use
`pwnx.backends.rop.SigreturnFrame`, `pwnx.backends.toolchain.asm`, or
`pwnx.backends.transports.ProcessTube`.

### Migrating manual byte layouts to 0.5 bytecraft

Compatibility packing remains available, but competition solves can keep exact
layouts inside the same fact/plan/trace model:

| Manual/compatibility pattern | 0.5 glass-box form |
| --- | --- |
| `flat`, `fit`, repeated padding, or manual concatenation | `x.craft(name).raw().pad().pad_to().align().at()` |
| `p16`/`p32`/`p64` | `.int(value, bits=...)` or target-width `.word(value)` |
| Partial pointer slicing | `.ptr(value, bytes=N)` |
| Custom codec bytes | `.encoded(codec, value)` |
| Ad-hoc bad-byte/length checks | `.require(no=..., min_size=..., max_size=..., exact_size=..., encoding=..., constraint=...)` |
| `sendafter`/menu wrapper for constructed bytes | `x.send(craft, to=input_or_menu_operation)` |
| Mutating one stage for remote offsets | `plan.patch_payload(name, offset=..., data=..., label=..., reason=...)` |
| Printing unresolved placeholder bytes | `craft.show()`/`layout()` before facts; `hexdump()` only after resolution |

`Plan.payloads()` inventories structured sends and `Run.payload()` returns a
resolved `PayloadArtifact`. The latter carries bytes, layout, SHA-256,
provenance, stage/send identity, hexdump, and region diff. Bytecraft uses the
same underlying Payload and Emit IR; it is not a replacement tube or a renamed
pwntools packing module.

Constraints and patches are stricter than ad-hoc bytearray mutation:

- Chained `require()` calls only strengthen the contract: forbidden bytes,
  encodings, and predicates accumulate; minimum/maximum bounds converge; exact
  sizes must remain compatible.
- `Craft.replace()` and `Plan.patch_payload()` re-run the complete final
  validation before send, including compiler-generated payloads such as
  ret2win stages.
- Runtime `PayloadArtifact` values are immutable snapshots taken at each send.
  They survive later fact invalidation/rebinding, and sending one Craft twice
  produces two artifacts with distinct send IDs and send-time bytes.

### Migrating ad-hoc instance retry loops

When a per-instance fact violates line framing, declare the constraint on the
Craft or protected stack word and call `run(attempts=N)`. Pwnx retries only the
labelled `RetryableInstanceError` with a fresh process/connection, closes failed
instances, and records failures in trace metadata. It does not retry EOF,
protocol errors, explicit transports/replay, or targets without a fresh
lifecycle.

Retry classification is dependency-aware. A line terminator or forbidden byte
inside a dynamic symbolic Craft region is retryable because a fresh target may
produce different facts. The same byte in static Craft data is a normal
ConstraintError and opens only one instance. Raw channels do not apply line
framing.

## Custom facts and techniques

0.2 decorators continue to work. New extensions should register providers and
goal strategies:

~~~python
fact = Fact("libc.base", ADDRESS, artifact="libc")

@c.provider(name="rebase libc", requires=[leak], provides=[fact])
def rebase(context):
    return (declarative_bind_action,)

@c.strategy(name="ret2libc", goal="shell", requires=[fact, rip_control])
def ret2libc(context, goal):
    return (declarative_payload_action,)
~~~

Every returned action must implement the uniform contract or lower into
primitive actions.

## Unknown libc

Replace implicit image mutation with hypotheses:

~~~python
catalog = LibcCatalog.scan(["./libcs"])
action = IdentifyLibc(
    catalog,
    (LeakEvidence("puts", leaked_puts),),
    target=c.fact("libc.hypotheses", scope="artifact"),
)
c.sequence(action, name="identify libc")
~~~

Use HypothesisSet.next_probe to acquire discriminating evidence. Call
require_unique only when ambiguity is unacceptable.

## SSH files

Use ArtifactTransfer with an OpenSSHBackend:

~~~python
backend = OpenSSHBackend(host="host", user="ctf")
c.sequence(
    ArtifactTransfer.upload("./solve", "/tmp/solve", backend, executable=True),
    name="deploy exploit",
)
~~~

Transfers are bounded, hashed, service-scoped, recorded, and replayed without
repeating the external effect.

## Experiments

~~~python
experiment = c.plan().experiment(target=remote)
run = experiment.execute()
run.close()

print(experiment.report().describe())
experiment.replay().close()
~~~

Use Experiment.diff to compare attempts instead of reconstructing changes from
terminal output.

## Heap, FSOP, brute force, races, and discovery

Ordinary competition solves should migrate heap choreography to the advanced
frontend, not to allocator framework classes:

~~~python
notes = c.heap.menu(
    b"> ",
    commands={"alloc": 1, "edit": 2, "show": 3, "free": 4, "finish": 5},
    prompts={"slot": b"idx: ", "size": b"size: ", "data": b"data: "},
)

h = c.heap(notes, glibc="2.35", slots=range(32))
uaf = h.uaf(read=notes.show, write=notes.edit)
heap = h.leak.safe_link(
    uaf, slot=0, size=0x100, bias=0, tcache_empty=True
)
h.leak.unsorted(
    uaf, slot=2, guard=3, size=0x500, bias=0x219CE0,
    arena_linked=True,
)
~~~

The safe-link leak requires an explicit page-to-base relationship. `bias=0`
means local analysis proved the leaked fd-field page equals `heap.base`; use
`page_to_base=`/`bias=` for a nonzero relation. Pwnx does not infer it.

It also requires explicit singleton-bin evidence (`tcache_empty=True`,
`state="singleton"`, or `assumption=...`). Unsorted leaks require
`arena_linked=True` or a grooming assumption. These statements appear in
`Plan.assumptions`.

Tcache encoding follows the declared glibc model. Poisoning requires an 8-byte
freed-chunk writer (`write_word=`); the standard heap menu supplies one.
Unsorted recipes reject tcache-eligible normalized sizes.

Request normalization and eligibility now come from AllocatorModel. For shipped
glibc models, request `0x408` becomes chunk `0x410` and is tcache eligible;
request `0x409` becomes `0x420` and is not. Both tcache and unsorted recipes use
that boundary. Use `model=` for a tuned allocator and remove `glibc=` from the
same declaration; passing both is rejected.

Prefer `HeapStorage` returned by `h.store()`/`h.reserve()` for `read_file()`.
It carries owner and size evidence, allowing pwnx to reject foreign storage or
control, non-NUL paths, and undersized scratch regions. Raw addresses require
explicit `path_size=` and `scratch_size=`. Storage declarations require a
positive size, an in-domain non-negative slot, and a non-empty role.

Slot domains, pinned slot groups, and poison nodes are ordered: migrate sets to
tuples, lists, or ranges. Failed pinned reservations are atomic and do not
consume the next poison node.

Safe-linked models require one concrete fd-field address per access in
`nodes=`. Older non-safe-linked models may use `uses=N` as a finite operation
budget. Both inputs must be finite and ordered.

Failed authoring operations now roll back slots, poison cursors, generated
sequences, capabilities, assumptions, and menu operation IDs. `HeapFlow`
exceptions receive the same rollback.

Use `h.tcache_poison(...)` for finite arbitrary memory access, `HeapFlow` when
one recipe needs explicit steps, and `@c.boundary(...)` for a genuinely opaque
plain-function operation. `Plan.show()` is the semantic competition view;
`Plan.expand(stage)` replaces manual inspection of generated sends and payload
actions.

`AllocatorModel`, `HeapState`, `HeapTechniqueRegistry`, `FSOPProvider`, and
`StreamCapability` remain extension-author interfaces for adding new recipes or
proof backends. They are no longer the recommended happy path.

`@c.boundary` keeps scalar compatibility for one output or accepts a fact-keyed
mapping. Multiple outputs require exactly every declared key; missing/extra
keys and typed Fact validation failures are contract errors. Its replay identity
includes function code,
defaults, keyword defaults, and stable closure values; pass `semantic_id=` when
captured state is intentionally opaque.

Replace Python brute-force loops and ad-hoc threads with SearchAction and
RaceAction so budgets, deadlines, reset/restart behavior, evidence, and replay
remain explicit. Set `scheduler="processes"` (the default) to make attempt
deadlines killable. It requires a host with fork process isolation; unsupported
hosts fail before a callback runs rather than falling back to leaking threads.

Replace hidden symbolic-execution or external-analysis calls with Investigation
requests. Reports contain hypotheses and evidence; callers decide whether and
how to promote them into facts.

## Devices, Windows, and kernel targets

Do not hide platform launch strings in tube constructors or mutable profiles.
Use `ADBRecipe`, `WindowsProcessRecipe`, `CDBRecipe`, or `KernelVMRecipe` and
register the recipe with `Challenge.on`. Recipes are pure manifests; they carry
tool and artifact identity, lifecycle policy, and support evidence. The runtime
refuses an unsupported host/tool combination before launching it.

`KernelVMRecipe(..., gdb_port=1234)` binds the QEMU debugger stub to
`127.0.0.1`. Exposing it on another interface is deliberately noisy and
requires both `gdb_host=...` and `unsafe_remote_gdb=True`.

PE inspection uses `parse_pe`, which returns immutable sections, imports,
mitigations, and artifact identity. Target-side binary layouts use an explicit
`TargetABI` selected with `target_abi(...)`; there is no global architecture or
endianness setting.

## Protocol transformations

Replace hand-written `zlib`, CRC, or HMAC glue around sends and receives with a
symmetric codec pipeline:

~~~python
packet = bytes_().through(
    CompressionTransform("zlib", max_decoded_size=1 << 20),
    DigestTransform(
        "sha256",
        key=session_key,
        key_ref="credential:challenge-hmac",
    ),
)
~~~

The pipeline records its algorithms and limits, builds outgoing bytes, and
reverses itself while parsing. Variable-size pipelines belong inside `frame`.
Unkeyed hashes and CRCs detect corruption; use a keyed `DigestTransform` when
the protocol purpose is authentication. `key_ref` is an opaque credential
reference for plans and traces; pwnx never records the key or its digest.

## External services and shellcode validation

Use `AcquireWebArtifact` for verified downloads; the expected SHA-256 is
mandatory and the action owns TLS, origin, redirect, cache, size, and deadline
policy. Use `ShellUploadAction` when the only remote capability is a command
shell. Use an authorized `SubmissionRequest` with an idempotency key for
competition submission.

`ShellcodeExperiment` replaces an imperative local shellcode runner. It is a
bounded external-effect action that returns portable exit/signal, output,
memory-map, duration, and payload-hash evidence. Its result is replayed without
executing code again. The Linux subprocess backend is explicit about being a
containment aid rather than a hardened security boundary.

## Deprecation policy

- 0.2 mechanism imports move to `pwnx.compat` or `pwnx.backends` in 0.3.
- The primary package exposes only the purpose-native API.
- Compatibility-shaped conveniences are documented under pwnx.compat.
- Backend mechanisms are documented under pwnx.backends.
- Removal requires a later major version and a working purpose-native
  replacement.

