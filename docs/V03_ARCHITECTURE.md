# Pwnx 0.5 architecture over the 0.3 semantic kernel

## Product model

Pwnx is an exploit specification compiler. Its primary language consists of
target recipes, conversations, evidence, capabilities, technique proofs, and
experiments.

Mechanisms such as ROP gadget search, assembly, SSH, ELF parsing, packing, or
memory lookup are backend implementations. They are not separate authoring
models.

## Competition authoring frontend

`exploit.py` is a compression layer over the semantic kernel. It does not add a
second execution model. Its heap-menu, leak, memory-access, stack-control, and
ORW recipes lower into the existing Actions, providers, contracts, facts,
transactions, trace, and replay boundaries.

The abstraction boundary is mechanics versus reasoning:

- Authors declare commands/prompts, vulnerable operations, allocator version,
  leak relationships, usable poison-node addresses, storage layout, and goals.
- Pwnx supplies deterministic slot selection, allocator choreography,
  safe-link encoding, captures, fact propagation, payload construction, and
  stage scheduling.
- Pwnx never guesses a vulnerability, a main-arena bias, a heap layout, or a
  saved-return-address delta.

The frontend has three depths over one IR:

1. Intent recipes (`safe_link`, `unsorted`, `tcache_poison`, `read_file`) cover
   established mechanics.
2. `HeapFlow` replaces one recipe with local allocation/free/edit/show/derive
   primitives while the rest of the solve remains at intent level.
3. `Challenge.boundary` wraps a plain function in an explicit opaque contract
   for proprietary operations. The author does not implement an Action class.

A one-output boundary accepts a legacy scalar or a fact-keyed mapping. Multiple
outputs require exactly the declared fact keys; missing and extra outputs fail,
and values pass the normal typed Fact validators. Its stable identity covers code,
constants, defaults, keyword defaults, and stably encodable closure values;
captured opaque objects require `semantic_id=`. Replay rejects a changed
identity rather than reusing the recorded result.

Automatic slots are deterministic. Pinned `slot=`/`slots=` and finite poison
`nodes=` are part of the plan and provenance. `Plan.show()` renders compact
semantic stages; `Plan.expand(stage)` renders generated protocol and payload
actions. Both views describe the same plan.

Heap resources are ordered. Slot domains, pinned slots, and poison nodes use
tuples, lists, or ranges; sets and mappings are rejected. Multi-slot validation
is atomic, and a failed access reservation restores the poison-node cursor.

All frontend authoring mutations use one resource transaction. A failed recipe
restores slot ownership, memory-access cursors, generated sequences,
capabilities, narrative assumptions, and menu operation IDs. `HeapFlow`
exceptions roll back through the same boundary.

Safe-link recipes bind the leaked fd-field page separately from `heap.base`.
`page_to_base=` (or `bias=`) is mandatory, including an explicit zero when
equality is proved. Link encoding consults the declared AllocatorModel: models
without safe-linking use the raw target; safe-linked models encode against the
declared node. Unsorted recipes reject normalized tcache-eligible sizes, and
tcache poisoning requires an explicit qword writer rather than strengthening a
generic byte writer.

AllocatorModel owns glibc request2size normalization and the normalized
`tcache_max`. The reference boundary is `0x410`: request `0x408` normalizes to
`0x410` and remains eligible; request `0x409` normalizes to `0x420` and does
not. Tcache-poison and unsorted-bin frontends call the same
`model.tcache_eligible()` predicate, preventing divergent boundary logic. A
target may supply a tuned `model=` or select a shipped `glibc=` model, never
both.

Safe-link singleton decoding additionally requires `tcache_empty=True`,
`state="singleton"`, or an explicit grooming assumption. Unsorted disclosure
requires `arena_linked=True` or an explicit arena-link assumption. These
statements enter `Plan.assumptions` and the semantic plan rendering. Safe-linked
access consumes concrete ordered `nodes=` addresses; pre-safe-linking models may
instead consume a finite ordered budget created with `uses=N`.

`HeapStorage` records the owning HeapExploit/Challenge, address, size, slot, and
stored data. Read-file goals require matching path, scratch, memory access, and
return control; validate path NUL termination and scratch capacity; and require
explicit sizes for raw addresses. Storage size must be positive, its slot must
be non-negative and in the declared domain, and its role must be non-empty.
Cross-challenge storage/control is rejected.

The canonical advanced acceptance solve is
`examples/advanced_heap_orw.py`. Its AST contains no user-defined class,
function, lambda, internal Action/contract/fact type, backend compiler, packing,
or tube call. The easy ret2win path remains unchanged.

### Stack-flow frontend

The quick stack frontend composes existing protocol and control primitives:

- `Challenge.format_leak()` builds one ordered positional-pointer exchange from
  named stack positions, consumes an optional response prefix, parses separator-
  delimited hex fields, and returns a namespace of process-scoped facts.
- `Challenge.relate()` lowers an explicit symbolic equation to a normal Bind
  action, preserving provenance and dependency ordering.
- `InputSurface.return_address(..., canary=(offset, fact))` adds an aligned,
  bounded protected qword to the existing overflow control declaration.
- The existing call/ROP strategy consumes the rebound libc and control facts;
  no stack-flow-specific runtime path or planner type switch exists.

The generated format exchange, relationship, and sparse protected payload are
ordinary Actions and contracts. Semantic `Plan.show()` omits raw exploit bytes;
`Plan.expand(stage)` exposes the exact format payload, prompt parsing, codecs,
protected offsets, and generated chain.

`examples/cage.py` is the canonical quick CTF example and has executed locally
against the real Cage challenge. The opt-in Docker shell test is gated by
`PWNX_CAGE_CHALLENGE` and `PWNX_RUN_CTF_E2E=1`.

### Glass-box bytecraft and fresh-instance retries

`bytecraft.py` is an immutable competition-facing frontend over the existing
Payload representation. It is deliberately below intent recipes and above
packing/backend internals.

- Craft operations create labelled raw, padding, aligned, sparse, integer,
  pointer, partial-pointer, and codec-encoded regions.
- Symbolic values retain fact dependencies. Structural `layout()` and `show()`
  work unresolved; byte-level `build()` and `hexdump()` require a binding
  context and never fabricate placeholder bytes.
- Craft constraints reuse Payload forbidden bytes and support size, encoding,
  predicate, and reusable byte validators.
- `Challenge.send()` lowers a Craft through the same Emit action used by raw,
  line, and menu recipes.

Constraint composition is monotonic across immutable builder calls: forbidden
sets accumulate, size bounds only strengthen, encodings/predicates accumulate,
and conflicting exact bounds fail immediately. Craft replacements and Plan
patches use unchecked reconstruction followed by the same final validation, so
patching cannot bypass bad-byte, size, encoding, predicate, or channel rules.

The Plan recursively inventories structured sends as `PlannedPayload` records
with stable payload/send/stage identity. Runtime resolves them into the only
primary exported implementation type, `PayloadArtifact`, containing bytes,
layout, dependencies, SHA-256, provenance, hexdump, and region diff. Trace
payload metadata uses the same payload and send IDs.

PayloadArtifact is appended at Emit time from the bytes and facts actually sent.
It is never recomputed from the final fact store. Fact invalidation/rebinding
cannot alter an earlier artifact; repeated sends of one Craft create distinct
artifacts with distinct send IDs.

`Plan.patch_payload()` returns a new Plan whose selected payload has an
explicit labelled, reasoned, same-size patch. It does not mutate the source
Plan, add dependencies, or bypass constraints. Replay rejects a trace recorded
for different bytes; Trace diff correlates changed ranges with layout labels
and send identity.

Line channels add generic Craft feasibility after symbolic resolution/final
validation and before send. A dynamic labelled region containing a terminator
or forbidden byte raises RetryableInstanceError with label, offset, byte, and
channel evidence. Static invalid bytes remain nonretryable ConstraintError; raw
channels do not apply line framing.
`Challenge.run(attempts=N)` catches only that error, opens a fresh target epoch,
closes failed instances, and records retry budget/use/failures. Explicit
transports, replay, persistent lifecycles, and nonretryable errors do not enter
the loop.

`examples/bytecraft.py` is the canonical byte-layout example. The Cage example
uses `attempts=64` because its leaked canary is instance-scoped and may be
incompatible with line framing.

### Generic constrained control flow

`control_flow.py` provides the same mechanics-versus-reasoning boundary for
hard control-flow challenges that do not resemble a standard overflow.

`sugar.py` and the fluent control-flow builders form the opinionated 0.5
competition surface:

- `Challenge.menu()` maps command or `(command, prompt, type, ...)` tuple specs
  into the existing typed Menu/Choice/Field model.
- `buffer(..., encoding=...).written_by()` configures the writer;
  `buffer.qword(offset)` creates the bounded dispatch slice.
- `QuickOperation.indexes()` delegates to `indirect_call()` with register
  keyword state; `pivot(register=..., stack=..., gadget=...)` is the only
  primary pivot form.
- `Challenge.rop(constraint).pop(...).zero(...).move(...).syscall(...)` is the
  immutable semantic chain builder.

This veneer adds no action, provider, payload, or replay type. Acceptance tests
compare its plan dictionary, lowered Actions, EffectContracts, channels, codecs,
payload bytes, table index, execution, and replay to the explicit API. It does
not add a general operator-overload DSL; challenge relationships remain
explicit method arguments.

When `written_by()` receives a QuickOperation, binding requires exactly one
bytes field. The bound BytesCodec maximum becomes
`min(explicit_max, controlled_buffer_size)`; an inferred maximum is capped at
the buffer, and a stricter explicit limit is never widened. Binding returns a
new QuickOperation and Choice view; the source operation, Menu choices, and
siblings remain immutable. Independent buffer bindings are order-invariant.
Their only shared authoring state is the Menu's monotonic operation-ID counter,
which is also shared with explicit invocation.

- The byte-constraint contract validates every fixed gadget/value and complete payload;
  `utf8()` is the shipped encoding constraint.
- The controlled buffer owns a target address, finite size, writer operation,
  constraints, and one region map for stored data, generated ROP qwords, the
  dispatch qword, and generated path bytes. Role/range diagnostics reject every
  partial or complete overlap.
- Indexed-call control computes the index from the declared table and target
  slice, validates entry alignment, records the trigger and register state, and
  returns a capability.
- Pivot control requires the declared pointer register to equal the controlled
  buffer address and validates the pinned pivot gadget.
- The finalized semantic palette maps fluent `pop`, `zero`, `move`, and
  `syscall` declarations to pinned addresses. It is owned by the creating
  Challenge, executable artifact digest, and target architecture. Register
  aliases normalize to canonical 64-bit names and are then validated against
  the target ArchitectureSpec. The frontend validates byte representations but
  does not discover gadgets or infer semantics.
- The execve goal compiler places the path and dispatch qword, realizes the
  register state, validates the complete constrained payload, and orders the
  buffer write, computed index operation, and trigger.

This API deliberately leaves unusual addresses and relationships in the solve
while removing manual qword packing, table-index arithmetic, payload layout,
and choreography. Compact `Plan.show()` exposes semantic buffer, index,
register, pivot, palette, and strategy fields without raw payload bytes;
`Plan.expand(stage)` exposes the exact payload and operations. They are two
views of the same lowered Actions and contracts.

### Advanced flexibility surface

Explicit construction types and map-based helpers are intentionally outside
the primary namespace:

~~~python
from pwnx.advanced import controlled_buffer, pivot, rop_palette
~~~

This surface exists for generated gadgets, unusual schemas, and integration
authors. It produces the same IR as the canonical API. Primary `pwnx.__all__`
does not export Action, EffectContract, Payload, BufferSlice, ControlledBuffer,
RopBuilder, or RopPalette.

`examples/message_store_sugar.py` is the primary hard-challenge example;
`examples/message_store_constrained.py` preserves the explicit fallback. The
solve has executed locally against the real Dice challenge. Unit tests
also execute the generated UTF-8 payload/index/trigger sequence and prove trace
replay performs no live effects. An opt-in Docker E2E test, gated by
`PWNX_RUN_CTF_E2E=1` plus `PWNX_DICE_CHALLENGE=/path/to/artifact-directory`,
sends a shell sentinel through the actual challenge and requires it in the
output. The directory contains the `challenge` binary and canonical
`solve_pwnx.py`.

Constrained-goal preparation owns protocol operation numbering. Successful
preparation consumes unique menu IDs; failed preparation restores all
discovered counters. Prepared actions are cached by controlled-buffer revision,
so repeated plan construction is idempotent while multiple goals keep distinct
IDs.

## Architecture invariants

1. Declaration and planning perform no target I/O.
2. Common solves state evidence, capabilities, missing facts, and goals.
3. Beginner and advanced workflows lower to one action and provider graph.
4. Every external effect in a compiled solve has an EffectContract and appears
   in the plan/trace; direct backend escape hatches remain explicitly outside
   that guarantee.
5. Facts have an explicit sort, scope, provenance, and epoch.
6. Service, process, and connection lifetimes are independent.
7. Environments are immutable target recipes with artifact identity.
8. Technique selection returns a proof with prerequisites, cost, reliability,
   assumptions, and rejected alternatives.
9. Replay never repeats external effects and rejects changed identities/inputs.
10. State invalidation is enforced during planning and runtime.
11. Backends are replaceable and selected by declared architecture predicates.
12. New integrations use provider/action contracts instead of central type
    switches.

## Typed domain

domain.py defines:

- Sort and built-in integer, Boolean, bytes, string, address, and offset sorts.
- Scope for artifact, service, process, and connection lifetimes.
- Epochs with independent reconnect/restart transitions.
- Fact, FactValue, and FactStore for typed, lifetime-safe bindings.
- Evidence and Constraint.
- EffectContract and Capability.
- TechniqueProof.
- Generic Environment and TargetManifest.

FactStore and the common runtime use the same Sort validators and structural
fact identity: name, sort semantics, scope, and artifact. They reject wrong
Python types, incompatible same-name facts, conflicting live evidence, and
unresolved values. A stale binding may be replaced after its service, process,
or connection epoch changes; a conflicting binding in the current epoch may
not.

Constraint equality is semantic rather than name-based. Pure Python predicates
receive a stable identity derived from bytecode, constants, defaults, and
stably encodable closure values. Predicates closing over application objects
must declare `semantic_id=` explicitly; object reprs and function addresses are
never used as contract identity.

## Uniform effects

Every Action exposes:

~~~text
action.contract() -> EffectContract
action.lower(planning_context) -> tuple[Action, ...]
action.execute(runtime) -> result | NotImplemented
action.describe() -> str
~~~

Lowering is recursive and finishes during planning with a read-only
`ActionPlanningContext`; the runtime never discovers new actions after target
I/O begins. The runtime provides ActionRuntime with:

- tube, trace, and binding context.
- resolve(value).
- bind(target, value, source=...).
- provide(capability).

Runtime actions cannot execute newly constructed nested actions. Composed work
must be returned from `lower(planning_context)` so it is visible in the plan.

An external package can implement and execute a new Action without changing the
central planner or interpreter. Optional action executors can also be registered
by type through the action executor registry. Direct execution, registered
execution, replay, and lowered actions pass through one enforcement boundary:
requirements and constraints are checked, invalidations are applied once, and
declared fact/capability products must actually materialize.

Atomic fact changes are transactional. Runtime validates and snapshots
requirements, executes while consumed facts remain readable, captures declared
products, then commits canonical invalidations and restores the products. An
exception rolls fact state back without committing invalidations. If an
external effect completes but product validation or commit fails, fact state is
rolled back and `contract_failures` evidence explicitly states that the
external effect cannot be rolled back.

Bindings use bounded copy-in/copy-out snapshots. Primitive immutable values,
tuples/frozensets, portable dict/list/set containers, mapping proxies, and
deeply snapshot-safe frozen dataclasses are supported; cycles and unknown
mutable objects are rejected before effects. Callers never receive an alias to
stored mutable fact state. When an action both provides and invalidates a fact,
the transaction requires an explicit `bind()` during that execution—even when
the replacement value compares equal—so an old binding cannot masquerade as a
new product.

Primitive actions remain stable: observation, emit, expect, capture, bind,
check, delay, sequence, and branch. Observation declares connection-stream
reads, cursor/fact writes, provided facts, timeout, and byte bounds like every
other Action.

## Providers and strategies

providers.py defines a registry and graph planner:

- Provider: structurally satisfied requirements to facts/capabilities/actions.
- GoalStrategy: goal and capability requirements to actions.
- ProviderContext: target, known values, capabilities, and policy.
- ProviderPlanner: transitive acquisition, cycle detection, stable ranking,
  rollback of rejected candidates, and TechniqueProof output.

Challenge owns one ProviderRegistry. Challenge.provider and Challenge.strategy
register extensions. GoalRequest enters the generic graph path while existing
0.2 goals continue through compatibility adapters.

Fact requirements are never satisfied by name alone: Sort semantics, scope,
and artifact must agree. Capability labels are explanatory; satisfaction is a
proof that the available effect contract covers the required reads, writes,
products, prerequisites, invalidations, constraints, and scope.

## Environments

architecture.py separates architecture description from backend availability:

- ArchitectureSpec for AMD64, i386, AArch64, ARM, MIPS, MIPSEL, and RISC-V.
- CapabilityPredicate and BackendRegistry.
- Immutable target recipes for local processes, QEMU user mode, SSH processes,
  serial devices, and TCP/TLS.
- MaterializedTarget with argv/endpoint, artifacts, architecture, lifecycle,
  independent epochs, adapter identity, and evidence.

Challenge.on registers a named target recipe, or fluently selects a default
recipe when called as `challenge.on(recipe)`. `tcp(host, port)` is the compact
TCP/TLS recipe constructor. Plan.run(on=...) materializes the selected recipe and
uses the runtime environment adapter registry. Traces record its identity and
artifacts. A target-bearing trace cannot be replayed through public
`Plan.run(replay=...)` without the matching `on=` recipe, and replay rejects a
changed recipe identity.

## Evidence and experiments

Experiment wraps a plan, target, trace, run, evidence, report, replay, and diff.
ExperimentReport summarizes goals, selected strategy, stages, facts, payloads,
assumptions, evidence, and event counts.

Trace remains the causal source for runtime effects. Semantic metadata remains
derived evidence rather than terminal scrollback.

## Purpose-native adapters

- libc.py produces immutable candidates and HypothesisSet results. It preserves
  ambiguity and suggests discriminating observations; it never mutates
  Challenge.libc.
- transfers.py models SSH upload/download/stat/hash as ArtifactTransfer actions
  with hashes, limits, service scope, identity, and replayed result boundaries.
- architecture.py makes unsupported architecture/backend combinations explicit.
- Memory resolution, format discovery, and opaque operations reuse the same
  recorded external-effect boundary.
- platforms.py applies the same recipe/action contracts to ADB, native/Wine
  Windows processes, CDB, PE evidence, and kernel QEMU VMs. Missing host tools
  produce support evidence and the runtime refuses unsupported materializations
  before spawning a process. Kernel QEMU GDB listeners default to loopback;
  non-loopback binding requires `unsafe_remote_gdb=True`.
- abi.py supplies immutable, versioned call/syscall layouts, constants, and
  binary schemas. Architecture is an input to ABI selection, never ambient
  context.
- services.py models content-addressed HTTPS acquisition, authorized
  competition submission, and shell-only verified upload. Credentials remain
  references and redirects, output, size, and deadline policy are explicit.
- effects.py models raw-code validation as an authorized ShellcodeExperiment.
  Its Linux reference backend records payload identity, exit or signal,
  stdout/stderr, memory maps, duration, bounds, and containment limitations;
  replay consumes the result without executing native code again.

## Protocol transform pipelines

Codec transformations are value-independent `ByteTransform` stages. A
`TransformCodec` applies them in declared wire order and reverses that order
when parsing. Shipped stages cover CRC/checksum, zlib/gzip/bz2/lzma, and
hash/HMAC framing.

Every stage declares encoded-size behavior and metadata. Compression has
encoded, decoded, and ratio limits; decoders reject truncation and trailing
data. Checksum and digest frames use constant-time tag comparison. Unkeyed
hashes are labelled as integrity checks, while only keyed HMAC stages claim
authentication. HMAC metadata includes an opaque caller-supplied `key_ref`,
never key bytes or a deterministic key fingerprint. Variable-size pipelines
require an enclosing frame for reads.

## Advanced capability proofs

Heap and stream exploitation do not expose framework classes or a catalogue of
named attacks as the normal authoring model. The competition frontend declares
allocator facts, established primitives, and the desired effect. Providers
choose a realization and return its name, assumptions, actions, and rejected
alternatives as proof evidence. The lower-level model remains an extension API.

Current execution evidence includes deterministic scripted transport and replay
for safe-link and unsorted leaks, tcache arbitrary-read choreography, fact
propagation, slot pinning, diagnostics, and ORW plan compilation. Executing the
final ORW chain against a native vulnerable glibc-2.35 fixture remains integration
hardening; the architecture does not present that unrun fixture as evidence.

heap.py separates allocator state from exploit technique names:

- AllocatorModel declares implementation/version semantics and safe-linking.
- HeapState applies immutable allocation/free/edit/consolidation transitions.
- HeapPrimitive objects describe observed capabilities such as dangling reads,
  UAF, double free, overlap, arbitrary read/write, and heap-address knowledge.
- HeapGoal states the desired outcome.
- HeapTechniqueRegistry returns ranked TechniqueProof values with prerequisites,
  assumptions, rejected alternatives, and proof steps.

fsop.py uses explicit versioned FILE layouts. FSOPProvider consumes an
process-scoped capability whose contract writes `process.memory` and a
StreamCapability goal. Controlled-call proofs contain separate labelled writes
for the FILE object, wide-data object, fake wide vtable, and call target.
Read-only or unrelated capabilities, missing storage, unsupported layouts, and
validated-wide-vtable conditions fail explicitly.

The SROP backend consumes `TargetABI.schema("rt_sigreturn")`; the shipped
reference schema is explicitly Linux AMD64 and versioned independently from
the encoder. Other ABIs fail rather than inheriting AMD64 offsets.

## Search, races, and investigations

SearchAction and RaceAction are explicit opaque-effect boundaries. They declare
attempt budgets, per-attempt deadlines, reset/restart contracts, success
predicates, lanes, barriers, state domains, invalidations, and evidence.
Their `processes` scheduler uses killable fork-isolated workers; a timed-out
worker is terminated before reset, restart, or another attempt begins. Hosts
without that isolation receive explicit unsupported evidence instead of a
thread fallback. Attempt-local facts do not escape failed attempts. Replay
consumes recorded portable results without repeating concurrency or
brute-force effects.

Investigation is a bounded evidence-producing Action. Adapters declare supported
request kinds and architectures. Built-in static and crash triage produce
hypotheses; SubprocessJSONAdapter isolates optional external analyzers behind
time, memory/state/output budgets. Investigation reports retain candidates,
rejections, metrics, artifacts, and evidence and never bind a hypothesis as a
fact automatically.

Search, race, and investigation callbacks are deliberately opaque at the
effect boundary, not ambient escape hatches. Their inputs, budgets, identities,
results, and invalidations remain inspectable and replay-safe.

## Compatibility and backends

pwnx.compat.pwntools contains migration conveniences such as packing aliases,
cyclic helpers, and transport constructors.

pwnx.backends exposes mechanism-level ROP, toolchain, memory, diagnostics, and
transport implementations for provider/technique authors.

0.2 mechanism imports are available only through these explicit namespaces;
the primary package does not retain hidden direct attributes for them.

