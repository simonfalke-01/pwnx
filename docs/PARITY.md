# Pwntools purpose-parity audit

Baseline: pwntools stable documentation labelled 4.15.0, retrieved
2026-11-06. Pwnx measures parity by the operator job, not by module, function,
or spelling. A row is covered only when pwnx has a purpose-native model, a
working reference path or an honest unsupported result, lifecycle/effect
semantics, and tests.

The primary pwnx model is six concepts: target recipes, conversations,
evidence, capabilities, technique proofs, and experiments. Familiar imperative
helpers remain quarantined under `pwnx.compat.pwntools`; mechanism compilers
remain under `pwnx.backends`.

## Purpose matrix

| ID | Operator job | Pwnx-native answer | Implementation and acceptance evidence | Status |
| --- | --- | --- | --- | --- |
| P01 | Declare a reproducible target | Immutable target recipes with architecture, artifacts, credential references, lifecycle, and epochs | `architecture.py`; `test_architecture.py` | Covered |
| P02 | Converse with a target safely | Typed channels plus `Observation`, emit, expect, and capture as self-describing Actions; every stream read declares bounds and cursor effects, with distinct timeout, EOF, and mismatch failures | `challenge.py`, `channels.py`, `actions.py`, `runtime.py`; observation/action/runtime tests | Covered |
| P03 | Describe messages and protocols | Symmetric codecs, frames, structs, fields, menus, choices, ordered protocol actions, and a compact conventional heap-menu adapter | `codecs.py`, `protocols.py`, `exploit.py`; `test_codecs.py`, `test_protocols.py`, `test_exploit.py` | Covered |
| P04 | Reach process, stream, datagram, listener, TLS, or serial endpoints | Explicit environment and transport adapters | `architecture.py`, `transport.py`; architecture/transport tests | Covered |
| P05 | Reproduce a local target faithfully | Loader/library-aware local recipe with immutable artifact and lifecycle identity | `architecture.py`; `test_architecture.py` | Covered |
| P06 | Inspect binary facts | Immutable ELF and PE symbols, sections, imports, mappings, mitigations, and hashes | `artifacts.py`, `platforms.py`; artifact/platform tests | Covered for declared formats |
| P07 | Modify an artifact without losing identity | Immutable patch/save derivation; output is a new hashed artifact | `artifacts.py`; artifact tests | Covered |
| P08 | Construct exact payload bytes | Typed codecs and labelled sparse `Payload` regions tied to a target ABI | `payload.py`, `codecs.py`; payload/codec tests | Covered |
| P09 | Turn a crash into control-offset evidence | Bounded cyclic evidence and crash/core investigations | `packing.py`, `diagnostics.py`, `investigation.py`; related tests | Covered |
| P10 | Inspect and transform bytes | Evidence renderers plus typed reversible transform pipelines; compatibility aliases are not the primary API | `codecs.py`, `packing.py`; codec/packing tests | Covered |
| P11 | Compile or inspect target code | Explicit toolchain and effect-oriented shellcode backends with architecture support evidence | `toolchain.py`, `shellcode.py`, `architecture.py`; toolchain/shellcode tests | Covered for declared backends |
| P12 | Realize a control-flow or machine-state goal | Provider/strategy graph returns ranked proofs; optional natural syntax is pure compression over identical IR, with immutable per-buffer writer views that cap inferred codecs, never widen explicit limits, leave the source menu unchanged, bind order-independently, and share only monotonic menu IDs; the explicit API remains the fallback | `sugar.py`, `control_flow.py`, `providers.py`, `techniques.py`; explicit-vs-sugar action/contract/channel/codec/plan/payload/index/execution/replay, immutable multi-buffer binding, and E2E tests; `examples/message_store_sugar.py`, `message_store_constrained.py` | Covered for declared strategies, target identities, architectures, and constraints |
| P13 | Use signal-return execution | The SROP backend consumes the versioned Linux AMD64 `TargetABI` rt-sigreturn schema and rejects ABIs without one | `abi.py`, `techniques.py`; ABI/technique tests | Covered for the declared Linux AMD64 schema |
| P14 | Resolve through the dynamic linker | Goal strategy and ret2dlresolve backend, rather than a separate solve language | `providers.py`, `techniques.py`; technique tests | Covered |
| P15 | Discover/read/write with a format-string primitive | Explicit capability, bounded discovery action, proof/backend, and replayed evidence | `formats.py`, `challenge.py`; format tests | Covered |
| P16 | Model libc streams and FSOP | Versioned FILE layouts, explicit process-memory-write capability checks, and labelled FILE/wide-data/wide-vtable writes for controlled calls | `fsop.py`; `test_fsop.py` | Covered for shipped layouts without unsupported wide-vtable validation |
| P17 | Use arbitrary memory reads safely | Scoped, epoch-aware memory capability with bounded cache and provenance | `memory.py`; `test_memory.py` | Covered |
| P18 | Resolve symbols from remote memory | Bounded resolution actions whose callback effects are recorded and not replayed | `memory.py`; `test_memory.py` | Covered for the ELF64 AMD64 reference backend |
| P19 | Identify an unknown libc | Offline immutable catalog, ambiguity-preserving hypotheses, conflicts, and discriminating next probes | `libc.py`; `test_libc.py` | Covered |
| P20 | Inspect live and crashed process state | Maps, memory, cores, failure artifacts, and crash-triage hypotheses | `diagnostics.py`, `investigation.py`; related tests | Covered for declared platforms |
| P21 | Debug repeated attempts | Structured debugger recipes/actions and bounded external analyzer adapters | `challenge.py`, `runtime.py`, `platforms.py`, `investigation.py`; debugger/platform tests | Covered for GDB and CDB reference paths |
| P22 | Execute a foreign architecture | QEMU user recipes plus architecture predicates and explicit unsupported evidence | `architecture.py`; `test_architecture.py` | Covered when a declared emulator exists |
| P23 | Transfer remote artifacts | Hashed, bounded, atomic, replay-safe SSH transfer actions | `transfers.py`; `test_transfers.py` | Covered |
| P24 | Work with Android and Windows targets | ADB actions/recipe, native/Wine/CDB recipes, PE evidence, and host-support decisions | `platforms.py`; `test_platforms.py` | Covered |
| P25 | Move artifacts through a shell-only session | Injection-safe bounded chunk plan, remote digest/size verification, invalidation, and replay | `services.py`; `test_services.py` | Covered |
| P26 | Execute raw shellcode while collecting evidence | Authorized `ShellcodeExperiment` with a Linux subprocess containment backend, resource/deadline/output bounds, maps, exit/signal evidence, and replay | `effects.py`; `test_effects.py` | Covered for matching Linux host architecture |
| P27 | Materialize ABI and kernel structures | Versioned call/syscall layouts, constants, struct schemas, and kernel-VM recipes with loopback-default GDB policy | `abi.py`, `platforms.py`; ABI/platform tests | Covered for declared ABIs |
| P28 | Check, compress, and authenticate protocol data | Symmetric CRC/checksum, zlib/gzip/bz2/lzma, and hash/HMAC pipelines with decode limits and opaque HMAC key references | `codecs.py`; `test_codecs.py` | Covered |
| P29 | Reason about heap techniques | Competition recipes require visible singleton/arena assumptions, explicit page-to-base relations, one AllocatorModel-owned request2size/tcache boundary, finite node/token budgets, owned storage, stack control, and ORW; tuned models are supported and one authoring transaction rolls back partial declarations | `exploit.py`, `heap.py`; adversarial assumptions/rollback/ownership/size/order/encoding and 0x408/0x409 boundary tests in `test_exploit.py`/`test_heap.py`; `examples/advanced_heap_orw.py` | Covered for the hardened glibc-2.35 reference journey and declared/tuned allocator models |
| P30 | Brute-force or race deliberately | Bounded search/race actions with killable process isolation, deadlines, reset/restart, barriers, unsupported-host evidence, and replay | `concurrency.py`; `test_concurrency.py` | Covered on hosts with fork process isolation |
| P31 | Automate bounded discovery or triage | Opt-in investigations with time/memory/state/result/output budgets that emit hypotheses, never silent exploit choices | `investigation.py`; `test_investigation.py` | Covered |
| P32 | Reproduce, explain, compare, and replay attempts | `Experiment`, semantic reports, compact `Plan.show()`, raw `Plan.expand(stage)`, causal traces, diffs, identities, and non-repeating opaque effects; target-bearing replay requires the same recipe | `planner.py`, `experiment.py`, `runtime.py`, `trace.py`; exploit/experiment/trace tests | Covered |
| P33 | Submit a competition result | Explicitly authorized, idempotent, credential-referenced irreversible action with redirect protection and replay | `services.py`; `test_services.py` | Covered |
| P34 | Acquire a challenge artifact from the web | Mandatory SHA-256 identity, TLS/origin policy, bounded redirects/size/deadline, atomic cache, provenance, and replay | `services.py`; `test_services.py` | Covered |
| P35 | Extend unusual targets and integrate ordinary Python tooling | Three depths share one IR: intent recipes, transactional `HeapFlow` primitives, and plain-function `@boundary`; strict fact-keyed multi-output mappings and typed validation retain scalar one-output compatibility, while code/default/closure/explicit semantic identity guards replay | `exploit.py`, `challenge.py`, `domain.py`, `actions.py`, `providers.py`, `planner.py`, `runtime.py`, `backends/`; AST ergonomics, boundary mapping/type/identity/replay, flow/resource rollback, direct/registry/Opaque/lowering tests | Covered / deliberate standard-library use |

There are no uncovered operator jobs in this matrix. Coverage is deliberately
conditional where execution inherently depends on an installed emulator,
debugger, device tool, host OS, architecture, or libc version. Those conditions
produce inspectable support decisions; pwnx does not claim a backend it cannot
run.

## What was corrected from 0.2

The 0.2 pass copied several useful pwntools-shaped surfaces too close to the
primary API: packing aliases, tube verbs, direct ROP/shellcode/toolchain
compilers, and mutable environment profiles. Version 0.3 keeps their working
implementations but changes their architectural role:

- `pwnx.compat.pwntools` is the explicit migration namespace.
- `pwnx.backends` is the mechanism-author namespace.
- Primary authoring describes facts, capabilities, effects, target recipes,
  technique proofs, and experiments.
- New platform, service, transform, concurrency, and investigation purposes use
  the uniform contracts; none adds a planner/runtime type switch.

## Deliberate non-parity

Pwnx does not duplicate ambient global context, magic command-line arguments,
logging/progress frameworks, or package management. Standard Python already
fulfils those jobs without weakening target ownership or provenance. Pwnx also
refuses unbounded automatic exploitation, silent network acquisition,
credential values embedded in manifests, and replaying external effects.

This is full purpose parity, not a claim that every architecture-specific
template or every pwntools symbol is present. New architecture implementations
plug into the same contracts and must provide support evidence and acceptance
tests before they are described as covered.
