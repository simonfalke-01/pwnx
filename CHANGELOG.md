# Changelog

## 0.5.0

- Added a competition-facing advanced exploit frontend: compact heap menus,
  UAF declarations, safe-link and unsorted-bin leaks, deterministic or pinned
  slots, finite tcache memory access, heap storage, stack return control, and
  library-owned ORW compilation.
- Added three progressive authoring depths over one IR: intent recipes,
  per-stage `HeapFlow` primitives, and plain-function `Challenge.boundary`
  escape hatches. Normal advanced solves no longer implement Actions,
  contracts, payload builders, or ROP compilers.
- Added compact semantic `Plan.show()` output and `Plan.expand(stage)` for raw
  generated choreography, plus `tcp()` and fluent default target selection.
- Hardened advanced recipes with explicit page-to-base leak relationships,
  allocator-aware tcache encoding, unsorted-bin size checks, qword-write
  requirements, owned/sized heap storage, cross-challenge control rejection,
  and atomic ordered slot/node reservation.
- Added explicit singleton-tcache and arena-link assumptions to heap leaks,
  surfaced them in plans, distinguished safe-link node addresses from finite
  pre-safe-link access tokens, and centralized authoring rollback across slots,
  cursors, sequences, capabilities, assumptions, and menu operation IDs.
- Defined plain-function boundary results and stable identity: scalar or keyed
  mapping outputs, code/default/closure-aware hashes, explicit `semantic_id`
  for opaque state, and replay divergence when that identity changes.
- Tightened multi-output boundaries to exact fact-keyed mappings and retained
  normal typed Fact validation for every returned value.
- Centralized request2size and tcache eligibility in AllocatorModel, including
  the glibc `0x408` eligible / `0x409` ineligible request boundary; tcache and
  unsorted recipes now share that decision, and tuned `model=` selection is
  supported as an alternative to `glibc=`.
- Added a generic constrained-control frontend: encoding-constrained controlled
  buffers, computed indexed indirect calls, register-state-validated stack
  pivots, semantic pinned ROP palettes, and an execve goal compiler that owns
  string/dispatch placement, packing, operation ordering, and final validation.
- Added `examples/message_store_constrained.py`, verified locally against the
  real Dice challenge, plus execution/replay and failure-diagnostic tests.
- Documented the opt-in real Dice shell gate with
  `PWNX_DICE_CHALLENGE=<artifact-directory>` and `PWNX_RUN_CTF_E2E=1`.
- Unified constrained-buffer layout across stored data, ROP qwords, dispatch,
  and generated path regions with role/range overlap diagnostics; bound ROP
  palettes to Challenge, executable SHA-256, and architecture; tightened pinned
  gadget grammar and normalized register aliases.
- Split constrained plan rendering into semantic `Plan.show()` fields without
  payload dumps and exact-byte `Plan.expand(stage)` output, and added an opt-in
  Docker E2E test that verifies a shell on the real Dice challenge.
- Validated normalized state, pivot, explicit palette, and pinned registers
  against the target architecture; retained eax/edx/r8d aliases while rejecting
  unknown registers in every declaration path.
- Made constrained-goal menu-ID preparation transactional and cached by buffer
  revision: successful goals consume unique IDs, failed preparation restores
  counters, and repeated plan construction is idempotent.
- Finalized the opinionated 0.5 constrained-control syntax: tuple-defined menus,
  `buffer(..., encoding=...).written_by(op)`, `buffer.qword(offset)`, indexed
  operations, explicit `pivot(register=..., stack=..., gadget=...)`, and the
  immutable `x.rop(constraint).pop().zero().move().syscall()` builder. It lowers
  to identical IR, payload, index, and replay without a general operator DSL.
- Made `examples/message_store_sugar.py` the primary Dice solve while retaining
  `message_store_constrained.py` as the explicit advanced fallback.
- Bound natural-syntax buffer writers to the controlled-buffer capacity without
  widening stricter explicit codec limits; binding now returns immutable,
  order-independent per-buffer QuickOperation/Choice views while leaving the
  original menu and siblings unchanged. Views share only the monotonic Menu ID
  counter, and explicit/sugar lowering has direct Action/contract/channel/codec
  equality coverage.
- Moved map-based palettes, explicit controlled-buffer construction, pivot
  helpers, and implementation types to `pwnx.advanced`; removed their primary
  aliases and added migration diagnostics for 0.4 solves.

## 0.3.0

- Added typed sorts, independent lifecycle epochs, capabilities, effect
  contracts, evidence, and technique proofs.
- Added generic provider and goal-strategy planning with stable ranking.
- Added uniform plugin Action contracts and runtime executor registration.
- Added immutable target recipes for local, TCP/TLS, SSH, QEMU, and serial
  environments with architecture and artifact identity.
- Added Experiment reports, replay, and comparison.
- Added offline ambiguity-preserving libc hypotheses and discriminating probes.
- Added replay-safe SSH artifact transfer actions.
- Added versioned allocator state, explicit heap primitives, effect-oriented
  heap goals, and ranked capability proofs that keep technique names in proof
  evidence.
- Added versioned FILE layouts and stream-capability proofs that validate an
  explicit process-memory-write primitive and label FILE, wide-data, and fake
  wide-vtable writes.
- Added bounded search and race actions with killable process-isolated attempts,
  explicit reset or restart policies, lanes, barriers, deadlines, unsupported
  host failures, and replayed results.
- Added bounded static, crash, and subprocess investigations that return
  hypotheses, rejections, artifacts, metrics, and evidence without silently
  creating facts.
- Added Android/ADB, native/Wine Windows, CDB, PE inspection, and kernel-QEMU
  target adapters with explicit host support evidence and loopback-default GDB
  listeners that require an unsafe acknowledgement for remote exposure.
- Added versioned target ABIs with call/syscall placement, constants, binary
  schemas, and a Linux AMD64 rt-sigreturn schema consumed by the SROP backend.
- Added content-addressed HTTPS acquisition, verified shell-only upload, and
  explicitly authorized/idempotent competition submission actions.
- Added symmetric CRC/checksum, zlib/gzip/bz2/lzma, hash/HMAC transform
  pipelines with bounded decoding, authentication semantics, and opaque HMAC
  key references instead of key-derived metadata.
- Added authorized, resource-bounded shellcode experiments whose exit/signal,
  output, maps, duration, and payload identity are recorded and replayed
  without repeating native execution.
- Quarantined pwntools-shaped helpers under pwnx.compat and mechanism-level
  compilers under pwnx.backends; they are no longer direct primary-package
  attributes.
- Rewrote primary documentation around purpose-native workflows.

## 0.2.0

- Added explicit packing/unpacking, sparse layouts, cyclic patterns, crash
  offsets, and common byte utilities.
- Added static checksec facts, Linux process maps/memory, and AMD64 core files.
- Added process-scoped MemoryOracle and bounded DynResolver.
- Added strict tube convenience methods, UDP, listeners, and POSIX serial.
- Added system OpenSSH, QEMU user-mode, scripted GDB launch, and GDB attach.
- Added cached AMD64 assembly/disassembly and labelled Linux shellcode.
- Added register goals with multi-pop accounting, pivots, migration, and
  ret2csu.
- Added traced format-string argument discovery for repeatable services.
- Added CLI checksec, cyclic, asm, and disasm commands.

## 0.1.0

- Initial declarative facts, capabilities, recipes, goals, planner, runtime,
  provenance, trace/replay, ELF64 AMD64, ROP, SROP frames, format writes, and
  ret2dlresolve.
