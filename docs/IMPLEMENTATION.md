# Implementation contract

This document coordinates the initial implementation. SPEC.md is the design target;
README.md will document the behavior actually implemented and its boundaries.

The package has no runtime dependencies. Python 3.11+ is supported. Source modules
live under src/pwnx; tests use pytest. All planning is local and performs no target I/O.

## Module interfaces

- `expressions.py`: `Expr`, `Call`, `BindingContext`, `Resolved`, `as_expr`.
  An Expr supports arithmetic/bitwise operations, `equals()`, `low(bits)`, a stable
  `key` string, `dependencies` (set of fact-key strings), `describe()`, and
  `evaluate(context)`. No implicit bool/int/bytes conversion. `Expr.fact(name,
  scope='process')`, `Expr.literal(value)`. `BindingContext(instance_id=None)`
  supports `bind(expr, value, source='')`, `resolve(expr_or_value)`, `has(expr)` and
  `explain(expr)`. Binding a linear address expression solves its base. `Resolved`
  carries its source Expr and instance_id and must be rejected in other contexts.
  `Call(target, args)` is a pure symbolic call expression; `target` is an Expr.
- `artifacts.py`: `Image(path, name='exe')` statically parses AMD64 little-endian
  ELF. `.base`, `.symbol(name)`, `.offset(name)`, `.call(name,*args)`, `.got[name]`,
  `.plt[name]`, `.find(bytes)`, `.bss`, `.pointer_size`, `.sha256`, `.path`,
  `.relocatable`, `.load_base`, `.symbols` (raw virtual addresses), `.segments`.
  Dynamic attribute access is symbol sugar. Addresses use base + image-relative
  offsets. `.address(vaddr, label=None)` returns an Expr. `.search(bytes,
  executable=False)` returns raw virtual addresses. `.read(vaddr,n)` reads file
  content. `.dynamic` maps integer DT_* tags to values. `.section(name)` returns
  section metadata. Missing symbols and malformed/unsupported files fail clearly.
- `codecs.py`: codec objects expose `parse(data)->value`, `build(value)->bytes`,
  `.size` (int or None), `.read(io)->value` where io supports read_exact/read_until.
  Fact binding stays in the runtime, not codecs. Helpers: pointer(n=8),
  word(bits=64,endian='little'), hex_pointer(), integer(), bytes_(n=None),
  cstring(), struct(**fields), frame(), xor(). Partial pointer widths preserve an
  explicit extension policy and reject implicit zero-padding.
- `channels.py`: immutable `Channel` with prompt:bytes, terminator:bytes|None,
  max_size:int|None, forbidden:bytes, timeout:float, max_receive:int.
  `line(prompt=b'',...)`, `raw(prompt=b'',...)`; `.encode(payload)->bytes` checks
  payload restrictions then applies framing. `.describe()`.
- `transport.py`: synchronous `Tube` with `read_exact(n,timeout=None)`,
  `read_until(delimiter,timeout=None,max_bytes=None)`, `send(bytes,timeout=None)`,
  `close()`, `interactive()`. Timeouts retain buffered bytes and never send.
  `ProcessTube(argv,env=None,cwd=None,timeout=3)` and
  `SocketTube(host,port,timeout=3,tls=False)`. IO must be interruptible/bounded.
- `trace.py`: `Trace` JSON event ledger and `RecordingTube(tube,trace)` plus
  `ReplayTube(trace)` implementing Tube interface. Replay compares outbound
  effects and allows parsing boundaries to change within recorded receive spans;
  changed sends stop replay. Metadata includes artifact hashes. Bytes serialize
  as explicit base64 or hex, never pickle. `Trace.save(path)`, `Trace.load(path)`.
- `payload.py`: `Payload` holds ordered segments of bytes and Expr words with
  origin labels; `.pad(n,fill=b'A')`, `.word(expr,label=None)`, `.append(payload
  or bytes)`, `.build(context)->bytes`, `.layout(context=None)->list[dict]`,
  `.dependencies`, `.size`. Supports explicit placement/overlap checks.
- `techniques.py`: native AMD64 compiler. `ROPCompiler(images)` exposes
  `.call(Call, resume=None, entry_sp_mod16=0, forbidden=b'')->Payload` and
  `.syscall(number,args,...)->Payload`. Finds simple validated executable pop/ret
  gadgets and performs SysV alignment. No target I/O. Literal C strings resolve
  to image bytes or a clear missing-storage diagnostic. `SigreturnFrame` encodes
  Linux AMD64 rt_sigframe, `fmtstr_payload` generates positional writes, and a
  `dlresolve` builder produces symbolic first-stage chain plus resolver blob.
- `actions.py`, `challenge.py`, `planner.py`, `runtime.py`, `cli.py`: root-owned.
  Root composes the above through those interfaces. Agents must report interface
  changes before assuming other modules have matching changes.

## Verification

Unit tests cover semantics and failure boundaries. Host-independent synthetic ELF
fixtures test parsing/compilation. Linux AMD64 local binaries test real execution,
including leak/rebase/call where a Linux runner is available. TCP tests exercise
fragmentation/timeouts and trace replay. Test claims must distinguish actual
target execution from fixture/parser/compiler validation.
