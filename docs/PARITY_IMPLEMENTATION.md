# Parity implementation contracts

All additions remain dependency-free at runtime. Optional system tools must be
detected and fail with a precise UnsupportedFeature message.

## Packing and cyclic

Owner files: src/pwnx/packing.py and tests/test_packing.py.

Public API: pack, unpack, p8/p16/p32/p64, u8/u16/u32/u64, Packed, flat, fit,
layout, cyclic, cyclic_find, offset_from, xor_bytes, bits, unbits, rol, ror,
enhex, unhex, and hexdump.

Packed symbolic values expose dependencies, size, build(context), and describe.
layout returns a labelled Payload and supports nested sequences, offset
dictionaries, explicit target/word size, filler, length, and overlap errors.
There is no ambient architecture context.

## Binary and crash diagnostics

Owner files: src/pwnx/diagnostics.py, additions to artifacts.py and
transport.py, and tests.

Public API: immutable SecurityReport; Image.security and Image.checksec();
MemoryMap, ProcessMaps, Corefile; ProcessTube maps(), libs(), read_memory(),
and write_memory(). Linux-only operations fail clearly.

Checksec detects PIE, NX via PT_GNU_STACK, canary import, RELRO via
PT_GNU_RELRO and bind-now tags, executable stack, RWX segments, and stripped.
Corefile supports Linux AMD64 PT_NOTE PRSTATUS, SIGINFO, NT_FILE, PT_LOAD
memory, and registers needed for crash analysis.

## Transport parity

Owner files: additions to transport.py and trace.py plus tests.

Tube conveniences preserve pwnx semantics: timeout raises and retains partial
bytes; send-after methods never send after a failed match. Add recv, recvn,
recvuntil, recvline, recvregex, clean, unrecv, sendline, sendafter,
sendlineafter, wait, and half-close.

Add DatagramTube, ListenerTube, and Unix SerialTube with bounded I/O. Trace and
replay cover message boundaries and listener acceptance.

## Toolchain and profiles

Owner files: src/pwnx/toolchain.py, src/pwnx/shellcode.py, Challenge/runtime
additions, and tests.

Public API: asm, disasm, cpp, Toolchain, shellcode; Challenge qemu() and
improved debug() with breakpoints and scripts. Tool output is cached by input,
target, and executable version and returned as labelled Payload where useful.
The first target is Linux AMD64. There is no ambient target context.

## Memory oracle and dynamic resolution

Owner files: src/pwnx/memory.py and tests.

Public API: MemoryOracle, MemorySnapshot, and DynResolver. Cache keys include
the process instance; mutation and restart invalidate data. Reads are bounded
and explainable. DynResolver locates an ELF base and resolves symbols from
DT_HASH or GNU_HASH using an arbitrary-read function. It never performs online
libc lookup.
