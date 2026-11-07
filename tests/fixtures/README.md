# Linux AMD64 exploit fixtures

These programs are compiled at test time with stack canaries, PIE, CET, and
compiler optimization disabled. Generated binaries stay in pytest temporary
directories.

| Fixture | Contract |
| --- | --- |
| `ret2win.c` | 64-byte stack buffer, saved RIP at offset 72, `gadget_ret`, and `win` emitting `PWNX_RET2WIN_OK` |
| `staged_libc.c` | Offset-72 overflow, explicit pop gadgets, resolved `puts@got`, `write@plt`, and `stage2_command` for a real leak/rebase/`system` exploit |
| `direct_libc.c` | Startup output `puts: 0x...`, offset-72 overflow, and `direct_command` for observation-driven libc rebasing |
| `dlresolve.c` | Offset-72 overflow and `read@plt`; the prompt uses a raw syscall so no output function is available through the dynamic linker |
| `format_string.c` | One-shot stack format string followed by an indirect `hook` call; `win` emits `PWNX_FMT_OK` |

Run all tests in a cached Ubuntu 24.04 AMD64 container from the repository root:

```sh
scripts/test-linux.sh -q
```

Run only the fixture contract checks:

```sh
scripts/test-linux.sh -q tests/integration/test_fixture_contracts.py
```
