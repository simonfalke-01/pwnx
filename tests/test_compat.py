def test_pwntools_compatibility_namespace_preserves_explicit_semantics():
    from pwnx.compat import pwntools

    assert pwntools.p64(1) == b"\x01" + b"\0" * 7
    assert pwntools.cyclic_find(pwntools.cyclic(16)[4:8]) == 4
    assert pwntools.process is pwntools.ProcessTube


def test_backend_namespaces_expose_mechanisms_outside_primary_model():
    import pwnx
    for name in (
        "p64",
        "flat",
        "cyclic",
        "Tube",
        "ProcessTube",
        "ROPCompiler",
        "SigreturnFrame",
        "Toolchain",
        "asm",
        "MemoryOracle",
        "Corefile",
    ):
        assert not hasattr(pwnx, name), name
    if hasattr(pwnx, "shellcode"):
        assert not callable(pwnx.shellcode)

    from pwnx.backends import diagnostics, memory, rop, toolchain, transports

    assert rop.ROPCompiler
    assert memory.MemoryOracle
    assert diagnostics.Corefile
    assert toolchain.Toolchain
    assert toolchain.asm
    assert toolchain.shellcode
    assert transports.SocketTube
