from __future__ import annotations

import pytest

from pwnx.architecture import (
    AARCH64,
    AMD64,
    I386,
    MIPS,
    MIPSEL,
    RISCV64,
    ArchitectureSpec,
    BackendCapabilities,
    BackendRegistry,
    CapabilityPredicate,
    CredentialReference,
    LifecyclePolicy,
    LocalProcessRecipe,
    QemuUserRecipe,
    SSHProcessRecipe,
    SerialRecipe,
    TcpRecipe,
    architecture,
)
from pwnx.errors import UnsupportedFeature


def test_builtin_architectures_are_explicit_and_aliases_resolve() -> None:
    assert architecture("x86_64") is AMD64
    assert architecture("x86") is I386
    assert architecture("arm64") is AARCH64
    assert MIPS.endian == "big"
    assert MIPSEL.endian == "little"
    assert RISCV64.pointer_width == 8
    with pytest.raises(UnsupportedFeature, match="unknown architecture"):
        architecture("mystery")


def test_capability_registry_selects_supported_backend_and_explains_rejections() -> None:
    registry = BackendRegistry()
    registry.register(
        BackendCapabilities(
            "amd64-native",
            frozenset({"assemble", "disassemble"}),
            CapabilityPredicate.names("amd64"),
            version="1",
        ),
        object(),
        priority=2,
    )
    selected_impl = object()
    registry.register(
        BackendCapabilities(
            "multi",
            frozenset({"assemble"}),
            CapabilityPredicate(
                architectures=frozenset({"amd64", "aarch64"}),
            ),
            version="2",
        ),
        selected_impl,
        priority=1,
    )

    selected = registry.select("assemble", AARCH64)
    assert selected.implementation is selected_impl
    assert selected.rejected[0][0] == "amd64-native"
    assert "architecture aarch64" in selected.explain()
    with pytest.raises(UnsupportedFeature, match="no backend"):
        registry.select("shellcode", AMD64)


def test_local_recipe_materializes_artifacts_loader_and_lifecycle(tmp_path) -> None:
    executable = tmp_path / "chall"
    loader = tmp_path / "ld.so"
    libc = tmp_path / "libc.so"
    executable.write_bytes(b"ELF")
    loader.write_bytes(b"LD")
    libc.write_bytes(b"LIBC")
    recipe = LocalProcessRecipe(
        str(executable),
        arguments=("--test",),
        env={"FLAG": "dummy"},
        cwd=str(tmp_path),
        loader=str(loader),
        libraries=(str(libc),),
    )

    target = recipe.materialize(epoch_seed="one")
    assert target.argv == (
        str(loader.resolve()),
        "--library-path",
        str(tmp_path.resolve()),
        str(executable.resolve()),
        "--test",
    )
    assert len(target.artifacts) == 3
    assert target.env["FLAG"] == "dummy"
    assert target.epochs.process.startswith("process:")
    assert target.identity == recipe.materialize(epoch_seed="one").identity
    assert "artifact executable" in target.explain()
    with pytest.raises(TypeError):
        target.env["FLAG"] = "changed"


def test_qemu_and_remote_recipes_are_pure_manifests(tmp_path) -> None:
    emulator = tmp_path / "qemu-aarch64"
    executable = tmp_path / "chall"
    emulator.write_bytes(b"QEMU")
    executable.write_bytes(b"ELF")
    qemu = QemuUserRecipe(
        str(executable),
        AARCH64,
        str(emulator),
        sysroot=str(tmp_path),
        gdb_port=1234,
    ).materialize()
    assert qemu.argv[:5] == (
        str(emulator.resolve()),
        "-L",
        str(tmp_path.resolve()),
        "-g",
        "1234",
    )
    assert qemu.adapter == "qemu-user"

    tcp = TcpRecipe("example", 31337, architecture=AARCH64, tls=True).materialize()
    assert tcp.endpoint == ("example", 31337)
    assert tcp.adapter == "tls"
    serial = SerialRecipe("/dev/ttyS0", architecture=AARCH64).materialize()
    assert serial.options["baud"] == 115200


def test_ssh_recipe_keeps_credentials_as_references_and_argv_separate(tmp_path) -> None:
    identity = tmp_path / "id_ed25519"
    identity.write_text("not-a-real-key", encoding="ascii")
    credential = CredentialReference("ctf-key", str(identity))
    recipe = SSHProcessRecipe(
        "host",
        ("./chall", "argument with spaces", ";not-shell"),
        user="ctf",
        credential=credential,
        known_hosts="accept-new",
        architecture=AMD64,
    )
    target = recipe.materialize()
    assert target.argv[-3:-1] == (
        "ctf@host",
        "--",
    )
    assert target.argv[-1] == "./chall 'argument with spaces' ';not-shell'"
    assert credential.name in target.evidence[0]
    assert "not-a-real-key" not in repr(target)
    assert (
        recipe.materialize(epoch_seed="a").epochs.service
        == recipe.materialize(epoch_seed="b").epochs.service
    )
    assert (
        recipe.materialize(epoch_seed="a").epochs.connection
        != recipe.materialize(epoch_seed="b").epochs.connection
    )


def test_invalid_architecture_and_lifecycle_contracts_fail_early() -> None:
    with pytest.raises(ValueError):
        ArchitectureSpec("x", 7, "little", "linux", "abi", ("r0",), 1)
    with pytest.raises(ValueError):
        LifecyclePolicy(process="sometimes")
    with pytest.raises(ValueError):
        TcpRecipe("", 0).materialize()
