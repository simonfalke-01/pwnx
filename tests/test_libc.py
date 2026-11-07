from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from elf_factory import ELF_HEADER, PROGRAM_HEADER, SYMBOL, make_elf
from pwnx import Trace, expect
from pwnx.challenge import Challenge
from pwnx.errors import ArtifactError, ConstraintError
from pwnx.expressions import Expr
from pwnx.libc import (
    FULL_MASK,
    HypothesisSet,
    IdentifyLibc,
    LeakEvidence,
    LibcArtifact,
    LibcCatalog,
)
from pwnx.transport import Tube


class EmptyTube(Tube):
    def __init__(self, incoming=b"ready\n"):
        super().__init__(timeout=0.1)
        self.incoming = bytearray(incoming)

    def _recv_raw(self, max_bytes, timeout):
        if not self.incoming:
            return b""
        result = bytes(self.incoming[:max_bytes])
        del self.incoming[:max_bytes]
        return result

    def _send_raw(self, data, timeout):
        return len(data)

    def _close_raw(self):
        pass


def make_libc(
    path: Path,
    *,
    win_offset: int,
    puts_offset: int,
    build_id: bytes,
) -> Path:
    make_elf(path, pie=True)
    data = bytearray(path.read_bytes())

    header = list(ELF_HEADER.unpack_from(data))
    header[10] = 2
    data[: ELF_HEADER.size] = ELF_HEADER.pack(*header)
    note_offset = 0x250
    second_phdr = ELF_HEADER.size + PROGRAM_HEADER.size
    note = (
        struct.pack("<III", 4, len(build_id), 3)
        + b"GNU\x00"
        + build_id
        + b"\x00" * ((-len(build_id)) & 3)
    )
    data[second_phdr : second_phdr + PROGRAM_HEADER.size] = PROGRAM_HEADER.pack(
        4,
        4,
        note_offset,
        note_offset,
        note_offset,
        len(note),
        len(note),
        4,
    )
    data[note_offset : note_offset + len(note)] = note

    dynsym = 0x1A0
    data[dynsym + SYMBOL.size : dynsym + 2 * SYMBOL.size] = SYMBOL.pack(
        1, 0x12, 0, 1, win_offset, 8
    )
    data[dynsym + 2 * SYMBOL.size : dynsym + 3 * SYMBOL.size] = SYMBOL.pack(
        5, 0x12, 0, 1, puts_offset, 8
    )
    path.write_bytes(data)
    return path


@pytest.fixture
def catalog(tmp_path: Path) -> LibcCatalog:
    first = make_libc(
        tmp_path / "libc-a.so",
        win_offset=0x100,
        puts_offset=0x200,
        build_id=b"A" * 20,
    )
    second = make_libc(
        tmp_path / "libc-b.so",
        win_offset=0x2100,
        puts_offset=0x1200,
        build_id=b"B" * 20,
    )
    return LibcCatalog.scan([first, second], strict=True)


def test_artifact_extracts_identity_offsets_strings_and_build_id(tmp_path):
    path = make_libc(
        tmp_path / "libc.so",
        win_offset=0x100,
        puts_offset=0x200,
        build_id=bytes(range(20)),
    )
    artifact = LibcArtifact.from_path(path)

    assert artifact.build_id == bytes(range(20)).hex()
    assert artifact.offset("puts") == 0x200
    assert artifact.offset("win") == 0x100
    assert artifact.offset("/bin/sh", kind="string") == 0x110
    assert artifact.sha256
    assert artifact.architecture == "amd64"


def test_exact_leak_preserves_ambiguity_and_next_probe_discriminates(catalog):
    result = catalog.match(
        [LeakEvidence("puts", 0x7000_0200, source="stage-one leak")]
    )
    assert isinstance(result, HypothesisSet)
    assert len(result.viable) == 2
    assert {item.exact_base for item in result.viable} == {
        0x7000_0000,
        0x6FFF_F000,
    }
    probe = result.next_probe()
    assert probe is not None
    assert probe.kind == "symbol"
    assert probe.name == "win"
    assert len(set(probe.partitions.values())) == 2
    with pytest.raises(ConstraintError, match="ambiguous"):
        result.require_unique()


def test_second_leak_rejects_conflicting_candidate_without_auto_selection(catalog):
    result = catalog.match(
        [
            LeakEvidence("puts", 0x7000_0200),
            LeakEvidence("win", 0x7000_0100),
        ]
    )
    chosen = result.require_unique()
    assert Path(chosen.artifact.path).name == "libc-a.so"
    assert chosen.exact_base == 0x7000_0000
    assert len(result.rejected) == 1
    assert result.rejected[0].conflicts
    assert "1 viable" in result.explain()


def test_masked_leaks_keep_base_as_constraint_not_false_exact_value(catalog):
    leak = LeakEvidence.known_bits(
        "puts", 0xDEAD_BEEF_0200, 12, source="partial pointer"
    )
    result = catalog.match([leak])

    assert len(result.viable) == 2
    assert all(item.base_mask == 0xFFF for item in result.viable)
    assert all(item.exact_base is None for item in result.viable)
    assert all(item.base_residue == 0 for item in result.viable)


def test_missing_symbol_and_inconsistent_alignment_are_explicit_conflicts(catalog):
    missing = catalog.match([LeakEvidence("not_exported", 0x7000_0000)])
    assert not missing.viable
    assert all(item.conflicts for item in missing.rejected)

    unaligned = catalog.match([LeakEvidence("puts", 0x7000_0201)])
    assert not unaligned.viable
    assert "conflicts" in unaligned.explain()


def test_catalog_hash_build_id_manifest_and_json_roundtrip(catalog, tmp_path):
    first = tuple(catalog)[0]
    assert catalog.by_sha256(first.sha256) is first
    assert catalog.by_build_id(first.build_id or "") == (first,)

    manifest = catalog.save_manifest(tmp_path / "catalog.json")
    document = json.loads(manifest.read_text())
    assert document["format"] == "pwnx.libc-catalog.v1"
    loaded = LibcCatalog.load_manifest(manifest)
    assert len(loaded) == 2
    assert [item.sha256 for item in loaded] == [
        item.sha256 for item in catalog
    ]


def test_catalog_is_bounded_deduplicated_and_offline(tmp_path):
    artifact = make_libc(
        tmp_path / "libc.so",
        win_offset=0x100,
        puts_offset=0x200,
        build_id=b"C" * 20,
    )
    duplicate = tmp_path / "copy.so"
    duplicate.write_bytes(artifact.read_bytes())
    catalog = LibcCatalog.scan([artifact, duplicate])
    assert len(catalog) == 1

    with pytest.raises(ConstraintError, match="max_files"):
        LibcCatalog.scan([tmp_path], max_files=1)
    with pytest.raises(ConstraintError, match="limit"):
        LibcCatalog.scan([artifact], strict=True, max_file_size=64)

    skipped = LibcCatalog.scan([tmp_path / "missing"])
    assert skipped.errors and "does not exist" in skipped.errors[0]
    with pytest.raises(ArtifactError):
        LibcCatalog.scan([tmp_path / "missing"], strict=True)


def test_identification_action_is_pure_and_never_mutates_challenge(catalog, tmp_path):
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    assert challenge.libc is None


def test_identification_action_runs_through_generic_plugin_executor(
    catalog, tmp_path
):
    challenge = Challenge(make_elf(tmp_path / "chall", pie=False))
    target = Expr.fact("libc.hypotheses", scope="artifact", kind="hypothesis")
    action = IdentifyLibc(
        catalog,
        (
            LeakEvidence("puts", 0x7000_0200),
            LeakEvidence("win", 0x7000_0100),
        ),
        target,
    )
    challenge.sequence(action, name="identify libc")
    challenge.want(expect(b"ready\n"))
    trace = Trace()
    run = challenge.run(transport=EmptyTube(), trace=trace)
    assert run.value(target).require_unique().exact_base == 0x7000_0000
    recorded = trace.metadata["libc_hypotheses"][0]["hypotheses"]
    assert sum(not item["conflicts"] for item in recorded) == 1
    run.close()
    target = Expr.fact("libc.hypotheses", scope="artifact", kind="hypothesis")
    action = IdentifyLibc(
        catalog,
        (
            LeakEvidence("puts", 0x7000_0200),
            LeakEvidence("win", 0x7000_0100),
        ),
        target,
        require_unique=False,
    )

    result = action.identify()
    assert isinstance(result, HypothesisSet)
    assert result.require_unique().exact_base == 0x7000_0000
    assert action.output is target
    assert "identify libc hypothesis set" in action.describe()
    assert challenge.libc is None


def test_leak_masks_must_be_contiguous_low_bits():
    with pytest.raises(ValueError, match="contiguous"):
        LeakEvidence("puts", 1, mask=0b101)
    assert LeakEvidence("puts", 1, mask=FULL_MASK).exact
