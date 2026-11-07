"""Offline libc identification as immutable, ambiguity-preserving evidence.

This module deliberately does not download libraries and never mutates a
Challenge's selected images.  It turns explicit artifacts and leaks into a
ranked set of hypotheses, together with the next observation that would best
separate the remaining candidates.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from .actions import Action
from .artifacts import Image
from .errors import ArtifactError, ConstraintError
from .expressions import Expr


NOTE_HEADER = struct.Struct("<III")
PT_NOTE = 4
NT_GNU_BUILD_ID = 3
FULL_MASK = (1 << 64) - 1
PAGE_MASK = 0xFFF
DEFAULT_STRINGS = (b"/bin/sh\x00",)


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _immutable_mapping(values: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(values))


def _read_build_id(image: Image, data: bytes) -> str | None:
    for segment in image.segments:
        if segment.type != PT_NOTE:
            continue
        start = segment.offset
        end = start + segment.filesz
        if start < 0 or end > len(data):
            raise ArtifactError("ELF PT_NOTE extends beyond the artifact")
        cursor = start
        while cursor + NOTE_HEADER.size <= end:
            namesz, descsz, kind = NOTE_HEADER.unpack_from(data, cursor)
            cursor += NOTE_HEADER.size
            name_end = cursor + namesz
            desc_start = cursor + _align4(namesz)
            desc_end = desc_start + descsz
            if name_end > end or desc_end > end:
                raise ArtifactError("malformed GNU note in libc artifact")
            name = data[cursor:name_end].rstrip(b"\x00")
            description = data[desc_start:desc_end]
            if name == b"GNU" and kind == NT_GNU_BUILD_ID and description:
                return description.hex()
            cursor = desc_start + _align4(descsz)
    return None


@dataclass(frozen=True, slots=True)
class LibcArtifact:
    """Static identity and useful offsets for one candidate libc."""

    path: str
    sha256: str
    size: int
    build_id: str | None
    architecture: str
    load_base: int
    symbols: Mapping[str, int]
    strings: Mapping[str, tuple[int, ...]]

    def __post_init__(self) -> None:
        object.__setattr__(self, "symbols", _immutable_mapping(self.symbols))
        object.__setattr__(
            self,
            "strings",
            MappingProxyType(
                {name: tuple(offsets) for name, offsets in self.strings.items()}
            ),
        )

    @classmethod
    def from_path(
        cls,
        path: str | os.PathLike[str],
        *,
        string_needles: Iterable[bytes | str] = DEFAULT_STRINGS,
        max_size: int = 64 * 1024 * 1024,
    ) -> "LibcArtifact":
        artifact_path = Path(path).expanduser().resolve()
        try:
            stat = artifact_path.stat()
        except OSError as error:
            raise ArtifactError(f"cannot stat libc artifact {artifact_path}: {error}") from error
        if not artifact_path.is_file():
            raise ArtifactError(f"libc artifact is not a file: {artifact_path}")
        if stat.st_size > max_size:
            raise ConstraintError(
                f"libc artifact {artifact_path} is {stat.st_size} bytes, "
                f"limit is {max_size}"
            )
        data = artifact_path.read_bytes()
        image = Image(artifact_path, name="libc-candidate")
        defined = getattr(image, "_defined_symbols", frozenset(image.symbols))
        symbols = {
            name: value - image.load_base
            for name, value in image.symbols.items()
            if name in defined
        }
        strings: dict[str, tuple[int, ...]] = {}
        for needle in string_needles:
            encoded = needle.encode() if isinstance(needle, str) else bytes(needle)
            if not encoded:
                raise ValueError("libc string needle cannot be empty")
            key = encoded.rstrip(b"\x00").decode("utf-8", "backslashreplace")
            strings[key] = tuple(
                address - image.load_base for address in image.search(encoded)
            )
        return cls(
            str(artifact_path),
            hashlib.sha256(data).hexdigest(),
            len(data),
            _read_build_id(image, data),
            image.architecture,
            image.load_base,
            symbols,
            strings,
        )

    @property
    def identity(self) -> str:
        return self.build_id or self.sha256

    def offset(self, name: str, *, kind: str = "symbol") -> int:
        if kind == "symbol":
            try:
                return int(self.symbols[name])
            except KeyError as error:
                raise ArtifactError(
                    f"{Path(self.path).name} has no symbol {name!r}"
                ) from error
        if kind == "string":
            offsets = self.strings.get(name, ())
            if not offsets:
                raise ArtifactError(
                    f"{Path(self.path).name} has no string {name!r}"
                )
            return offsets[0]
        raise ValueError("artifact offset kind must be 'symbol' or 'string'")

    def to_manifest(self, *, relative_to: str | os.PathLike[str] | None = None) -> dict[str, Any]:
        path = Path(self.path)
        if relative_to is not None:
            try:
                rendered_path = str(path.relative_to(Path(relative_to).resolve()))
            except ValueError:
                rendered_path = str(path)
        else:
            rendered_path = str(path)
        return {
            "path": rendered_path,
            "sha256": self.sha256,
            "size": self.size,
            "build_id": self.build_id,
            "architecture": self.architecture,
            "load_base": self.load_base,
            "symbols": dict(self.symbols),
            "strings": {name: list(offsets) for name, offsets in self.strings.items()},
        }

    @classmethod
    def from_manifest(
        cls,
        record: Mapping[str, Any],
        *,
        base_directory: str | os.PathLike[str] | None = None,
        verify_file: bool = True,
    ) -> "LibcArtifact":
        path = Path(str(record["path"]))
        if base_directory is not None and not path.is_absolute():
            path = Path(base_directory) / path
        artifact = cls(
            str(path.resolve()),
            str(record["sha256"]),
            int(record["size"]),
            str(record["build_id"]) if record.get("build_id") else None,
            str(record["architecture"]),
            int(record.get("load_base", 0)),
            {str(name): int(value) for name, value in record["symbols"].items()},
            {
                str(name): tuple(int(value) for value in offsets)
                for name, offsets in record.get("strings", {}).items()
            },
        )
        if verify_file:
            try:
                data = Path(artifact.path).read_bytes()
            except OSError as error:
                raise ArtifactError(
                    f"manifest artifact cannot be read: {artifact.path}: {error}"
                ) from error
            digest = hashlib.sha256(data).hexdigest()
            if digest != artifact.sha256 or len(data) != artifact.size:
                raise ArtifactError(
                    f"manifest identity mismatch for {artifact.path}"
                )
        return artifact


@dataclass(frozen=True, slots=True)
class LeakEvidence:
    symbol: str
    address: int
    mask: int = FULL_MASK
    source: str = ""
    kind: str = "symbol"

    def __post_init__(self) -> None:
        if not self.symbol:
            raise ValueError("leak evidence name cannot be empty")
        if not isinstance(self.address, int) or not 0 <= self.address <= FULL_MASK:
            raise ValueError("leak address must be an unsigned 64-bit integer")
        if not isinstance(self.mask, int) or not 0 < self.mask <= FULL_MASK:
            raise ValueError("leak mask must be a nonzero unsigned 64-bit integer")
        if self.mask & (self.mask + 1):
            raise ValueError("leak mask must describe contiguous low known bits")
        if self.kind not in {"symbol", "string"}:
            raise ValueError("leak evidence kind must be 'symbol' or 'string'")

    @classmethod
    def known_bits(
        cls,
        symbol: str,
        address: int,
        bits: int,
        *,
        source: str = "",
        kind: str = "symbol",
    ) -> "LeakEvidence":
        if not 0 < bits <= 64:
            raise ValueError("known bits must be in 1..64")
        return cls(
            symbol,
            address,
            (1 << bits) - 1 if bits < 64 else FULL_MASK,
            source,
            kind,
        )

    @property
    def exact(self) -> bool:
        return self.mask == FULL_MASK

    def describe(self) -> str:
        scope = f" from {self.source}" if self.source else ""
        return (
            f"{self.kind} {self.symbol!r} at {self.address:#x} "
            f"(mask={self.mask:#x}){scope}"
        )


@dataclass(frozen=True, slots=True)
class LibcHypothesis:
    artifact: LibcArtifact
    base_residue: int
    base_mask: int
    matched: tuple[LeakEvidence, ...]
    conflicts: tuple[str, ...]
    confidence: float
    reasons: tuple[str, ...]

    @property
    def viable(self) -> bool:
        return not self.conflicts

    @property
    def exact_base(self) -> int | None:
        return self.base_residue if self.base_mask == FULL_MASK else None

    def predict(self, name: str, *, kind: str = "symbol") -> tuple[int, int]:
        offset = self.artifact.offset(name, kind=kind)
        return (self.base_residue + offset) & self.base_mask, self.base_mask

    def explain(self) -> str:
        status = "viable" if self.viable else "rejected"
        base = (
            f"{self.exact_base:#x}"
            if self.exact_base is not None
            else f"{self.base_residue:#x} & {self.base_mask:#x}"
        )
        lines = [
            f"{Path(self.artifact.path).name} [{status}] confidence={self.confidence:.2f}",
            f"  identity={self.artifact.identity}, base={base}",
        ]
        lines.extend(f"  matched: {item.describe()}" for item in self.matched)
        lines.extend(f"  conflict: {item}" for item in self.conflicts)
        lines.extend(f"  reason: {item}" for item in self.reasons)
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class ProbeSuggestion:
    kind: str
    name: str
    partitions: Mapping[str, int]
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "partitions", _immutable_mapping(self.partitions))

    def describe(self) -> str:
        return f"probe {self.kind} {self.name!r}: {self.reason}"


@dataclass(frozen=True, slots=True)
class HypothesisSet:
    hypotheses: tuple[LibcHypothesis, ...]
    evidence: tuple[LeakEvidence, ...]

    @property
    def viable(self) -> tuple[LibcHypothesis, ...]:
        return tuple(
            sorted(
                (item for item in self.hypotheses if item.viable),
                key=lambda item: (-item.confidence, item.artifact.identity),
            )
        )

    @property
    def rejected(self) -> tuple[LibcHypothesis, ...]:
        return tuple(item for item in self.hypotheses if not item.viable)

    def require_unique(self) -> LibcHypothesis:
        candidates = self.viable
        if len(candidates) != 1:
            raise ConstraintError(
                f"libc identity is ambiguous: expected one viable candidate, "
                f"found {len(candidates)}"
            )
        return candidates[0]

    def next_probe(self) -> ProbeSuggestion | None:
        candidates = self.viable
        if len(candidates) < 2:
            return None
        observed = {(item.kind, item.symbol) for item in self.evidence}
        options: list[tuple[int, int, str, str, dict[str, int]]] = []
        names = set.intersection(
            *(set(item.artifact.symbols) for item in candidates)
        )
        for name in names:
            if ("symbol", name) in observed:
                continue
            partitions = {
                item.artifact.identity: item.artifact.offset(name) & 0xFFFFF
                for item in candidates
            }
            distinct = len(set(partitions.values()))
            if distinct > 1:
                options.append((distinct, len(partitions), "symbol", name, partitions))
        string_names = set.intersection(
            *(set(item.artifact.strings) for item in candidates)
        )
        for name in string_names:
            if ("string", name) in observed:
                continue
            if any(not item.artifact.strings.get(name) for item in candidates):
                continue
            partitions = {
                item.artifact.identity: item.artifact.offset(name, kind="string")
                & 0xFFFFF
                for item in candidates
            }
            distinct = len(set(partitions.values()))
            if distinct > 1:
                options.append((distinct, len(partitions), "string", name, partitions))
        if not options:
            return None
        distinct, total, kind, name, partitions = max(
            options,
            key=lambda item: (item[0], -len(item[3]), item[3]),
        )
        return ProbeSuggestion(
            kind,
            name,
            partitions,
            f"{distinct} distinct offset groups across {total} viable candidates",
        )

    def explain(self) -> str:
        lines = [
            f"libc hypotheses: {len(self.viable)} viable, "
            f"{len(self.rejected)} rejected"
        ]
        lines.extend(item.explain() for item in self.viable)
        lines.extend(item.explain() for item in self.rejected)
        suggestion = self.next_probe()
        if suggestion is not None:
            lines.append("next: " + suggestion.describe())
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence": [
                {
                    "symbol": item.symbol,
                    "address": item.address,
                    "mask": item.mask,
                    "source": item.source,
                    "kind": item.kind,
                }
                for item in self.evidence
            ],
            "hypotheses": [
                {
                    "artifact": item.artifact.identity,
                    "base_residue": item.base_residue,
                    "base_mask": item.base_mask,
                    "matched": [evidence.symbol for evidence in item.matched],
                    "conflicts": list(item.conflicts),
                    "confidence": item.confidence,
                    "reasons": list(item.reasons),
                }
                for item in self.hypotheses
            ],
        }


class LibcCatalog:
    """A bounded, explicit collection of local libc artifacts."""

    def __init__(
        self,
        artifacts: Sequence[LibcArtifact],
        *,
        errors: Iterable[str] = (),
    ) -> None:
        unique: dict[str, LibcArtifact] = {}
        for artifact in artifacts:
            unique.setdefault(artifact.sha256, artifact)
        self._artifacts = tuple(
            sorted(unique.values(), key=lambda item: item.identity)
        )
        self.errors = tuple(errors)

    def __len__(self) -> int:
        return len(self._artifacts)

    def __iter__(self):
        return iter(self._artifacts)

    @classmethod
    def scan(
        cls,
        paths: Iterable[str | os.PathLike[str]],
        *,
        recursive: bool = True,
        strict: bool = False,
        max_files: int = 4096,
        max_file_size: int = 64 * 1024 * 1024,
        string_needles: Iterable[bytes | str] = DEFAULT_STRINGS,
    ) -> "LibcCatalog":
        if max_files <= 0:
            raise ValueError("max_files must be positive")
        candidates: list[Path] = []
        path_errors: list[str] = []
        for supplied in paths:
            path = Path(supplied).expanduser().resolve()
            if path.is_file():
                candidates.append(path)
            elif path.is_dir():
                iterator = path.rglob("*") if recursive else path.glob("*")
                for candidate in iterator:
                    if candidate.is_file():
                        candidates.append(candidate)
                        if len(candidates) > max_files:
                            raise ConstraintError(
                                f"libc catalog exceeds max_files={max_files}"
                            )
            else:
                message = f"catalog path does not exist: {path}"
                if strict:
                    raise ArtifactError(message)
                path_errors.append(message)
        candidates = sorted(dict.fromkeys(candidates))
        if len(candidates) > max_files:
            raise ConstraintError(f"libc catalog exceeds max_files={max_files}")
        artifacts: list[LibcArtifact] = []
        errors: list[str] = list(path_errors)
        for path in candidates:
            try:
                artifacts.append(
                    LibcArtifact.from_path(
                        path,
                        string_needles=string_needles,
                        max_size=max_file_size,
                    )
                )
            except (ArtifactError, ConstraintError, OSError, ValueError) as error:
                if strict:
                    raise
                errors.append(f"{path}: {error}")
        return cls(artifacts, errors=errors)

    def by_sha256(self, digest: str) -> LibcArtifact | None:
        return next((item for item in self if item.sha256 == digest), None)

    def by_build_id(self, build_id: str) -> tuple[LibcArtifact, ...]:
        normalized = build_id.lower()
        return tuple(
            item for item in self if item.build_id == normalized
        )

    def match(self, evidence: Iterable[LeakEvidence]) -> HypothesisSet:
        observations = tuple(evidence)
        if not observations:
            raise ValueError("at least one libc leak is required")
        hypotheses = tuple(
            _match_artifact(artifact, observations) for artifact in self
        )
        return HypothesisSet(hypotheses, observations)

    def to_manifest(self, *, relative_to: str | os.PathLike[str] | None = None) -> dict[str, Any]:
        return {
            "format": "pwnx.libc-catalog.v1",
            "artifacts": [
                item.to_manifest(relative_to=relative_to) for item in self
            ],
            "errors": list(self.errors),
        }

    def save_manifest(self, path: str | os.PathLike[str]) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(
                self.to_manifest(relative_to=destination.parent),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return destination

    @classmethod
    def load_manifest(
        cls,
        path: str | os.PathLike[str],
        *,
        verify_files: bool = True,
    ) -> "LibcCatalog":
        manifest_path = Path(path).expanduser().resolve()
        try:
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ArtifactError(f"cannot load libc catalog manifest: {error}") from error
        if document.get("format") != "pwnx.libc-catalog.v1":
            raise ArtifactError("unsupported libc catalog manifest format")
        artifacts = [
            LibcArtifact.from_manifest(
                record,
                base_directory=manifest_path.parent,
                verify_file=verify_files,
            )
            for record in document.get("artifacts", ())
        ]
        return cls(artifacts, errors=document.get("errors", ()))


def _merge_constraint(
    residue: int,
    mask: int,
    new_residue: int,
    new_mask: int,
) -> tuple[int, int] | None:
    if (residue ^ new_residue) & (mask & new_mask):
        return None
    merged_mask = mask | new_mask
    merged_residue = (residue & mask) | (new_residue & new_mask)
    return merged_residue & merged_mask, merged_mask


def _match_artifact(
    artifact: LibcArtifact,
    evidence: tuple[LeakEvidence, ...],
) -> LibcHypothesis:
    residue = 0
    mask = PAGE_MASK
    matched: list[LeakEvidence] = []
    conflicts: list[str] = []
    reasons: list[str] = ["ELF load base constrained to page alignment"]
    for item in evidence:
        try:
            offset = artifact.offset(item.symbol, kind=item.kind)
        except ArtifactError as error:
            conflicts.append(str(error))
            continue
        candidate = (item.address - offset) & item.mask
        merged = _merge_constraint(residue, mask, candidate, item.mask)
        if merged is None:
            conflicts.append(
                f"{item.describe()} implies base residue {candidate:#x}, "
                f"which conflicts with {residue:#x} & {mask:#x}"
            )
            continue
        residue, mask = merged
        matched.append(item)
        reasons.append(
            f"{item.symbol} offset {offset:#x} agrees with base mask {mask:#x}"
        )
    if conflicts:
        confidence = 0.0
    elif mask == FULL_MASK:
        confidence = min(0.99, 0.70 + max(0, len(matched) - 1) * 0.10)
    else:
        confidence = min(0.80, 0.25 + len(matched) * 0.10)
    return LibcHypothesis(
        artifact,
        residue,
        mask,
        tuple(matched),
        tuple(conflicts),
        confidence,
        tuple(reasons),
    )


@dataclass(frozen=True, slots=True)
class AcquiredArtifact:
    path: str
    url: str
    sha256: str
    license: str | None = None
    evidence: tuple[str, ...] = ()


class AcquisitionAdapter(Protocol):
    def acquire(self, reference: str) -> AcquiredArtifact: ...


@dataclass(frozen=True, slots=True)
class IdentifyLibc(Action):
    catalog: LibcCatalog
    evidence: tuple[LeakEvidence, ...]
    target: Expr
    require_unique: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.target, Expr):
            raise TypeError("libc identification target must be an Expr")
        if not self.evidence:
            raise ValueError("libc identification requires leak evidence")

    @property
    def output(self) -> Expr:
        return self.target

    def identify(self) -> HypothesisSet | LibcHypothesis:
        result = self.catalog.match(self.evidence)
        return result.require_unique() if self.require_unique else result

    def describe(self) -> str:
        mode = "unique libc" if self.require_unique else "libc hypothesis set"
        return (
            f"identify {mode} from {len(self.evidence)} leak(s) across "
            f"{len(self.catalog)} local artifact(s) -> {self.target.describe()}"
        )

