from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from elf_factory import make_elf


REPO = Path(__file__).resolve().parents[1]
CORPUS_CLI = REPO / "scripts" / "corpus.py"
REAL_ROOT = Path(
    os.environ.get(
        "PWNX_CHALLENGE_ROOT",
        "/Users/brandonli/Downloads/pwn-challenges",
    )
)


def invoke(
    *arguments: str,
    check: bool = True,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(CORPUS_CLI), *map(str, arguments)],
        cwd=REPO,
        env=environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"corpus CLI failed ({result.returncode})\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_row(root: Path, path: Path, *, kind: str = "file") -> dict[str, str]:
    relative = path.relative_to(root).as_posix()
    return {
        "path": relative,
        "bytes": str(path.stat().st_size),
        "sha256": sha256(path),
        "mode": oct(path.stat().st_mode & 0o777),
        "type": kind,
        "link_target": "",
    }


@pytest.fixture
def synthetic_corpus(tmp_path: Path) -> Path:
    root = tmp_path / "challenges"
    alpha = root / "event-a" / "pwn" / "alpha"
    beta = root / "event-b" / "beta"
    alpha.mkdir(parents=True)
    beta.mkdir(parents=True)

    binary = make_elf(alpha / "chall", pie=False)
    (alpha / "solve_pwnx.py").write_text(
        "print('alpha solved')\n",
        encoding="utf-8",
    )
    (alpha / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (alpha / "README.md").write_text("stack overflow\n", encoding="utf-8")
    pe = beta / "friendly.exe"
    pe_data = bytearray(b"MZ" + b"\0" * 0x7E)
    pe_data[0x3C:0x40] = (0x40).to_bytes(4, "little")
    pe_data[0x40:0x44] = b"PE\0\0"
    pe_data[0x44:0x46] = (0x14C).to_bytes(2, "little")
    pe.write_bytes(pe_data)

    challenge_rows = (
        {
            "path": "event-a/pwn/alpha",
            "files": "4",
            "bytes": str(sum(item.stat().st_size for item in alpha.iterdir())),
            "note": "",
        },
        {
            "path": "event-b/beta",
            "files": "1",
            "bytes": str(pe.stat().st_size),
            "note": "windows outlier",
        },
    )
    with (root / "CHALLENGES.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=("path", "files", "bytes", "note"))
        writer.writeheader()
        writer.writerows(challenge_rows)

    files = [
        binary,
        alpha / "solve_pwnx.py",
        alpha / "Dockerfile",
        alpha / "README.md",
        pe,
    ]
    with (root / "MANIFEST.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = ("path", "bytes", "sha256", "mode", "type", "link_target")
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(manifest_row(root, item) for item in files)
    return root


def inventory(root: Path, output: Path) -> dict[str, object]:
    result = invoke(
        "inventory",
        "--root",
        str(root),
        "--challenges",
        str(root / "CHALLENGES.csv"),
        "--manifest",
        str(root / "MANIFEST.csv"),
        "--output",
        str(output),
        "--json",
    )
    return json.loads(result.stdout)


def read_matrix(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def write_matrix(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)


def test_help_lists_the_supported_corpus_workflows() -> None:
    result = invoke("--help")
    for command in ("inventory", "check", "list", "status", "run"):
        assert command in result.stdout


def test_inventory_creates_one_unique_row_per_curated_challenge(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    matrix = tmp_path / "coverage.csv"
    summary = inventory(synthetic_corpus, matrix)
    rows = read_matrix(matrix)

    assert summary["total"] == 2
    assert len(rows) == 2
    assert len({row["id"] for row in rows}) == 2
    assert [row["path"] for row in rows] == [
        "event-a/pwn/alpha",
        "event-b/beta",
    ]


def test_inventory_records_artifacts_and_honest_solve_status(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    matrix = tmp_path / "coverage.csv"
    inventory(synthetic_corpus, matrix)
    rows = {row["path"]: row for row in read_matrix(matrix)}

    alpha = rows["event-a/pwn/alpha"]
    assert alpha["format"] == "ELF64"
    assert alpha["existing_solve"] == "solve_pwnx.py"
    assert alpha["docker"] == "Dockerfile"
    assert alpha["native_status"] == "not_run"
    assert alpha["pwnx_status"] == "implemented"

    beta = rows["event-b/beta"]
    assert beta["format"] == "PE"
    assert beta["existing_solve"] == ""
    assert beta["missing_primitive"]


def test_inventory_is_byte_deterministic(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    inventory(synthetic_corpus, first)
    inventory(synthetic_corpus, second)

    assert first.read_bytes() == second.read_bytes()


def test_environment_selects_the_default_corpus_root(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    matrix = tmp_path / "coverage.csv"
    environment = {**os.environ, "PWNX_CHALLENGE_ROOT": str(synthetic_corpus)}
    result = invoke(
        "inventory",
        "--output",
        str(matrix),
        "--json",
        environment=environment,
    )

    assert json.loads(result.stdout)["total"] == 2
    assert len(read_matrix(matrix)) == 2


def test_check_accepts_a_fresh_matrix_and_reports_counts(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    matrix = tmp_path / "coverage.csv"
    inventory(synthetic_corpus, matrix)
    result = invoke(
        "check",
        "--root",
        str(synthetic_corpus),
        "--matrix",
        str(matrix),
        "--json",
    )
    report = json.loads(result.stdout)

    assert report["ok"] is True
    assert report["rows"] == 2


def test_list_and_status_emit_stable_json(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    matrix = tmp_path / "coverage.csv"
    inventory(synthetic_corpus, matrix)

    listed = json.loads(invoke("list", "--matrix", str(matrix), "--json").stdout)
    status = json.loads(invoke("status", "--matrix", str(matrix), "--json").stdout)

    assert [item["path"] for item in listed] == [
        "event-a/pwn/alpha",
        "event-b/beta",
    ]
    assert status["total"] == 2
    assert status["native_status"] == {"not_run": 2}
    assert status["pwnx_status"] == {"implemented": 1, "not_started": 1}


def test_dry_run_describes_the_command_without_executing_it(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    matrix = tmp_path / "coverage.csv"
    inventory(synthetic_corpus, matrix)
    alpha = next(row for row in read_matrix(matrix) if row["path"].endswith("alpha"))

    result = invoke(
        "run",
        "--root",
        str(synthetic_corpus),
        "--matrix",
        str(matrix),
        "--id",
        alpha["id"],
        "--dry-run",
        "--json",
    )
    report = json.loads(result.stdout)

    assert report["dry_run"] is True
    assert report["argv"][-1] == "solve_pwnx.py"
    assert Path(report["cwd"]).resolve() == (synthetic_corpus / alpha["path"]).resolve()


def test_docker_dry_run_is_offline_and_does_not_execute(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    matrix = tmp_path / "coverage.csv"
    inventory(synthetic_corpus, matrix)
    alpha = next(row for row in read_matrix(matrix) if row["path"].endswith("alpha"))

    report = json.loads(
        invoke(
            "run",
            "--root",
            str(synthetic_corpus),
            "--matrix",
            str(matrix),
            "--id",
            alpha["id"],
            "--docker",
            "--dry-run",
            "--json",
        ).stdout
    )

    assert report["dry_run"] is True
    assert report["argv"][:4] == ["docker", "run", "--rm", "--network"]
    assert "none" in report["argv"]


def test_run_enforces_timeout_without_leaving_the_process_alive(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    matrix = tmp_path / "coverage.csv"
    inventory(synthetic_corpus, matrix)
    alpha = next(row for row in read_matrix(matrix) if row["path"].endswith("alpha"))
    solve = synthetic_corpus / alpha["path"] / "solve_pwnx.py"
    solve.write_text("import time\ntime.sleep(5)\n", encoding="utf-8")

    result = invoke(
        "run",
        "--root",
        str(synthetic_corpus),
        "--matrix",
        str(matrix),
        "--id",
        alpha["id"],
        "--timeout",
        "0.05",
        "--json",
        check=False,
    )
    report = json.loads(result.stdout)

    assert result.returncode == 124
    assert report["timed_out"] is True


def test_run_bounds_recorded_output(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    matrix = tmp_path / "coverage.csv"
    inventory(synthetic_corpus, matrix)
    alpha = next(row for row in read_matrix(matrix) if row["path"].endswith("alpha"))
    solve = synthetic_corpus / alpha["path"] / "solve_pwnx.py"
    solve.write_text("print('X' * 4096)\n", encoding="utf-8")

    report = json.loads(
        invoke(
            "run",
            "--root",
            str(synthetic_corpus),
            "--matrix",
            str(matrix),
            "--id",
            alpha["id"],
            "--max-output",
            "32",
            "--json",
        ).stdout
    )

    assert report["output_truncated"] is True
    assert len(report["output"].encode()) == 32


def test_manifest_paths_cannot_escape_the_corpus_root(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    manifest = synthetic_corpus / "MANIFEST.csv"
    with manifest.open("a", encoding="utf-8") as stream:
        stream.write("../escape,1,00,0o644,file,\n")
    result = invoke(
        "inventory",
        "--root",
        str(synthetic_corpus),
        "--challenges",
        str(synthetic_corpus / "CHALLENGES.csv"),
        "--manifest",
        str(manifest),
        "--output",
        str(tmp_path / "coverage.csv"),
        "--json",
        check=False,
    )

    assert result.returncode != 0
    output = (result.stdout + result.stderr).lower()
    assert "outside" in output or "escape" in output


def test_malformed_manifest_reports_a_clean_error(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    manifest = synthetic_corpus / "MANIFEST.csv"
    manifest.write_text("path,bytes\nmissing,not-a-number\n", encoding="utf-8")
    result = invoke(
        "inventory",
        "--root",
        str(synthetic_corpus),
        "--challenges",
        str(synthetic_corpus / "CHALLENGES.csv"),
        "--manifest",
        str(manifest),
        "--output",
        str(tmp_path / "coverage.csv"),
        check=False,
    )

    assert result.returncode != 0
    output = (result.stdout + result.stderr).lower()
    assert "manifest" in output
    assert "traceback" not in output


def test_external_symlink_is_catalogued_without_dereferencing_it(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    link = synthetic_corpus / "event-a" / "pwn" / "alpha" / "sh"
    link.symlink_to("/bin/sh")
    manifest = synthetic_corpus / "MANIFEST.csv"
    with manifest.open("a", encoding="utf-8") as stream:
        stream.write(
            "event-a/pwn/alpha/sh,7,"
            "77bafa9e3a8a092afc4f1dd84e6e1cc58b68f42eb934bf0f6b73deb2518f78a3,"
            "0o777,symlink,/bin/sh\n"
        )
    matrix = tmp_path / "coverage.csv"

    inventory(synthetic_corpus, matrix)
    alpha = next(row for row in read_matrix(matrix) if row["path"].endswith("alpha"))

    assert "sh" in alpha["artifacts"].split(";")
    assert alpha["format"] == "ELF64"


def test_check_rejects_invalid_status_values(
    synthetic_corpus: Path,
    tmp_path: Path,
) -> None:
    matrix = tmp_path / "coverage.csv"
    inventory(synthetic_corpus, matrix)
    rows = read_matrix(matrix)
    rows[0]["native_status"] = "maybe"
    write_matrix(matrix, rows)

    result = invoke(
        "check",
        "--root",
        str(synthetic_corpus),
        "--matrix",
        str(matrix),
        "--json",
        check=False,
    )
    report = json.loads(result.stdout)

    assert result.returncode == 1
    assert report["ok"] is False
    assert any("native_status" in error for error in report["errors"])


@pytest.mark.skipif(not REAL_ROOT.is_dir(), reason="external pwn corpus is not mounted")
def test_real_corpus_contains_the_131_curated_rows(tmp_path: Path) -> None:
    matrix = tmp_path / "coverage.csv"
    summary = inventory(REAL_ROOT, matrix)
    rows = read_matrix(matrix)

    assert summary["total"] == 131
    assert len(rows) == 131
    assert len({row["path"] for row in rows}) == 131
    assert sum(not row["existing_solve"] for row in rows) == 20

