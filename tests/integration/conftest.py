from __future__ import annotations

import platform
import subprocess
from pathlib import Path

import pytest


FIXTURES = Path(__file__).parents[1] / "fixtures"
LINUX_AMD64 = platform.system() == "Linux" and platform.machine() == "x86_64"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if LINUX_AMD64:
        return
    skip = pytest.mark.skip(reason="Linux AMD64 integration fixture")
    for item in items:
        if item.path.parent == Path(__file__).parent:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def compiled_fixtures(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    output_dir = tmp_path_factory.mktemp("linux-fixtures")
    binaries: dict[str, Path] = {}

    common = [
        "-O0",
        "-g0",
        "-fno-stack-protector",
        "-fno-omit-frame-pointer",
        "-fcf-protection=none",
        "-no-pie",
        "-Wl,-z,relro,-z,lazy",
    ]
    for source in FIXTURES.glob("*.c"):
        output = output_dir / source.stem
        subprocess.run(
            ["gcc", *common, str(source), "-o", str(output)],
            check=True,
            text=True,
            capture_output=True,
        )
        binaries[source.stem] = output

    return binaries

