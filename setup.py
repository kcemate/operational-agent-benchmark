from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Sequence

from setuptools import setup

ROOT = Path(__file__).resolve().parent
DESTINATION = Path("share") / "operational-agent-benchmark"
EXCLUDED_PARTS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "build",
    "dist",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
EXCLUDED_NAMES = {".DS_Store"}


def release_data_files() -> list[tuple[str, Sequence[str]]]:
    groups: dict[str, list[str]] = defaultdict(list)
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if not path.is_file():
            continue
        if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        if relative.name in EXCLUDED_NAMES or relative.suffix in EXCLUDED_SUFFIXES:
            continue
        destination = (DESTINATION / relative.parent).as_posix()
        groups[destination].append(relative.as_posix())
    return [(destination, files) for destination, files in sorted(groups.items())]


setup(data_files=release_data_files())
