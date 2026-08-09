from __future__ import annotations

import shutil
import stat
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent
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


def release_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if any(
            part in EXCLUDED_PARTS or part.endswith(".egg-info")
            for part in relative.parts
        ):
            continue
        if relative.name in EXCLUDED_NAMES or relative.suffix in EXCLUDED_SUFFIXES:
            continue
        try:
            info = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"release source unreadable: {relative}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f"release source symlink rejected: {relative}")
        if stat.S_ISREG(info.st_mode):
            files.append(relative)
    return files


class FrozenReleaseBuildPy(build_py):
    """Install the frozen release tree beside code in a relocatable package."""

    def run(self) -> None:
        super().run()
        destination = Path(self.build_lib) / "oab_release_data" / "tree"
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir(parents=True, exist_ok=False)
        for relative in release_files():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target, follow_symlinks=False)


setup(cmdclass={"build_py": FrozenReleaseBuildPy})
