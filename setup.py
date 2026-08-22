from __future__ import annotations

import shutil
import stat
import json
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent
EXCLUDED_PARTS = {
    ".git",
    ".hermes",  # local agent runtime/plans: git-ignored, never release content
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
    manifest_path = ROOT / "RELEASE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise RuntimeError("release manifest files invalid")
    files = [Path("RELEASE_MANIFEST.json")]
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise RuntimeError("release manifest entry invalid")
        relative = Path(entry["path"])
        path = ROOT / relative
        try:
            info = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"release source unreadable: {relative}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f"release source symlink rejected: {relative}")
        if stat.S_ISREG(info.st_mode):
            files.append(relative)
        else:
            raise RuntimeError(f"release source is not regular: {relative}")
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
