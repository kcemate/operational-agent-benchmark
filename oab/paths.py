from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path

_DATA_DIR_NAME = "operational-agent-benchmark"
_EXECUTABLE_PACKAGES = ("oab", "tools")


def _python_files(root: Path, package: str, errors: list[str]) -> dict[str, Path]:
    package_root = root / package
    if not package_root.is_dir() or package_root.is_symlink():
        errors.append(f"installed_code_package_invalid:{package}")
        return {}
    found: dict[str, Path] = {}
    for current, directories, filenames in os.walk(package_root, followlinks=False):
        current_path = Path(current)
        for directory in tuple(directories):
            candidate = current_path / directory
            if candidate.is_symlink():
                errors.append(f"installed_code_symlink_rejected:{candidate.relative_to(root).as_posix()}")
                directories.remove(directory)
        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            path = current_path / filename
            relative = path.relative_to(root).as_posix()
            found[relative] = path
    return found


def _secure_digest(path: Path, relative: str, errors: list[str]) -> str | None:
    try:
        info = path.lstat()
    except OSError:
        errors.append(f"installed_code_unreadable:{relative}")
        return None
    if stat.S_ISLNK(info.st_mode):
        errors.append(f"installed_code_symlink_rejected:{relative}")
        return None
    if not stat.S_ISREG(info.st_mode):
        errors.append(f"installed_code_special_file_rejected:{relative}")
        return None
    if info.st_nlink != 1:
        errors.append(f"installed_code_hardlink_rejected:{relative}")
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        errors.append(f"installed_code_unreadable:{relative}")
        return None
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            errors.append(f"installed_code_inode_invalid:{relative}")
            return None
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def verify_installed_code_binding(package_parent: Path, frozen_root: Path) -> list[str]:
    """Bind installed Python modules to manifest-covered frozen copies."""
    errors: list[str] = []
    package_parent = package_parent.resolve(strict=True)
    frozen_root = frozen_root.resolve(strict=True)
    for package in _EXECUTABLE_PACKAGES:
        installed = _python_files(package_parent, package, errors)
        frozen = _python_files(frozen_root, package, errors)
        if set(installed) != set(frozen):
            errors.append(f"installed_code_path_set_mismatch:{package}")
            continue
        for relative in sorted(installed):
            installed_digest = _secure_digest(installed[relative], relative, errors)
            frozen_digest = _secure_digest(frozen[relative], relative, errors)
            if installed_digest is not None and frozen_digest is not None and installed_digest != frozen_digest:
                errors.append(f"installed_code_digest_mismatch:{relative}")
    return errors


def benchmark_root() -> Path:
    """Return the release tree, binding installed code to frozen data."""
    source_root = Path(__file__).resolve().parents[1]
    if (source_root / "cases.json").is_file() and (source_root / "RELEASE_MANIFEST.json").is_file():
        return source_root.resolve()

    installed_root = Path(sys.prefix).resolve() / "share" / _DATA_DIR_NAME
    if (installed_root / "cases.json").is_file() and (installed_root / "RELEASE_MANIFEST.json").is_file():
        binding_errors = verify_installed_code_binding(source_root, installed_root)
        if binding_errors:
            raise RuntimeError("installed_code_binding_failed:" + ",".join(binding_errors))
        return installed_root.resolve()
    raise RuntimeError(
        "benchmark_data_root_missing: expected cases.json and RELEASE_MANIFEST.json "
        f"under {source_root} or {installed_root}"
    )
