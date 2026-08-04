from __future__ import annotations

import hashlib
import importlib.util
import marshal
import os
import stat
import sys
import types
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path

_DATA_DIR_NAME = "operational-agent-benchmark"
_EXECUTABLE_PACKAGES = ("oab", "tools")
_NATIVE_SUFFIXES = tuple(EXTENSION_SUFFIXES)


def _read_regular_bytes(path: Path, *, max_bytes: int | None = None) -> bytes | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or (max_bytes is not None and info.st_size > max_bytes)
    ):
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (max_bytes is not None and opened.st_size > max_bytes)
        ):
            return None
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(descriptor)


def _bytecode_matches_source(
    path: Path, root: Path, filename_root: Path | None
) -> bool:
    try:
        if path.parent.name == "__pycache__":
            source_name = path.name.split(".", 1)[0] + ".py"
            source = path.parent.parent / source_name
        else:
            source = path.with_suffix(".py")
        bytecode = _read_regular_bytes(path, max_bytes=16 * 1024 * 1024)
        source_bytes = _read_regular_bytes(source, max_bytes=4 * 1024 * 1024)
        if bytecode is None or source_bytes is None or len(bytecode) < 16:
            return False
        if bytecode[:4] != importlib.util.MAGIC_NUMBER:
            return False
        optimization = 0
        if ".opt-" in path.name:
            optimization = int(path.name.split(".opt-", 1)[1].split(".", 1)[0])
        filenames = [str(source)]
        if filename_root is not None:
            filenames.append(str(filename_root / source.relative_to(root)))
        flags = int.from_bytes(bytecode[4:8], "little")
        if flags & ~3:
            return False
        if flags & 1:
            if bytecode[8:16] != importlib.util.source_hash(source_bytes):
                return False
        else:
            source_stat = source.stat()
            recorded_mtime = int.from_bytes(bytecode[8:12], "little")
            recorded_size = int.from_bytes(bytecode[12:16], "little")
            if recorded_mtime != int(source_stat.st_mtime) & 0xFFFFFFFF:
                return False
            if recorded_size != len(source_bytes) & 0xFFFFFFFF:
                return False
        # Decode only the bounded pyc payload for structural comparison; never execute it.
        observed_code = marshal.loads(bytecode[16:])
        if not isinstance(observed_code, types.CodeType):
            return False
        for filename in dict.fromkeys(filenames):
            expected_code = compile(
                source_bytes,
                filename,
                "exec",
                dont_inherit=True,
                optimize=optimization,
            )
            if observed_code == expected_code:
                return True
        return False
    except (OSError, SyntaxError, ValueError, TypeError, EOFError):
        return False


def _python_files(
    root: Path,
    package: str,
    errors: list[str],
    *,
    reject_shadows: bool,
    bytecode_filename_root: Path | None = None,
) -> dict[str, Path]:
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
            path = current_path / filename
            relative = path.relative_to(root).as_posix()
            if reject_shadows:
                if filename.endswith(".pyc") and not _bytecode_matches_source(
                    path, root, bytecode_filename_root
                ):
                    errors.append(f"installed_code_shadow_artifact:{relative}")
                elif filename.endswith((".pyo", *_NATIVE_SUFFIXES)):
                    errors.append(f"installed_code_shadow_artifact:{relative}")
            if not filename.endswith(".py"):
                continue
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
    package_parent_filename_root = package_parent.absolute()
    package_parent = package_parent.resolve(strict=True)
    frozen_root = frozen_root.resolve(strict=True)
    for package in _EXECUTABLE_PACKAGES:
        installed = _python_files(
            package_parent,
            package,
            errors,
            reject_shadows=True,
            bytecode_filename_root=package_parent_filename_root,
        )
        frozen = _python_files(frozen_root, package, errors, reject_shadows=False)
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
