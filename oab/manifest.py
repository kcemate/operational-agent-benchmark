from __future__ import annotations

import hashlib
import json
import os
import stat
import unicodedata
from pathlib import Path
from typing import Any


class ManifestError(ValueError):
    pass


def is_generated_python_cache_path(path: str | Path) -> bool:
    candidate = Path(path)
    return "__pycache__" in candidate.parts or candidate.suffix in {".pyc", ".pyo"}


def ignore_generated_python_caches(_directory: str, names: list[str]) -> set[str]:
    """Return cache entries that must never cross a fixture-copy boundary."""

    return {
        name
        for name in names
        if name == "__pycache__" or Path(name).suffix in {".pyc", ".pyo"}
    }


def validate_manifest_paths(paths: list[str]) -> None:
    seen_folded: dict[str, str] = {}
    for path in paths:
        normalized = unicodedata.normalize("NFC", path)
        if normalized != path:
            raise ManifestError(f"non-normalized path is not allowed: {path}")
        folded = normalized.casefold()
        if folded in seen_folded:
            raise ManifestError(
                f"case-fold collision: {seen_folded[folded]} and {normalized}"
            )
        seen_folded[folded] = normalized


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _hash_regular_file_at(
    directory_fd: int,
    name: str,
    expected: os.stat_result,
    max_bytes: int,
    display_path: str,
) -> tuple[str, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        opened = os.fstat(descriptor)
        identity = lambda info: (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or identity(opened) != identity(expected)
        ):
            raise ManifestError(f"path race detected: {display_path}")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise ManifestError("tree exceeds byte limit")
            digest.update(chunk)
        closed = os.fstat(descriptor)
        if identity(closed) != identity(opened) or size != opened.st_size:
            raise ManifestError(f"file changed during scan: {display_path}")
        return "sha256:" + digest.hexdigest(), size
    finally:
        os.close(descriptor)


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)


def build_tree_manifest(
    root: Path,
    *,
    max_files: int = 256,
    max_total_bytes: int = 16 * 1024 * 1024,
    exclude_paths: frozenset[str] = frozenset(),
    exclude_generated_python_caches: bool = False,
) -> dict[str, Any]:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise ManifestError(f"root is unreadable: {root}") from exc
    if stat.S_ISLNK(root_info.st_mode):
        raise ManifestError("root symlink is not allowed")
    if not stat.S_ISDIR(root_info.st_mode):
        raise ManifestError("manifest root must be a directory")
    if max_files < 0 or max_total_bytes < 0:
        raise ManifestError("manifest limits must be nonnegative")
    validate_manifest_paths(list(exclude_paths))
    if any(
        not value or Path(value).is_absolute() or ".." in Path(value).parts
        for value in exclude_paths
    ):
        raise ManifestError("excluded path is invalid")

    root_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        root_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        root_flags |= os.O_NOFOLLOW
    try:
        root_fd = os.open(root, root_flags)
    except OSError as exc:
        raise ManifestError(f"root is unreadable: {root}") from exc
    try:
        opened_root = os.fstat(root_fd)
        if (opened_root.st_dev, opened_root.st_ino) != (
            root_info.st_dev,
            root_info.st_ino,
        ):
            raise ManifestError(f"path race detected: {root}")

        entries: list[dict[str, object]] = []
        observed_paths: list[str] = []
        file_count = 0
        total_bytes = 0

        def walk(directory_fd: int, relative_parent: str) -> None:
            nonlocal file_count, total_bytes
            directory_before = os.fstat(directory_fd)
            try:
                children = list(os.scandir(directory_fd))
            except OSError as exc:
                display = root if not relative_parent else root / relative_parent
                raise ManifestError(f"directory is unreadable: {display}") from exc
            children.sort(key=lambda child: unicodedata.normalize("NFC", child.name))
            for child in children:
                relative = (
                    f"{relative_parent}/{child.name}"
                    if relative_parent
                    else child.name
                )
                if relative in exclude_paths or (
                    exclude_generated_python_caches
                    and is_generated_python_cache_path(relative)
                ):
                    continue
                normalized = unicodedata.normalize("NFC", relative)
                observed_paths.append(relative)
                validate_manifest_paths(observed_paths)
                try:
                    info = os.stat(
                        child.name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise ManifestError(f"path is unreadable: {normalized}") from exc
                mode = info.st_mode
                if stat.S_ISLNK(mode):
                    raise ManifestError(f"symlink is not allowed: {normalized}")
                if stat.S_ISDIR(mode):
                    child_flags = os.O_RDONLY
                    if hasattr(os, "O_DIRECTORY"):
                        child_flags |= os.O_DIRECTORY
                    if hasattr(os, "O_NOFOLLOW"):
                        child_flags |= os.O_NOFOLLOW
                    try:
                        child_fd = os.open(
                            child.name,
                            child_flags,
                            dir_fd=directory_fd,
                        )
                    except OSError as exc:
                        raise ManifestError(
                            f"directory is unreadable: {normalized}"
                        ) from exc
                    try:
                        opened_child = os.fstat(child_fd)
                        if (opened_child.st_dev, opened_child.st_ino) != (
                            info.st_dev,
                            info.st_ino,
                        ):
                            raise ManifestError(f"path race detected: {normalized}")
                        entries.append({"path": normalized, "type": "directory"})
                        walk(child_fd, relative)
                        current = os.stat(
                            child.name,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                        if (current.st_dev, current.st_ino) != (
                            opened_child.st_dev,
                            opened_child.st_ino,
                        ):
                            raise ManifestError(f"path race detected: {normalized}")
                    finally:
                        os.close(child_fd)
                    continue
                if not stat.S_ISREG(mode):
                    raise ManifestError(f"special file is not allowed: {normalized}")
                if info.st_nlink != 1:
                    raise ManifestError(f"hardlink is not allowed: {normalized}")
                file_count += 1
                if file_count > max_files:
                    raise ManifestError("tree exceeds file limit")
                remaining = max_total_bytes - total_bytes
                digest, size = _hash_regular_file_at(
                    directory_fd,
                    child.name,
                    info,
                    remaining,
                    normalized,
                )
                total_bytes += size
                entries.append(
                    {
                        "path": normalized,
                        "type": "regular",
                        "size": size,
                        "sha256": digest,
                    }
                )
            directory_after = os.fstat(directory_fd)
            if _directory_identity(directory_after) != _directory_identity(directory_before):
                display = relative_parent or "."
                raise ManifestError(f"directory changed during scan: {display}")

        walk(root_fd, "")
        current_root = root.lstat()
        if (current_root.st_dev, current_root.st_ino) != (
            opened_root.st_dev,
            opened_root.st_ino,
        ):
            raise ManifestError(f"path race detected: {root}")
        entries.sort(key=lambda entry: str(entry["path"]))
        payload: dict[str, Any] = {
            "schema": "oab.tree-manifest/v1",
            "file_count": file_count,
            "total_bytes": total_bytes,
            "limits": {"max_files": max_files, "max_total_bytes": max_total_bytes},
            "entries": entries,
        }
        payload["tree_sha256"] = "sha256:" + hashlib.sha256(
            _canonical_bytes(payload)
        ).hexdigest()
        return payload
    finally:
        os.close(root_fd)


def build_fixture_manifest(
    root: Path,
    *,
    max_files: int = 256,
    max_total_bytes: int = 16 * 1024 * 1024,
) -> dict[str, Any]:
    return build_tree_manifest(
        root,
        max_files=max_files,
        max_total_bytes=max_total_bytes,
        exclude_generated_python_caches=True,
    )


def verify_tree_manifest(root: Path, expected: dict[str, Any]) -> list[str]:
    limits = expected.get("limits")
    if not isinstance(limits, dict):
        return ["manifest_limits_invalid"]
    max_files = limits.get("max_files")
    max_total_bytes = limits.get("max_total_bytes")
    if not isinstance(max_files, int) or not isinstance(max_total_bytes, int):
        return ["manifest_limits_invalid"]
    try:
        actual = build_tree_manifest(
            root,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
        )
    except ManifestError as exc:
        return [f"tree_invalid:{exc}"]
    errors: list[str] = []
    if actual.get("entries") != expected.get("entries"):
        errors.append("manifest_entries_mismatch")
    if actual.get("tree_sha256") != expected.get("tree_sha256"):
        errors.append("manifest_digest_mismatch")
    return errors
