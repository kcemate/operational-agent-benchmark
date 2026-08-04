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


def _hash_regular_file(path: Path, expected: os.stat_result, max_bytes: int) -> tuple[str, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise ManifestError(f"path race detected: {path}")
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
        if (
            (closed.st_dev, closed.st_ino, closed.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_size)
            or size != opened.st_size
        ):
            raise ManifestError(f"file changed during scan: {path}")
        return "sha256:" + digest.hexdigest(), size
    finally:
        os.close(descriptor)


def build_tree_manifest(
    root: Path,
    *,
    max_files: int = 256,
    max_total_bytes: int = 16 * 1024 * 1024,
    exclude_paths: frozenset[str] = frozenset(),
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

    entries: list[dict[str, object]] = []
    observed_paths: list[str] = []
    file_count = 0
    total_bytes = 0

    def walk(directory: Path) -> None:
        nonlocal file_count, total_bytes
        try:
            children = list(os.scandir(directory))
        except OSError as exc:
            raise ManifestError(f"directory is unreadable: {directory}") from exc
        children.sort(key=lambda child: unicodedata.normalize("NFC", child.name))
        for child in children:
            relative = Path(child.path).relative_to(root).as_posix()
            if relative in exclude_paths:
                continue
            normalized = unicodedata.normalize("NFC", relative)
            observed_paths.append(relative)
            validate_manifest_paths(observed_paths)
            info = child.stat(follow_symlinks=False)
            mode = info.st_mode
            if stat.S_ISLNK(mode):
                raise ManifestError(f"symlink is not allowed: {normalized}")
            if stat.S_ISDIR(mode):
                entries.append({"path": normalized, "type": "directory"})
                walk(Path(child.path))
                continue
            if not stat.S_ISREG(mode):
                raise ManifestError(f"special file is not allowed: {normalized}")
            if info.st_nlink != 1:
                raise ManifestError(f"hardlink is not allowed: {normalized}")
            file_count += 1
            if file_count > max_files:
                raise ManifestError("tree exceeds file limit")
            remaining = max_total_bytes - total_bytes
            digest, size = _hash_regular_file(Path(child.path), info, remaining)
            total_bytes += size
            entries.append(
                {
                    "path": normalized,
                    "type": "regular",
                    "size": size,
                    "sha256": digest,
                }
            )

    walk(root)
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
