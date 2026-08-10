from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from oab import __version__
from oab.paths import benchmark_root

_SCHEMA = "oab.release-manifest/v1"
_EXCLUDED_PARTS = {
    ".git",
    ".hermes",  # local agent runtime/plans: git-ignored, never release content
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "build",
    "dist",
}
_EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
_EXCLUDED_NAMES = {".DS_Store", "RELEASE_MANIFEST.json"}


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _included(relative: PurePosixPath) -> bool:
    if any(part in _EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
        return False
    if relative.name in _EXCLUDED_NAMES or relative.suffix in _EXCLUDED_SUFFIXES:
        return False
    return True


def build_release_manifest(root: Path) -> dict[str, Any]:
    root = root.absolute()
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise ValueError("release_root_invalid") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise ValueError("release_root_invalid")

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(root, directory_flags)
    except OSError as exc:
        raise ValueError("release_root_invalid") from exc

    def identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    entries: list[dict[str, object]] = []

    def walk(directory_fd: int, relative_parent: PurePosixPath | None) -> None:
        directory_before = os.fstat(directory_fd)
        try:
            children = list(os.scandir(directory_fd))
        except OSError as exc:
            raise ValueError("release_directory_unreadable") from exc
        children.sort(key=lambda child: child.name)
        for child in children:
            relative = (
                PurePosixPath(child.name)
                if relative_parent is None
                else relative_parent / child.name
            )
            if not _included(relative):
                continue
            try:
                before = os.stat(child.name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise ValueError(f"release_path_unreadable:{relative}") from exc
            mode = before.st_mode
            if stat.S_ISLNK(mode):
                raise ValueError(f"release_symlink_rejected:{relative}")
            if stat.S_ISDIR(mode):
                try:
                    child_fd = os.open(child.name, directory_flags, dir_fd=directory_fd)
                except OSError as exc:
                    raise ValueError(f"release_directory_unreadable:{relative}") from exc
                try:
                    opened = os.fstat(child_fd)
                    if identity(opened) != identity(before):
                        raise ValueError(f"release_path_race_detected:{relative}")
                    walk(child_fd, relative)
                    after_entry = os.stat(
                        child.name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if identity(after_entry) != identity(opened):
                        raise ValueError(f"release_path_race_detected:{relative}")
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(mode):
                raise ValueError(f"release_special_file_rejected:{relative}")
            if before.st_nlink != 1:
                raise ValueError(f"release_hardlink_rejected:{relative}")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(child.name, flags, dir_fd=directory_fd)
            except OSError as exc:
                raise ValueError(f"release_path_unreadable:{relative}") from exc
            try:
                opened = os.fstat(descriptor)
                if identity(opened) != identity(before):
                    raise ValueError(f"release_path_race_detected:{relative}")
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                payload = b"".join(chunks)
                after_read = os.fstat(descriptor)
                if identity(after_read) != identity(opened):
                    raise ValueError(f"release_path_race_detected:{relative}")
                after_entry = os.stat(
                    child.name, dir_fd=directory_fd, follow_symlinks=False
                )
                if identity(after_entry) != identity(opened):
                    raise ValueError(f"release_path_race_detected:{relative}")
            finally:
                os.close(descriptor)
            entries.append(
                {
                    "path": relative.as_posix(),
                    "bytes": len(payload),
                    "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
                    "executable": bool(opened.st_mode & 0o111),
                }
            )
        directory_after = os.fstat(directory_fd)
        if identity(directory_after) != identity(directory_before):
            display = relative_parent.as_posix() if relative_parent is not None else "."
            raise ValueError(f"release_directory_race_detected:{display}")

    try:
        opened_root = os.fstat(root_fd)
        if identity(opened_root) != identity(root_info):
            raise ValueError("release_root_race_detected")
        walk(root_fd, None)
        final_root = root.lstat()
        if identity(final_root) != identity(opened_root):
            raise ValueError("release_root_race_detected")
    finally:
        os.close(root_fd)
    if not entries:
        raise ValueError("release_manifest_empty")
    entries.sort(key=lambda entry: str(entry["path"]))
    tree_sha256 = "sha256:" + hashlib.sha256(_canonical_bytes(entries)).hexdigest()
    return {
        "schema": _SCHEMA,
        "benchmark_version": __version__,
        "file_count": len(entries),
        "tree_sha256": tree_sha256,
        "files": entries,
    }


def verify_release_manifest(
    root: Path,
    manifest_path: Path,
    *,
    expected_tree_sha256: str | None = None,
) -> list[str]:
    try:
        expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ["release_manifest_unreadable"]
    if not isinstance(expected, dict) or expected.get("schema") != _SCHEMA:
        return ["release_manifest_schema_invalid"]
    try:
        actual = build_release_manifest(root)
    except (OSError, ValueError) as exc:
        return [str(exc)]
    errors: list[str] = []
    if expected_tree_sha256 is not None:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", expected_tree_sha256) is None:
            errors.append("externally_pinned_tree_digest_invalid")
        elif actual["tree_sha256"] != expected_tree_sha256:
            errors.append("externally_pinned_tree_digest_mismatch")
    if expected.get("file_count") != actual["file_count"]:
        errors.append("release_file_count_mismatch")
    if expected.get("tree_sha256") != actual["tree_sha256"]:
        errors.append("release_tree_digest_mismatch")
    if expected.get("files") != actual["files"]:
        errors.append("release_file_entries_mismatch")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Build or verify the curated OAB v2 release manifest")
    parser.add_argument("--root", type=Path, default=benchmark_root())
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--verify", type=Path, default=None)
    parser.add_argument("--expected-tree-sha256", default=None)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    if args.verify is not None:
        errors = verify_release_manifest(
            root,
            args.verify.resolve(strict=True),
            expected_tree_sha256=args.expected_tree_sha256,
        )
        for error in errors:
            print(error)
        return 1 if errors else 0
    output = args.output or (root / "RELEASE_MANIFEST.json")
    manifest = build_release_manifest(root)
    output.write_bytes(_canonical_bytes(manifest) + b"\n")
    print(f"{output.resolve()} {manifest['tree_sha256']} files={manifest['file_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
