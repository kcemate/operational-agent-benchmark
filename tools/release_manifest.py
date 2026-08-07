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
_EXCLUDED_PARTS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "build", "dist"}
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
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("release_root_invalid")
    entries: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = PurePosixPath(path.relative_to(root).as_posix())
        if not _included(relative):
            continue
        info = path.lstat()
        mode = info.st_mode
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISLNK(mode):
            raise ValueError(f"release_symlink_rejected:{relative}")
        if not stat.S_ISREG(mode):
            raise ValueError(f"release_special_file_rejected:{relative}")
        if info.st_nlink != 1:
            raise ValueError(f"release_hardlink_rejected:{relative}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError(f"release_special_file_rejected:{relative}")
            if opened.st_nlink != 1:
                raise ValueError(f"release_hardlink_rejected:{relative}")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            payload = b"".join(chunks)
            mode = opened.st_mode
        finally:
            os.close(descriptor)
        entries.append(
            {
                "path": relative.as_posix(),
                "bytes": len(payload),
                "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
                "executable": bool(mode & 0o111),
            }
        )
    if not entries:
        raise ValueError("release_manifest_empty")
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
