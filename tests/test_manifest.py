from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.manifest import (
    ManifestError,
    build_tree_manifest,
    validate_manifest_paths,
    verify_tree_manifest,
)


class TreeManifestTests(unittest.TestCase):
    def test_same_size_file_mutation_during_hash_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "output"
            root.mkdir()
            target = root / "payload.txt"
            target.write_text("before", encoding="utf-8")
            original_read = os.read
            raced = False

            def raced_read(descriptor: int, size: int) -> bytes:
                nonlocal raced
                data = original_read(descriptor, size)
                if data and not raced:
                    raced = True
                    target.write_text("change", encoding="utf-8")
                return data

            with patch("oab.manifest.os.read", side_effect=raced_read):
                with self.assertRaisesRegex(ManifestError, "file changed during scan"):
                    build_tree_manifest(root)

    def test_directory_to_symlink_substitution_during_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "output"
            nested = root / "nested"
            outside = base / "outside"
            nested.mkdir(parents=True)
            outside.mkdir()
            (nested / "inside.txt").write_text("inside", encoding="utf-8")
            secret = outside / "secret.txt"
            secret.write_text("outside", encoding="utf-8")
            original_stat = os.stat
            raced = False

            def raced_stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
                nonlocal raced
                result = original_stat(path, *args, **kwargs)
                if not raced and path == "nested" and kwargs.get("dir_fd") is not None:
                    raced = True
                    shutil.rmtree(nested)
                    nested.symlink_to(outside, target_is_directory=True)
                return result

            with patch("oab.manifest.os.stat", side_effect=raced_stat):
                with self.assertRaises(ManifestError):
                    build_tree_manifest(root)
            self.assertEqual("outside", secret.read_text(encoding="utf-8"))

    def test_regular_tree_has_canonical_paths_hashes_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "output"
            (root / "nested").mkdir(parents=True)
            (root / "a.txt").write_text("alpha\n", encoding="utf-8")
            (root / "nested/b.bin").write_bytes(b"\x00\xff")
            manifest = build_tree_manifest(root, max_files=4, max_total_bytes=100)
            self.assertEqual(["a.txt", "nested", "nested/b.bin"], [entry["path"] for entry in manifest["entries"]])
            self.assertTrue(manifest["tree_sha256"].startswith("sha256:"))
            self.assertEqual([], verify_tree_manifest(root, manifest))

    def test_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "output"
            root.mkdir()
            (root / "target.txt").write_text("x", encoding="utf-8")
            (root / "link.txt").symlink_to(root / "target.txt")
            with self.assertRaisesRegex(ManifestError, "symlink"):
                build_tree_manifest(root)

    def test_hardlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "output"
            root.mkdir()
            (root / "a.txt").write_text("x", encoding="utf-8")
            os.link(root / "a.txt", root / "b.txt")
            with self.assertRaisesRegex(ManifestError, "hardlink"):
                build_tree_manifest(root)

    def test_fifo_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "output"
            root.mkdir()
            os.mkfifo(root / "pipe")
            with self.assertRaisesRegex(ManifestError, "special"):
                build_tree_manifest(root)

    def test_limits_and_casefold_collisions_fail_closed(self) -> None:
        with self.assertRaisesRegex(ManifestError, "case-fold"):
            validate_manifest_paths(["A.txt", "a.TXT"])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "output"
            root.mkdir()
            (root / "A.txt").write_text("123", encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "byte limit"):
                build_tree_manifest(root, max_total_bytes=2)


if __name__ == "__main__":
    unittest.main()
