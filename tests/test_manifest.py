from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.manifest import (
    ManifestError,
    build_tree_manifest,
    validate_manifest_paths,
    verify_tree_manifest,
)


class TreeManifestTests(unittest.TestCase):
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
