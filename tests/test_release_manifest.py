from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from tools.release_manifest import build_release_manifest, verify_release_manifest


class ReleaseManifestTests(unittest.TestCase):
    def test_build_is_deterministic_and_ignores_cache_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("alpha", encoding="utf-8")
            cache = root / "__pycache__"
            cache.mkdir()
            (cache / "noise.pyc").write_bytes(b"noise")
            first = build_release_manifest(root)
            second = build_release_manifest(root)
            self.assertEqual(first, second)
            self.assertEqual(1, first["file_count"])
            self.assertEqual("a.txt", first["files"][0]["path"])

    def test_verify_detects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "a.txt"
            target.write_text("alpha", encoding="utf-8")
            manifest = build_release_manifest(root)
            path = root / "RELEASE_MANIFEST.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual([], verify_release_manifest(root, path))
            target.write_text("tampered", encoding="utf-8")
            self.assertIn("release_tree_digest_mismatch", verify_release_manifest(root, path))

    def test_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "a.txt"
            target.write_text("alpha", encoding="utf-8")
            (root / "alias.txt").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "release_symlink_rejected"):
                build_release_manifest(root)

    def test_rejects_hardlinked_release_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "release"
            root.mkdir()
            target = root / "a.txt"
            target.write_text("alpha", encoding="utf-8")
            os.link(target, Path(td) / "external-alias.txt")
            with self.assertRaisesRegex(ValueError, "release_hardlink_rejected"):
                build_release_manifest(root)

    def test_external_tree_pin_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("hello", encoding="utf-8")
            manifest = build_release_manifest(root)
            manifest_path = root / "RELEASE_MANIFEST.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            errors = verify_release_manifest(
                root,
                manifest_path,
                expected_tree_sha256="sha256:" + "0" * 64,
            )
            self.assertIn("externally_pinned_tree_digest_mismatch", errors)


if __name__ == "__main__":
    unittest.main()
