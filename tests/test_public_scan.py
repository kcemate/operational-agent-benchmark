from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.public_scan import Finding, load_denylist, scan_tree


class PublicTreeScanTests(unittest.TestCase):
    def test_scanner_reports_case_insensitive_content_and_path_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "docs").mkdir()
            (root / "docs" / "PrivateBrandX-notes.md").write_text("safe", encoding="utf-8")
            (root / "README.md").write_text("mentions InternalPersonY", encoding="utf-8")
            denylist = root / "denylist.txt"
            denylist.write_text("PrivateBrandX\nInternalPersonY\n", encoding="utf-8")

            findings = scan_tree(root, load_denylist(denylist), exclude={"denylist.txt"})

        self.assertEqual(
            [
                Finding(path="README.md", term="InternalPersonY", location="content"),
                Finding(
                    path="docs/PrivateBrandX-notes.md",
                    term="PrivateBrandX",
                    location="path",
                ),
            ],
            findings,
        )

    def test_scanner_skips_binary_cache_and_version_control_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for directory in (".git", "__pycache__"):
                (root / directory).mkdir()
                (root / directory / "PrivateBrandX.bin").write_bytes(b"PrivateBrandX\x00")
            self.assertEqual([], scan_tree(root, ["PrivateBrandX"]))

    def test_denylist_rejects_blank_or_comment_only_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "denylist.txt"
            path.write_text("# public release denylist\n\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "denylist is empty"):
                load_denylist(path)


if __name__ == "__main__":
    unittest.main()
