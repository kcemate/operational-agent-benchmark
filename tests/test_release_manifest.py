from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.release_guard import check_manifest, check_version
from tools.release_manifest import build_release_manifest, verify_release_manifest
from tools.release_notes import build_notes, changelog_section


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

    def test_local_agent_runtime_is_never_part_of_the_release_tree(self) -> None:
        """`.hermes/` holds local agent runtime and plans, never release content.

        It is git-ignored, so a filesystem walk would otherwise bind untracked —
        and possibly secret-bearing — agent state into the published release-tree
        digest.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("alpha", encoding="utf-8")
            runtime = root / ".hermes" / "runtime"
            runtime.mkdir(parents=True)
            (runtime / "session-receipt.md").write_text("local", encoding="utf-8")
            (root / ".hermes" / "plans").mkdir()
            (root / ".hermes" / "plans" / "plan.md").write_text("plan", encoding="utf-8")
            manifest = build_release_manifest(root)
            paths = [entry["path"] for entry in manifest["files"]]
            self.assertEqual(["a.txt"], paths)
            self.assertEqual(1, manifest["file_count"])

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

    def test_verify_rejects_ordinary_file_replacement_during_open(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "release"
            root.mkdir()
            target = root / "a.txt"
            target.write_text("EXPECTED", encoding="utf-8")
            manifest = build_release_manifest(root)
            manifest_path = root / "RELEASE_MANIFEST.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            target.write_text("MALICIOUS", encoding="utf-8")
            expected_swap = base / "expected-swap"
            expected_swap.write_text("EXPECTED", encoding="utf-8")
            displaced = base / "displaced"
            opened_expected = base / "opened-expected"
            real_open = os.open
            raced = False

            def swapping_open(
                path: str | bytes | os.PathLike[str],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal raced
                if path == "a.txt" and dir_fd is not None and not raced:
                    raced = True
                    target.rename(displaced)
                    expected_swap.rename(target)
                    descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                    target.rename(opened_expected)
                    displaced.rename(target)
                    return descriptor
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with patch("tools.release_manifest.os.open", side_effect=swapping_open):
                errors = verify_release_manifest(root, manifest_path)

            self.assertTrue(raced)
            self.assertIn("release_path_race_detected:a.txt", errors)
            self.assertEqual("MALICIOUS", target.read_text(encoding="utf-8"))


class CommittedManifestFreshnessTests(unittest.TestCase):
    """The committed manifest must always describe the current working tree.

    Catches a stale RELEASE_MANIFEST.json on every push instead of at tag time,
    so a release can never publish a digest that does not match the tree.
    """

    def test_committed_manifest_matches_working_tree(self) -> None:
        root = Path(__file__).resolve().parents[1]
        manifest_path = root / "RELEASE_MANIFEST.json"
        errors = verify_release_manifest(root, manifest_path)
        self.assertEqual(
            [],
            errors,
            "RELEASE_MANIFEST.json is stale; regenerate it with "
            "tools/release_manifest.py before committing.",
        )


class ReleaseGuardTests(unittest.TestCase):
    def test_stale_manifest_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            exported = root / "exported.json"
            committed = root / "committed.json"
            exported.write_text(
                json.dumps({"tree_sha256": "sha256:" + "a" * 64, "file_count": 1}),
                encoding="utf-8",
            )
            committed.write_text(
                json.dumps({"tree_sha256": "sha256:" + "b" * 64, "file_count": 1}),
                encoding="utf-8",
            )
            errors = check_manifest(exported, committed)
            self.assertTrue(errors)
            self.assertIn("release_manifest_stale", errors[0])

    def test_matching_manifest_passes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            payload = json.dumps(
                {"tree_sha256": "sha256:" + "c" * 64, "file_count": 1}
            )
            exported = root / "exported.json"
            committed = root / "committed.json"
            exported.write_text(payload, encoding="utf-8")
            committed.write_text(payload, encoding="utf-8")
            self.assertEqual([], check_manifest(exported, committed))

    def test_version_must_match_tag(self) -> None:
        self.assertEqual([], check_version("v2.1.0", "2.1.0"))
        self.assertTrue(check_version("v2.1.0", "2.0.2"))


class ReleaseNotesTests(unittest.TestCase):
    def test_changelog_section_is_extracted_for_the_tagged_version(self) -> None:
        changelog = (
            "# Changelog\n\n"
            "## 2.1.0 - 2026-08-07\n\n- new thing\n\n"
            "## 2.0.2 - 2026-08-07\n\n- older thing\n"
        )
        section = changelog_section(changelog, "2.1.0")
        self.assertIn("new thing", section)
        self.assertNotIn("older thing", section)

    def test_missing_changelog_section_is_reported_not_fabricated(self) -> None:
        section = changelog_section("# Changelog\n\n## 2.0.2\n\n- old\n", "9.9.9")
        self.assertIn("no CHANGELOG entry found", section)

    def test_notes_carry_computed_digests(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wheel = Path(td) / "pkg-2.1.0-py3-none-any.whl"
            wheel.write_bytes(b"wheel-bytes")
            expected = hashlib.sha256(b"wheel-bytes").hexdigest()
            notes = build_notes(
                tag="v2.1.0",
                wheel_path=wheel,
                manifest={"tree_sha256": "sha256:" + "d" * 64, "file_count": 160},
                changelog="## 2.1.0\n\n- entry\n",
                commit="abc123",
            )
            self.assertIn(expected, notes)
            self.assertIn("sha256:" + "d" * 64, notes)
            self.assertIn("160", notes)


if __name__ == "__main__":
    unittest.main()
