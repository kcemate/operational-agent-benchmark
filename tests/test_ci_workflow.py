from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CiWorkflowContractTests(unittest.TestCase):
    def test_linux_ci_supplies_public_scan_denylist(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("python -m oab.public_scan . --denylist", workflow)

    def test_ci_covers_both_supported_sandbox_backends(self) -> None:
        """Both shipped sandbox backends must be exercised by CI.

        The harness selects bubblewrap on Linux and sandbox-exec on macOS; a
        Linux-only matrix cannot catch macOS-specific boundary regressions.
        """
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("runs-on: ubuntu-latest", workflow)
        self.assertIn("runs-on: macos-latest", workflow)


class ReleaseWorkflowContractTests(unittest.TestCase):
    """The release workflow must verify digests and never auto-publish."""

    def _workflow(self) -> str:
        return (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )

    def test_release_workflow_exists_and_is_tag_driven(self) -> None:
        workflow = self._workflow()
        self.assertIn('- "v*"', workflow)

    def test_release_is_draft_only(self) -> None:
        """A human must review verified digests before anything is published."""
        self.assertIn("--draft", self._workflow())

    def test_release_guards_manifest_and_version_before_building(self) -> None:
        workflow = self._workflow()
        self.assertIn("tools/release_guard.py", workflow)
        self.assertIn("tools/release_notes.py", workflow)

    def test_release_actions_are_pinned_by_sha(self) -> None:
        for line in self._workflow().splitlines():
            stripped = line.strip()
            if stripped.startswith("- uses:") or stripped.startswith("uses:"):
                reference = stripped.split("uses:", 1)[1].strip()
                _, _, version = reference.partition("@")
                self.assertRegex(
                    version.split()[0],
                    r"^[0-9a-f]{40}$",
                    f"action must be pinned to a full commit SHA: {stripped}",
                )


if __name__ == "__main__":
    unittest.main()
