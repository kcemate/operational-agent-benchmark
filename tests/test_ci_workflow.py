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


if __name__ == "__main__":
    unittest.main()
