from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CiWorkflowContractTests(unittest.TestCase):
    def test_linux_ci_supplies_public_scan_denylist(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("python -m oab.public_scan . --denylist", workflow)


if __name__ == "__main__":
    unittest.main()
