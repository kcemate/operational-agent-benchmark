from __future__ import annotations

import unittest

from tools.agent_workflow import _parser


class NoApprovalGateContractTests(unittest.TestCase):
    def test_cli_has_no_approval_gate_surface(self) -> None:
        parser = _parser()
        help_text = parser.format_help()
        self.assertNotIn("approval-preview", help_text)
        self.assertNotIn("approval-request", help_text)

        benchmark = parser.parse_args(
            [
                "benchmark",
                "--all-accessible",
                "--output-root",
                "/tmp/campaign",
                "--reasoning-effort",
                "high",
            ]
        )
        self.assertFalse(hasattr(benchmark, "approval_public_key"))

        resume = parser.parse_args(
            [
                "resume",
                "/tmp/campaign",
                "--stage",
                "qualification",
                "--observed-cost-stop-usd",
                "5",
                "--max-api-calls",
                "48",
                "--max-routes",
                "2",
                "--allow-unknown-costs",
            ]
        )
        self.assertEqual("qualification", resume.stage)
        self.assertFalse(hasattr(resume, "approval_signature"))
        self.assertFalse(hasattr(resume, "approval_public_key"))
        self.assertFalse(hasattr(resume, "qualification_approval"))
        self.assertFalse(hasattr(resume, "full_approval"))


if __name__ == "__main__":
    unittest.main()
