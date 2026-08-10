"""Release-blocking offline acceptance for the v2.3.0 qualification contract.

Wraps tools/qualification_acceptance.py so the acceptance gate runs as part of
`python -m unittest discover -s tests`. No provider calls are made.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.qualification_acceptance import (  # noqa: E402
    ABSOLUTE_CALLS_PER_ROUTE,
    MAX_STEPS_PER_EPISODE,
    PROBES_PER_ROUTE,
    SCENARIOS,
    run_acceptance,
)


class QualificationAcceptanceTests(unittest.TestCase):
    def test_offline_acceptance_gate_passes_every_scenario(self) -> None:
        report = run_acceptance()
        scenarios = report["scenarios"]
        assert isinstance(scenarios, list)
        failed = [item for item in scenarios if not item["passed"]]
        self.assertEqual([], failed, report)
        self.assertTrue(report["passed"])
        self.assertEqual(len(SCENARIOS), report["passed_count"])

    def test_acceptance_gate_covers_every_required_scenario(self) -> None:
        required = {
            "two_turn_success",
            "denial_recovery",
            "loop_exhaustion",
            "direct_answer_agent_loop_incompatible",
            "route_mismatch",
            "telemetry_known_cost",
            "telemetry_unknown_cost",
            "telemetry_missing_api_calls",
        }
        self.assertEqual(required, set(SCENARIOS))

    def test_acceptance_gate_declares_the_v230_plumbing_bounds(self) -> None:
        report = run_acceptance()
        self.assertEqual("v2.3.0", report["contract"])
        self.assertEqual(2, PROBES_PER_ROUTE)
        self.assertEqual(4, MAX_STEPS_PER_EPISODE)
        self.assertEqual(16, ABSOLUTE_CALLS_PER_ROUTE)
        self.assertEqual(0, report["provider_calls"])

    def test_acceptance_report_contains_no_quality_percentage(self) -> None:
        serialized = json.dumps(run_acceptance())
        for banned in ("completion_rate", "pair_stability", "gate_pass_rate", "%"):
            self.assertNotIn(banned, serialized)

    def test_acceptance_cli_exits_zero_and_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "acceptance.json"
            process = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/qualification_acceptance.py"),
                    "--json",
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
            )
            self.assertEqual(0, process.returncode, process.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual("oab.qualification-acceptance/v1", payload["schema"])
            self.assertTrue(payload["passed"])


if __name__ == "__main__":
    unittest.main()
