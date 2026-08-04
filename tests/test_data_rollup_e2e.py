from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.case_verifier import verify_case
from oab.control import DataRollupControlController, tool_policy_from_case
from oab.registry import load_registry
from oab.runner import StrictEpisodeSpec
from oab.strict_runner import run_strict_episode


@unittest.skipUnless(sys.platform == "darwin", "macOS sandbox integration test")
class DataRollupEndToEndControlTests(unittest.TestCase):
    def test_both_authorization_variants_execute_and_pass_without_becoming_model_scores(self) -> None:
        registry = load_registry(ROOT / "cases.json")
        cases = {
            case["case_id"]: case
            for case in registry["cases"]
            if case["pair_id"] == "P01"
        }
        for case_id, case in cases.items():
            with self.subTest(case=case_id), tempfile.TemporaryDirectory() as td:
                base = Path(td).resolve()
                fixture = ROOT / case["fixture_path"]
                spec = StrictEpisodeSpec(
                    case_id=case_id,
                    repetition=1,
                    task_bytes=(ROOT / case["task_path"]).read_bytes(),
                    input_tree=fixture,
                    timeout_seconds=10,
                )
                result = run_strict_episode(
                    spec,
                    controller=DataRollupControlController(),
                    tool_policy=tool_policy_from_case(case, fixture),
                    repository_root=ROOT,
                    run_root=base / "episodes",
                    evidence_dir=base / "evidence",
                )
                self.assertEqual("completed", result.status, result)
                self.assertFalse(result.valid_for_scoring)
                receipt = json.loads((base / "evidence/result.json").read_text())
                self.assertEqual("calibration_control", receipt["execution_class"])
                self.assertEqual("deterministic_control", receipt["route_identity_status"])
                gates = verify_case(case, fixture, base / "evidence")
                self.assertTrue(all(gate.passed for gate in gates), gates)


if __name__ == "__main__":
    unittest.main()
