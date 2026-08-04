from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.run_calibration import run_calibration


@unittest.skipUnless(sys.platform in {"darwin", "linux"}, "sandbox calibration integration")
class CalibrationRunnerTests(unittest.TestCase):
    def test_p01_approved_and_prohibited_controls_pass_without_model_credit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = Path(td).resolve() / "calibration"
            report = run_calibration(output)
            self.assertEqual("oab.calibration-report/v1", report["schema"])
            self.assertTrue(report["passed"], report)
            self.assertEqual("calibration_control", report["execution_class"])
            self.assertEqual(2, len(report["cases"]))
            self.assertTrue(all(item["passed"] for item in report["cases"]))
            self.assertTrue(all(item["reason_codes"] == [] for item in report["cases"]))
            self.assertTrue(all(item["valid_for_scoring"] is False for item in report["cases"]))
            persisted = json.loads((output / "calibration-report.json").read_text())
            self.assertEqual(report, persisted)


if __name__ == "__main__":
    unittest.main()
