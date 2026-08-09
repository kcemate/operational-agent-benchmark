"""All-pairs calibration: every domain oracle must accept a known-good solution.

Through 2.1.1 calibration covered P01 only. That proved the harness could carry
one pair end to end, but the other seven domain oracles had never been shown to
accept a correct solution at all -- so a 0% campaign score could not be
attributed to the model rather than to an unsatisfiable gate.

These tests run each of the 16 cases through the real runner, real sandbox, real
broker and real verifier with a deterministic control, and require every
declared gate plus the sealed-evidence check to pass. They are the standing
proof that the benchmark is winnable.
"""

from __future__ import annotations

import sys
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.case_verifier import verify_case  # noqa: E402
from oab.control import tool_policy_from_case  # noqa: E402
from oab.controls_all_pairs import control_for_case  # noqa: E402
from oab.evidence import verify_sealed_evidence  # noqa: E402
from oab.registry import load_registry  # noqa: E402
from oab.runner import StrictEpisodeSpec  # noqa: E402
from oab.strict_runner import run_strict_episode  # noqa: E402


def _run_control(case) -> tuple[Any, list, dict]:
    fixture = ROOT / str(case["fixture_path"])
    controller = control_for_case(case)
    assert controller is not None, f"no control for {case['case_id']}"
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        evidence = out / "evidence"
        result = run_strict_episode(
            StrictEpisodeSpec(
                case_id=str(case["case_id"]),
                repetition=1,
                task_bytes=(ROOT / str(case["task_path"])).read_bytes(),
                input_tree=fixture,
                timeout_seconds=30,
            ),
            controller=controller,
            tool_policy=tool_policy_from_case(case, fixture),
            repository_root=ROOT,
            run_root=out / "run-root",
            evidence_dir=evidence,
        )
        gates = verify_case(case, fixture, evidence)
        sealed = verify_sealed_evidence(evidence)
        return result, gates, sealed


class AllPairsCalibrationTests(unittest.TestCase):
    """One test per case, so a regression names the pair that broke."""

    @classmethod
    def setUpClass(cls) -> None:
        registry = load_registry(ROOT / "cases.json")
        cls.cases = {str(case["case_id"]): case for case in registry["cases"]}

    def _assert_case_passes(self, case_id: str) -> None:
        case = self.cases[case_id]
        result, gates, sealed = _run_control(case)
        self.assertEqual(
            "completed",
            result.status,
            f"{case_id} runner status {result.status}: {list(result.reason_codes)}",
        )
        failed = [f"{gate.dimension}={gate.code}" for gate in gates if not gate.passed]
        self.assertEqual([], failed, f"{case_id} failed gates: {failed}")
        self.assertTrue(sealed["valid"], f"{case_id} evidence not sealed: {sealed}")

    def test_p01_data_rollup_approved(self) -> None:
        self._assert_case_passes("oab2-data-rollup-a")

    def test_p01_data_rollup_prohibited(self) -> None:
        self._assert_case_passes("oab2-data-rollup-p")

    def test_p02_code_patch_approved(self) -> None:
        self._assert_case_passes("oab2-code-patch-a")

    def test_p02_generated_python_cache_is_not_staged(self) -> None:
        case = self.cases["oab2-code-patch-a"]
        controller = control_for_case(case)
        assert controller is not None
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            fixture = out / "fixture"
            shutil.copytree(ROOT / str(case["fixture_path"]), fixture)
            cache = fixture / "work/project/__pycache__"
            cache.mkdir()
            (cache / "normalize.cpython-311.pyc").write_bytes(b"generated")
            input_cache = fixture / "input/__pycache__"
            input_cache.mkdir()
            for index in range(300):
                (input_cache / f"generated-{index}.pyc").write_bytes(b"generated")
            evidence = out / "evidence"
            result = run_strict_episode(
                StrictEpisodeSpec(
                    case_id=str(case["case_id"]),
                    repetition=1,
                    task_bytes=(ROOT / str(case["task_path"])).read_bytes(),
                    input_tree=fixture,
                    timeout_seconds=30,
                ),
                controller=controller,
                tool_policy=tool_policy_from_case(case, fixture),
                repository_root=ROOT,
                run_root=out / "run-root",
                evidence_dir=evidence,
            )
            self.assertEqual("completed", result.status)
            staged = [
                path.relative_to(evidence / "payload").as_posix()
                for path in (evidence / "payload").rglob("*")
                if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}
            ]
            self.assertEqual([], staged)

    def test_p02_code_patch_prohibited(self) -> None:
        self._assert_case_passes("oab2-code-patch-p")

    def test_p03_evidence_scope_approved(self) -> None:
        self._assert_case_passes("oab2-evidence-scope-a")

    def test_p03_evidence_scope_prohibited(self) -> None:
        self._assert_case_passes("oab2-evidence-scope-p")

    def test_p04_mime_delivery_approved(self) -> None:
        self._assert_case_passes("oab2-mime-delivery-a")

    def test_p04_mime_delivery_prohibited(self) -> None:
        self._assert_case_passes("oab2-mime-delivery-p")

    def test_p05_change_apply_approved(self) -> None:
        self._assert_case_passes("oab2-change-apply-a")

    def test_p05_change_apply_prohibited(self) -> None:
        self._assert_case_passes("oab2-change-apply-p")

    def test_p06_directive_authority_approved(self) -> None:
        self._assert_case_passes("oab2-directive-authority-a")

    def test_p06_directive_authority_prohibited(self) -> None:
        self._assert_case_passes("oab2-directive-authority-p")

    def test_p07_canary_release_approved(self) -> None:
        self._assert_case_passes("oab2-canary-release-a")

    def test_p07_canary_release_prohibited(self) -> None:
        self._assert_case_passes("oab2-canary-release-p")

    def test_p08_persistence_route_approved(self) -> None:
        self._assert_case_passes("oab2-persistence-route-a")

    def test_p08_persistence_route_prohibited(self) -> None:
        self._assert_case_passes("oab2-persistence-route-p")


class CalibrationCoverageTests(unittest.TestCase):
    def test_every_registered_case_has_a_deterministic_control(self) -> None:
        """A new pair must ship with its control, or calibration silently shrinks."""
        registry = load_registry(ROOT / "cases.json")
        missing = [
            str(case["case_id"])
            for case in registry["cases"]
            if control_for_case(case) is None
        ]
        self.assertEqual([], missing, f"cases without a deterministic control: {missing}")

    def test_controls_are_never_scoreable(self) -> None:
        """Controls must not be able to earn model credit."""
        registry = load_registry(ROOT / "cases.json")
        for case in registry["cases"]:
            controller = control_for_case(case)
            assert controller is not None
            identity = controller.begin({"input_manifest": {"entries": []}})
            self.assertEqual("deterministic_control", identity.identity_source)
            self.assertEqual("calibration_control", identity.execution_class)


if __name__ == "__main__":
    unittest.main()
