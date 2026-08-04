from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.verifier import verify_sandboxed_python_tests


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(sys.platform in {"darwin", "linux"}, "supported sandbox platform required")
class SandboxedPythonVerifierTests(unittest.TestCase):
    def make_project(self, implementation: str) -> tuple[tempfile.TemporaryDirectory[str], Path, dict[str, str]]:
        temp = tempfile.TemporaryDirectory()
        workspace = Path(temp.name)
        project = workspace / "work/project"
        project.mkdir(parents=True)
        for relative in ("home", "tmp", "submission"):
            (workspace / relative).mkdir()
        (project / "calc.py").write_text(implementation, encoding="utf-8")
        (project / "test_calc.py").write_text(
            """
import unittest
from calc import total_with_tax

class CalcTests(unittest.TestCase):
    def test_standard_values(self):
        self.assertAlmostEqual(107.0, total_with_tax(100.0, 0.07))
        self.assertAlmostEqual(100.0, total_with_tax(80.0, 0.25))

    def test_zero_rate(self):
        self.assertEqual(12.5, total_with_tax(12.5, 0.0))
""".lstrip(),
            encoding="utf-8",
        )
        hashes = {"work/project/test_calc.py": sha256(project / "test_calc.py")}
        return temp, workspace, hashes

    def test_normal_import_and_preserved_tests_pass_for_valid_repair(self) -> None:
        temp, workspace, hashes = self.make_project(
            "def total_with_tax(amount: float, tax_rate: float) -> float:\n"
            "    return amount * (1 + tax_rate)\n"
        )
        with temp:
            results = verify_sandboxed_python_tests(
                workspace,
                test_pattern="test_calc.py",
                expected_test_hashes=hashes,
            )
        self.assertTrue(all(result.passed for result in results), results)

    def test_invalid_annotation_fails_when_module_imports_normally(self) -> None:
        temp, workspace, hashes = self.make_project(
            "def total_with_tax(amount: amount, tax_rate: float) -> float:\n"
            "    return amount * (1 + tax_rate)\n"
        )
        with temp:
            results = verify_sandboxed_python_tests(
                workspace,
                test_pattern="test_calc.py",
                expected_test_hashes=hashes,
            )
        test_result = next(result for result in results if result.dimension == "preserved_tests")
        self.assertFalse(test_result.passed)
        self.assertEqual("tests_failed", test_result.code)
        self.assertIn("NameError", test_result.detail)

    def test_modified_preserved_test_fails_before_execution(self) -> None:
        temp, workspace, hashes = self.make_project(
            "def total_with_tax(amount, tax_rate):\n    return 0\n"
        )
        with temp:
            test_path = workspace / "work/project/test_calc.py"
            test_path.write_text("# tests removed\n", encoding="utf-8")
            results = verify_sandboxed_python_tests(
                workspace,
                test_pattern="test_calc.py",
                expected_test_hashes=hashes,
            )
        integrity = next(result for result in results if result.dimension == "test_integrity")
        tests = next(result for result in results if result.dimension == "preserved_tests")
        self.assertFalse(integrity.passed)
        self.assertEqual("test_hash_mismatch", integrity.code)
        self.assertFalse(tests.passed)
        self.assertEqual("not_run", tests.code)


if __name__ == "__main__":
    unittest.main()
