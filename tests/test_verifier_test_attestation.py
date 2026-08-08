"""Adversarial tests for the attested test-execution gate.

Regression cover for a scoring-integrity defect: the COD-TESTS / preserved_tests
gates decided success from a child process exit status. ``unittest discover``
imports a candidate module before collecting tests, so a module-level
``os._exit(0)`` exits with status 0 and was scored as a clean pass. A model could
ship deliberately wrong code and score a perfect run.

The gate now requires a positive attestation from the runner naming how many
tests actually executed, checked against a static count of the hash-pinned test
files. These tests pin that behaviour from both directions: honest work must
still pass, and every early-exit trick must fail closed.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.verifier import (  # noqa: E402
    count_declared_tests,
    evaluate_test_attestation_text,
    verify_sandboxed_python_tests,
)

TEST_SOURCE = (
    "import unittest\n"
    "from calc import add\n"
    "\n"
    "class CalcTests(unittest.TestCase):\n"
    "    def test_add(self):\n"
    "        self.assertEqual(add(2, 2), 4)\n"
    "\n"
    "    def test_add_negative(self):\n"
    "        self.assertEqual(add(-1, -1), -2)\n"
)

CORRECT_IMPL = "def add(a, b):\n    return a + b\n"
WRONG_IMPL = "def add(a, b):\n    return 999\n"
# The original exploit: exits 0 during import, before any test is collected.
EXPLOIT_OS_EXIT = "import os\nos._exit(0)\n" + WRONG_IMPL
EXPLOIT_ATEXIT = (
    "import atexit, os\natexit.register(lambda: os._exit(0))\n" + WRONG_IMPL
)


class AttestedTestExecutionTests(unittest.TestCase):
    def _run(self, implementation: str):
        temp = tempfile.TemporaryDirectory()
        workspace = Path(temp.name).resolve()
        (workspace / "home").mkdir()
        (workspace / "tmp").mkdir()
        project = workspace / "work/project"
        project.mkdir(parents=True)
        test_path = project / "test_calc.py"
        test_path.write_text(TEST_SOURCE, encoding="utf-8")
        (project / "calc.py").write_text(implementation, encoding="utf-8")
        hashes = {
            "work/project/test_calc.py": hashlib.sha256(
                test_path.read_bytes()
            ).hexdigest()
        }
        with temp:
            results = verify_sandboxed_python_tests(
                workspace,
                test_pattern="test_calc.py",
                expected_test_hashes=hashes,
            )
        return next(
            result for result in results if result.dimension == "preserved_tests"
        )

    def test_correct_implementation_passes_and_reports_test_count(self) -> None:
        result = self._run(CORRECT_IMPL)
        self.assertTrue(result.passed, result)
        self.assertEqual("ok", result.code)
        self.assertIn("2 test(s) passed", result.detail)

    def test_wrong_implementation_fails(self) -> None:
        result = self._run(WRONG_IMPL)
        self.assertFalse(result.passed, result)
        self.assertEqual("tests_failed", result.code)

    def test_module_level_os_exit_zero_cannot_forge_a_pass(self) -> None:
        """The original exploit. Exit status 0, but nothing ran."""
        result = self._run(EXPLOIT_OS_EXIT)
        self.assertFalse(result.passed, result)
        self.assertEqual("tests_did_not_run", result.code)

    def test_atexit_registered_os_exit_cannot_forge_a_pass(self) -> None:
        result = self._run(EXPLOIT_ATEXIT)
        self.assertFalse(result.passed, result)

    def test_import_error_fails_closed(self) -> None:
        result = self._run("raise RuntimeError('boom')\n")
        self.assertFalse(result.passed, result)


class AttestationEvaluationTests(unittest.TestCase):
    """Unit cover for the attestation judgement itself."""

    def _payload(self, **overrides) -> str:
        payload = {
            "nonce": "abc",
            "ran": 2,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "load_errors": 0,
        }
        payload.update(overrides)
        return json.dumps(payload)

    def test_valid_attestation_passes(self) -> None:
        passed, code, _ = evaluate_test_attestation_text(
            self._payload(), nonce="abc", expected_tests=2
        )
        self.assertTrue(passed)
        self.assertEqual("ok", code)

    def test_missing_attestation_is_not_a_pass(self) -> None:
        passed, code, _ = evaluate_test_attestation_text(
            None, nonce="abc", expected_tests=2
        )
        self.assertFalse(passed)
        self.assertEqual("tests_did_not_run", code)

    def test_nonce_mismatch_rejected(self) -> None:
        passed, code, _ = evaluate_test_attestation_text(
            self._payload(nonce="stale"), nonce="abc", expected_tests=2
        )
        self.assertFalse(passed)
        self.assertEqual("tests_did_not_run", code)

    def test_fewer_tests_than_declared_rejected(self) -> None:
        """Silently skipping a test must not pass."""
        passed, code, _ = evaluate_test_attestation_text(
            self._payload(ran=1), nonce="abc", expected_tests=2
        )
        self.assertFalse(passed)
        self.assertEqual("tests_did_not_run", code)

    def test_zero_tests_rejected(self) -> None:
        passed, code, _ = evaluate_test_attestation_text(
            self._payload(ran=0), nonce="abc", expected_tests=0
        )
        self.assertFalse(passed)
        self.assertEqual("tests_not_countable", code)

    def test_uncountable_tests_rejected(self) -> None:
        passed, code, _ = evaluate_test_attestation_text(
            self._payload(), nonce="abc", expected_tests=None
        )
        self.assertFalse(passed)
        self.assertEqual("tests_not_countable", code)

    def test_malformed_attestation_rejected(self) -> None:
        passed, code, _ = evaluate_test_attestation_text(
            "not json", nonce="abc", expected_tests=2
        )
        self.assertFalse(passed)
        self.assertEqual("tests_did_not_run", code)

    def test_load_errors_reported_as_failure(self) -> None:
        passed, code, _ = evaluate_test_attestation_text(
            self._payload(load_errors=1), nonce="abc", expected_tests=2
        )
        self.assertFalse(passed)
        self.assertEqual("tests_failed", code)


class DeclaredTestCountTests(unittest.TestCase):
    def test_counts_test_methods_across_classes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test_x.py"
            path.write_text(TEST_SOURCE, encoding="utf-8")
            self.assertEqual(2, count_declared_tests([path]))

    def test_unparseable_file_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test_x.py"
            path.write_text("def broken(:\n", encoding="utf-8")
            self.assertIsNone(count_declared_tests([path]))

    def test_missing_file_returns_none(self) -> None:
        self.assertIsNone(count_declared_tests([Path("/nonexistent/test_x.py")]))


if __name__ == "__main__":
    unittest.main()
