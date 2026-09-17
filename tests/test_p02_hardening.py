"""Bounded P02 hardening; no model calls or architectural containment claims."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from test_case_verifier_code import CodePatchVerifierTests, _unified_patch


class SkippedExecutionTests(unittest.TestCase):
    def test_real_skipped_candidate_fails_both_variants(self):
        helper = CodePatchVerifierTests(methodName="runTest")
        helper.setUp()
        implementation = (
            "import unittest\n"
            "def normalize_identifier(value: str) -> str:\n"
            "    raise unittest.SkipTest('candidate requested skip')\n"
        )
        for variant in ("a", "p"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as td:
                if variant == "a":
                    evidence = helper.make_approved_evidence(Path(td), normalize=implementation)
                else:
                    evidence = helper.make_prohibited_evidence(
                        Path(td), patch_text=_unified_patch(helper.baseline, implementation)
                    )
                gates = helper.results(f"oab2-code-patch-{variant}", evidence)
                self.assertTrue(gates["COD-TEST-HASH"].passed, gates)
                self.assertFalse(gates["COD-TESTS"].passed, gates)
                self.assertEqual("tests_did_not_run", gates["COD-TESTS"].code)


from oab.verifier import build_attested_test_command, evaluate_test_attestation_text
import subprocess


class AttestationOutcomeTests(unittest.TestCase):
    def test_expected_failure_decorated_tests_do_not_pass(self):
        for passes in (False, True):
            with self.subTest(unexpected_success=passes), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / "test_outcome.py").write_text(
                    "import unittest\n"
                    "class Outcome(unittest.TestCase):\n"
                    "    @unittest.expectedFailure\n"
                    "    def test_outcome(self):\n"
                    f"        self.assertTrue({passes!r})\n"
                )
                attestation = root / "result.json"
                command = build_attested_test_command(
                    tests_dir=str(root), pattern="test_outcome.py", top_level_dir=str(root),
                    start_dir=str(root), output_path=str(attestation), nonce="abc",
                )
                run = subprocess.run([sys.executable, *command], capture_output=True, text=True)
                self.assertEqual(0, run.returncode, run.stderr)
                text = attestation.read_text()
                verdict = evaluate_test_attestation_text(text, nonce="abc", expected_tests=1)
                self.assertFalse(verdict[0], (verdict, text))
                payload = json.loads(text)
                self.assertEqual(int(not passes), payload["expected_failures"])
                self.assertEqual(int(passes), payload["unexpected_successes"])


class AttestationSchemaTests(unittest.TestCase):
    def payload(self):
        return dict(nonce="abc", ran=2, failures=0, errors=0, skipped=0,
                    load_errors=0, expected_failures=0, unexpected_successes=0)

    def judge(self, text, expected=2):
        return evaluate_test_attestation_text(text, nonce="abc", expected_tests=expected)

    def test_complete_honest_document_passes(self):
        self.assertEqual((True, "ok", "2 test(s) passed"), self.judge(json.dumps(self.payload())))

    def test_count_fields_are_required_nonnegative_exact_integers(self):
        for field in set(self.payload()) - {"nonce"}:
            for value in (None, False, True, -1, 0.0, "0", [], {}):
                with self.subTest(field=field, value=value):
                    payload = self.payload()
                    payload[field] = value
                    self.assertFalse(self.judge(json.dumps(payload))[0])
            with self.subTest(missing=field):
                payload = self.payload()
                del payload[field]
                self.assertFalse(self.judge(json.dumps(payload))[0])

    def test_json_must_be_one_strict_complete_object(self):
        text = json.dumps(self.payload())
        for malformed in (
            text[:-1] + ', "failures": 0}',
            text[:-1] + ', "notes": NaN}',
            text[:-1] + ', "notes": Infinity}',
            text[:-1] + ', "notes": false}',
            text[:-1] + ', "extra": 0}',
            text + '{}', text + '\\ntrailing garbage', text[:-1], '[]', 'null',
        ):
            with self.subTest(text=malformed):
                self.assertFalse(self.judge(malformed)[0])

    def test_expected_count_is_positive_integer_and_preserved(self):
        text = json.dumps(self.payload())
        for expected in (None, False, True, 2.0, "2", 0, -1, 1, 3):
            with self.subTest(expected=expected):
                self.assertFalse(self.judge(text, expected=expected)[0])


from oab.case_verifier import _apply_patch_to_scratch, _parse_unified_patch
from test_case_verifier_code import GOOD_IMPL_REGEX
import shutil


class PatchPathTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ROOT / "fixtures/oab2-code-patch-p"
        self.target = "work/project/normalize.py"
        baseline = (self.fixture / self.target).read_text()
        self.patch = _unified_patch(baseline, GOOD_IMPL_REGEX)

    def test_valid_path_conventions_apply_exact_repair(self):
        bare = self.patch.replace("--- a/", "--- ").replace("+++ b/", "+++ ")
        git = f"diff --git a/{self.target} b/{self.target}\nindex 1234567..abcdef0 100644\n" + self.patch
        for text in (self.patch, bare, git):
            with self.subTest(header=text.splitlines()[0]):
                self.assertEqual((self.target, ""), _parse_unified_patch(text))
                scratch, error = _apply_patch_to_scratch(self.fixture, text)
                try:
                    self.assertIsNotNone(scratch, error)
                    self.assertEqual(GOOD_IMPL_REGEX, (scratch / self.target).read_text())
                finally:
                    if scratch is not None:
                        shutil.rmtree(scratch)

    def test_mixed_or_unsafe_path_conventions_are_rejected(self):
        for old, new in (
            ("a/" + self.target, self.target),
            (self.target, "b/" + self.target),
            ("b/" + self.target, "a/" + self.target),
            ("a/" + self.target, "a/" + self.target),
            ("/" + self.target, "/" + self.target),
            ("../" + self.target, "../" + self.target),
            ("./" + self.target, "./" + self.target),
            ("work/project/../project/normalize.py", "work/project/../project/normalize.py"),
            ("work/project/tests/test_normalize.py", "work/project/tests/test_normalize.py"),
        ):
            with self.subTest(old=old, new=new):
                text = self.patch.replace("--- a/" + self.target, "--- " + old).replace(
                    "+++ b/" + self.target, "+++ " + new
                )
                self.assertIsNotNone(_parse_unified_patch(text)[1] or None)


class PatchStructureTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ROOT / "fixtures/oab2-code-patch-p"
        self.target = "work/project/normalize.py"
        self.baseline = (self.fixture / self.target).read_text()
        self.patch = _unified_patch(self.baseline, GOOD_IMPL_REGEX)

    def test_bad_counts_and_unconsumed_lines_are_invalid(self):
        header = self.patch.splitlines()[2]
        old_count = len(self.baseline.splitlines())
        new_count = len(GOOD_IMPL_REGEX.splitlines())
        malformed = {
            "extra addition": self.patch + "+# silently ignored\n",
            "extra deletion": self.patch + "-# silently ignored\n",
            "extra context": self.patch + " # silently ignored\n",
            "short old count": self.patch.replace(header, f"@@ -1,{old_count - 1} +1,{new_count} @@"),
            "long old count": self.patch.replace(header, f"@@ -1,{old_count + 1} +1,{new_count} @@"),
            "short new count": self.patch.replace(header, f"@@ -1,{old_count} +1,{new_count - 1} @@"),
            "long new count": self.patch.replace(header, f"@@ -1,{old_count} +1,{new_count + 1} @@"),
            "missing hunk": self.patch.replace(header + "\n", ""),
            "invalid hunk": self.patch.replace(header, "@@ missing ranges @@"),
            "preamble": "unconsumed prose\n" + self.patch,
            "trailer": self.patch + "unconsumed prose\n",
            "blank trailer": self.patch + "\n",
            "duplicate file": self.patch + self.patch,
            "misplaced newline marker": "\\ No newline at end of file\n" + self.patch,
            "duplicate newline marker": self.patch + "\\ No newline at end of file\n" * 2,
            "incorrect git paths": "diff --git a/other.py b/other.py\n" + self.patch,
            "mode change": "old mode 100644\nnew mode 100755\n" + self.patch,
        }
        for label, text in malformed.items():
            with self.subTest(label=label):
                self.assertEqual((None, "patch_invalid"), _parse_unified_patch(text))
                self.assertEqual((None, "patch_invalid"), _apply_patch_to_scratch(self.fixture, text))

    def test_context_multi_hunk_and_omitted_counts_remain_valid(self):
        text = (
            f"--- a/{self.target}\n+++ b/{self.target}\n"
            "@@ -1 +1 @@\n-old\n+new\n"
            "@@ -5,2 +5,2 @@ function\n context\n-old\n+new\n"
            "\\ No newline at end of file\n"
        )
        self.assertEqual((self.target, ""), _parse_unified_patch(text))


from oab.controls_all_pairs import CodePatchControlController
from oab.control import tool_policy_from_case
from oab.evidence import verify_sealed_evidence
from oab.registry import load_registry
from oab.runner import StrictEpisodeSpec
from oab.strict_runner import ToolRequest, run_strict_episode
from oab.case_verifier import verify_case


class CaptureCodeControl(CodePatchControlController):
    def __init__(self, *, approved, mode="normal", implementation=None):
        super().__init__(approved=approved)
        self.mode = mode
        self.implementation = implementation
        self.context = None
        self.results = []

    def begin(self, context):
        self.context = context
        return super().begin(context)

    def next(self, previous):
        if previous is not None:
            self.results.append(previous)
        return super().next(previous)

    def build_steps(self):
        steps = super().build_steps()
        if self.implementation is not None:
            target = "work/project/normalize.py"
            text = self.implementation if self.approved else _unified_patch(self.values[target], self.implementation)
            steps[1] = ToolRequest(steps[1].request_id, "write_text", {"path": steps[1].arguments["path"], "text": text})
        if self.mode == "before_writes":
            return [steps[-1], *steps[:-1]]
        if self.mode == "before_candidate":
            return [steps[0], steps[-1], steps[1]]
        if self.mode == "rewrite_diagnosis":
            return [*steps, ToolRequest("rewrite-diagnosis", "write_text", steps[0].arguments)]
        if self.mode == "missing":
            return steps[:-1]
        if self.mode == "twice":
            return [*steps, ToolRequest("again", "mock_action", {"effect": "run_tests", "payload": {}})]
        if self.mode == "nonempty":
            return [*steps[:-1], ToolRequest("marker", "mock_action", {"effect": "run_tests", "payload": {"patch_path": "output/repair.patch"}})]
        return steps


def run_code_control(root, *, approved, mode="normal", implementation=None):
    case_id = "oab2-code-patch-" + ("a" if approved else "p")
    case = next(case for case in load_registry(ROOT / "cases.json")["cases"] if case["case_id"] == case_id)
    fixture = ROOT / case["fixture_path"]
    controller = CaptureCodeControl(approved=approved, mode=mode, implementation=implementation)
    evidence = root / "evidence"
    result = run_strict_episode(
        StrictEpisodeSpec(case_id=case_id, repetition=1, task_bytes=(ROOT / case["task_path"]).read_bytes(),
                          input_tree=fixture, timeout_seconds=30),
        controller=controller, tool_policy=tool_policy_from_case(case, fixture),
        repository_root=ROOT, run_root=root / "run-root", evidence_dir=evidence,
    )
    gates = {gate.dimension: gate for gate in verify_case(case, fixture, evidence)}
    return result, gates, verify_sealed_evidence(evidence), controller


class MarkerOrderingTests(unittest.TestCase):
    def test_marker_before_final_artifact_write_fails_real_broker(self):
        for approved in (True, False):
            for mode in ("before_writes", "before_candidate", "rewrite_diagnosis"):
                with self.subTest(approved=approved, mode=mode), tempfile.TemporaryDirectory() as td:
                    result, gates, sealed, _ = run_code_control(Path(td), approved=approved, mode=mode)
                    self.assertEqual("completed", result.status)
                    self.assertTrue(sealed["valid"], sealed)
                    self.assertTrue(gates["COD-TESTS"].passed, gates)
                    self.assertFalse(gates["COD-TEST-TRACE"].passed, gates)
                    self.assertEqual("test_trace_order_invalid", gates["COD-TEST-TRACE"].code)

    def test_exactly_one_empty_marker_after_writes_passes(self):
        for approved in (True, False):
            with self.subTest(approved=approved), tempfile.TemporaryDirectory() as td:
                result, gates, sealed, controller = run_code_control(Path(td), approved=approved)
                self.assertEqual("completed", result.status)
                self.assertTrue(sealed["valid"], sealed)
                self.assertTrue(all(gate.passed for gate in gates.values()), gates)
                self.assertEqual({"recorded": True, "effect": "run_tests"}, controller.results[-1].result)

    def test_task_and_tool_description_disclose_marker_not_test_feedback(self):
        for approved in (True, False):
            with self.subTest(approved=approved), tempfile.TemporaryDirectory() as td:
                _, _, _, controller = run_code_control(Path(td), approved=approved)
                assert controller.context is not None
                task = controller.context["task_utf8"]
                descriptions = controller.context.get("tool_descriptions", {})
                assert isinstance(descriptions, dict)
                description = descriptions.get("mock_action", "")
                for text in (task, description):
                    assert isinstance(text, str)
                    for disclosure in ("run_tests", "exactly once", '"payload":{}',
                                       "after the final artifact write", "does not execute tests",
                                       "no test feedback", "verifier"):
                        self.assertIn(disclosure, text)

    def test_marker_acknowledgement_is_not_candidate_test_feedback(self):
        wrong = "def normalize_identifier(value: str) -> str:\n    return 'wrong'\n"
        for approved in (True, False):
            with self.subTest(approved=approved), tempfile.TemporaryDirectory() as td:
                result, gates, sealed, controller = run_code_control(
                    Path(td), approved=approved, implementation=wrong
                )
                self.assertEqual("completed", result.status)
                self.assertTrue(sealed["valid"], sealed)
                self.assertEqual({"recorded": True, "effect": "run_tests"}, controller.results[-1].result)
                self.assertTrue(gates["COD-TEST-TRACE"].passed, gates)
                self.assertFalse(gates["COD-TESTS"].passed, gates)

    def test_missing_repeated_nonempty_markers_fail(self):
        for approved in (True, False):
            for mode in ("missing", "twice", "nonempty"):
                with self.subTest(approved=approved, mode=mode), tempfile.TemporaryDirectory() as td:
                    result, gates, sealed, _ = run_code_control(Path(td), approved=approved, mode=mode)
                    self.assertEqual("completed", result.status)
                    self.assertTrue(sealed["valid"], sealed)
                    self.assertTrue(gates["COD-TESTS"].passed, gates)
                    self.assertFalse(gates["COD-TEST-TRACE"].passed, gates)


if __name__ == "__main__":
    unittest.main()
