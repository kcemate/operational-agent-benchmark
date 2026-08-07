from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.explain import explain_episode, format_explanation


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")


class ExplainEpisodeTests(unittest.TestCase):
    def _evidence(
        self,
        root: Path,
        *,
        case_id: str = "oab2-data-rollup-a",
        status: str = "completed",
        summary: object | None = None,
        reason_codes: list[str] | None = None,
    ) -> Path:
        evidence = root / "evidence" / "rep-01" / case_id
        _write(
            evidence / "result.json",
            {
                "schema": "oab.episode-result/v1",
                "case_id": case_id,
                "repetition": 1,
                "status": status,
                "valid_for_scoring": False,
                "reason_codes": reason_codes or ["provider_identity_source_unverified"],
                "protocol_normalized_turns": 2,
                "controller_identity": {
                    "requested_route": "custom/model",
                    "returned_route": "custom/model",
                    "identity_source": "adapter_runtime",
                    "reasoning_effort": "high",
                },
                "controller_usage": {"api_calls": 4},
            },
        )
        if summary is not None:
            _write(evidence / "payload" / "output" / "summary.json", summary)
        return evidence

    def test_explains_right_numbers_wrong_shape(self) -> None:
        """The motivating case: correct values under the wrong keys."""
        with tempfile.TemporaryDirectory() as td:
            evidence = self._evidence(
                Path(td),
                summary={
                    "regions": [{"region": "north", "units": 4, "total": 40.00}],
                    "total": {"total_units": 10, "total_cost": 95.00},
                },
            )
            explanation = explain_episode(evidence)

            self.assertEqual("oab2-data-rollup-a", explanation["case_id"])
            self.assertEqual("P01", explanation["pair_id"])
            self.assertEqual("approved", explanation["variant"])
            self.assertEqual(2, explanation["protocol_normalized_turns"])

            expectation = explanation["schema_expectation"]
            self.assertEqual(
                ["regions", "total_cost", "total_units"],
                expectation["expected_exact_keys"],
            )
            self.assertEqual(["regions", "total"], expectation["actual_top_level_keys"])
            self.assertEqual(["total_cost", "total_units"], expectation["missing_keys"])
            self.assertEqual(["total"], expectation["unexpected_keys"])

            # The task text must be present so a reader can judge the failure.
            self.assertIn("Regional data rollup", explanation["task"])

    def test_artifacts_are_listed_with_inline_content(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = self._evidence(Path(td), summary={"regions": []})
            explanation = explain_episode(evidence)
            paths = [artifact["path"] for artifact in explanation["artifacts"]]
            self.assertIn("summary.json", paths)
            self.assertIn("regions", explanation["artifacts"][0]["content"])

    def test_missing_evidence_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ValueError, "evidence_directory_missing"):
                explain_episode(Path(td) / "nope")

    def test_episode_without_artifacts_still_explains(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = self._evidence(
                Path(td),
                status="task_failed",
                reason_codes=["controller_protocol_invalid"],
            )
            explanation = explain_episode(evidence)
            self.assertEqual("task_failed", explanation["runner_status"])
            self.assertEqual([], explanation["artifacts"])
            rendered = format_explanation(explanation)
            self.assertIn("(none)", rendered)

    def test_explanation_is_read_only(self) -> None:
        """Post-mortems must never mutate a sealed evidence tree."""
        with tempfile.TemporaryDirectory() as td:
            evidence = self._evidence(Path(td), summary={"regions": []})
            before = sorted(
                (path.relative_to(evidence).as_posix(), path.stat().st_mtime_ns)
                for path in evidence.rglob("*")
                if path.is_file()
            )
            explain_episode(evidence)
            after = sorted(
                (path.relative_to(evidence).as_posix(), path.stat().st_mtime_ns)
                for path in evidence.rglob("*")
                if path.is_file()
            )
            self.assertEqual(before, after)

    def test_rendered_output_names_failing_gates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = self._evidence(Path(td), summary={"regions": []})
            rendered = format_explanation(explain_episode(evidence))
            self.assertIn("--- GATES ---", rendered)
            self.assertIn("DAT-SCHEMA", rendered)
            self.assertIn("--- SCHEMA EXPECTATION ---", rendered)


if __name__ == "__main__":
    unittest.main()
