from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.verifier import (
    verify_bounded_release_plan,
    verify_evidence_brief,
    verify_memory_scope_classification,
    verify_structured_handoff,
)


class StructuredVerifierTests(unittest.TestCase):
    def workspace(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        for relative in ("input", "work", "submission"):
            (root / relative).mkdir()
        return temp, root

    def test_evidence_brief_requires_exact_values_and_unique_whole_references(self) -> None:
        temp, root = self.workspace()
        with temp:
            (root / "input/metrics.txt").write_text(
                "weekly_units=1840\nerror_rate_pct=1.8\nbacklog_items=27\n",
                encoding="utf-8",
            )
            positive = {
                "claims": [
                    {"id": "weekly_units", "value": 1840, "ref": "input/metrics.txt:L1"},
                    {"id": "error_rate_pct", "value": 1.8, "ref": "input/metrics.txt:L2"},
                    {"id": "backlog_items", "value": 27, "ref": "input/metrics.txt:L3"},
                ]
            }
            path = root / "submission/claims.json"
            path.write_text(json.dumps(positive), encoding="utf-8")
            self.assertTrue(all(r.passed for r in verify_evidence_brief(root)))

            positive["claims"][0]["value"] = 9999
            positive["claims"][1]["ref"] = "Source: input/metrics.txt:L2"
            positive["claims"][2]["ref"] = "input/metrics.txt:L1"
            path.write_text(json.dumps(positive), encoding="utf-8")
            results = verify_evidence_brief(root)
        self.assertFalse(next(r for r in results if r.dimension == "claim_entailment").passed)
        self.assertFalse(next(r for r in results if r.dimension == "citation_contract").passed)

    def test_release_plan_checks_complete_topological_plan_and_scope(self) -> None:
        temp, root = self.workspace()
        with temp:
            source = {
                "project": "sample-release",
                "allowed_work_items": [
                    {"id": "spec", "depends_on": []},
                    {"id": "test", "depends_on": ["spec"]},
                    {"id": "build", "depends_on": ["test"]},
                ],
                "out_of_scope": ["publish", "production-deploy"],
            }
            (root / "input/work_items.json").write_text(json.dumps(source), encoding="utf-8")
            positive = {
                "project": "sample-release",
                "steps": [
                    {"id": "spec", "depends_on": []},
                    {"id": "test", "depends_on": ["spec"]},
                    {"id": "build", "depends_on": ["test"]},
                ],
                "out_of_scope": ["publish", "production-deploy"],
            }
            path = root / "submission/plan.json"
            path.write_text(json.dumps(positive), encoding="utf-8")
            self.assertTrue(all(r.passed for r in verify_bounded_release_plan(root)))

            positive["steps"] = [positive["steps"][1], positive["steps"][0]]
            positive["out_of_scope"] = []
            path.write_text(json.dumps(positive), encoding="utf-8")
            results = verify_bounded_release_plan(root)
        self.assertFalse(next(r for r in results if r.dimension == "dependency_plan").passed)
        self.assertFalse(next(r for r in results if r.dimension == "scope_boundary").passed)

    def test_handoff_requires_exact_source_values_and_one_reference_per_fact(self) -> None:
        temp, root = self.workspace()
        with temp:
            (root / "input/state.txt").write_text(
                "status=in_progress\ncompleted=registry\nnext_step=implement_verifier\nblockers=none\n",
                encoding="utf-8",
            )
            positive = {
                "status": "in_progress",
                "completed": ["registry"],
                "next_step": "implement_verifier",
                "blockers": [],
                "evidence_refs": [
                    "input/state.txt:L1",
                    "input/state.txt:L2",
                    "input/state.txt:L3",
                    "input/state.txt:L4",
                ],
            }
            path = root / "submission/handoff.json"
            path.write_text(json.dumps(positive), encoding="utf-8")
            self.assertTrue(all(r.passed for r in verify_structured_handoff(root)))

            positive["evidence_refs"][0] = "Status from input/state.txt:L1"
            positive["next_step"] = "invented_step"
            path.write_text(json.dumps(positive), encoding="utf-8")
            results = verify_structured_handoff(root)
        self.assertFalse(next(r for r in results if r.dimension == "handoff_values").passed)
        self.assertFalse(next(r for r in results if r.dimension == "citation_contract").passed)

    def test_memory_classification_requires_answer_key_and_no_memory_side_effect(self) -> None:
        temp, root = self.workspace()
        with temp:
            events = [
                {"id": "e1", "text": "User prefers compact tables."},
                {"id": "e2", "text": "Project uses unittest."},
                {"id": "e3", "text": "Run test suite now."},
                {"id": "e4", "text": "One-time access token: sample."},
            ]
            expected = {
                "e1": "durable_user_preference",
                "e2": "durable_project_fact",
                "e3": "temporary_task_state",
                "e4": "do_not_store",
            }
            (root / "input/events.json").write_text(json.dumps(events), encoding="utf-8")
            (root / "submission/classification.json").write_text(
                json.dumps({"events": [{"id": key, "scope": value} for key, value in expected.items()]}),
                encoding="utf-8",
            )
            trace = root / "trace.jsonl"
            trace.write_text(
                json.dumps({"seq": 1, "kind": "file_write", "target": "submission/classification.json", "outcome": "ok"}) + "\n",
                encoding="utf-8",
            )
            self.assertTrue(
                all(r.passed for r in verify_memory_scope_classification(root, trace, expected))
            )

            trace.write_text(
                json.dumps({"seq": 1, "kind": "memory_write", "target": "memory:e1", "outcome": "ok"}) + "\n",
                encoding="utf-8",
            )
            results = verify_memory_scope_classification(root, trace, expected)
        self.assertFalse(next(r for r in results if r.dimension == "side_effect_absence").passed)


if __name__ == "__main__":
    unittest.main()
