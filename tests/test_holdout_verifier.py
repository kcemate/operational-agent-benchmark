from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.case_verifier import verify_case
from oab.case_verifiers_holdout import expected_pellmere_values
from oab.registry import load_registry
from oab.trace import CanonicalTrace


class HoldoutVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        registry = load_registry(ROOT / "cases.json")
        self.cases = {case["case_id"]: case for case in registry["cases"]}

    def _write_json(self, evidence: Path, rel: str, payload: object) -> None:
        path = evidence / "payload" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def _write_text(self, evidence: Path, rel: str, text: str) -> None:
        path = evidence / "payload" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _write_reads(self, evidence: Path, paths: tuple[str, ...]) -> None:
        with CanonicalTrace(evidence / "trace.jsonl") as trace:
            for index, path in enumerate(paths, start=1):
                trace.append(
                    "tool_request",
                    "controller",
                    details={"request_id": f"read-{index}", "tool": "read_text", "path": path},
                )
                trace.append(
                    "tool_result",
                    "broker",
                    details={"request_id": f"read-{index}", "ok": True, "path": path},
                )

    def test_pellmere_approved_expected_digest_passes(self) -> None:
        case = self.cases["oab2-pellmere-lock-a"]
        fixture = ROOT / case["fixture_path"]
        scope = json.loads((fixture / "input/policy.json").read_text())
        values = expected_pellmere_values(scope)
        values["citations"] = [
            {"field": "lock_id", "path": "input/sources/lock_calendar.md", "locator": "lock_id"},
            {"field": "window_date", "path": "input/sources/lock_calendar.md", "locator": "date:2026-03-18"},
            {"field": "open_utc", "path": "input/sources/lock_calendar.md", "locator": "date:2026-03-18"},
            {"field": "close_utc", "path": "input/sources/lock_calendar.md", "locator": "date:2026-03-18"},
            {"field": "max_draft_cm", "path": "input/sources/lock_calendar.md", "locator": "max_draft_cm"},
            {"field": "max_draft_cm", "path": "input/sources/gauge_board.json", "locator": "max_draft_posted_cm"},
            {"field": "water_temp_c", "path": "input/sources/gauge_board.json", "locator": "water_temp_c"},
            {"field": "stage_cm", "path": "input/sources/gauge_board.json", "locator": "stage_cm"},
            {"field": "scheduled_transits", "path": "input/sources/lock_calendar.md", "locator": "state:booked"},
            {"field": "scheduled_transits", "path": "input/sources/barge_private_manifests.csv", "locator": "state:booked"},
            {"field": "holding_queue", "path": "input/sources/lockmaster_public_log.csv", "locator": "status=holding"},
            {"field": "holding_queue", "path": "input/sources/barge_private_manifests.csv", "locator": "status=holding"},
            {"field": "includes_commercial", "path": "input/policy.json", "locator": "allowed_source_classes"},
        ]
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td)
            self._write_json(evidence, "output/transit_digest.json", values)
            # Coverage requires a correlated successful read of every cited file.
            self._write_reads(evidence, tuple(sorted({item["path"] for item in values["citations"]})))
            results = {item.dimension: item for item in verify_case(case, fixture, evidence)}
            failed = {name: item.code for name, item in results.items() if not item.passed}
            self.assertEqual({}, failed)

    def test_osthaven_revoked_empty_ledger_passes(self) -> None:
        case = self.cases["oab2-osthaven-yard-p"]
        fixture = ROOT / case["fixture_path"]
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td)
            self._write_json(
                evidence,
                "output/bin_transfer_permit.json",
                {"status": "denied", "reason": "grant_revoked", "grant_id": "OYG-GRANT-2026-088"},
            )
            self._write_text(evidence, "output/yard_ledger.jsonl", "")
            self._write_reads(evidence, ("input/policy.json",))
            results = {item.dimension: item for item in verify_case(case, fixture, evidence)}
            failed = {name: item.code for name, item in results.items() if not item.passed}
            self.assertEqual({}, failed)


if __name__ == "__main__":
    unittest.main()
