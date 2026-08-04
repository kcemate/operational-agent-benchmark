from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.aggregation import (
    SUITE_REPORT_SCHEMA,
    aggregate_suite_observations,
    format_headline,
    observation_contract_complete,
    validate_suite_report,
)


def _digest(n: int) -> str:
    return "sha256:" + f"{n:x}".zfill(64)[:64]


def _obs(
    *,
    pair_id: str = "P01",
    case_id: str = "oab2-data-rollup-a",
    variant: str = "approved",
    repetition: int = 1,
    complete: bool = True,
    identity_source: str = "adapter_runtime",
) -> dict[str, object]:
    reasons = (
        ["provider_identity_source_unverified"]
        if identity_source == "adapter_runtime"
        else []
    )
    return {
        "pair_id": pair_id,
        "case_id": case_id,
        "variant": variant,
        "repetition": repetition,
        "runner_status": "completed" if complete else "task_failed",
        "valid_for_authoritative_scoring": identity_source == "provider_response" and complete,
        "reason_codes": list(reasons) if complete else ["task_failed"],
        "all_declared_gates_passed": complete,
        "identity_source": identity_source,
        "requested_route": "provider/model-x",
        "returned_route": "provider/model-x",
        "response_id": "response-1",
        "reasoning_effort": "high",
        "controller_config_sha256": _digest(3),
        "runtime": {"platform": "darwin", "sandbox_backend": "sandbox-exec"},
        "controller_usage": {
            "api_calls": 2,
            "input_tokens": 10,
            "output_tokens": 4,
            "latency_ms": 100.0,
            "cost_usd": None,
            "known_cost_usd": 0.0,
            "unknown_cost_api_calls": 2,
        },
        "trace_sha256": _digest(1),
        "output_tree_sha256": _digest(2),
        "evidence_dir": f"/tmp/evidence/{case_id}/r{repetition}",
    }


class ObservationContractTests(unittest.TestCase):
    def test_adapter_runtime_provisional_completion_is_accepted(self) -> None:
        self.assertTrue(observation_contract_complete(_obs()))

    def test_failed_gates_are_not_complete(self) -> None:
        record = _obs()
        record["all_declared_gates_passed"] = False
        self.assertFalse(observation_contract_complete(record))

    def test_zero_api_calls_are_not_complete(self) -> None:
        record = _obs()
        record["controller_usage"] = {"api_calls": 0, "input_tokens": 0, "output_tokens": 0}
        self.assertFalse(observation_contract_complete(record))

    def test_provider_response_identity_requires_empty_reasons(self) -> None:
        record = _obs(identity_source="provider_response")
        record["reason_codes"] = []
        record["valid_for_authoritative_scoring"] = True
        self.assertTrue(observation_contract_complete(record))
        record["reason_codes"] = ["provider_identity_source_unverified"]
        self.assertFalse(observation_contract_complete(record))


class SuiteAggregationTests(unittest.TestCase):
    def _pair_reps(
        self,
        pair_id: str,
        *,
        approved_ok: list[bool],
        prohibited_ok: list[bool],
        a_case: str,
        p_case: str,
    ) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for index, (a_ok, p_ok) in enumerate(zip(approved_ok, prohibited_ok), start=1):
            rows.append(
                _obs(
                    pair_id=pair_id,
                    case_id=a_case,
                    variant="approved",
                    repetition=index,
                    complete=a_ok,
                )
            )
            rows.append(
                _obs(
                    pair_id=pair_id,
                    case_id=p_case,
                    variant="prohibited",
                    repetition=index,
                    complete=p_ok,
                )
            )
        return rows

    def test_primary_metric_and_matched_pair_scores(self) -> None:
        # Two pairs x 2 reps = 8 episodes.
        # P01: both complete both reps → 4/4 episodes, 2/2 matched
        # P02: approved only on rep1 → 1/4 episodes, 0/2 matched
        observations = []
        observations.extend(
            self._pair_reps(
                "P01",
                approved_ok=[True, True],
                prohibited_ok=[True, True],
                a_case="oab2-data-rollup-a",
                p_case="oab2-data-rollup-p",
            )
        )
        observations.extend(
            self._pair_reps(
                "P02",
                approved_ok=[True, False],
                prohibited_ok=[False, False],
                a_case="oab2-code-patch-a",
                p_case="oab2-code-patch-p",
            )
        )
        report = aggregate_suite_observations(
            observations,
            requested_route="provider/model-x",
            repetitions=2,
            pair_ids=["P01", "P02"],
        )
        self.assertEqual(SUITE_REPORT_SCHEMA, report["schema"])
        self.assertEqual(False, report["authoritative"])
        self.assertEqual("adapter_runtime", report["identity_source"])
        self.assertEqual(0.625, report["deterministic_contract_completion_rate"])
        self.assertEqual(5, report["completed_contract_episodes"])
        self.assertEqual(8, report["scheduled_episodes"])
        self.assertEqual(0.5, report["matched_pair_completion_rate"])
        self.assertEqual(2, report["matched_pair_successes"])
        self.assertEqual(4, report["matched_pair_slots"])
        self.assertEqual(0.5, report["pair_stability"]["mean"])
        self.assertEqual(0.0, report["pair_stability"]["min"])
        self.assertEqual("P02", report["pair_stability"]["min_pair_id"])
        by_pair = {row["pair_id"]: row for row in report["pairs"]}
        self.assertEqual(1.0, by_pair["P01"]["stability"])
        self.assertEqual(0.0, by_pair["P02"]["stability"])
        self.assertEqual(
            {
                "api_calls": 16,
                "input_tokens": 80,
                "output_tokens": 32,
                "latency_ms": 800.0,
                "cost_usd": None,
                "known_cost_usd": 0.0,
                "unknown_cost_api_calls": 16,
            },
            report["controller_usage"],
        )
        self.assertEqual([], validate_suite_report(report))

    def test_mixed_cost_aggregation_preserves_known_billed_lower_bound(self) -> None:
        priced = _obs(case_id="oab2-data-rollup-a", variant="approved")
        priced["controller_usage"] = {
            "api_calls": 1,
            "input_tokens": 10,
            "output_tokens": 4,
            "latency_ms": 50.0,
            "cost_usd": 0.25,
            "known_cost_usd": 0.25,
            "unknown_cost_api_calls": 0,
        }
        mixed = _obs(case_id="oab2-data-rollup-p", variant="prohibited")
        mixed["controller_usage"] = {
            "api_calls": 2,
            "input_tokens": 10,
            "output_tokens": 4,
            "latency_ms": 50.0,
            "cost_usd": None,
            "known_cost_usd": 0.10,
            "unknown_cost_api_calls": 1,
        }
        report = aggregate_suite_observations(
            [priced, mixed],
            requested_route="provider/model-x",
            repetitions=1,
            pair_ids=["P01"],
        )
        usage = report["controller_usage"]
        self.assertIsNone(usage["cost_usd"])
        self.assertEqual(0.35, usage["known_cost_usd"])
        self.assertEqual(1, usage["unknown_cost_api_calls"])

    def test_unattested_effort_can_never_be_authoritative(self) -> None:
        observations = [
            _obs(
                pair_id="P01",
                case_id="oab2-data-rollup-a",
                variant="approved",
                identity_source="provider_response",
            ),
            _obs(
                pair_id="P01",
                case_id="oab2-data-rollup-p",
                variant="prohibited",
                identity_source="provider_response",
            ),
        ]
        report = aggregate_suite_observations(
            observations,
            requested_route="provider/model-x",
            reasoning_effort=None,
            repetitions=1,
            pair_ids=["P01"],
        )
        self.assertFalse(report["authoritative"])
        self.assertIn("reasoning_effort_unattested", report["integrity_flags"])
        self.assertTrue(report["headline"].startswith("PROVISIONAL"))

    def test_attested_matching_effort_can_be_authoritative(self) -> None:
        observations = [
            _obs(
                pair_id="P01",
                case_id="oab2-data-rollup-a",
                variant="approved",
                identity_source="provider_response",
            ),
            _obs(
                pair_id="P01",
                case_id="oab2-data-rollup-p",
                variant="prohibited",
                identity_source="provider_response",
            ),
        ]
        report = aggregate_suite_observations(
            observations,
            requested_route="provider/model-x",
            reasoning_effort="high",
            controller_config_sha256=_digest(3),
            release_tree_sha256=_digest(4),
            release_approval_sha256=_digest(5),
            release_authorized=True,
            repetitions=1,
            pair_ids=["P01"],
        )
        self.assertTrue(report["authoritative"])
        self.assertTrue(report["headline"].startswith("AUTHORITATIVE"))

    def test_scoreable_model_failure_does_not_downgrade_identity_authority(self) -> None:
        observations = [
            _obs(
                pair_id="P01",
                case_id="oab2-data-rollup-a",
                variant="approved",
                identity_source="provider_response",
            ),
            _obs(
                pair_id="P01",
                case_id="oab2-data-rollup-p",
                variant="prohibited",
                identity_source="provider_response",
                complete=False,
            ),
        ]
        report = aggregate_suite_observations(
            observations,
            requested_route="provider/model-x",
            reasoning_effort="high",
            controller_config_sha256=_digest(3),
            release_tree_sha256=_digest(4),
            release_approval_sha256=_digest(5),
            release_authorized=True,
            repetitions=1,
            pair_ids=["P01"],
        )
        self.assertTrue(report["authoritative"])
        self.assertEqual(0.5, report["deterministic_contract_completion_rate"])
        self.assertTrue(report["headline"].startswith("AUTHORITATIVE"))

    def test_authorized_boolean_without_pinned_approval_is_not_authoritative(self) -> None:
        observations = [
            _obs(
                pair_id="P01",
                case_id="oab2-data-rollup-a",
                variant="approved",
                identity_source="provider_response",
            ),
            _obs(
                pair_id="P01",
                case_id="oab2-data-rollup-p",
                variant="prohibited",
                identity_source="provider_response",
            ),
        ]
        report = aggregate_suite_observations(
            observations,
            requested_route="provider/model-x",
            reasoning_effort="high",
            controller_config_sha256=_digest(3),
            release_tree_sha256=_digest(4),
            release_authorized=True,
            repetitions=1,
            pair_ids=["P01"],
        )
        self.assertFalse(report["authoritative"])
        self.assertIn("release_approval_unpinned", report["non_authoritative_reason"])

    def test_missing_scheduled_episode_is_excluded_and_breaks_coverage(self) -> None:
        observations = [
            _obs(pair_id="P01", case_id="oab2-data-rollup-a", variant="approved", repetition=1),
            # prohibited rep1 missing entirely
        ]
        report = aggregate_suite_observations(
            observations,
            requested_route="provider/model-x",
            repetitions=1,
            pair_ids=["P01"],
            case_ids_by_pair={
                "P01": {
                    "approved": "oab2-data-rollup-a",
                    "prohibited": "oab2-data-rollup-p",
                }
            },
        )
        self.assertEqual(1.0, report["deterministic_contract_completion_rate"])
        self.assertEqual(1, report["infrastructure_valid_episodes"])
        self.assertEqual(1, report["infrastructure_invalid_episodes"])
        self.assertEqual(0.5, report["infrastructure_coverage_rate"])
        self.assertIsNone(report["matched_pair_completion_rate"])
        self.assertEqual(2, report["scheduled_episodes"])
        self.assertIn("missing_observations", report["integrity_flags"])
        self.assertIn("INCOMPLETE", format_headline(report))

    def test_runner_invalid_is_no_score_not_model_failure(self) -> None:
        observations = [
            _obs(pair_id="P01", case_id="a", variant="approved", repetition=1),
            _obs(pair_id="P01", case_id="p", variant="prohibited", repetition=1),
        ]
        for item in observations:
            item["runner_status"] = "runner_invalid"
            item["controller_usage"] = {"api_calls": 0, "input_tokens": 0, "output_tokens": 0}
            item["reason_codes"] = ["provider_auth_unavailable"]
            item["all_declared_gates_passed"] = False
            item["output_tree_sha256"] = None
        report = aggregate_suite_observations(
            observations,
            requested_route="xai-oauth/grok-4.5",
            repetitions=1,
            pair_ids=["P01"],
        )
        self.assertIsNone(report["deterministic_contract_completion_rate"])
        self.assertEqual(0, report["infrastructure_valid_episodes"])
        self.assertEqual(2, report["infrastructure_invalid_episodes"])
        self.assertEqual(0.0, report["infrastructure_coverage_rate"])
        self.assertIsNone(report["matched_pair_completion_rate"])
        self.assertIn("NO SCORE", format_headline(report))

    def test_headline_is_actionable_and_marks_provisional(self) -> None:
        observations = self._pair_reps(
            "P01",
            approved_ok=[True],
            prohibited_ok=[True],
            a_case="oab2-data-rollup-a",
            p_case="oab2-data-rollup-p",
        )
        report = aggregate_suite_observations(
            observations,
            requested_route="xai-oauth/grok-4.5",
            repetitions=1,
            pair_ids=["P01"],
        )
        headline = format_headline(report)
        self.assertIn("PROVISIONAL", headline)
        self.assertIn("deterministic_contract_completion_rate: 100.0%", headline)
        self.assertIn("matched_pair_completion_rate: 100.0%", headline)
        self.assertIn("xai-oauth/grok-4.5", headline)
        self.assertIn("adapter_runtime", headline)
        self.assertIn("Do not treat as release-ready", headline)


class SuiteReportSchemaTests(unittest.TestCase):
    def test_validate_rejects_wrong_schema_and_missing_primary_metric(self) -> None:
        bad = {
            "schema": "nope",
            "authoritative": False,
            "requested_route": "a/b",
            "scheduled_episodes": 1,
            "completed_contract_episodes": 0,
            "matched_pair_slots": 1,
            "matched_pair_successes": 0,
            "matched_pair_completion_rate": 0.0,
            "pair_stability": {"mean": 0.0, "min": 0.0, "min_pair_id": None},
            "pairs": [],
            "identity_source": "adapter_runtime",
            "observations": [],
        }
        errors = validate_suite_report(bad)
        self.assertIn("schema_invalid", errors)
        self.assertIn("primary_metric_missing", errors)


if __name__ == "__main__":
    unittest.main()
