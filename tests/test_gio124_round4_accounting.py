from __future__ import annotations

import unittest

from oab.agent_workflow import classify_qualification
from oab.qualification_contract import (
    aggregate_telemetry,
    build_physical_attempt,
    build_qualification_report,
    qualification_contract_for_route_count,
    qualification_probe_definitions,
    telemetry_errors,
)
from qualification_fixtures import qualification_identity, qualification_runtime, qualification_usage


class QualificationAccountingRoundFourTests(unittest.TestCase):
    route = "offline/accounting"
    effort = "high"

    def _attempt(self, probe: dict[str, object], telemetry: dict[str, object]) -> dict[str, object]:
        return build_physical_attempt(
            probe=probe,
            attempt_number=1,
            runner_status="completed",
            reason_codes=[],
            identity=qualification_identity(self.route, effort=self.effort),
            telemetry=telemetry,
            runtime=qualification_runtime(),
            trace_sha256="sha256:" + "1" * 64,
            output_tree_sha256="sha256:" + "2" * 64,
            probe_contract_satisfied=True,
            requested_route=self.route,
            reasoning_effort=self.effort,
        )

    def _report(self, usages: list[dict[str, object]]) -> dict[str, object]:
        probes = qualification_probe_definitions()
        return build_qualification_report(
            qualification_contract=qualification_contract_for_route_count(1),
            requested_route=self.route,
            reasoning_effort=self.effort,
            release_tree_sha256="sha256:" + "3" * 64,
            controller_config_sha256="sha256:" + "4" * 64,
            created_at="2026-08-11T00:00:00+00:00",
            attempts=[self._attempt(probe, usage) for probe, usage in zip(probes, usages)],
        )

    def test_cost_tuple_requires_declared_known_or_positive_unknown_state(self) -> None:
        valid = (
            qualification_usage(api_calls=0, cost_usd=0.0, known_cost_usd=0.0, unknown_cost_api_calls=0),
            qualification_usage(api_calls=3, cost_usd=0.125, known_cost_usd=0.125, unknown_cost_api_calls=0),
            qualification_usage(api_calls=3, cost_usd=None, known_cost_usd=0.025, unknown_cost_api_calls=1),
        )
        invalid = (
            qualification_usage(api_calls=4, cost_usd=None, known_cost_usd=0.0, unknown_cost_api_calls=0),
            qualification_usage(api_calls=4, cost_usd=0.1, known_cost_usd=0.1, unknown_cost_api_calls=1),
            qualification_usage(api_calls=4, cost_usd=0.1, known_cost_usd=0.09, unknown_cost_api_calls=0),
            qualification_usage(api_calls=1, cost_usd=None, known_cost_usd=0.0, unknown_cost_api_calls=2),
            qualification_usage(api_calls=0, cost_usd=0.1, known_cost_usd=0.1, unknown_cost_api_calls=0),
        )
        for usage in valid:
            with self.subTest(valid=usage):
                self.assertEqual([], telemetry_errors(usage, per_attempt=True))
        for usage in invalid:
            with self.subTest(invalid=usage):
                self.assertEqual(["controller_usage_invalid"], telemetry_errors(usage, per_attempt=True))

    def test_aggregate_never_hides_invalid_null_zero_unknown_or_cross_attempt_cost(self) -> None:
        malformed = qualification_usage(
            api_calls=4, cost_usd=None, known_cost_usd=0.0, unknown_cost_api_calls=0
        )
        priced = qualification_usage(
            api_calls=4, cost_usd=0.20, known_cost_usd=0.20, unknown_cost_api_calls=0
        )
        aggregate = aggregate_telemetry([{"telemetry": malformed}, {"telemetry": priced}])

        self.assertEqual(8, aggregate["api_calls"])
        self.assertIsNone(aggregate["cost_usd"])
        self.assertEqual(0, aggregate["unknown_cost_api_calls"])
        self.assertEqual(["controller_usage_invalid"], telemetry_errors(aggregate, per_attempt=False))

    def test_selected_completed_probe_requires_two_to_four_calls_at_construction_and_report(self) -> None:
        zero = qualification_usage(api_calls=0, cost_usd=0.0, known_cost_usd=0.0, unknown_cost_api_calls=0)
        four = qualification_usage(api_calls=4, cost_usd=0.0, known_cost_usd=0.0, unknown_cost_api_calls=0)
        two = qualification_usage(api_calls=2, cost_usd=0.0, known_cost_usd=0.0, unknown_cost_api_calls=0)
        three = qualification_usage(api_calls=3, cost_usd=0.0, known_cost_usd=0.0, unknown_cost_api_calls=0)

        zero_attempt = self._attempt(qualification_probe_definitions()[0], zero)
        self.assertFalse(zero_attempt["readiness_evidence"])
        self.assertIn("qualification_probe_calls_insufficient", zero_attempt["reason_codes"])
        self.assertEqual("NOT_READY", self._report([zero, four])["readiness"])
        self.assertEqual("READY", self._report([two, three])["readiness"])

    def test_declared_unknown_cost_requires_explicit_signed_policy_at_classification(self) -> None:
        unknown = qualification_usage(api_calls=2, cost_usd=None, known_cost_usd=0.0, unknown_cost_api_calls=2)
        report = self._report([unknown, unknown])

        blocked = classify_qualification(
            report,
            requested_route=self.route,
            reasoning_effort=self.effort,
            execution_contract="oab.qualification-readiness/v1",
            allow_unknown_costs=False,
        )
        allowed = classify_qualification(
            report,
            requested_route=self.route,
            reasoning_effort=self.effort,
            execution_contract="oab.qualification-readiness/v1",
            allow_unknown_costs=True,
        )

        self.assertEqual("cost_telemetry_unknown", blocked["status"])
        self.assertEqual("qualified", allowed["status"])


if __name__ == "__main__":
    unittest.main()
