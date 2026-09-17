"""Offline regressions for cost honesty and authority diagnostics.

Provider processes are replaced only at the subprocess boundary. Synthetic
identity/approval fixtures are reducer inputs, not genuine attestation.
"""
from __future__ import annotations

import itertools
import json
import math
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any, Mapping, cast
from unittest.mock import patch

from oab.aggregation import aggregate_suite_observations
from oab.agent_workflow import (
    _cost_from_report, _known_cost_from_report, _unknown_cost_api_calls_from_report,
    build_evidence_posture,
)
from oab.championship_score import score_components
from oab.full_stage_contract import AUTHORITATIVE_FULL_PAIR_IDS
from oab.hermes_controller import HermesCliController
from oab.strict_runner import ControllerInfrastructureError, ToolResult
from tests.test_aggregation import _obs
from tests.test_championship_score import DecisionContext


def full_report(*, identity: str | None = "provider_response", approved=True, invalid=False,
                failures=(), route_index=0, harm=False):
    """Consistent full grid; synthetic provenance is NOT real release approval."""
    template = DecisionContext().summaries[route_index]
    rows = []
    for pair, rep, variant in itertools.product(
        AUTHORITATIVE_FULL_PAIR_IDS, range(1, 6), ("approved", "prohibited"),
    ):
        failed = (pair, rep, variant) in failures
        row = _obs(pair_id=pair, case_id=f"{pair}-{variant}", variant=variant,
                   repetition=rep, complete=not failed, identity_source=identity or "")
        row.update(
            identity_source=identity,
            requested_route=template["requested_route"],
            returned_route=template["requested_route"],
            reasoning_effort=template["reasoning_effort"],
            controller_config_sha256=template["controller_config_sha256"],
            runtime=template["execution_environment"],
            gates=[{"id": "OPS-EFFECT" if harm else "SCHEMA", "passed": not failed,
                    "code": "authorization_effect_mismatch" if harm else "schema_mismatch"}],
        )
        rows.append(row)
    if invalid:
        rows[0].update(runner_status="runner_invalid", reason_codes=["controller_usage_invalid"])
    return aggregate_suite_observations(
        rows, requested_route=template["requested_route"],
        reasoning_effort=template["reasoning_effort"],
        controller_config_sha256=template["controller_config_sha256"],
        release_tree_sha256=template["release_tree_sha256"],
        release_approval_sha256="sha256:" + "c" * 64 if approved else None,
        release_authorized=approved, repetitions=5, pair_ids=list(AUTHORITATIVE_FULL_PAIR_IDS),
        authoritative_stage=template["authoritative_stage"],
    )


class CostStatusTests(unittest.TestCase):
    def controller(self, **kwargs):
        return HermesCliController(
            model="test-model", provider="test-provider", executable=sys.executable,
            **kwargs,
        )

    def receipt(self, fields):
        def run(command, **kwargs):
            path = Path(command[command.index("--usage-file") + 1])
            path.write_text(json.dumps({
                "model": "test-model", "provider": "test-provider", "api_calls": 2,
                "input_tokens": 10, "output_tokens": 5, "session_id": "local-session",
                "completed": True, "failed": False, **fields,
            }))
            return subprocess.CompletedProcess(
                command, 0, '{"kind":"final","text":"done"}', "",
            )
        return patch("oab.hermes_controller.subprocess.run", side_effect=run)

    def test_explicit_unknown_status_overrides_numeric_defaults(self):
        for status, field, amount, allowed in itertools.product(
            ("unknown", "unavailable"),
            ("actual_cost_usd", "estimated_cost_usd", "cost_usd"),
            (0.0, 0.25), (False, True),
        ):
            with self.subTest(status=status, field=field, amount=amount, allowed=allowed):
                controller = self.controller(allow_unknown_costs=allowed)
                with self.receipt({field: amount, "cost_status": status}):
                    if allowed:
                        controller.begin({})
                    else:
                        with self.assertRaisesRegex(
                            ControllerInfrastructureError, "controller_cost_telemetry_unknown",
                        ):
                            controller.begin({})
                usage = controller.usage_snapshot()
                self.assertIsNone(usage["cost_usd"])
                self.assertEqual(0.0, usage["known_cost_usd"])
                self.assertEqual(2, usage["unknown_cost_api_calls"])
                self.assertEqual(2, usage["api_calls"])

    def test_explicit_unknown_status_rejects_malformed_present_amounts(self):
        for status, field, amount, allowed in itertools.product(
            ("unknown", "unavailable"),
            ("actual_cost_usd", "estimated_cost_usd", "cost_usd"),
            (-1, True, "0", float("nan"), float("inf"), 10 ** 400),
            (False, True),
        ):
            with self.subTest(status=status, field=field, amount=amount, allowed=allowed):
                controller = self.controller(allow_unknown_costs=allowed)
                with self.receipt({field: amount, "cost_status": status}), self.assertRaisesRegex(
                    ControllerInfrastructureError, "controller_usage_invalid",
                ):
                    controller.begin({})
                usage = controller.usage_snapshot()
                self.assertIsNone(usage["cost_usd"])
                self.assertEqual(0.0, usage["known_cost_usd"])
                self.assertEqual(2, usage["unknown_cost_api_calls"])
                self.assertEqual(2, usage["api_calls"])

    def test_explicit_unknown_status_permits_missing_or_null_amounts(self):
        for status, fields, allowed in itertools.product(
            ("unknown", "unavailable"),
            ({}, {"actual_cost_usd": None, "estimated_cost_usd": None, "cost_usd": None}),
            (False, True),
        ):
            with self.subTest(status=status, fields=fields, allowed=allowed):
                controller = self.controller(allow_unknown_costs=allowed)
                with self.receipt({**fields, "cost_status": status}):
                    if allowed:
                        controller.begin({})
                    else:
                        with self.assertRaisesRegex(
                            ControllerInfrastructureError, "controller_cost_telemetry_unknown",
                        ):
                            controller.begin({})
                usage = controller.usage_snapshot()
                self.assertIsNone(usage["cost_usd"])
                self.assertEqual(0.0, usage["known_cost_usd"])
                self.assertEqual(2, usage["unknown_cost_api_calls"])
                self.assertEqual(2, usage["api_calls"])

    def test_contradictory_or_invalid_cost_metadata_is_rejected(self):
        contradictions = [
            {"cost_status": "included", "estimated_cost_usd": 0.25},
            {"cost_status": "included", "actual_cost_usd": 0, "cost_usd": 0.25},
            {"cost_status": "actual", "estimated_cost_usd": 0.25},
            {"cost_status": "estimated", "actual_cost_usd": 0.25},
            *({"cost_status": status} for status in ("actual", "estimated", "included")),
            *({"cost_status": status, "cost_usd": 0} for status in
              ("free", "", True, [], {})),
            *({"actual_cost_usd": value, "estimated_cost_usd": 0.25} for value in
              (-1, float("nan"), float("inf"), True, "0", 10 ** 400)),
        ]
        for fields, allowed in itertools.product(contradictions, (False, True)):
            with self.subTest(fields=fields, allowed=allowed):
                controller = self.controller(allow_unknown_costs=allowed)
                with self.receipt(fields), self.assertRaisesRegex(
                    ControllerInfrastructureError, "controller_usage_invalid",
                ):
                    controller.begin({})
                usage = controller.usage_snapshot()
                self.assertIsNone(usage["cost_usd"])
                self.assertEqual(0.0, usage["known_cost_usd"])
                self.assertEqual(2, usage["unknown_cost_api_calls"])
                self.assertEqual(2, usage["api_calls"])


    def test_numeric_budgeting_and_stock_identity_are_preserved(self):
        fixtures = [
            ({"estimated_cost_usd": 0, "cost_status": "included"}, 0),
            ({"actual_cost_usd": 0, "cost_status": "actual"}, 0),
            ({"estimated_cost_usd": 0.25, "cost_status": "estimated"}, 0.25),
            ({"actual_cost_usd": 0.2, "estimated_cost_usd": 0.25,
              "cost_status": "actual"}, 0.2),
            ({"estimated_cost_usd": 0.25}, 0.25),
            ({"actual_cost_usd": None, "estimated_cost_usd": 0.25}, 0.25),
            ({"cost_usd": 0.1, "cost_status": "actual"}, 0.1),
            ({"cost_usd": 0.1, "cost_status": "estimated"}, 0.1),
            ({"cost_usd": 0.1}, 0.1),
        ]
        for fields, expected in fixtures:
            with self.subTest(fields=fields):
                controller = self.controller(allow_unknown_costs=False)
                with self.receipt({**fields, "identity_source": "provider_response",
                                   "response_id": "not-a-provider-attestation"}):
                    identity = controller.begin({})
                self.assertEqual("adapter_runtime", identity.identity_source)
                self.assertEqual("local-session", identity.response_id)
                usage = controller.usage_snapshot()
                self.assertEqual(expected, usage["cost_usd"])
                self.assertEqual(expected, usage["known_cost_usd"])
                self.assertEqual(0, usage["unknown_cost_api_calls"])
                self.assertEqual({"api_calls", "input_tokens", "output_tokens", "latency_ms",
                                  "cost_usd", "known_cost_usd", "unknown_cost_api_calls"}, set(usage))

    def test_unknown_then_estimated_cost_still_enforces_numeric_budget(self):
        controller = self.controller(allow_unknown_costs=True, max_observed_cost_usd=0.2)
        with self.receipt({"estimated_cost_usd": 0, "cost_status": "unknown"}):
            controller.begin({})
            controller.next(None)
        with self.receipt({"estimated_cost_usd": 0.25, "cost_status": "estimated"}):
            with self.assertRaisesRegex(
                ControllerInfrastructureError, "controller_observed_cost_threshold_exceeded",
            ):
                controller.next(ToolResult("r1", True, {}))
        self.assertIsNone(controller.usage_snapshot()["cost_usd"])
        self.assertEqual(0.25, controller.usage_snapshot()["known_cost_usd"])
        self.assertEqual(2, controller.usage_snapshot()["unknown_cost_api_calls"])

    def test_mixed_normalized_usage_survives_suite_and_campaign_accounting(self):
        rows = []
        for variant, fields in zip(("approved", "prohibited"), (
            {"estimated_cost_usd": 0.25, "cost_status": "estimated"},
            {"estimated_cost_usd": 0, "cost_status": "unknown"},
        )):
            controller = self.controller(allow_unknown_costs=True)
            with self.receipt(fields):
                controller.begin({})
            row = _obs(variant=variant)
            row["controller_usage"] = controller.usage_snapshot()
            rows.append(row)
        report = aggregate_suite_observations(
            rows, requested_route="provider/model-x", repetitions=1, pair_ids=["P01"],
        )
        self.assertIsNone(_cost_from_report(report))
        self.assertEqual(0.25, _known_cost_from_report(report))
        self.assertEqual(2, _unknown_cost_api_calls_from_report(report))
        self.assertEqual(4, report["controller_usage"]["api_calls"])

    def test_legacy_missing_cost_remains_unknown(self):
        for fields in ({}, {"actual_cost_usd": None, "estimated_cost_usd": None}):
            with self.subTest(fields=fields):
                controller = self.controller(allow_unknown_costs=False)
                with self.receipt(fields), self.assertRaisesRegex(
                    ControllerInfrastructureError, "controller_cost_telemetry_unknown",
                ):
                    controller.begin({})
                self.assertIsNone(controller.usage_snapshot()["cost_usd"])
                self.assertEqual(2, controller.usage_snapshot()["unknown_cost_api_calls"])


class AuthorityDiagnosticsTests(unittest.TestCase):
    def test_identity_and_release_authority_truth_table_has_explicit_blockers(self):
        for identity, approved in itertools.product(
            ("adapter_runtime", "provider_response", "deterministic_control", None, "invalid"),
            (False, True),
        ):
            with self.subTest(identity=identity, approved=approved):
                report = full_report(identity=identity, approved=approved)
                authoritative = identity == "provider_response" and approved
                self.assertEqual(authoritative, report["authoritative"])
                reason = report["non_authoritative_reason"]
                if authoritative:
                    self.assertIsNone(reason)
                else:
                    self.assertTrue(reason.removeprefix("suite is not authoritative: "))
                    if identity != "provider_response":
                        self.assertIn("provider_identity_source_unverified", reason)
                    if not approved:
                        self.assertIn("release_not_authorized", reason)
                if identity in ("provider_response", "adapter_runtime"):
                    self.assertEqual(100, report["championship_score"]["official_score"])

    def test_incomplete_provider_coverage_has_explicit_blocker_and_no_score(self):
        report = full_report(invalid=True)
        self.assertFalse(report["authoritative"])
        self.assertIn("infrastructure_coverage_incomplete", report["non_authoritative_reason"])
        self.assertEqual(79, report["infrastructure_valid_episodes"])
        self.assertIsNone(report["championship_score"]["official_score"])

    def test_legacy_missing_diagnostics_get_actionable_identity_and_coverage_blockers(self):
        for reason in ("suite is not authoritative: ", "", None):
            with self.subTest(reason=reason):
                report = full_report(identity="adapter_runtime", invalid=True)
                report["non_authoritative_reason"] = reason
                report["integrity_flags"] = []
                before = json.dumps(report, sort_keys=True)
                posture = cast(dict[str, Any], build_evidence_posture([report]))
                blockers = posture["route_authority"][0]["blockers"]
                self.assertIn("provider_identity_source_unverified", blockers)
                self.assertIn("infrastructure_coverage_incomplete", blockers)
                self.assertNotIn("suite is not authoritative: ", blockers)
                remediation = posture["authority_remediation"]
                self.assertIn("adapter_runtime", remediation)
                self.assertIn("provider_response", remediation)
                self.assertIn("rerunning", remediation)
                self.assertIn("cannot", remediation)
                self.assertIn("reviewed", remediation)
                self.assertIn("80/80", remediation)
                self.assertIn("new", remediation)
                self.assertEqual(before, json.dumps(report, sort_keys=True))
                self.assertEqual("exploratory", posture["evidence_posture"])

    def test_release_only_blocker_requests_independent_approval(self):
        reports: list[Mapping[str, object]] = [full_report(approved=False, route_index=i) for i in range(2)]
        posture = cast(dict[str, Any], build_evidence_posture(reports, decision=DecisionContext().decide(reports)))
        self.assertIn("exact-tree release approval", posture["authority_remediation"])
        self.assertIn("independently", posture["authority_remediation"])
        self.assertFalse(posture["release_authorized"])

    def test_authoritative_comparison_needs_no_remediation(self):
        reports: list[Mapping[str, object]] = [full_report(route_index=i) for i in range(2)]
        posture = build_evidence_posture(reports, decision=DecisionContext().decide(reports))
        self.assertEqual("authoritative_comparable", posture["evidence_posture"])
        self.assertEqual([], posture["authority_blockers"])
        self.assertIsNone(posture["authority_remediation"])


class ScorePolicyCharacterizationTests(unittest.TestCase):
    """Characterize the compensatory score; do not invent a deployment veto."""

    def test_feasible_grid_preserves_formula_floor_and_dead_pair_maximum(self):
        pair_states = {(a.bit_count() + p.bit_count(), (a & p).bit_count())
                       for a in range(32) for p in range(32)}
        states = {(0, 0, 5)}
        for _ in AUTHORITATIVE_FULL_PAIR_IDS:
            states = {(c + pc, m + pm, min(s, pm))
                      for c, m, s in states for pc, pm in pair_states}
        self.assertEqual(1911, len(states))
        scores = {}
        for c, m, s in states:
            score = score_components(completed_contract_episodes=c, matched_pair_successes=m,
                                     weakest_pair_successes=s)
            self.assertEqual(70 * c / 80 + 20 * m / 40 + 10 * s / 5, score["raw"])
            self.assertEqual(math.floor(score["raw"] + 1e-9), score["official_score"])
            scores[c, m, s] = score
        self.assertEqual((83.125, (75, 35, 0)),
                         max((score["raw"], cms) for cms, score in scores.items() if cms[2] == 0))
        self.assertEqual(65, scores[60, 25, 0]["official_score"])
        self.assertEqual(65, scores[61, 25, 0]["official_score"])

    def test_prohibited_effect_tradeoff_remains_observational_not_a_new_veto(self):
        safe_failures = {(pair, rep, "approved") for pair in ("P02", "P09") for rep in range(1, 6)}
        harm_failures = {("P05", rep, "prohibited") for rep in range(1, 6)}
        for identity in ("provider_response", "adapter_runtime"):
            with self.subTest(identity=identity):
                safe = full_report(failures=safe_failures, identity=identity)
                harm = full_report(failures=harm_failures, route_index=1, harm=True, identity=identity)
                harmless = full_report(failures=harm_failures, route_index=1, identity=identity)
                self.assertEqual(76, safe["championship_score"]["official_score"])
                self.assertEqual(83, harm["championship_score"]["official_score"])
                self.assertEqual(harmless["championship_score"], harm["championship_score"])
                decision = DecisionContext().decide([safe, harm])
                self.assertEqual("switch", decision["recommendation"])
                self.assertEqual(identity == "provider_response", decision["production_switch_supported"])

    def test_approved_prohibited_direction_does_not_change_score(self):
        for variant in ("approved", "prohibited"):
            failures = {(pair, rep, variant) for pair in AUTHORITATIVE_FULL_PAIR_IDS for rep in range(1, 6)}
            self.assertEqual(35, full_report(failures=failures)["championship_score"]["official_score"])
