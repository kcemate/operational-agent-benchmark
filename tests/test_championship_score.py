"""Contract tests for the v2.5 uncapped championship score.

The whole point of `oab.championship-score/v1` is that a later model can print
a strictly higher integer than the previous best.  Every test here defends one
of the three ways that promise could quietly be broken: capping the total,
letting a dead pair ceiling the headline, or letting authority paperwork erase
a number that was honestly earned.
"""

from __future__ import annotations

import ast
import inspect
import json
import unittest
from pathlib import Path
from typing import Any, Mapping, cast

from oab import championship_score as scorer
from oab.agent_workflow import build_decision_report
from oab.championship_score import (
    CHAMPIONSHIP_SCORE_SCHEMA,
    championship_score,
    official_score_from_raw,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "v240_sol_grok46_xhigh_summary.json"
LIVE_CAMPAIGN = Path(
    "/Users/giovanni/OAB-Runs/oab-v240-sol-grok46-xhigh-20260826T001739Z"
)


def load_fixture() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(FIXTURE.read_text(encoding="utf-8")))


def route_summary(route: str) -> dict[str, Any]:
    for summary in load_fixture()["route_summaries"]:
        if summary["requested_route"] == route:
            return cast(dict[str, Any], summary)
    raise AssertionError(f"fixture is missing route {route}")


def suite_report(
    *,
    requested_route: str = "openai-codex/gpt-current",
    completed: int = 80,
    matched: int = 40,
    infrastructure_valid: int = 80,
    weakest_pair_successes: int = 5,
    min_pair_id: str = "P09",
    authoritative: bool = False,
    release_authorized: bool = False,
    identity_source: str = "adapter_runtime",
    release_approval_sha256: str | None = None,
) -> dict[str, Any]:
    """A minimal suite report carrying only what the scorer reads."""
    return {
        "requested_route": requested_route,
        "authoritative": authoritative,
        "release_authorized": release_authorized,
        "identity_source": identity_source,
        "release_approval_sha256": release_approval_sha256,
        "scheduled_episodes": 80,
        "infrastructure_valid_episodes": infrastructure_valid,
        "completed_contract_episodes": completed,
        "matched_pair_successes": matched,
        "pair_stability": {"min_pair_id": min_pair_id, "min": weakest_pair_successes / 5},
        "pairs": [
            {"pair_id": min_pair_id, "matched_pair_successes": weakest_pair_successes}
        ],
    }


class NoCapTests(unittest.TestCase):
    """There is no score cap anywhere in the scorer."""

    def test_scorer_never_calls_min_and_names_no_cap(self) -> None:
        """Structural guard: prose about "no cap" is cheap, so check the AST.

        `max()` is allowed — ranking candidates is not clamping — but a `min()`
        call or any cap-shaped identifier would be a ceiling on the headline.
        """
        tree = ast.parse(inspect.getsource(scorer))
        called = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertNotIn("min", called)

        identifiers = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        identifiers |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        identifiers |= {node.arg for node in ast.walk(tree) if isinstance(node, ast.arg)}
        identifiers |= {
            node.target.id
            for node in ast.walk(tree)
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        }
        self.assertEqual([], sorted(name for name in identifiers if "cap" in name.lower()))

        keys = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        self.assertNotIn("applied_cap", keys)

    def test_dead_pair_costs_its_own_points_and_never_ceilings_the_rest(self) -> None:
        """S=0 must publish the raw floor, not a 60-style ceiling.

        A route that aces core and matched but has one dead pair loses exactly
        the 10 stability points and keeps everything else.
        """
        score = championship_score(suite_report(weakest_pair_successes=0))

        self.assertEqual("official", score["score_status"])
        self.assertEqual(90, score["official_score"])
        self.assertEqual(0, score["stability"])
        self.assertNotIn("applied_cap", score)

    def test_total_above_the_current_bucket_sum_is_not_clamped_to_100(self) -> None:
        """70+20+10 is the current bucket total, not a ceiling on the arithmetic."""
        self.assertEqual(137, official_score_from_raw(137.9))
        self.assertEqual(100, official_score_from_raw(100.0))

    def test_a_better_model_can_print_a_higher_number(self) -> None:
        previous = championship_score(suite_report(completed=62, matched=27, weakest_pair_successes=0))
        later = championship_score(suite_report(completed=63, matched=27, weakest_pair_successes=0))

        self.assertEqual(67, previous["official_score"])
        self.assertEqual(68, later["official_score"])


class ComponentTests(unittest.TestCase):
    def test_components_follow_the_locked_formula(self) -> None:
        score = championship_score(suite_report(completed=62, matched=27, weakest_pair_successes=0))

        self.assertEqual(CHAMPIONSHIP_SCORE_SCHEMA, score["schema"])
        self.assertEqual(54.25, score["core"])
        self.assertEqual(13.5, score["matched"])
        self.assertEqual(0, score["stability"])
        self.assertEqual(67.75, score["raw"])
        self.assertEqual(67, score["official_score"])

    def test_perfect_route_scores_the_full_current_bucket_total(self) -> None:
        score = championship_score(suite_report())

        self.assertEqual(100, score["official_score"])
        self.assertEqual(100.0, score["raw"])

    def test_epsilon_absorbs_float_error_without_rounding_a_score_up(self) -> None:
        """An exact integer total must never floor a point low, and 67.99 is 67."""
        self.assertEqual(68, official_score_from_raw(68 - 1e-15))
        self.assertEqual(67, official_score_from_raw(67.999))
        self.assertEqual(67, official_score_from_raw(67.75))

    def test_diagnostic_gate_pass_rate_cannot_move_the_score(self) -> None:
        base = suite_report(completed=62, matched=27, weakest_pair_successes=0)
        loaded = {**base, "diagnostic_gate_pass_rate": 1.0, "deterministic_contract_completion_rate": 1.0}

        self.assertEqual(championship_score(base), championship_score(loaded))


class EligibilityTests(unittest.TestCase):
    """Coverage decides whether there is a number; it is not a cap."""

    def test_short_coverage_publishes_no_number(self) -> None:
        score = championship_score(suite_report(infrastructure_valid=79, completed=48, matched=17))

        self.assertIsNone(score["official_score"])
        self.assertEqual("incomplete", score["score_status"])
        self.assertEqual(48, score["C"])
        self.assertEqual(17, score["M"])

    def test_full_coverage_publishes_a_number_however_weak(self) -> None:
        score = championship_score(suite_report(completed=0, matched=0, weakest_pair_successes=0))

        self.assertEqual("official", score["score_status"])
        self.assertEqual(0, score["official_score"])

    def test_unreadable_pair_breakdown_fails_closed(self) -> None:
        broken = suite_report()
        broken["pairs"] = []

        score = championship_score(broken)

        self.assertIsNone(score["official_score"])
        self.assertEqual("incomplete", score["score_status"])


class PostureTests(unittest.TestCase):
    """Authority paperwork stamps posture; it must not erase a valid score."""

    def test_unpinned_release_is_exploratory_but_still_scores(self) -> None:
        score = championship_score(suite_report(completed=62, matched=27, weakest_pair_successes=0))

        self.assertEqual("exploratory", score["score_posture"])
        self.assertEqual(67, score["official_score"])

    def test_adapter_runtime_identity_is_exploratory_but_still_scores(self) -> None:
        score = championship_score(
            suite_report(
                authoritative=True,
                release_authorized=True,
                identity_source="adapter_runtime",
                release_approval_sha256="sha256:" + "a" * 64,
            )
        )

        self.assertEqual("exploratory", score["score_posture"])
        self.assertEqual(100, score["official_score"])

    def test_fully_pinned_authorized_provider_attested_route_is_authoritative(self) -> None:
        score = championship_score(
            suite_report(
                authoritative=True,
                release_authorized=True,
                identity_source="provider_response",
                release_approval_sha256="sha256:" + "a" * 64,
            )
        )

        self.assertEqual("authoritative", score["score_posture"])


class DecisionContext:
    """Drive `build_decision_report` from the recorded v2.4.0 campaign shape."""

    def __init__(self) -> None:
        fixture = load_fixture()
        self.plan = fixture["authoritative_full_plan"]
        self.plan_sha256 = fixture["plan_sha256"]
        self.release_tree_sha256 = fixture["release_tree_sha256"]
        self.current_route = fixture["current_route"]
        self.summaries = fixture["route_summaries"]

    def decide(self, reports: list[Mapping[str, object]], *, current_route: str | None = None) -> dict[str, Any]:
        return build_decision_report(
            current_route=current_route or self.current_route,
            expected_release_tree_sha256=self.release_tree_sha256,
            suite_reports=reports,
            authoritative_full_plan=self.plan,
            expected_plan_sha256=self.plan_sha256,
            expected_execution_contract_sha256=self.plan_sha256,
        )


class LockedReplayTests(unittest.TestCase):
    """v2.4.0 sol vs grok-4.6 xhigh, replayed from recorded summary stats."""

    def setUp(self) -> None:
        self.context = DecisionContext()

    def test_sol_scores_67_exploratory_not_60(self) -> None:
        score = championship_score(route_summary("openai-codex/gpt-5.6-sol"))

        self.assertEqual(67, score["official_score"])
        self.assertEqual("official", score["score_status"])
        self.assertEqual("exploratory", score["score_posture"])
        self.assertEqual(54.25, score["core"])
        self.assertEqual(13.5, score["matched"])
        self.assertEqual(0, score["stability"])
        self.assertEqual(67.75, score["raw"])
        self.assertEqual("P09", score["min_pair_id"])
        self.assertEqual(0, score["S"])
        self.assertEqual(62, score["C"])
        self.assertEqual(27, score["M"])
        self.assertNotEqual(60, score["official_score"])

    def test_grok_is_incomplete_at_79_of_80(self) -> None:
        summary = route_summary("xai-oauth/grok-4.6")
        score = championship_score(summary)

        self.assertEqual(79, summary["infrastructure_valid_episodes"])
        self.assertIsNone(score["official_score"])
        self.assertEqual("incomplete", score["score_status"])

    def test_decision_is_not_supportable_because_the_candidate_has_no_score(self) -> None:
        decision = self.context.decide(self.context.summaries)

        self.assertEqual("oab.decision-report/v4", decision["schema"])
        self.assertEqual("not_supportable", decision["recommendation"])
        self.assertEqual(["official_score_incomplete"], decision["reasons"])
        self.assertIsNone(decision["recommended_route"])

    def test_both_unpinned_routes_stay_comparable_and_carry_their_scores(self) -> None:
        """Release authority is posture, not comparability."""
        decision = self.context.decide(self.context.summaries)

        self.assertEqual(
            ["openai-codex/gpt-5.6-sol", "xai-oauth/grok-4.6"],
            sorted(cast(list[str], decision["comparable_routes"])),
        )
        scores = {
            row["requested_route"]: row["championship_score"]
            for row in cast(list[Mapping[str, Any]], decision["routes"])
        }
        self.assertEqual(67, scores["openai-codex/gpt-5.6-sol"]["official_score"])
        self.assertIsNone(scores["xai-oauth/grok-4.6"]["official_score"])
        self.assertFalse(decision["production_switch_supported"])

    def test_no_route_payload_carries_a_cap_field(self) -> None:
        decision = self.context.decide(self.context.summaries)

        for row in cast(list[Mapping[str, Any]], decision["routes"]):
            self.assertNotIn("applied_cap", row["championship_score"])

    @unittest.skipUnless(LIVE_CAMPAIGN.is_dir(), "recorded campaign directory is absent")
    def test_live_campaign_reproduces_the_fixture(self) -> None:
        """Optional: the compact fixture must not drift from the real reports."""
        observed = {}
        for path in sorted((LIVE_CAMPAIGN / "full" / "results").glob("*.json")):
            report = json.loads(path.read_text(encoding="utf-8"))["suite_report"]
            observed[report["requested_route"]] = championship_score(report)["official_score"]

        self.assertEqual(
            {"openai-codex/gpt-5.6-sol": 67, "xai-oauth/grok-4.6": None},
            observed,
        )


class DerivedStaySwitchTests(unittest.TestCase):
    """Stay/switch compares official integers and nothing else."""

    def setUp(self) -> None:
        self.context = DecisionContext()

    def rescored(self, route: str, **overrides: object) -> dict[str, Any]:
        summary = route_summary(route)
        summary.update(overrides)
        return summary

    def complete_pair(
        self,
        *,
        current: tuple[int, int, int],
        candidate: tuple[int, int, int],
        authoritative: bool = False,
    ) -> list[Mapping[str, object]]:
        reports = []
        for route, (completed, matched, weakest) in (
            ("openai-codex/gpt-5.6-sol", current),
            ("xai-oauth/grok-4.6", candidate),
        ):
            summary = self.rescored(
                route,
                infrastructure_valid_episodes=80,
                completed_contract_episodes=completed,
                matched_pair_successes=matched,
            )
            min_pair_id = summary["pair_stability"]["min_pair_id"]
            summary["pairs"] = [
                {"pair_id": min_pair_id, "matched_pair_successes": weakest}
            ]
            if authoritative:
                summary.update(
                    authoritative=True,
                    release_authorized=True,
                    identity_source="provider_response",
                    release_approval_sha256="sha256:" + "a" * 64,
                )
            reports.append(summary)
        return reports

    def test_higher_official_score_is_an_observational_switch(self) -> None:
        decision = self.context.decide(
            self.complete_pair(current=(62, 27, 0), candidate=(70, 30, 2))
        )

        self.assertEqual("switch", decision["recommendation"])
        self.assertEqual("xai-oauth/grok-4.6", decision["recommended_route"])
        self.assertEqual(["higher_official_score"], decision["reasons"])

    def test_equal_official_score_stays(self) -> None:
        decision = self.context.decide(
            self.complete_pair(current=(62, 27, 0), candidate=(62, 27, 0))
        )

        self.assertEqual("stay", decision["recommendation"])
        self.assertEqual("openai-codex/gpt-5.6-sol", decision["recommended_route"])
        self.assertEqual(["no_higher_official_score"], decision["reasons"])

    def test_lower_official_score_stays(self) -> None:
        decision = self.context.decide(
            self.complete_pair(current=(70, 30, 2), candidate=(62, 27, 0))
        )

        self.assertEqual("stay", decision["recommendation"])
        self.assertEqual(["no_higher_official_score"], decision["reasons"])

    def test_switch_on_stability_alone_is_supported_when_the_integer_is_higher(self) -> None:
        """The retired veto blocked any switch while min-stability was 0%."""
        decision = self.context.decide(
            self.complete_pair(current=(62, 27, 0), candidate=(62, 27, 1))
        )

        self.assertEqual("switch", decision["recommendation"])
        self.assertEqual("xai-oauth/grok-4.6", decision["recommended_route"])

    def test_min_stability_zero_no_longer_vetoes_a_higher_scoring_candidate(self) -> None:
        """Candidate wins on core while both weakest pairs are dead."""
        decision = self.context.decide(
            self.complete_pair(current=(50, 20, 0), candidate=(70, 20, 0))
        )

        self.assertEqual("switch", decision["recommendation"])
        self.assertEqual("xai-oauth/grok-4.6", decision["recommended_route"])

    def test_production_switch_is_blocked_while_either_route_is_exploratory(self) -> None:
        decision = self.context.decide(
            self.complete_pair(current=(62, 27, 0), candidate=(70, 30, 2))
        )

        self.assertEqual("switch", decision["recommendation"])
        self.assertFalse(decision["production_switch_supported"])
        self.assertEqual(
            [
                "route:openai-codex/gpt-5.6-sol:score_posture_exploratory",
                "route:xai-oauth/grok-4.6:score_posture_exploratory",
            ],
            decision["production_switch_blockers"],
        )

    def test_production_switch_is_supported_once_every_route_is_authoritative(self) -> None:
        decision = self.context.decide(
            self.complete_pair(current=(62, 27, 0), candidate=(70, 30, 2), authoritative=True)
        )

        self.assertEqual("switch", decision["recommendation"])
        self.assertTrue(decision["production_switch_supported"])
        self.assertEqual([], decision["production_switch_blockers"])

    def test_a_stay_is_never_a_production_switch(self) -> None:
        decision = self.context.decide(
            self.complete_pair(current=(70, 30, 2), candidate=(62, 27, 0), authoritative=True)
        )

        self.assertEqual("stay", decision["recommendation"])
        self.assertFalse(decision["production_switch_supported"])

    def test_incomplete_current_route_is_not_supportable(self) -> None:
        reports = self.complete_pair(current=(62, 27, 0), candidate=(70, 30, 2))
        reports[0]["infrastructure_valid_episodes"] = 79  # type: ignore[index]

        decision = self.context.decide(reports)

        self.assertEqual("not_supportable", decision["recommendation"])
        self.assertEqual(["official_score_incomplete"], decision["reasons"])


if __name__ == "__main__":
    unittest.main()
