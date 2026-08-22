from __future__ import annotations

import unittest

from oab.full_stage_contract import (
    AUTHORITATIVE_FULL_PAIR_IDS,
    FULL_API_CALL_CEILING_PER_ROUTE,
    FULL_EPISODES_PER_ROUTE,
    FULL_MAX_API_CALLS_PER_EPISODE,
    FULL_REPETITIONS,
    authoritative_full_contract_for_route_count,
    build_authoritative_stage_binding,
    validate_authoritative_full_stage_plan,
)
from oab.agent_workflow import build_decision_report


class AuthoritativeFullStageContractTests(unittest.TestCase):
    def test_exact_eight_pair_five_repetition_tuple_is_the_only_authoritative_shape(self) -> None:
        full_plan = authoritative_full_contract_for_route_count(2)

        validated = validate_authoritative_full_stage_plan(full_plan, route_count=2)

        self.assertEqual(list(AUTHORITATIVE_FULL_PAIR_IDS), validated["authoritative_contract"]["pair_ids"])
        self.assertEqual(FULL_REPETITIONS, validated["authoritative_contract"]["repetitions"])
        self.assertEqual(FULL_EPISODES_PER_ROUTE, validated["authoritative_contract"]["episodes_per_route"])
        self.assertEqual(FULL_MAX_API_CALLS_PER_EPISODE, validated["authoritative_contract"]["max_api_calls_per_episode"])
        self.assertEqual(FULL_API_CALL_CEILING_PER_ROUTE, validated["authoritative_contract"]["api_call_ceiling_per_route"])
        self.assertEqual(2 * FULL_EPISODES_PER_ROUTE, validated["scheduled_episodes"])

    def test_two_episode_report_cannot_gain_switch_authority(self) -> None:
        full_plan = authoritative_full_contract_for_route_count(2)
        reports = []
        for route_id, route, output_name in (
            ("r1", "offline/a", "a" * 32),
            ("r2", "offline/b", "b" * 32),
        ):
            binding = build_authoritative_stage_binding(
                plan_sha256="sha256:" + "1" * 64,
                execution_contract_sha256="sha256:" + "2" * 64,
                route_id=route_id,
                output_relative_path=f"full/attempts/{output_name}.evidence",
                full_plan=full_plan,
                route_count=2,
            )
            reports.append(
                {
                    "authoritative": True,
                    "authoritative_stage": binding,
                    "requested_route": route,
                    "scheduled_episodes": 2,
                    "infrastructure_valid_episodes": 2,
                    "pair_ids": ["P01"],
                    "repetitions": 1,
                    "release_tree_sha256": "sha256:" + "3" * 64,
                    "controller_usage": {"api_calls": 2},
                    "reasoning_effort": "high",
                    "controller_config_sha256": "sha256:" + "4" * 64,
                    "execution_environment": {
                        "platform": "test",
                        "sandbox_backend": "test",
                    },
                }
            )
        decision = build_decision_report(
            current_route="offline/a",
            expected_release_tree_sha256="sha256:" + "3" * 64,
            suite_reports=reports,
            authoritative_full_plan=full_plan,
            expected_plan_sha256="sha256:" + "1" * 64,
            expected_execution_contract_sha256="sha256:" + "2" * 64,
        )
        self.assertEqual("not_supportable", decision["recommendation"])
        self.assertEqual(["fewer_than_two_authoritative_routes"], decision["reasons"])

    def test_custom_or_incomplete_full_tuple_is_rejected_fail_closed(self) -> None:
        valid = authoritative_full_contract_for_route_count(1)
        mutations = {
            "custom_pair": lambda payload: payload["authoritative_contract"].update({"pair_ids": ["P01"]}),
            "custom_repetition": lambda payload: payload["authoritative_contract"].update({"repetitions": 1}),
            "reordered_pair": lambda payload: payload["authoritative_contract"].update({"pair_ids": list(reversed(AUTHORITATIVE_FULL_PAIR_IDS))}),
            "wrong_episode_count": lambda payload: payload["authoritative_contract"].update({"episodes_per_route": 2}),
            "wrong_per_episode_ceiling": lambda payload: payload["authoritative_contract"].update({"max_api_calls_per_episode": 18}),
            "wrong_route_ceiling": lambda payload: payload["authoritative_contract"].update({"api_call_ceiling_per_route": 2}),
            "wrong_scheduled_count": lambda payload: payload.update({"scheduled_episodes": 2}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                candidate = {
                    **valid,
                    "authoritative_contract": dict(valid["authoritative_contract"]),
                }
                mutate(candidate)
                with self.assertRaisesRegex(ValueError, "authoritative_full_contract_invalid"):
                    validate_authoritative_full_stage_plan(candidate, route_count=1)


if __name__ == "__main__":
    unittest.main()
