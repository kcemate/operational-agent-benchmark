from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from oab.strict_runner import ToolPolicy
from tools.run_suite import _bounded_tool_policy, _run_observations


class RunSuiteQualificationBoundsTests(unittest.TestCase):
    def test_episode_step_bound_is_immutable_and_never_broadens_policy(self) -> None:
        policy = ToolPolicy(
            allowed_reads=("input/a.json",),
            allowed_writes=("submission/out.json",),
            allowed_effects=(),
            max_steps=16,
            max_write_bytes=1024,
        )

        bounded = _bounded_tool_policy(policy, 1)

        self.assertEqual(16, policy.max_steps)
        self.assertEqual(1, bounded.max_steps)
        self.assertEqual(policy.allowed_reads, bounded.allowed_reads)
        self.assertEqual(16, _bounded_tool_policy(policy, 99).max_steps)
        self.assertIs(policy, _bounded_tool_policy(policy, None))

    def test_episode_step_bound_rejects_non_positive_values(self) -> None:
        policy = ToolPolicy((), (), (), 16, 1024)
        for invalid in (0, -1, True):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "max_steps_per_episode_invalid"):
                    _bounded_tool_policy(policy, invalid)

    def test_disallowed_unknown_cost_stops_suite_before_next_episode(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "fixture").mkdir()
            (root / "task.txt").write_text("opaque", encoding="utf-8")
            created_controllers: list[object] = []

            class FakeController:
                controller_config_sha256 = "sha256:" + "a" * 64

                def __init__(self, **kwargs: object) -> None:
                    created_controllers.append(self)

                def usage_snapshot(self) -> dict[str, object]:
                    return {
                        "api_calls": 1,
                        "cost_usd": None,
                        "known_cost_usd": 0.0,
                        "unknown_cost_api_calls": 1,
                    }

            args = argparse.Namespace(
                repetitions=17,
                max_observed_cost_usd=5.0,
                model="model",
                provider="provider",
                timeout_seconds=1.0,
                reasoning_effort="high",
                allow_unknown_costs=False,
                max_api_calls=34,
                max_steps_per_episode=1,
                episode_timeout_seconds=1.0,
            )
            case: dict[str, object] = {
                "case_id": "case",
                "pair_id": "P01",
                "variant": "approved",
                "fixture_path": "fixture",
                "task_path": "task.txt",
            }
            result = SimpleNamespace(
                status="runner_invalid",
                valid_for_scoring=False,
                reason_codes=("controller_cost_telemetry_unknown",),
                trace_sha256="sha256:" + "b" * 64,
                output_tree_sha256=None,
            )
            with (
                patch("tools.run_suite.ROOT", root),
                patch("tools.run_suite.HermesCliController", FakeController),
                patch("tools.run_suite.tool_policy_from_case", return_value=ToolPolicy((), (), (), 1, 1)),
                patch("tools.run_suite.run_strict_episode", return_value=result),
                patch("tools.run_suite.verify_case", return_value=[]),
                patch("tools.run_suite._identity_from_result", return_value=None),
                patch("tools.run_suite._runtime_from_result", return_value=None),
            ):
                observations = _run_observations(
                    args=args,
                    selected_cases=[case],
                    output_root=root / "output",
                    runtime_home=root,
                )

            self.assertEqual(1, len(observations))
            self.assertEqual(1, len(created_controllers))


if __name__ == "__main__":
    unittest.main()