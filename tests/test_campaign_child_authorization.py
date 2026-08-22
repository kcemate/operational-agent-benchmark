from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from oab.campaign_contract import (
    campaign_plan_sha256,
    canonical_bytes,
    verify_campaign_child_contract,
)
from oab.full_stage_contract import authoritative_full_contract_for_route_count
from oab.qualification_contract import qualification_contract_for_route_count


class CampaignChildContractTests(unittest.TestCase):
    def _campaign(self, root: Path, *, stage: str = "qualification") -> tuple[Path, str]:
        attempts = root / stage / "attempts"
        attempts.mkdir(parents=True)
        output_name = "a" * 32 + ".evidence"
        route = "offline/test"
        plan: dict[str, object] = {
            "schema": "oab.campaign-plan/v3",
            "created_at": "2026-08-13T00:00:00+00:00",
            "campaign_id": "child-contract-test",
            "routes": [{"route_id": "route-1", "requested_route": route}],
            "route_count": 1,
            "baseline_route": route,
            "reasoning_effort": "high",
            "qualification": qualification_contract_for_route_count(1),
            "qualification_execution": {
                "known_cost_stop_usd": 1.0,
                "max_api_calls": 24,
                "max_routes": 1,
                "allow_unknown_costs": False,
                "cost_control_mode": "post_provider_call_observed_known_cost_stop",
                "max_cost_overshoot_api_calls": 1,
            },
            "full_run": authoritative_full_contract_for_route_count(1),
            "full_execution": {
                "known_cost_stop_usd": 50.0,
                "max_api_calls": 1360,
                "max_routes": 1,
                "allow_unknown_costs": False,
                "cost_control_mode": "post_provider_call_observed_known_cost_stop",
                "max_cost_overshoot_api_calls": 1,
            },
            "release_tree_sha256": "sha256:" + "a" * 64,
        }
        plan["plan_sha256"] = campaign_plan_sha256(plan)
        (root / "PLAN.json").write_bytes(canonical_bytes(plan))
        (root / "CALIBRATION.json").write_bytes(
            canonical_bytes({"schema": "oab.calibration-report/v2", "passed": True})
        )
        return attempts, output_name

    def _verify(self, root: Path, attempts: Path, output_name: str, **overrides: object):
        stage = str(overrides.pop("stage", "qualification"))
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        attempts_fd = os.open(attempts, os.O_RDONLY | os.O_DIRECTORY)
        try:
            values: dict[str, object] = {
                "stage": stage,
                "campaign_root_path": root,
                "campaign_root_fd": root_fd,
                "output_parent_fd": attempts_fd,
                "requested_route": "offline/test",
                "reasoning_effort": "high",
                "output_name": output_name,
                "max_api_calls": 24 if stage == "qualification" else 1360,
                "max_observed_cost_usd": 1.0 if stage == "qualification" else 50.0,
                "allow_unknown_costs": False,
            }
            values.update(overrides)
            return verify_campaign_child_contract(**values)
        finally:
            os.close(attempts_fd)
            os.close(root_fd)

    def test_exact_plan_bound_child_contract_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            attempts, output_name = self._campaign(root)
            contract = self._verify(root, attempts, output_name)
            self.assertEqual("route-1", contract["route_id"])
            self.assertEqual("qualification", contract["stage"])
            self.assertNotIn("approval", json.dumps(contract).lower())

    def test_route_effort_cost_output_and_plan_tampering_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            attempts, output_name = self._campaign(root)
            cases = (
                {"requested_route": "offline/other"},
                {"reasoning_effort": "low"},
                {"max_observed_cost_usd": 1.01},

                {"max_api_calls": 15},
                {"allow_unknown_costs": True},
            )
            for values in cases:
                with self.subTest(values=values), self.assertRaises(ValueError):
                    self._verify(root, attempts, output_name, **values)
            plan = json.loads((root / "PLAN.json").read_text(encoding="utf-8"))
            plan["reasoning_effort"] = "low"
            (root / "PLAN.json").write_bytes(canonical_bytes(plan))
            with self.assertRaises(ValueError):
                self._verify(root, attempts, output_name)

    def test_output_parent_descriptor_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            attempts, output_name = self._campaign(root)
            redirected = root / "redirected"
            redirected.mkdir()
            with self.assertRaises(ValueError):
                self._verify(root, redirected, output_name)

    def test_full_stage_uses_distinct_plan_controls(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            attempts, output_name = self._campaign(root, stage="full")
            contract = self._verify(root, attempts, output_name, stage="full")
            self.assertEqual("full", contract["stage"])
            self.assertEqual(1360, contract["max_api_calls"])


if __name__ == "__main__":
    unittest.main()
