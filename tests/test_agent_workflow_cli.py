from __future__ import annotations

import hashlib
import json
import os
import gc
import sys
import tempfile
import time
import unittest
import warnings
from io import StringIO
from pathlib import Path
from typing import Mapping, cast
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oab.agent_workflow import _planned_stage_routes, load_campaign
from oab.full_stage_contract import build_authoritative_stage_binding
from oab.qualification_contract import (
    QUALIFICATION_CONTRACT_ID,
    qualification_contract_for_route_count,
    qualification_probe_definitions,
    validate_qualification_contract,
)
from oab.strict_runner import StrictEpisodeResult
from qualification_fixtures import (
    qualification_usage,
    write_probe_evidence,
    write_qualification_suite,
)
from tools import run_suite
from tools.agent_workflow import (
    _classify_route_failure,
    _production_suite_runner,
    _run_route_process,
    _verify_campaign,
    main,
)

_REAL_CLI_MAIN = main


class AgentWorkflowCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._key_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._key_directory.cleanup)
        self._approval_private_key = Ed25519PrivateKey.generate()
        self._approval_public_path = Path(self._key_directory.name) / "campaign-approval-public.pem"
        self._approval_public_path.write_bytes(
            self._approval_private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        self._main_patch = patch(__name__ + ".main", side_effect=self._main_with_pinned_test_key)
        self._main_patch.start()
        self.addCleanup(self._main_patch.stop)

    def _main_with_pinned_test_key(self, argv: list[str], **kwargs: object) -> int:
        forwarded = list(argv)
        needs_pinned_key = forwarded and (
            forwarded[0] == "benchmark"
            or (
                forwarded[0] == "approval-request"
                and "--conversation-approval-reference" not in forwarded
            )
        )
        if needs_pinned_key and "--approval-public-key" not in forwarded:
            forwarded.extend(["--approval-public-key", str(self._approval_public_path)])
        if forwarded and forwarded[0] == "test-model":
            kwargs.setdefault(
                "trusted_test_model_context_loader",
                lambda: {
                    "release_tree_sha256": json.loads(
                        (run_suite.ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8")
                    )["tree_sha256"],
                    "approval_public_key_path": self._approval_public_path,
                },
            )
        return _REAL_CLI_MAIN(forwarded, **kwargs)

    def benchmark_campaign(self, root: Path) -> None:
        self.assertEqual(
            0,
            main(
                ["benchmark", "--all-accessible", "--output-root", str(root), "--reasoning-effort", "high"],
                doctor_fn=self.doctor,
                inventory_loader=self.inventory,
                calibration_runner=self.calibration,
            ),
        )

    def signed_parent_qualification_route(
        self,
        root: Path,
        *,
        max_cost_usd: float = 5.0,
        allow_unknown_costs: bool = False,
    ) -> tuple[dict[str, object], list[str]]:
        self.benchmark_campaign(root)
        approval = self.signed_cli_approval(
            root,
            stage="qualification",
            max_cost_usd=max_cost_usd,
            max_api_calls=32,
            max_routes=2,
            allow_unknown_costs=allow_unknown_costs,
        )
        _plan, routes = _planned_stage_routes(
            root.resolve(), load_campaign(root), stage="qualification", route_cap=2
        )
        route = dict(cast(Mapping[str, object], routes[0]))
        receipt = json.loads(Path(approval[1]).read_text(encoding="utf-8"))
        plan = json.loads((root / "PLAN.json").read_text(encoding="utf-8"))
        execution_context = cast(Mapping[str, object], receipt["execution_context"])
        context_rows = cast(list[object], execution_context["routes"])
        output_relative_path = next(
            str(row["output_relative_path"])
            for row in context_rows
            if isinstance(row, Mapping) and row.get("route_id") == route["route_id"]
        )
        route.update(
            {
                "max_observed_cost_usd": max_cost_usd,
                "max_api_calls": 16,
                "_qualification_contract_version": QUALIFICATION_CONTRACT_ID,
                "_qualification_contract": cast(Mapping[str, object], plan["qualification"]),
                "allow_unknown_costs": allow_unknown_costs,
                "_campaign_root_path": str(root.resolve()),
                "_campaign_output_relative_path": output_relative_path,
                "_campaign_approval_path": approval[1],
                "_campaign_approval_signature_path": approval[3],
                "_campaign_approval_public_key_path": approval[5],
            }
        )
        return route, approval

    def native_qualification_report(
        self,
        route: Mapping[str, object],
        output: Path,
        effort: str,
        *,
        qualification_contract_tuple: Mapping[str, object],
        telemetry: Mapping[str, object],
    ) -> dict[str, object]:
        """Production-shaped test double bound to the signed PLAN tuple."""
        self.assertEqual(
            QUALIFICATION_CONTRACT_ID,
            route.get("_qualification_contract_version"),
        )
        actual_contract = validate_qualification_contract(
            route.get("_qualification_contract"), route_count=2
        )
        self.assertEqual(
            qualification_contract_for_route_count(2),
            dict(qualification_contract_tuple),
        )
        self.assertEqual(dict(qualification_contract_tuple), actual_contract)
        probes = qualification_probe_definitions()
        release_tree_sha256 = "sha256:" + "e" * 64
        campaign_root = route.get("_campaign_root_path")
        if isinstance(campaign_root, str):
            release_tree_sha256 = str(
                json.loads((Path(campaign_root) / "PLAN.json").read_text(encoding="utf-8"))["release_tree_sha256"]
            )
        return write_qualification_suite(
            output,
            route=str(route["requested_route"]),
            contract=actual_contract,
            effort=effort,
            attempts=[
                {
                    "probe": probe,
                    "attempt_number": 1,
                    "telemetry": dict(telemetry),
                }
                for probe in probes
            ],
            release_tree_sha256=release_tree_sha256,
        )

    def native_full_report(
        self,
        root: Path,
        route: Mapping[str, object],
        output: Path,
        effort: str,
        *,
        completion_rate: float = 0.85,
        matched_rate: float = 0.80,
        stability: float = 0.60,
        release_authorized: bool = False,
        release_approval_sha256: str | None = None,
    ) -> dict[str, object]:
        """Offline full-report double carrying the signed child binding, never argv authority."""
        plan = json.loads((root / "PLAN.json").read_text(encoding="utf-8"))
        approval = json.loads(
            Path(str(route["_campaign_approval_path"])).read_text(encoding="utf-8")
        )
        report: dict[str, object] = {
            "requested_route": route["requested_route"],
            "authoritative": True,
            "reasoning_effort": effort,
            "controller_config_sha256": "sha256:" + "b" * 64,
            "release_tree_sha256": plan["release_tree_sha256"],
            "release_authorized": release_authorized,
            "release_approval_sha256": release_approval_sha256,
            "identity_source": "provider_response",
            "execution_environment": {
                "platform": "darwin",
                "sandbox_backend": "macos-sandbox-exec",
            },
            "scheduled_episodes": 80,
            "infrastructure_valid_episodes": 80,
            "infrastructure_invalid_episodes": 0,
            "pair_ids": [f"P{index:02d}" for index in range(1, 9)],
            "repetitions": 5,
            "deterministic_contract_completion_rate": completion_rate,
            "matched_pair_completion_rate": matched_rate,
            "pair_stability": {"min": stability},
            "controller_usage": {
                "api_calls": 1360,
                "cost_usd": 2.0,
                "known_cost_usd": 2.0,
                "unknown_cost_api_calls": 0,
            },
            "authoritative_stage": build_authoritative_stage_binding(
                plan_sha256=str(plan["plan_sha256"]),
                stage_approval_sha256=str(approval["receipt_sha256"]),
                route_id=str(route["route_id"]),
                output_relative_path=str(output.resolve().relative_to(root.resolve())),
                full_plan=cast(Mapping[str, object], plan["full_run"]),
                route_count=int(plan["route_count"]),
            ),
        }
        output.mkdir(parents=True, exist_ok=False)
        (output / "suite-report.json").write_text(
            json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
        )
        returned = dict(report)
        returned["campaign_suite_verified"] = True
        returned["campaign_elapsed_seconds"] = 1.0
        return returned

    def synthetic_release_approval(self, root: Path) -> tuple[Path, str]:
        """Create a local, offline v1 release approval with an explicit file digest."""
        tree = str(json.loads((root / "PLAN.json").read_text(encoding="utf-8"))["release_tree_sha256"])
        receipt: dict[str, object] = {
            "schema": "oab.release-approval/v1",
            "release_tree_sha256": tree,
            "reviews": [
                {
                    "role": "security",
                    "reviewer": "synthetic-independent-security",
                    "decision": "APPROVE",
                    "reviewed_tree_sha256": tree,
                    "claim_limitations_acknowledged": True,
                },
                {
                    "role": "product",
                    "reviewer": "synthetic-independent-product",
                    "decision": "APPROVE",
                    "reviewed_tree_sha256": tree,
                    "claim_limitations_acknowledged": True,
                },
            ],
        }
        path = root.parent / "synthetic-release-approval.json"
        path.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def test_verify_campaign_rejects_symlinked_internal_parent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            self.assertEqual(
                0,
                main(
                    [
                        "benchmark",
                        "--all-accessible",
                        "--output-root",
                        str(root),
                        "--reasoning-effort",
                        "high",
                    ],
                    doctor_fn=self.doctor,
                    inventory_loader=self.inventory,
                    calibration_runner=self.calibration,
                ),
            )
            outside = Path(td) / "outside-results"
            outside.mkdir()
            results = root / "qualification/results"
            results.rmdir()
            results.symlink_to(outside, target_is_directory=True)
            verification = _verify_campaign(root)
            self.assertFalse(verification["valid"])
            errors = verification["errors"]
            self.assertIsInstance(errors, list)
            self.assertIn("campaign_internal_path_unsafe", cast(list[object], errors))

    def test_approval_preview_prints_exact_no_spend_controls(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            self.assertEqual(
                0,
                main(
                    ["benchmark", "--all-accessible", "--output-root", str(root), "--reasoning-effort", "high"],
                    doctor_fn=self.doctor,
                    inventory_loader=self.inventory,
                    calibration_runner=self.calibration,
                ),
            )
            with patch("sys.stdout", new_callable=StringIO) as stdout:
                code = main(
                    [
                        "approval-preview",
                        str(root),
                        "--stage",
                        "qualification",
                        "--observed-cost-stop-usd",
                        "5",
                        "--max-api-calls",
                        "32",
                        "--max-routes",
                        "2",
                        "--allow-unknown-costs",
                    ]
                )
            self.assertEqual(0, code)
            preview = json.loads(stdout.getvalue())
            self.assertEqual("oab.approval-preview/v1", preview["schema"])
            self.assertEqual(
                ["openai-codex/current", "openai-codex/candidate"],
                [item["requested_route"] for item in preview["routes"]],
            )
            self.assertEqual(2, preview["episodes_per_route"])
            self.assertEqual(4, preview["scheduled_episodes"])
            # First attempt: 2 routes × 2 probes × 4 steps = 16 calls.
            self.assertEqual(16, preview["minimum_required_api_calls"])
            # Absolute reserve with one infrastructure retry/probe: 2 × 16 = 32.
            self.assertEqual(32, preview["absolute_reserved_api_calls"])
            self.assertEqual(8, preview["first_attempt_api_calls_per_route"])
            self.assertEqual(16, preview["absolute_api_calls_per_route"])
            self.assertEqual(4, preview["max_api_calls_per_episode"])
            self.assertTrue(preview["call_ceiling_sufficient"])
            self.assertIn("plumbing", preview["stage_purpose"].lower())
            self.assertIn("no model-quality score", preview["stage_purpose"].lower())
            self.assertEqual("post_provider_call_observed_known_cost_stop", preview["cost_control_mode"])
            self.assertEqual(1, preview["max_cost_overshoot_api_calls"])
            self.assertTrue(preview["allow_unknown_costs"])
            self.assertEqual("exploratory_by_default", preview["intended_evidence_posture"])

    def test_production_runner_forwards_turn_level_cost_controls(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            route, _approval = self.signed_parent_qualification_route(
                root, max_cost_usd=4.75, allow_unknown_costs=True
            )
            output = root / str(route["_campaign_output_relative_path"])
            runner = _production_suite_runner(
                source_hermes_home=None,
                release_approval=None,
                expected_release_approval_sha256=None,
                timeout_seconds=10,
            )
            with patch(
                "tools.agent_workflow._run_route_process",
                return_value={
                    "timed_out": False,
                    "returncode": 1,
                    "diagnostic_sha256": "sha256:" + "0" * 64,
                    "error_code": "campaign_controller_failed",
                },
            ) as execute:
                with self.assertRaisesRegex(RuntimeError, "campaign_controller_failed"):
                    runner(route, "qualification", output, "high")
            command = execute.call_args.args[0]
            self.assertIn("--qualification-readiness-v1", command)
            self.assertNotIn("--qualification-contract-json", command)
            self.assertIn("--campaign-root-fd", command)
            self.assertIn("--campaign-authorization-fd", command)
            self.assertNotIn("--repetitions", command)
            self.assertNotIn("--max-steps-per-episode", command)
            self.assertEqual("16", command[command.index("--max-api-calls") + 1])
            self.assertIn("--max-observed-cost-usd", command)
            self.assertEqual("4.75", command[command.index("--max-observed-cost-usd") + 1])
            self.assertIn("--allow-unknown-costs", command)

    def test_production_runner_schedules_two_bounded_v230_probes(self) -> None:
        """The real child command must schedule P01's two variants once each."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            route, _approval = self.signed_parent_qualification_route(root)
            attempts = root / "qualification" / "attempts"
            output = root / str(route["_campaign_output_relative_path"])
            runner = _production_suite_runner(
                source_hermes_home=None,
                release_approval=None,
                expected_release_approval_sha256=None,
                timeout_seconds=10,
            )
            qualification_contract_tuple = cast(
                Mapping[str, object], route["_qualification_contract"]
            )
            step_limits: list[int] = []
            controller_budgets: list[object] = []

            class OfflineController:
                controller_config_sha256 = "sha256:" + "a" * 64
                protocol_normalized_turns = 0

                def __init__(self, **kwargs: object) -> None:
                    controller_budgets.append(kwargs.get("max_api_calls"))

                def usage_snapshot(self) -> dict[str, object]:
                    return {
                        "api_calls": 4,
                        "input_tokens": 1,
                        "output_tokens": 1,
                        "latency_ms": 1.0,
                        "cost_usd": 0.0,
                        "known_cost_usd": 0.0,
                        "unknown_cost_api_calls": 0,
                    }

            class OfflineRuntime:
                home = root
                config_sha256 = "sha256:" + "b" * 64

                def __enter__(self) -> "OfflineRuntime":
                    return self

                def __exit__(self, *_args: object) -> None:
                    return None

            def fake_episode(
                spec: object,
                *,
                evidence_dir: Path,
                tool_policy: object,
                artifact_profile: str = "standard",
                **_kwargs: object,
            ) -> StrictEpisodeResult:
                step_limits.append(getattr(tool_policy, "max_steps"))
                self.assertEqual("qualification_readiness", artifact_profile)
                receipt = write_probe_evidence(
                    evidence_dir,
                    case_id=str(getattr(spec, "case_id")),
                    repetition=int(getattr(spec, "repetition")),
                    route=str(route["requested_route"]),
                    telemetry=qualification_usage(),
                )
                return StrictEpisodeResult(
                    case_id=str(receipt["case_id"]),
                    repetition=cast(int, receipt["repetition"]),
                    status=str(receipt["status"]),
                    valid_for_scoring=bool(receipt["readiness_evidence"]),
                    reason_codes=tuple(
                        str(code) for code in cast(list[object], receipt["reason_codes"])
                    ),
                    evidence_dir=evidence_dir,
                    trace_sha256=cast(str, receipt["trace_sha256"]),
                    output_tree_sha256=cast(str, receipt["output_tree_sha256"]),
                )

            def fake_seal(
                output_root: Path, *, release_manifest: Path | None = None
            ) -> tuple[Path, str]:
                del release_manifest
                seal = output_root / "SUITE_SEAL.json"
                seal.write_text('{"schema":"test"}\n', encoding="utf-8")
                return seal, "sha256:" + "e" * 64

            def execute(
                command: list[str], *, timeout_seconds: float, pass_fds: tuple[int, ...]
            ) -> dict[str, object]:
                del timeout_seconds
                self.assertGreaterEqual(len(pass_fds), 3)
                self.assertNotIn("--qualification-contract-json", command)
                self.assertIn("--campaign-root-fd", command)
                self.assertIn("--campaign-authorization-fd", command)
                saved_cwd = os.open(".", os.O_RDONLY)
                try:
                    with (
                        patch.object(sys, "argv", ["run_suite", *command[3:]]),
                        patch("tools.run_suite.verify_release_manifest", return_value=[]),
                        patch("tools.run_suite.pinned_hermes_runtime", return_value=OfflineRuntime()),
                        patch("tools.run_suite.HermesCliController", OfflineController),
                        patch("tools.run_suite.run_strict_episode", side_effect=fake_episode),
                        patch("tools.run_suite.verify_case", return_value=[]),
                        patch("oab.suite_seal.verify_case", return_value=[]),
                        patch("tools.run_suite.write_suite_seal", side_effect=fake_seal),
                    ):
                        returncode = run_suite.main()
                finally:
                    os.fchdir(saved_cwd)
                    os.close(saved_cwd)
                return {
                    "timed_out": False,
                    "returncode": returncode,
                    "diagnostic_sha256": "sha256:" + "f" * 64,
                    "error_code": "campaign_controller_failed",
                }

            with (
                patch("tools.agent_workflow._run_route_process", side_effect=execute),
                patch("tools.agent_workflow.verify_suite_seal", return_value=[]),
            ):
                report = runner(route, "qualification", output, "high")

            self.assertEqual(qualification_contract_tuple, report["qualification_contract"])
            self.assertEqual("READY", report["readiness"])
            self.assertEqual(2, len(cast(list[object], report["probes"])))
            self.assertEqual(2, len(cast(list[object], report["attempts"])))
            usage = cast(dict[str, object], report["controller_usage"])
            self.assertEqual(8, usage["api_calls"])
            self.assertEqual([4, 4], step_limits)
            self.assertEqual([4, 4], controller_budgets)

    def test_production_runner_refuses_legacy_qualification_contract(self) -> None:
        """Even a signed parent proof cannot revive a legacy readiness contract."""
        runner = _production_suite_runner(
            source_hermes_home=None,
            release_approval=None,
            expected_release_approval_sha256=None,
            timeout_seconds=10,
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            route, _approval = self.signed_parent_qualification_route(root)
            route["_qualification_contract_version"] = "v2.2.3"
            output = root / str(route["_campaign_output_relative_path"])
            with warnings.catch_warnings(record=True) as caught, patch(
                "tools.agent_workflow.tempfile.TemporaryFile", wraps=tempfile.TemporaryFile
            ) as authorization_stream, patch("tools.agent_workflow._run_route_process") as execute:
                warnings.simplefilter("always", ResourceWarning)
                with self.assertRaisesRegex(ValueError, "qualification_execution_contract_invalid"):
                    runner(route, "qualification", output, "high")
                gc.collect()
            execute.assert_not_called()
            authorization_stream.assert_not_called()
            self.assertFalse(
                [warning for warning in caught if issubclass(warning.category, ResourceWarning)]
            )

    def test_production_runner_raises_controlled_error_for_timeout(self) -> None:
        runner = _production_suite_runner(
            source_hermes_home=None,
            release_approval=None,
            expected_release_approval_sha256=None,
            timeout_seconds=10,
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            route, _approval = self.signed_parent_qualification_route(root)
            output = root / str(route["_campaign_output_relative_path"])
            with patch(
                "tools.agent_workflow._run_route_process",
                return_value={
                    "timed_out": True,
                    "returncode": None,
                    "diagnostic_sha256": "sha256:" + "0" * 64,
                    "error_code": "campaign_route_timeout",
                },
            ):
                with self.assertRaisesRegex(RuntimeError, "campaign_route_timeout"):
                    runner(route, "qualification", output, "high")

    def test_production_runner_rejects_substituted_suite_output_parent(self) -> None:
        runner = _production_suite_runner(
            source_hermes_home=None,
            release_approval=None,
            expected_release_approval_sha256=None,
            timeout_seconds=10,
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            route, _approval = self.signed_parent_qualification_route(root)
            attempts = root / "qualification" / "attempts"
            output = root / str(route["_campaign_output_relative_path"])
            attempts.rename(root / "qualification" / "retained-attempts")
            outside = root / "attacker-selected"
            outside.mkdir()
            attempts.symlink_to(outside, target_is_directory=True)
            with patch("tools.agent_workflow._run_route_process") as execute:
                with self.assertRaisesRegex(ValueError, "campaign_internal_path_unsafe"):
                    runner(route, "qualification", output, "high")
            execute.assert_not_called()
            self.assertFalse((outside / output.name).exists())

    def test_production_runner_verifies_descriptor_created_evidence_after_parent_swap(self) -> None:
        runner = _production_suite_runner(
            source_hermes_home=None,
            release_approval=None,
            expected_release_approval_sha256=None,
            timeout_seconds=10,
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            route, _approval = self.signed_parent_qualification_route(root)
            qualification_contract_tuple = cast(
                Mapping[str, object], route["_qualification_contract"]
            )
            attempts = root / "qualification" / "attempts"
            output = root / str(route["_campaign_output_relative_path"])
            output_name = output.name

            def execute(
                command: list[str], *, timeout_seconds: float, pass_fds: tuple[int, ...]
            ) -> dict[str, object]:
                del timeout_seconds
                self.assertGreaterEqual(len(pass_fds), 3)
                parent_fd = pass_fds[0]
                self.assertNotIn("--qualification-contract-json", command)
                self.assertIn("--campaign-authorization-fd", command)
                self.assertGreaterEqual(parent_fd, 0)
                write_qualification_suite(
                    output,
                    route=str(route["requested_route"]),
                    contract=qualification_contract_tuple,
                )
                attempts.rename(root / "qualification" / "retained-attempts")
                replacement = root / "qualification" / "attempts"
                (replacement / output_name).mkdir(parents=True)
                (replacement / output_name / "suite-report.json").write_text(
                    '{"requested_route":"attacker/route"}', encoding="utf-8"
                )
                return {
                    "timed_out": False,
                    "returncode": 0,
                    "diagnostic_sha256": "sha256:" + "0" * 64,
                    "error_code": "campaign_controller_failed",
                }

            verified_routes: list[str] = []

            def verify(
                path: Path, *, seal_bytes: bytes, report_bytes: bytes
            ) -> list[str]:
                report_value = json.loads(report_bytes.decode("utf-8"))
                verified_routes.append(str(report_value["requested_route"]))
                self.assertEqual(
                    qualification_contract_tuple,
                    report_value["qualification_contract"],
                )
                (path / "suite-report.json").write_text(
                    '{"requested_route":"attacker-after-verify"}', encoding="utf-8"
                )
                self.assertEqual(
                    qualification_contract_tuple,
                    json.loads(seal_bytes)["qualification_contract"],
                )
                return []

            with patch(
                "tools.agent_workflow._run_route_process", side_effect=execute
            ), patch(
                "tools.agent_workflow.verify_suite_seal", side_effect=verify
            ):
                report = runner(route, "qualification", output, "high")

            self.assertEqual([str(route["requested_route"])], verified_routes)
            self.assertEqual(str(route["requested_route"]), report["requested_route"])
            self.assertEqual(qualification_contract_tuple, report["qualification_contract"])

    def test_route_failure_classifier_returns_actionable_sanitized_codes(self) -> None:
        cases = {
            "release manifest verification failed: release_tree_digest_mismatch": "campaign_release_manifest_invalid",
            "release approval invalid": "campaign_release_approval_invalid",
            "runtime profile source Hermes home missing": "campaign_runtime_profile_invalid",
            "FileExistsError: output root already exists": "campaign_output_exists",
            "bubblewrap unavailable": "campaign_containment_unavailable",
            "hermes_usage_api_calls_invalid": "campaign_controller_telemetry_invalid",
        }
        for diagnostic, expected in cases.items():
            with self.subTest(diagnostic=diagnostic):
                self.assertEqual(expected, _classify_route_failure(diagnostic))

    def signed_cli_approval(
        self,
        root: Path,
        *,
        stage: str,
        max_cost_usd: float,
        max_api_calls: int,
        max_routes: int,
        allow_unknown_costs: bool = False,
    ) -> list[str]:
        public_path = self._approval_public_path
        request_path = root.parent / f"{stage}-approval.json"
        signature_path = root.parent / f"{stage}-approval.sig"
        code = main(
            [
                "approval-request", str(root), "--stage", stage,
                "--max-cost-usd", str(max_cost_usd), "--max-api-calls", str(max_api_calls),
                "--max-routes", str(max_routes), "--approval-public-key", str(public_path),
                "--output", str(request_path),
            ]
            + (["--allow-unknown-costs"] if allow_unknown_costs else [])
        )
        self.assertEqual(0, code)
        receipt = json.loads(request_path.read_text(encoding="utf-8"))
        canonical = json.dumps(
            receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        signed_bytes = Path(str(request_path) + ".signing-payload").read_bytes()
        self.assertEqual(canonical, signed_bytes)
        signature_path.write_bytes(self._approval_private_key.sign(signed_bytes))
        gate = "--qualification-approval" if stage == "qualification" else "--full-approval"
        return [
            gate, str(request_path), "--approval-signature", str(signature_path),
            "--approval-public-key", str(public_path),
        ]

    @unittest.skipUnless(os.name == "posix", "process-group containment is POSIX-specific")
    def test_route_timeout_kills_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sentinel = Path(td) / "descendant-survived"
            child_code = (
                "import time; from pathlib import Path; "
                f"time.sleep(0.4); Path({str(sentinel)!r}).write_text('survived')"
            )
            parent_code = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable,'-c',{child_code!r}]); time.sleep(5)"
            )
            result = _run_route_process([sys.executable, "-c", parent_code], timeout_seconds=0.1)
            self.assertTrue(result["timed_out"])
            time.sleep(0.6)
            self.assertFalse(sentinel.exists())

    @staticmethod
    def inventory() -> dict[str, object]:
        return {
            "provider": "openai-codex",
            "model": "current",
            "providers": [
                {"slug": "openai-codex", "models": ["current", "candidate"]},
            ],
        }

    @staticmethod
    def doctor(**_: object) -> dict[str, object]:
        return {
            "schema": "oab.doctor/v1",
            "ready": True,
            "platform": "darwin",
            "sandbox_backend": "macos-sandbox-exec",
            "release_tree_sha256": json.loads(
                (run_suite.ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8")
            )["tree_sha256"],
            "checks": [],
        }

    @staticmethod
    def calibration(output: Path) -> dict[str, object]:
        output.mkdir(parents=True, exist_ok=False)
        report = {
            "schema": "oab.calibration-report/v2",
            "passed": True,
            "pair_count": 8,
            "case_count": 16,
            "cases": [],
        }
        (output / "calibration-report.json").write_text(json.dumps(report), encoding="utf-8")
        return report

    def test_discover_forwards_explicit_api_url_without_accepting_cli_secret(self) -> None:
        received: list[dict[str, object]] = []

        def loader(**kwargs: object) -> dict[str, object]:
            received.append(dict(kwargs))
            return self.inventory()

        code = main(
            ["discover", "--json", "--hermes-api-url", "http://127.0.0.1:8642"],
            inventory_loader=loader,
        )
        self.assertEqual(0, code)
        self.assertEqual([{"api_base_url": "http://127.0.0.1:8642"}], received)

    def test_benchmark_initializes_no_spend_plan_and_calibrates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            runner_calls: list[str] = []

            def suite_runner(*args: object, **kwargs: object) -> dict[str, object]:
                runner_calls.append("unexpected")
                raise AssertionError("no model suite may run without approval")

            code = main(
                [
                    "benchmark",
                    "--all-accessible",
                    "--output-root",
                    str(root),
                    "--reasoning-effort",
                    "high",
                ],
                doctor_fn=self.doctor,
                inventory_loader=self.inventory,
                calibration_runner=self.calibration,
                suite_runner=suite_runner,
            )
            self.assertEqual(0, code)
            self.assertEqual([], runner_calls)
            state = json.loads((root / "CAMPAIGN.json").read_text(encoding="utf-8"))
            self.assertEqual("awaiting_qualification_approval", state["status"])
            self.assertTrue((root / "CALIBRATION.json").is_file())

    def test_test_model_builds_two_route_campaign_and_compact_approval_card(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            runner_calls: list[str] = []

            def suite_runner(*args: object, **kwargs: object) -> dict[str, object]:
                runner_calls.append("unexpected")
                raise AssertionError("test-model must not call a provider before approval")

            with patch("sys.stdout", new_callable=StringIO) as stdout:
                code = main(
                    [
                        "test-model",
                        "openai-codex/candidate",
                        "--output-root",
                        str(root),
                        "--reasoning-effort",
                        "high",
                        "--qualification-cost-stop-usd",
                        "5",
                    ],
                    doctor_fn=self.doctor,
                    inventory_loader=self.inventory,
                    calibration_runner=self.calibration,
                    suite_runner=suite_runner,
                )

            self.assertEqual(0, code)
            self.assertEqual([], runner_calls)
            card = json.loads(stdout.getvalue())
            self.assertEqual("oab.test-model-approval-card/v1", card["schema"])
            self.assertEqual("openai-codex/current", card["baseline"])
            self.assertEqual("openai-codex/candidate", card["candidate"])
            self.assertEqual("qualification", card["stage"])
            self.assertEqual(4, card["episodes"])
            self.assertEqual(32, card["maximum_api_calls"])
            self.assertEqual(5.0, card["observed_known_billed_cost_stop_usd"])
            self.assertEqual(0, card["model_inference_calls_performed"])
            self.assertEqual("exploratory_by_default", card["evidence_posture"])
            self.assertIn("qualification provider calls only", card["approval_authorizes"])
            self.assertEqual("approval_required", card["next_action"])
            self.assertEqual(str(root.resolve()), card["campaign_root"])
            plan = json.loads((root / "PLAN.json").read_text(encoding="utf-8"))
            self.assertEqual(2, plan["route_count"])
            self.assertEqual("openai-codex/current", plan["baseline_route"])

    def test_test_model_needs_only_the_candidate_intent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "automatic-campaign"
            with patch(
                "tools.agent_workflow._default_test_model_output_root",
                return_value=root,
            ):
                with patch("sys.stdout", new_callable=StringIO) as stdout:
                    code = main(
                        ["test-model", "openai-codex/candidate"],
                        doctor_fn=self.doctor,
                        inventory_loader=self.inventory,
                        calibration_runner=self.calibration,
                    )
            self.assertEqual(0, code)
            card = json.loads(stdout.getvalue())
            self.assertEqual(str(root.resolve()), card["campaign_root"])
            self.assertEqual(5.0, card["observed_known_billed_cost_stop_usd"])
            self.assertEqual("high", json.loads((root / "PLAN.json").read_text())["reasoning_effort"])

    def test_test_model_card_uses_canonical_candidate_route(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            with patch("sys.stdout", new_callable=StringIO) as stdout:
                code = main(
                    [
                        "test-model",
                        "  openai-codex/candidate  ",
                        "--output-root",
                        str(root),
                    ],
                    doctor_fn=self.doctor,
                    inventory_loader=self.inventory,
                    calibration_runner=self.calibration,
                )
            self.assertEqual(0, code)
            card = json.loads(stdout.getvalue())
            self.assertEqual("openai-codex/candidate", card["candidate"])
            self.assertEqual(
                ["openai-codex/current", "openai-codex/candidate"],
                card["routes"],
            )

    def test_test_model_status_projects_next_host_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            with patch("sys.stdout", new_callable=StringIO):
                self.assertEqual(
                    0,
                    main(
                        ["test-model", "openai-codex/candidate", "--output-root", str(root)],
                        doctor_fn=self.doctor,
                        inventory_loader=self.inventory,
                        calibration_runner=self.calibration,
                    ),
                )
            with patch("sys.stdout", new_callable=StringIO) as stdout:
                code = main(["test-model-status", str(root)])
            self.assertEqual(0, code)
            projected = json.loads(stdout.getvalue())
            self.assertEqual("qualification_approval_required", projected["state"])
            self.assertEqual("awaiting_qualification_approval", projected["campaign_status"])

    def test_test_model_rejects_unknown_candidate_before_campaign_creation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            with patch("sys.stdout", new_callable=StringIO) as stdout:
                code = main(
                    [
                        "test-model",
                        "openai-codex/missing",
                        "--output-root",
                        str(root),
                        "--reasoning-effort",
                        "high",
                        "--qualification-cost-stop-usd",
                        "5",
                    ],
                    doctor_fn=self.doctor,
                    inventory_loader=self.inventory,
                    calibration_runner=self.calibration,
                )
            self.assertEqual(2, code)
            self.assertEqual(
                "model_comparison_candidate_unavailable",
                json.loads(stdout.getvalue())["error"],
            )
            self.assertFalse(root.exists())

    def test_test_model_requires_host_approval_authority_without_user_key_ceremony(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            with patch("sys.stdout", new_callable=StringIO) as stdout:
                code = _REAL_CLI_MAIN(
                        [
                            "test-model",
                            "openai-codex/candidate",
                            "--output-root",
                            str(root),
                            "--qualification-cost-stop-usd",
                            "5",
                        ],
                        doctor_fn=self.doctor,
                        inventory_loader=self.inventory,
                        calibration_runner=self.calibration,
                    )
            self.assertEqual(2, code)
            self.assertEqual("trusted_test_model_context_unavailable", json.loads(stdout.getvalue())["error"])
            self.assertFalse(root.exists())

    def test_test_model_ignores_caller_signer_and_release_environment(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            with patch.dict(
                os.environ,
                {
                    "OAB_APPROVAL_PUBLIC_KEY": "/tmp/caller-controlled.pem",
                    "OAB_TREE_SHA256": "sha256:" + "b" * 64,
                },
                clear=True,
            ):
                with patch("sys.stdout", new_callable=StringIO) as stdout:
                    code = _REAL_CLI_MAIN(
                        ["test-model", "openai-codex/candidate", "--output-root", str(root)],
                        doctor_fn=self.doctor,
                        inventory_loader=self.inventory,
                        calibration_runner=self.calibration,
                    )
            self.assertEqual(2, code)
            self.assertEqual("trusted_test_model_context_unavailable", json.loads(stdout.getvalue())["error"])
            self.assertFalse(root.exists())

    def test_test_model_rejects_doctor_substitution_of_trusted_release_pin(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            trusted_pin = "sha256:" + "a" * 64

            def substituted_doctor(**_: object) -> dict[str, object]:
                return {
                    "schema": "oab.doctor/v1",
                    "ready": True,
                    "platform": "darwin",
                    "sandbox_backend": "macos-sandbox-exec",
                    "release_tree_sha256": "sha256:" + "b" * 64,
                    "checks": [],
                }

            with patch("sys.stdout", new_callable=StringIO) as stdout:
                code = _REAL_CLI_MAIN(
                    ["test-model", "openai-codex/candidate", "--output-root", str(root)],
                    doctor_fn=substituted_doctor,
                    inventory_loader=self.inventory,
                    calibration_runner=self.calibration,
                    trusted_test_model_context_loader=lambda: {
                        "release_tree_sha256": trusted_pin,
                        "approval_public_key_path": self._approval_public_path,
                    },
                )
            self.assertEqual(2, code)
            self.assertEqual("trusted_release_pin_mismatch", json.loads(stdout.getvalue())["error"])
            self.assertFalse(root.exists())

    def test_benchmark_failed_doctor_stops_before_inventory_or_campaign_creation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            inventory_calls: list[str] = []

            def failed_doctor(**_: object) -> dict[str, object]:
                return {"schema": "oab.doctor/v1", "ready": False, "checks": []}

            def inventory_loader(**_: object) -> dict[str, object]:
                inventory_calls.append("called")
                return self.inventory()

            code = main(
                ["benchmark", "--all-accessible", "--output-root", str(root), "--reasoning-effort", "high"],
                doctor_fn=failed_doctor,
                inventory_loader=inventory_loader,
                calibration_runner=self.calibration,
            )
            self.assertEqual(2, code)
            self.assertEqual([], inventory_calls)
            self.assertFalse(root.exists())

    def test_qualification_approval_requires_positive_budget(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            main(
                ["benchmark", "--all-accessible", "--output-root", str(root), "--reasoning-effort", "high"],
                doctor_fn=self.doctor,
                inventory_loader=self.inventory,
                calibration_runner=self.calibration,
            )
            code = main(
                [
                    "resume", str(root),
                    "--qualification-approval", str(Path(td) / "missing.json"),
                    "--approval-signature", str(Path(td) / "missing.sig"),
                    "--approval-public-key", str(Path(td) / "missing.pem"),
                ],
                suite_runner=lambda *args, **kwargs: {},
            )
            self.assertEqual(2, code)

    def test_unverified_conversational_receipt_cannot_authorize_resume(self) -> None:
        """`approval-request --conversation-approval-reference` must be refused.

        The reference is caller-asserted, so it is not host-verified evidence of
        approval and may not produce a spend-capable receipt.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            self.assertEqual(
                0,
                main(
                    ["benchmark", "--all-accessible", "--output-root", str(root), "--reasoning-effort", "high"],
                    doctor_fn=self.doctor,
                    inventory_loader=self.inventory,
                    calibration_runner=self.calibration,
                ),
            )
            approval = Path(td) / "qualification-conversation.json"
            with patch("sys.stdout", new_callable=StringIO) as stdout:
                code = main(
                    [
                        "approval-request", str(root), "--stage", "qualification",
                        "--max-cost-usd", "5", "--max-api-calls", "68", "--max-routes", "2",
                        "--allow-unknown-costs",
                        "--conversation-approval-reference", "telegram:user-confirmed:$5:68:2:unknown-cost",
                        "--output", str(approval),
                    ]
                )
            self.assertEqual(2, code)
            self.assertIn(
                "conversation_approval_not_host_verified", stdout.getvalue()
            )
            self.assertFalse(approval.exists())

            # A hand-written conversational receipt must not authorize resume either.
            plan = json.loads((root / "PLAN.json").read_text(encoding="utf-8"))
            state = json.loads((root / "CAMPAIGN.json").read_text(encoding="utf-8"))
            _plan, routes = _planned_stage_routes(
                root.resolve(), load_campaign(root), stage="qualification", route_cap=2
            )
            body: dict[str, object] = {
                "schema": "oab.conversational-stage-approval/v2",
                "created_at": "2026-08-09T00:00:00+00:00",
                "approval_assurance": "conversation_attested",
                "user_approval_reference": "telegram:user-confirmed:$5:68:2:unknown-cost",
                "stage": "qualification",
                "plan_sha256": plan["plan_sha256"],
                "calibration_sha256": state["calibration_sha256"],
                "route_ids": [str(route["route_id"]) for route in routes],
                "observed_cost_stop_usd": 5.0,
                "cost_control_mode": "post_provider_call_observed_known_cost_stop",
                "max_cost_overshoot_api_calls": 1,
                "max_api_calls": 68,
                "max_routes": 2,
                "allow_unknown_costs": True,
            }
            body["receipt_sha256"] = "sha256:" + hashlib.sha256(
                json.dumps(
                    body, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False, allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            approval.write_text(json.dumps(body), encoding="utf-8")
            calls: list[str] = []

            def counting_runner(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                calls.append(str(route["requested_route"]))
                return {}

            with patch("sys.stdout", new_callable=StringIO) as stdout:
                code = main(
                    [
                        "resume", str(root), "--qualification-approval", str(approval),
                        "--max-cost-usd", "5", "--max-api-calls", "68", "--max-routes", "2",
                        "--allow-unknown-costs",
                    ],
                    suite_runner=counting_runner,
                )
            self.assertEqual(2, code)
            self.assertIn(
                "conversation_approval_not_host_verified", stdout.getvalue()
            )
            self.assertEqual([], calls)

    def test_signed_qualification_and_full_flow_completes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            self.assertEqual(
                0,
                main(
                    ["benchmark", "--all-accessible", "--output-root", str(root), "--reasoning-effort", "high"],
                    doctor_fn=self.doctor,
                    inventory_loader=self.inventory,
                    calibration_runner=self.calibration,
                ),
            )
            approval = self.signed_cli_approval(
                root, stage="qualification", max_cost_usd=5.0, max_api_calls=32,
                max_routes=2, allow_unknown_costs=True,
            )
            qualification_contract_tuple = qualification_contract_for_route_count(2)

            def runner(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                if stage == "qualification":
                    return self.native_qualification_report(
                        route,
                        output,
                        effort,
                        qualification_contract_tuple=qualification_contract_tuple,
                        telemetry=qualification_usage(
                            api_calls=4,
                            cost_usd=None,
                            known_cost_usd=0.0,
                            unknown_cost_api_calls=4,
                        ),
                    )
                return self.native_full_report(root, route, output, effort)

            self.assertEqual(
                0,
                main(
                    [
                        "resume", str(root), *approval,
                        "--max-cost-usd", "5", "--max-api-calls", "32", "--max-routes", "2",
                        "--allow-unknown-costs",
                    ],
                    suite_runner=runner,
                ),
            )
            state = json.loads((root / "CAMPAIGN.json").read_text(encoding="utf-8"))
            self.assertEqual("external_signature", state["spend"]["qualification_approval_assurance"])

            full_approval = self.signed_cli_approval(
                root, stage="full", max_cost_usd=50.0, max_api_calls=2720,
                max_routes=2, allow_unknown_costs=True,
            )
            self.assertEqual(
                0,
                main(
                    [
                        "resume", str(root), *full_approval,
                        "--max-cost-usd", "50", "--max-api-calls", "2720", "--max-routes", "2",
                        "--allow-unknown-costs",
                    ],
                    suite_runner=runner,
                ),
            )
            state = json.loads((root / "CAMPAIGN.json").read_text(encoding="utf-8"))
            self.assertEqual("external_signature", state["spend"]["full_run_approval_assurance"])
            self.assertEqual("exploratory", state["evidence_posture"])
            self.assertFalse(state["release_authorized"])
            self.assertIn("release_not_authorized", state["authority_blockers"])
            with patch("sys.stdout", new_callable=StringIO) as stdout:
                self.assertEqual(0, main(["report", str(root)]))
            public_report = json.loads(stdout.getvalue())
            self.assertEqual("exploratory", public_report["evidence_posture"])
            self.assertEqual(2, len(public_report["route_authority"]))
            self.assertEqual(
                0,
                main(["verify", str(root)], suite_verifier=lambda _output: []),
            )

            result_path = next((root / "qualification" / "results").glob("*.json"))
            result = json.loads(result_path.read_text(encoding="utf-8"))
            canonical = lambda value: "sha256:" + hashlib.sha256(
                json.dumps(
                    value,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            self.assertTrue(result["campaign_suite_verified"])
            self.assertGreaterEqual(result["campaign_elapsed_seconds"], 0)
            valid_elapsed = result["campaign_elapsed_seconds"]
            self.assertNotIn("campaign_suite_verified", result["suite_report"])
            self.assertNotIn("campaign_elapsed_seconds", result["suite_report"])

            native_usage = cast(
                dict[str, object], result["suite_report"]["controller_usage"]
            )
            valid_api_calls = native_usage["api_calls"]
            native_usage["api_calls"] = False
            result["suite_report_sha256"] = canonical(result["suite_report"])
            unsigned_result = dict(result)
            unsigned_result.pop("receipt_sha256")
            result["receipt_sha256"] = canonical(unsigned_result)
            result_path.write_text(json.dumps(result), encoding="utf-8")
            self.assertEqual(
                2,
                main(["verify", str(root)], suite_verifier=lambda _output: []),
            )
            native_usage["api_calls"] = valid_api_calls
            result["suite_report_sha256"] = canonical(result["suite_report"])

            result["campaign_suite_verified"] = False
            unsigned_result = dict(result)
            unsigned_result.pop("receipt_sha256")
            result["receipt_sha256"] = canonical(unsigned_result)
            result_path.write_text(json.dumps(result), encoding="utf-8")
            self.assertEqual(
                2,
                main(["verify", str(root)], suite_verifier=lambda _output: []),
            )

            result["campaign_suite_verified"] = True
            result["campaign_elapsed_seconds"] = -1
            unsigned_result = dict(result)
            unsigned_result.pop("receipt_sha256")
            result["receipt_sha256"] = canonical(unsigned_result)
            result_path.write_text(json.dumps(result), encoding="utf-8")
            self.assertEqual(
                2,
                main(["verify", str(root)], suite_verifier=lambda _output: []),
            )

            result["campaign_elapsed_seconds"] = valid_elapsed
            result["suite_report"]["campaign_suite_verified"] = result.pop(
                "campaign_suite_verified"
            )
            result["suite_report"]["campaign_elapsed_seconds"] = result.pop(
                "campaign_elapsed_seconds"
            )
            legacy_tree = (
                "sha256:967445bec99f6df126ae5bbfd19cce47527f4cc50d78bd918ed8c339f8c99c68"
            )
            result["suite_report"]["release_tree_sha256"] = legacy_tree
            sealed_path = Path(result["suite_output"]) / "suite-report.json"
            sealed_report = json.loads(sealed_path.read_text(encoding="utf-8"))
            sealed_report["release_tree_sha256"] = legacy_tree
            sealed_path.write_text(json.dumps(sealed_report), encoding="utf-8")
            result["suite_report_sha256"] = canonical(result["suite_report"])
            unsigned_result = dict(result)
            unsigned_result.pop("receipt_sha256")
            result["receipt_sha256"] = canonical(unsigned_result)
            result_path.write_text(json.dumps(result), encoding="utf-8")
            attempt_id = result["attempt_id"]
            event_path = root / "qualification/attempts" / f"{attempt_id}.completed.json"
            event = json.loads(event_path.read_text(encoding="utf-8"))
            event["result_receipt_sha256"] = result["receipt_sha256"]
            unsigned_event = dict(event)
            unsigned_event.pop("receipt_sha256")
            event["receipt_sha256"] = canonical(unsigned_event)
            event_path.write_text(json.dumps(event), encoding="utf-8")
            self.assertEqual(
                2,
                main(["verify", str(root)], suite_verifier=lambda _output: []),
            )

            unsupported_tree = "sha256:" + "d" * 64
            result["suite_report"]["release_tree_sha256"] = unsupported_tree
            sealed_report["release_tree_sha256"] = unsupported_tree
            sealed_path.write_text(json.dumps(sealed_report), encoding="utf-8")
            result["suite_report_sha256"] = canonical(result["suite_report"])
            unsigned_result = dict(result)
            unsigned_result.pop("receipt_sha256")
            result["receipt_sha256"] = canonical(unsigned_result)
            result_path.write_text(json.dumps(result), encoding="utf-8")
            self.assertEqual(
                2,
                main(["verify", str(root)], suite_verifier=lambda _output: []),
            )

            result["suite_report"]["campaign_suite_verified"] = False
            result["suite_report_sha256"] = canonical(result["suite_report"])
            unsigned_result = dict(result)
            unsigned_result.pop("receipt_sha256")
            result["receipt_sha256"] = canonical(unsigned_result)
            result_path.write_text(json.dumps(result), encoding="utf-8")
            self.assertEqual(
                2,
                main(["verify", str(root)], suite_verifier=lambda _output: []),
            )

    def test_blocked_unknown_cost_returns_distinct_nonzero_status(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            self.assertEqual(
                0,
                main(
                    ["benchmark", "--all-accessible", "--output-root", str(root), "--reasoning-effort", "high"],
                    doctor_fn=self.doctor,
                    inventory_loader=self.inventory,
                    calibration_runner=self.calibration,
                ),
            )
            approval = self.signed_cli_approval(
                root, stage="qualification", max_cost_usd=1.0, max_api_calls=16, max_routes=1
            )
            qualification_contract_tuple = qualification_contract_for_route_count(2)

            def unknown_cost_runner(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                self.assertEqual("qualification", stage)
                return self.native_qualification_report(
                    route,
                    output,
                    effort,
                    qualification_contract_tuple=qualification_contract_tuple,
                    telemetry=qualification_usage(
                        api_calls=4,
                        cost_usd=None,
                        known_cost_usd=0.0,
                        unknown_cost_api_calls=4,
                    ),
                )

            code = main(
                [
                    "resume", str(root), *approval,
                    "--max-cost-usd", "1.0", "--max-api-calls", "16", "--max-routes", "1",
                ],
                suite_runner=unknown_cost_runner,
            )
            self.assertEqual(3, code)
            state = json.loads((root / "CAMPAIGN.json").read_text(encoding="utf-8"))
            self.assertEqual("blocked_unknown_cost", state["status"])

    def test_resume_runs_qualification_then_full_and_reports_decision(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            main(
                ["benchmark", "--all-accessible", "--output-root", str(root), "--reasoning-effort", "high"],
                doctor_fn=self.doctor,
                inventory_loader=self.inventory,
                calibration_runner=self.calibration,
            )
            calls: list[tuple[str, str]] = []
            qualification_contract_tuple = qualification_contract_for_route_count(2)
            release_approval_path, release_approval_sha256 = self.synthetic_release_approval(root)

            def suite_runner(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                requested = str(route["requested_route"])
                calls.append((stage, requested))
                if stage == "qualification":
                    return self.native_qualification_report(
                        route,
                        output,
                        effort,
                        qualification_contract_tuple=qualification_contract_tuple,
                        telemetry=qualification_usage(
                            api_calls=4,
                            cost_usd=0.05,
                            known_cost_usd=0.05,
                            unknown_cost_api_calls=0,
                        ),
                    )
                baseline = requested.endswith("current")
                return self.native_full_report(
                    root,
                    route,
                    output,
                    effort,
                    completion_rate=0.70 if baseline else 0.85,
                    matched_rate=0.60 if baseline else 0.80,
                    stability=0.40 if baseline else 0.60,
                    release_authorized=True,
                    release_approval_sha256=release_approval_sha256,
                )

            qualification_approval = self.signed_cli_approval(
                root, stage="qualification", max_cost_usd=1.0, max_api_calls=32, max_routes=2
            )
            qualification_code = main(
                [
                    "resume",
                    str(root),
                    *qualification_approval,
                    "--max-cost-usd",
                    "1.0",
                    "--max-api-calls",
                    "32",
                    "--max-routes",
                    "2",
                ],
                suite_runner=suite_runner,
            )
            self.assertEqual(0, qualification_code)
            full_approval = self.signed_cli_approval(
                root, stage="full", max_cost_usd=10.0, max_api_calls=2720, max_routes=2
            )
            full_code = main(
                [
                    "resume",
                    str(root),
                    *full_approval,
                    "--max-cost-usd",
                    "10.0",
                    "--max-api-calls",
                    "2720",
                    "--max-routes",
                    "2",
                    "--release-approval",
                    str(release_approval_path),
                    "--expected-release-approval-sha256",
                    release_approval_sha256,
                ],
                suite_runner=suite_runner,
            )
            self.assertEqual(0, full_code)
            self.assertEqual(4, len(calls))
            completed_state = json.loads((root / "CAMPAIGN.json").read_text(encoding="utf-8"))
            self.assertEqual("authoritative_comparable", completed_state["evidence_posture"])
            self.assertTrue(completed_state["release_authorized"])
            self.assertEqual([], completed_state["authority_blockers"])
            decision = json.loads((root / "DECISION_REPORT.json").read_text(encoding="utf-8"))
            self.assertEqual("switch", decision["recommendation"])
            report_code = main(["report", str(root)])
            self.assertEqual(0, report_code)
            verify_code = main(
                ["verify", str(root)],
                suite_verifier=lambda path: [],
            )
            self.assertEqual(0, verify_code)

            calibration_path = root / "CALIBRATION.json"
            original_calibration = calibration_path.read_text(encoding="utf-8")
            tampered_calibration = json.loads(original_calibration)
            tampered_calibration["cases"] = [{"tampered": True}]
            calibration_path.write_text(json.dumps(tampered_calibration), encoding="utf-8")
            self.assertEqual(
                2,
                main(["verify", str(root)], suite_verifier=lambda path: []),
            )
            calibration_path.write_text(original_calibration, encoding="utf-8")

            full_result_paths = sorted((root / "full" / "results").glob("*.json"))
            original_result = full_result_paths[0].read_text(encoding="utf-8")
            tampered_result = json.loads(original_result)
            tampered_result["observed_api_calls"] = 9999
            full_result_paths[0].write_text(json.dumps(tampered_result), encoding="utf-8")
            self.assertEqual(
                2,
                main(["verify", str(root)], suite_verifier=lambda path: []),
            )
            full_result_paths[0].write_text(original_result, encoding="utf-8")

            missing_result = full_result_paths[1].with_suffix(".held")
            full_result_paths[1].replace(missing_result)
            self.assertEqual(
                2,
                main(["verify", str(root)], suite_verifier=lambda path: []),
            )
            missing_result.replace(full_result_paths[1])

            decision["recommendation"] = "stay"
            (root / "DECISION_REPORT.json").write_text(
                json.dumps(decision, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            tampered_code = main(
                ["verify", str(root)],
                suite_verifier=lambda path: [],
            )
            self.assertEqual(2, tampered_code)


if __name__ == "__main__":
    unittest.main()
