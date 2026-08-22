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
        self.assertEqual(
            0,
            main(
                [
                    "benchmark", "--all-accessible", "--output-root", str(root),
                    "--reasoning-effort", "high",
                    "--qualification-cost-stop-usd", str(max_cost_usd),
                    "--qualification-max-routes", "2",
                    *(["--allow-unknown-costs"] if allow_unknown_costs else []),
                ],
                doctor_fn=self.doctor, inventory_loader=self.inventory,
                calibration_runner=self.calibration,
            ),
        )
        _plan, routes = _planned_stage_routes(
            root.resolve(), load_campaign(root), stage="qualification", route_cap=2
        )
        route = dict(cast(Mapping[str, object], routes[0]))
        plan = json.loads((root / "PLAN.json").read_text(encoding="utf-8"))
        route.update({
            "max_observed_cost_usd": max_cost_usd,
            "max_api_calls": 24,
            "_qualification_contract_version": QUALIFICATION_CONTRACT_ID,
            "_qualification_contract": cast(Mapping[str, object], plan["qualification"]),
            "allow_unknown_costs": allow_unknown_costs,
            "_campaign_root_path": str(root.resolve()),
            "_campaign_output_relative_path": "qualification/attempts/" + "f" * 32 + ".evidence",
        })
        return route, []

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
                execution_contract_sha256=str(plan["plan_sha256"]),
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
            self.assertNotIn("--campaign-contract-fd", command)
            self.assertNotIn("--repetitions", command)
            self.assertNotIn("--max-steps-per-episode", command)
            self.assertEqual("24", command[command.index("--max-api-calls") + 1])
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
                self.assertGreaterEqual(len(pass_fds), 2)
                self.assertNotIn("--qualification-contract-json", command)
                self.assertIn("--campaign-root-fd", command)
                self.assertNotIn("--campaign-contract-fd", command)
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
            self.assertEqual([6, 6], step_limits)
            self.assertEqual([6, 6], controller_budgets)

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
                self.assertGreaterEqual(len(pass_fds), 2)
                parent_fd = pass_fds[0]
                self.assertNotIn("--qualification-contract-json", command)
                self.assertNotIn("--campaign-contract-fd", command)
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
            self.assertEqual("ready_for_qualification", state["status"])
            self.assertTrue((root / "CALIBRATION.json").is_file())

    def test_test_model_allow_unknown_costs_binds_both_stage_plans(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"

            def suite_runner(*args: object, **kwargs: object) -> dict[str, object]:
                raise RuntimeError("qualification child must not run in this contract test")

            code = main(
                [
                    "test-model",
                    "openai-codex/candidate",
                    "--output-root",
                    str(root),
                    "--allow-unknown-costs",
                ],
                doctor_fn=self.doctor,
                inventory_loader=self.inventory,
                calibration_runner=self.calibration,
                suite_runner=suite_runner,
            )
            self.assertNotEqual(0, code)
            plan = json.loads((root / "PLAN.json").read_text(encoding="utf-8"))
            self.assertTrue(plan["qualification_execution"]["allow_unknown_costs"])
            self.assertTrue(plan["full_execution"]["allow_unknown_costs"])
            self.assertEqual(2, plan["full_execution"]["max_routes"])

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







if __name__ == "__main__":
    unittest.main()
