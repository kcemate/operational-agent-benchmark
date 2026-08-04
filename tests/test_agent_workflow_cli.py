from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.agent_workflow import (
    _classify_route_failure,
    _production_suite_runner,
    _run_route_process,
    main,
)


class AgentWorkflowCliTests(unittest.TestCase):
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
                        "68",
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
            self.assertEqual(34, preview["episodes_per_route"])
            self.assertEqual(68, preview["scheduled_episodes"])
            self.assertEqual(68, preview["minimum_required_api_calls"])
            self.assertEqual("post_provider_call_observed_known_cost_stop", preview["cost_control_mode"])
            self.assertEqual(1, preview["max_cost_overshoot_api_calls"])
            self.assertTrue(preview["allow_unknown_costs"])
            self.assertEqual("exploratory_by_default", preview["intended_evidence_posture"])

    def test_production_runner_forwards_turn_level_cost_controls(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            runner = _production_suite_runner(
                source_hermes_home=None,
                release_approval=None,
                expected_release_approval_sha256=None,
                timeout_seconds=10,
            )
            route: dict[str, object] = {
                "provider": "xai-oauth",
                "model": "grok-4.5",
                "requested_route": "xai-oauth/grok-4.5",
                "max_observed_cost_usd": 4.75,
                "max_api_calls": 34,
                "allow_unknown_costs": True,
            }
            with patch(
                "tools.agent_workflow._run_route_process",
                return_value={
                    "timed_out": False,
                    "returncode": 1,
                    "diagnostic_sha256": "sha256:" + "0" * 64,
                    "error_code": "campaign_controller_failed",
                },
            ) as execute:
                runner(route, "qualification", Path(td) / "suite", "high")
            command = execute.call_args.args[0]
            self.assertEqual("17", command[command.index("--repetitions") + 1])
            self.assertEqual("1", command[command.index("--max-steps-per-episode") + 1])
            self.assertEqual("34", command[command.index("--max-api-calls") + 1])
            self.assertIn("--max-observed-cost-usd", command)
            self.assertEqual("4.75", command[command.index("--max-observed-cost-usd") + 1])
            self.assertIn("--allow-unknown-costs", command)

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
    ) -> list[str]:
        private_key = Ed25519PrivateKey.generate()
        public_path = root.parent / f"{stage}-approval-public.pem"
        request_path = root.parent / f"{stage}-approval.json"
        signature_path = root.parent / f"{stage}-approval.sig"
        public_path.write_bytes(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        code = main(
            [
                "approval-request", str(root), "--stage", stage,
                "--max-cost-usd", str(max_cost_usd), "--max-api-calls", str(max_api_calls),
                "--max-routes", str(max_routes), "--approval-public-key", str(public_path),
                "--output", str(request_path),
            ]
        )
        self.assertEqual(0, code)
        receipt = json.loads(request_path.read_text(encoding="utf-8"))
        canonical = json.dumps(
            receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        signed_bytes = Path(str(request_path) + ".signing-payload").read_bytes()
        self.assertEqual(canonical, signed_bytes)
        signature_path.write_bytes(private_key.sign(signed_bytes))
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
            "release_tree_sha256": "sha256:" + "c" * 64,
            "checks": [],
        }

    @staticmethod
    def calibration(output: Path) -> dict[str, object]:
        output.mkdir(parents=True, exist_ok=False)
        report = {"schema": "oab.calibration-report/v1", "passed": True, "cases": []}
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

    def test_conversational_qualification_requires_no_key_files(self) -> None:
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
            self.assertEqual(
                0,
                main(
                    [
                        "approval-request", str(root), "--stage", "qualification",
                        "--max-cost-usd", "5", "--max-api-calls", "68", "--max-routes", "2",
                        "--allow-unknown-costs",
                        "--conversation-approval-reference", "telegram:user-confirmed:$5:68:2:unknown-cost",
                        "--output", str(approval),
                    ]
                ),
            )
            self.assertFalse(Path(str(approval) + ".signing-payload").exists())

            def runner(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                if stage == "qualification":
                    report = {
                        "requested_route": route["requested_route"],
                        "reasoning_effort": effort,
                        "scheduled_episodes": 34,
                        "infrastructure_valid_episodes": 34,
                        "infrastructure_invalid_episodes": 0,
                        "identity_source": "provider_response",
                        "controller_usage": {"api_calls": 34, "cost_usd": None},
                        "observations": [
                            {"runner_status": "completed", "reason_codes": []},
                            {"runner_status": "completed", "reason_codes": []},
                        ],
                    }
                else:
                    report = {
                        "requested_route": route["requested_route"],
                        "reasoning_effort": effort,
                        "scheduled_episodes": 80,
                        "infrastructure_valid_episodes": 80,
                        "infrastructure_invalid_episodes": 0,
                        "pair_ids": [f"P{index:02d}" for index in range(1, 9)],
                        "repetitions": 5,
                        "release_tree_sha256": "sha256:" + "c" * 64,
                        "identity_source": "provider_response",
                        "controller_usage": {"api_calls": 1360, "cost_usd": None},
                    }
                output.mkdir(parents=True, exist_ok=False)
                (output / "suite-report.json").write_text(
                    json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
                )
                return report

            self.assertEqual(
                0,
                main(
                    [
                        "resume", str(root), "--qualification-approval", str(approval),
                        "--max-cost-usd", "5", "--max-api-calls", "68", "--max-routes", "2",
                        "--allow-unknown-costs",
                    ],
                    suite_runner=runner,
                ),
            )
            state = json.loads((root / "CAMPAIGN.json").read_text(encoding="utf-8"))
            self.assertEqual("conversation_attested", state["spend"]["qualification_approval_assurance"])

            full_approval = Path(td) / "full-conversation.json"
            self.assertEqual(
                0,
                main(
                    [
                        "approval-request", str(root), "--stage", "full",
                        "--max-cost-usd", "50", "--max-api-calls", "2720", "--max-routes", "2",
                        "--allow-unknown-costs",
                        "--conversation-approval-reference", "telegram:user-confirmed:$50:2720:2:unknown-cost",
                        "--output", str(full_approval),
                    ]
                ),
            )
            self.assertEqual(
                0,
                main(
                    [
                        "resume", str(root), "--full-approval", str(full_approval),
                        "--max-cost-usd", "50", "--max-api-calls", "2720", "--max-routes", "2",
                        "--allow-unknown-costs",
                    ],
                    suite_runner=runner,
                ),
            )
            state = json.loads((root / "CAMPAIGN.json").read_text(encoding="utf-8"))
            self.assertEqual("conversation_attested", state["spend"]["full_run_approval_assurance"])
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
                root, stage="qualification", max_cost_usd=1.0, max_api_calls=34, max_routes=1
            )

            def unknown_cost_runner(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                return {
                    "requested_route": route["requested_route"],
                    "reasoning_effort": effort,
                    "scheduled_episodes": 34,
                    "infrastructure_valid_episodes": 34,
                    "infrastructure_invalid_episodes": 0,
                    "identity_source": "provider_response",
                    "controller_usage": {"api_calls": 34, "cost_usd": None},
                    "observations": [
                        {"runner_status": "completed", "reason_codes": []},
                        {"runner_status": "completed", "reason_codes": []},
                    ],
                }

            code = main(
                [
                    "resume", str(root), *approval,
                    "--max-cost-usd", "1.0", "--max-api-calls", "34", "--max-routes", "1",
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

            def suite_runner(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                requested = str(route["requested_route"])
                calls.append((stage, requested))
                if stage == "qualification":
                    report: dict[str, object] = {
                        "requested_route": requested,
                        "reasoning_effort": effort,
                        "scheduled_episodes": 34,
                        "infrastructure_valid_episodes": 34,
                        "infrastructure_invalid_episodes": 0,
                        "identity_source": "provider_response",
                        "controller_config_sha256": "sha256:" + "a" * 64,
                        "controller_usage": {"api_calls": 34, "cost_usd": 0.1},
                        "observations": [],
                    }
                else:
                    baseline = requested.endswith("current")
                    report = {
                        "requested_route": requested,
                        "authoritative": True,
                        "reasoning_effort": effort,
                        "controller_config_sha256": "sha256:" + "b" * 64,
                        "release_tree_sha256": "sha256:" + "c" * 64,
                        "release_authorized": True,
                        "execution_environment": {"platform": "darwin", "sandbox_backend": "sandbox-exec"},
                        "scheduled_episodes": 80,
                        "infrastructure_valid_episodes": 80,
                        "pair_ids": [f"P{index:02d}" for index in range(1, 9)],
                        "repetitions": 5,
                        "deterministic_contract_completion_rate": 0.70 if baseline else 0.85,
                        "matched_pair_completion_rate": 0.60 if baseline else 0.80,
                        "pair_stability": {"min": 0.40 if baseline else 0.60},
                        "controller_usage": {"api_calls": 80, "cost_usd": 2.0},
                    }
                output.mkdir(parents=True, exist_ok=False)
                (output / "suite-report.json").write_text(
                    json.dumps(report, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                return report

            qualification_approval = self.signed_cli_approval(
                root, stage="qualification", max_cost_usd=1.0, max_api_calls=68, max_routes=2
            )
            qualification_code = main(
                [
                    "resume",
                    str(root),
                    *qualification_approval,
                    "--max-cost-usd",
                    "1.0",
                    "--max-api-calls",
                    "68",
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
