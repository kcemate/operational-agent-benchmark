from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from typing import cast
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oab.agent_workflow import (
    build_campaign_plan,
    build_conversational_stage_approval,
    build_decision_report,
    build_stage_approval_request,
    classify_qualification,
    doctor_environment,
    initialize_campaign,
    load_hermes_inventory,
    load_campaign,
    record_calibration,
    run_full_stage,
    run_qualification_stage,
    sanitize_hermes_inventory,
    verify_stage_approval,
)

FULL_PAIR_IDS = [f"P{index:02d}" for index in range(1, 9)]


class AgentWorkflowContractTests(unittest.TestCase):
    def signed_stage_approval(
        self,
        root: Path,
        *,
        stage: str,
        max_cost_usd: float,
        max_api_calls: int,
        max_routes: int,
        allow_unknown_costs: bool,
    ) -> dict[str, Path]:
        state = load_campaign(root)
        if state.get("calibration_passed") is not True:
            record_calibration(
                root,
                {"schema": "oab.calibration-report/v1", "passed": True, "failures": []},
            )
        private_key = Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        serial = len(list(root.parent.glob("test-approval-*.json")))
        public_path = root.parent / f"test-approval-{serial}.pem"
        receipt_path = root.parent / f"test-approval-{serial}.json"
        signature_path = root.parent / f"test-approval-{serial}.sig"
        public_path.write_bytes(public_bytes)
        receipt = build_stage_approval_request(
            root,
            stage=stage,
            max_cost_usd=max_cost_usd,
            max_api_calls=max_api_calls,
            max_routes=max_routes,
            allow_unknown_costs=allow_unknown_costs,
            approval_public_key_path=public_path,
        )
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        signed_bytes = json.dumps(
            receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        signature_path.write_bytes(private_key.sign(signed_bytes))
        return {
            "approval_path": receipt_path,
            "approval_signature_path": signature_path,
            "approval_public_key_path": public_path,
        }

    def test_stage_approval_requires_valid_signature_and_exact_controls(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            private_key = Ed25519PrivateKey.generate()
            public_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            public_path = root / "approval-public.pem"
            public_path.write_bytes(public_bytes)
            body: dict[str, object] = {
                "schema": "oab.stage-approval/v4",
                "created_at": "2026-08-04T00:00:00+00:00",
                "stage": "qualification",
                "plan_sha256": "sha256:" + "a" * 64,
                "calibration_sha256": "sha256:" + "c" * 64,
                "route_ids": ["route-a", "route-b"],
                "observed_cost_stop_usd": 1.0,
                "cost_control_mode": "post_provider_call_observed_known_cost_stop",
                "max_cost_overshoot_api_calls": 1,
                "max_api_calls": 68,
                "max_routes": 2,
                "allow_unknown_costs": False,
                "approval_public_key_sha256": "sha256:" + hashlib.sha256(public_bytes).hexdigest(),
            }
            body_bytes = json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode("utf-8")
            receipt = dict(body)
            receipt["receipt_sha256"] = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
            signed_bytes = json.dumps(
                receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode("utf-8")
            receipt_path = root / "approval.json"
            signature_path = root / "approval.sig"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            signature_path.write_bytes(private_key.sign(signed_bytes))
            kwargs = {
                "expected_plan_sha256": body["plan_sha256"],
                "expected_calibration_sha256": body["calibration_sha256"],
                "expected_stage": "qualification",
                "expected_route_ids": ["route-a", "route-b"],
                "expected_max_cost_usd": 1.0,
                "expected_max_api_calls": 68,
                "expected_max_routes": 2,
                "expected_allow_unknown_costs": False,
                "public_key_path": public_path,
                "signature_path": signature_path,
            }
            self.assertEqual([], verify_stage_approval(receipt_path, **kwargs))
            self.assertIn(
                "stage_approval_calibration_mismatch",
                verify_stage_approval(
                    receipt_path,
                    **{**kwargs, "expected_calibration_sha256": "sha256:" + "d" * 64},
                ),
            )
            self.assertIn(
                "stage_approval_api_call_limit_mismatch",
                verify_stage_approval(receipt_path, **{**kwargs, "expected_max_api_calls": 69}),
            )
            signature_path.write_bytes(b"")
            self.assertIn("stage_approval_signature_invalid", verify_stage_approval(receipt_path, **kwargs))

    def test_conversational_approval_binds_exact_controls_without_key_ceremony(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                inventory_payload=self.inventory(),
                reasoning_effort="high",
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
            )
            record_calibration(root, {"schema": "oab.calibration-report/v1", "passed": True})
            approval_path = Path(td) / "qualification-conversation.json"
            with self.assertRaisesRegex(ValueError, "conversation_approval_reference_invalid"):
                build_conversational_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=5.0,
                    max_api_calls=68,
                    max_routes=2,
                    allow_unknown_costs=True,
                    user_approval_reference="telegram:user-approved\nembedded-text",
                )
            receipt = build_conversational_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=5.0,
                max_api_calls=68,
                max_routes=2,
                allow_unknown_costs=True,
                user_approval_reference="telegram:user-confirmed:$5:68:2:unknown-cost",
                output_path=approval_path,
            )
            self.assertEqual("oab.conversational-stage-approval/v2", receipt["schema"])
            self.assertEqual("conversation_attested", receipt["approval_assurance"])
            self.assertEqual(5.0, receipt["observed_cost_stop_usd"])
            self.assertEqual(
                "post_provider_call_observed_known_cost_stop", receipt["cost_control_mode"]
            )
            self.assertEqual(1, receipt["max_cost_overshoot_api_calls"])
            with self.assertRaisesRegex(ValueError, "conversation_approval_cost_limit_mismatch"):
                run_qualification_stage(
                    root,
                    runner=lambda route, _stage, _output, _effort: self.qualification_report(
                        str(route["requested_route"])
                    ),
                    approval_path=approval_path,
                    approval_signature_path=None,
                    approval_public_key_path=None,
                    max_cost_usd=6.0,
                    max_api_calls=68,
                    max_routes=2,
                    allow_unknown_costs=True,
                )
            state = run_qualification_stage(
                root,
                runner=lambda route, _stage, _output, _effort: self.qualification_report(
                    str(route["requested_route"])
                ),
                approval_path=approval_path,
                approval_signature_path=None,
                approval_public_key_path=None,
                max_cost_usd=5.0,
                max_api_calls=68,
                max_routes=2,
                allow_unknown_costs=True,
            )
            spend = state["spend"]
            assert isinstance(spend, dict)
            self.assertTrue(spend["qualification_approved"])
            self.assertEqual("conversation_attested", spend["qualification_approval_assurance"])

    def inventory(self) -> dict[str, object]:
        return {
            "provider": "openai-codex",
            "model": "gpt-current",
            "providers": [
                {
                    "slug": "openai-codex",
                    "models": ["gpt-current", "gpt-next", "gpt-current"],
                    "capabilities": {
                        "gpt-current": {"reasoning": True, "fast": False},
                        "gpt-next": {"reasoning": True, "fast": True},
                    },
                    "api_key": "MUST-NOT-LEAK",
                    "key_env": "PRIVATE_KEY_NAME",
                },
                {
                    "slug": "xai-oauth",
                    "models": ["grok-test"],
                    "auth_token": "MUST-NOT-LEAK-EITHER",
                },
                {"slug": "moa", "models": ["virtual-model"]},
            ],
        }

    def test_inventory_is_deduplicated_and_secret_free(self) -> None:
        report = sanitize_hermes_inventory(self.inventory())
        self.assertEqual("oab.route-discovery/v1", report["schema"])
        self.assertEqual("openai-codex/gpt-current", report["current_route"])
        self.assertEqual(
            [
                "openai-codex/gpt-current",
                "openai-codex/gpt-next",
                "xai-oauth/grok-test",
            ],
            [route["requested_route"] for route in report["routes"]],
        )
        encoded = json.dumps(report, sort_keys=True)
        self.assertNotIn("MUST-NOT-LEAK", encoded)
        self.assertNotIn("PRIVATE_KEY_NAME", encoded)
        self.assertNotIn("virtual-model", encoded)
        self.assertTrue(all(route["status"] == "configured_candidate" for route in report["routes"]))

    def test_inventory_loader_disables_live_probes_and_pricing(self) -> None:
        calls: list[dict[str, object]] = []

        def builder(context: object, **kwargs: object) -> dict[str, object]:
            self.assertEqual("context", context)
            calls.append(dict(kwargs))
            return self.inventory()

        payload = load_hermes_inventory(
            context_loader=lambda: "context",
            payload_builder=builder,
        )
        self.assertEqual(self.inventory(), payload)
        self.assertEqual(1, len(calls))
        self.assertTrue(calls[0]["explicit_only"])
        self.assertFalse(calls[0]["pricing"])
        self.assertFalse(calls[0]["probe_custom_providers"])
        self.assertFalse(calls[0]["probe_current_custom_provider"])

    def test_inventory_loader_prefers_authenticated_model_options_api_without_leaking_key(self) -> None:
        requests: list[object] = []
        payloads = [
            {
                "features": {"model_options": True},
                "endpoints": {"model_options": {"method": "GET", "path": "/api/model/options"}},
            },
            {
                "provider": "openai-codex",
                "model": "current",
                "providers": [
                    {"slug": "openai-codex", "authenticated": True, "models": ["current"]},
                    {"slug": "unauthenticated", "authenticated": False, "models": ["must-skip"]},
                ],
            },
        ]

        class Response:
            def __init__(self, payload: object) -> None:
                self.body = BytesIO(json.dumps(payload).encode("utf-8"))

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, limit: int = -1) -> bytes:
                return self.body.read(limit)

        def opener(request: object, *, timeout: float) -> Response:
            requests.append(request)
            return Response(payloads[len(requests) - 1])

        raw = load_hermes_inventory(
            api_base_url="http://127.0.0.1:8642",
            api_key="MUST-NOT-LEAK",
            urlopen=opener,
        )
        report = sanitize_hermes_inventory(raw)
        self.assertEqual(1, report["route_count"])
        self.assertEqual("hermes_api_model_options", report["source"])
        self.assertNotIn("MUST-NOT-LEAK", json.dumps(raw, sort_keys=True))
        self.assertEqual(2, len(requests))
        self.assertEqual("Bearer MUST-NOT-LEAK", getattr(requests[0], "get_header")("Authorization"))

    def test_inventory_api_never_sends_local_bearer_key_to_non_loopback_host(self) -> None:
        def opener(*args: object, **kwargs: object) -> object:
            self.fail("untrusted endpoint must be rejected before a request is opened")

        for url in ("http://attacker.example:8642", "https://attacker.example:8642"):
            with self.subTest(url=url):
                with self.assertRaisesRegex(RuntimeError, "inventory_api_credentials_require_loopback"):
                    load_hermes_inventory(
                        api_base_url=url,
                        api_key="MUST-NOT-LEAK",
                        urlopen=opener,
                    )

    def test_inventory_api_rejects_cleartext_non_loopback_without_key(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "inventory_api_credentials_require_loopback"):
            load_hermes_inventory(
                api_base_url="http://attacker.example:8642",
                api_key=None,
                urlopen=lambda *args, **kwargs: self.fail("request must not open"),
            )

    def test_doctor_fails_closed_on_manifest_or_sandbox_failure(self) -> None:
        with patch("oab.agent_workflow.importlib.util.find_spec") as find_spec:
            report = doctor_environment(
                benchmark_root=Path("/benchmark"),
                platform_name="linux",
                which=lambda name: "/usr/bin/hermes" if name == "hermes" else None,
                release_manifest_errors=["tree_sha256_mismatch"],
            )
        find_spec.assert_not_called()
        self.assertEqual("oab.doctor/v1", report["schema"])
        self.assertFalse(report["ready"])
        failed = {check["id"] for check in report["checks"] if check["status"] == "fail"}
        self.assertEqual({"release_manifest", "hermes_inventory", "sandbox_backend"}, failed)

    def test_doctor_can_be_ready_without_reading_credentials(self) -> None:
        report = doctor_environment(
            benchmark_root=Path("/benchmark"),
            platform_name="darwin",
            which=lambda name: f"/usr/bin/{name}" if name in {"hermes", "sandbox-exec"} else None,
            inventory_available=True,
            release_manifest_errors=[],
        )
        self.assertTrue(report["ready"])
        self.assertNotIn("credential", json.dumps(report).lower())

    def test_doctor_external_tree_pin_mismatch_blocks_readiness(self) -> None:
        from tools.release_manifest import build_release_manifest

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("hello", encoding="utf-8")
            manifest = build_release_manifest(root)
            (root / "RELEASE_MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
            report = doctor_environment(
                benchmark_root=root,
                platform_name="darwin",
                which=lambda name: f"/usr/bin/{name}" if name in {"hermes", "sandbox-exec"} else None,
                inventory_available=True,
                expected_release_tree_sha256="sha256:" + "0" * 64,
            )
        self.assertFalse(report["ready"])
        raw_checks = cast(list[dict[str, object]], report["checks"])
        release_check = next(check for check in raw_checks if check["id"] == "release_manifest")
        self.assertIn("externally_pinned_tree_digest_mismatch", str(release_check["detail"]))

    def test_doctor_reports_missing_hermes_package_without_crashing(self) -> None:
        with patch(
            "oab.agent_workflow.importlib.util.find_spec",
            side_effect=ModuleNotFoundError("No module named 'hermes_cli'"),
        ):
            report = doctor_environment(
                benchmark_root=Path("/benchmark"),
                platform_name="darwin",
                which=lambda name: f"/usr/bin/{name}" if name in {"hermes", "sandbox-exec"} else None,
                release_manifest_errors=[],
            )
        self.assertFalse(report["ready"])
        raw_checks = cast(list[dict[str, object]], report["checks"])
        checks = {str(check["id"]): check for check in raw_checks}
        self.assertEqual("fail", checks["hermes_inventory"]["status"])

    def test_plan_is_no_spend_and_counts_both_stages(self) -> None:
        discovery = sanitize_hermes_inventory(self.inventory())
        plan = build_campaign_plan(discovery, reasoning_effort="high")
        self.assertEqual("oab.campaign-plan/v1", plan["schema"])
        self.assertEqual("awaiting_calibration", plan["status"])
        self.assertEqual(3, plan["route_count"])
        self.assertEqual(6, plan["qualification"]["scheduled_episodes"])
        self.assertEqual(240, plan["full_run"]["scheduled_episodes"])
        self.assertEqual("unknown_until_qualification", plan["cost_estimate"]["status"])
        self.assertEqual("unknown_until_qualification", plan["duration_estimate"]["status"])
        self.assertFalse(plan["spend_authorized"])

    def test_scoreable_model_failure_still_qualifies_route(self) -> None:
        report = {
            "requested_route": "openai-codex/gpt-current",
            "reasoning_effort": "high",
            "scheduled_episodes": 2,
            "infrastructure_valid_episodes": 2,
            "infrastructure_invalid_episodes": 0,
            "identity_source": "provider_response",
            "controller_config_sha256": "sha256:" + "a" * 64,
            "controller_usage": {"api_calls": 2, "cost_usd": 0.12},
            "observations": [
                {"runner_status": "task_failed", "reason_codes": ["model_protocol_invalid"]},
                {"runner_status": "completed", "reason_codes": []},
            ],
        }
        result = classify_qualification(report, requested_route="openai-codex/gpt-current", reasoning_effort="high")
        self.assertEqual("qualified", result["status"])
        self.assertEqual(0.12, result["observed_cost_usd"])

    def test_auth_failure_is_not_a_model_score(self) -> None:
        report = {
            "requested_route": "xai-oauth/grok-test",
            "reasoning_effort": "high",
            "scheduled_episodes": 2,
            "infrastructure_valid_episodes": 0,
            "infrastructure_invalid_episodes": 2,
            "identity_source": None,
            "controller_usage": {"api_calls": 0, "cost_usd": 0.0},
            "observations": [
                {"runner_status": "runner_invalid", "reason_codes": ["provider_auth_unavailable"]},
                {"runner_status": "runner_invalid", "reason_codes": ["provider_auth_unavailable"]},
            ],
        }
        result = classify_qualification(report, requested_route="xai-oauth/grok-test", reasoning_effort="high")
        self.assertEqual("authentication_invalid", result["status"])
        self.assertFalse(result["scoreable"])

    def test_effort_mismatch_is_incompatible(self) -> None:
        report = {
            "requested_route": "openai-codex/gpt-current",
            "reasoning_effort": "medium",
            "scheduled_episodes": 2,
            "infrastructure_valid_episodes": 2,
            "infrastructure_invalid_episodes": 0,
            "identity_source": "provider_response",
            "controller_usage": {"api_calls": 2, "cost_usd": None},
            "observations": [],
        }
        result = classify_qualification(report, requested_route="openai-codex/gpt-current", reasoning_effort="high")
        self.assertEqual("effort_incompatible", result["status"])

    def test_route_rate_and_provider_failures_remain_distinct(self) -> None:
        cases = (
            ("provider_route_unavailable", "route_unavailable"),
            ("provider_rate_limited", "provider_rate_limited"),
            ("provider_unavailable", "provider_unavailable"),
            ("provider_reasoning_effort_unsupported", "effort_incompatible"),
        )
        for reason, expected in cases:
            with self.subTest(reason=reason):
                report = {
                    "requested_route": "openai-codex/gpt-current",
                    "reasoning_effort": "high",
                    "scheduled_episodes": 2,
                    "infrastructure_valid_episodes": 0,
                    "infrastructure_invalid_episodes": 2,
                    "controller_usage": {"cost_usd": 0.0},
                    "observations": [
                        {"runner_status": "runner_invalid", "reason_codes": [reason]}
                    ],
                }
                result = classify_qualification(
                    report,
                    requested_route="openai-codex/gpt-current",
                    reasoning_effort="high",
                )
                self.assertEqual(expected, result["status"])
                self.assertFalse(result["scoreable"])

    def test_initialization_writes_machine_readable_no_spend_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            doctor = {"schema": "oab.doctor/v1", "ready": True, "checks": []}
            state = initialize_campaign(
                root,
                doctor=doctor,
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            self.assertEqual("awaiting_calibration", state["status"])
            self.assertTrue((root / "DOCTOR.json").is_file())
            self.assertTrue((root / "DISCOVERY.json").is_file())
            self.assertTrue((root / "PLAN.json").is_file())
            self.assertTrue((root / "CAMPAIGN.json").is_file())
            encoded = "".join(path.read_text(encoding="utf-8") for path in root.glob("*.json"))
            self.assertNotIn("MUST-NOT-LEAK", encoded)
            self.assertEqual(state, load_campaign(root, expected_reasoning_effort="high"))
            plan = json.loads((root / "PLAN.json").read_text(encoding="utf-8"))
            self.assertRegex(plan["plan_sha256"], r"^sha256:[0-9a-f]{64}$")

    def test_stage_approval_request_requires_passing_calibration(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            public_path = Path(td) / "approval-public.pem"
            public_path.write_bytes(
                Ed25519PrivateKey.generate().public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            with self.assertRaisesRegex(ValueError, "campaign_calibration_required"):
                build_stage_approval_request(
                    root,
                    stage="qualification",
                    max_cost_usd=1.0,
                    max_api_calls=34,
                    max_routes=1,
                    allow_unknown_costs=False,
                    approval_public_key_path=public_path,
                )

    def test_resume_rejects_configuration_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            with self.assertRaisesRegex(ValueError, "campaign_reasoning_effort_mismatch"):
                load_campaign(root, expected_reasoning_effort="medium")

    def test_campaign_root_must_be_disjoint_from_benchmark_repository(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repository = Path(td) / "repository"
            repository.mkdir()
            with self.assertRaisesRegex(ValueError, "campaign_and_benchmark_must_be_disjoint"):
                initialize_campaign(
                    repository / "campaign",
                    doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                    inventory_payload=self.inventory(),
                    reasoning_effort="high",
                    repository_root=repository,
                )

    @staticmethod
    def qualification_report(route: str, *, cost: float | None = 0.1) -> dict[str, object]:
        return {
            "requested_route": route,
            "reasoning_effort": "high",
            "scheduled_episodes": 2,
            "infrastructure_valid_episodes": 2,
            "infrastructure_invalid_episodes": 0,
            "identity_source": "provider_response",
            "controller_config_sha256": "sha256:" + "a" * 64,
            "controller_usage": {"api_calls": 2, "cost_usd": cost},
            "campaign_elapsed_seconds": 2.0,
            "observations": [
                {"runner_status": "task_failed", "reason_codes": ["model_protocol_invalid"]},
                {"runner_status": "completed", "reason_codes": []},
            ],
        }

    def test_qualification_excludes_auth_failure_and_projects_known_cost(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            calls: list[str] = []

            def runner(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                requested = str(route["requested_route"])
                calls.append(requested)
                self.assertEqual("qualification", stage)
                self.assertEqual("high", effort)
                if requested.startswith("xai-oauth/"):
                    return {
                        "requested_route": requested,
                        "reasoning_effort": "high",
                        "scheduled_episodes": 2,
                        "infrastructure_valid_episodes": 0,
                        "infrastructure_invalid_episodes": 2,
                        "identity_source": None,
                        "controller_usage": {"api_calls": 1, "cost_usd": 0.4},
                        "observations": [
                            {"runner_status": "runner_invalid", "reason_codes": ["provider_auth_unavailable"]}
                        ],
                    }
                return self.qualification_report(requested)

            state = run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=102,
                max_routes=3,
                **self.signed_stage_approval(
                    root, stage="qualification", max_cost_usd=1.0, max_api_calls=102,
                    max_routes=3, allow_unknown_costs=False,
                ),
            )
            self.assertEqual("awaiting_full_run_approval", state["status"])
            self.assertEqual(3, len(calls))
            self.assertEqual(2, len(state["qualified_routes"]))
            self.assertEqual(1, len(state["excluded_routes"]))
            self.assertAlmostEqual(0.6, state["spend"]["observed_qualification_cost_usd"])
            approvals = list((root / "APPROVALS").glob("qualification-*.json"))
            self.assertEqual(1, len(approvals))
            approval = json.loads(approvals[0].read_text(encoding="utf-8"))
            self.assertEqual("qualification", approval["stage"])
            self.assertEqual(102, approval["max_api_calls"])
            self.assertEqual(3, approval["max_routes"])
            self.assertRegex(approval["receipt_sha256"], r"^sha256:[0-9a-f]{64}$")
            qualification = json.loads((root / "QUALIFICATION.json").read_text(encoding="utf-8"))
            self.assertEqual(8.0, qualification["projected_full_run_cost_usd"])
            self.assertEqual(160.0, qualification["projected_full_run_duration_seconds"])

    def test_infrastructure_invalid_known_cost_exhausts_signed_budget(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )

            def runner(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                return {
                    "requested_route": str(route["requested_route"]),
                    "reasoning_effort": "high",
                    "scheduled_episodes": 2,
                    "infrastructure_valid_episodes": 0,
                    "infrastructure_invalid_episodes": 2,
                    "identity_source": None,
                    "controller_usage": {"api_calls": 1, "cost_usd": 0.6},
                    "observations": [
                        {"runner_status": "runner_invalid", "reason_codes": ["provider_auth_unavailable"]}
                    ],
                }

            state = run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=0.5,
                allow_unknown_costs=False,
                max_api_calls=34,
                max_routes=1,
                **self.signed_stage_approval(
                    root, stage="qualification", max_cost_usd=0.5, max_api_calls=34,
                    max_routes=1, allow_unknown_costs=False,
                ),
            )
            self.assertEqual("qualification_budget_exhausted", state["status"])
            self.assertAlmostEqual(0.6, state["spend"]["observed_qualification_cost_usd"])
            self.assertEqual(1, len(state["excluded_routes"]))

    def test_unknown_cost_pauses_and_resume_does_not_repeat_completed_route(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            calls: list[str] = []

            def runner(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                requested = str(route["requested_route"])
                calls.append(requested)
                return self.qualification_report(requested, cost=None)

            first = run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=102,
                max_routes=3,
                **self.signed_stage_approval(
                    root, stage="qualification", max_cost_usd=1.0, max_api_calls=102,
                    max_routes=3, allow_unknown_costs=False,
                ),
            )
            self.assertEqual("blocked_unknown_cost", first["status"])
            self.assertEqual(1, len(calls))
            first_route = calls[0]
            second = run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=True,
                max_api_calls=102,
                max_routes=3,
                **self.signed_stage_approval(
                    root, stage="qualification", max_cost_usd=1.0, max_api_calls=102,
                    max_routes=3, allow_unknown_costs=True,
                ),
            )
            self.assertEqual("awaiting_full_run_approval", second["status"])
            self.assertEqual(1, calls.count(first_route))
            self.assertEqual(3, len(calls))

    def test_full_stage_builds_switch_decision(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={
                    "schema": "oab.doctor/v1",
                    "ready": True,
                    "release_tree_sha256": "sha256:" + "c" * 64,
                    "checks": [],
                },
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )

            def qualify(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                return self.qualification_report(str(route["requested_route"]))

            run_qualification_stage(
                root,
                runner=qualify,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=102,
                max_routes=3,
                **self.signed_stage_approval(
                    root, stage="qualification", max_cost_usd=1.0, max_api_calls=102,
                    max_routes=3, allow_unknown_costs=False,
                ),
            )

            state_path = root / "CAMPAIGN.json"
            mutable_state = json.loads(state_path.read_text(encoding="utf-8"))
            mutable_state["current_route"] = "openai-codex/gpt-next"
            state_path.write_text(
                json.dumps(mutable_state, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            full_calls: list[str] = []

            def full(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                requested = str(route["requested_route"])
                full_calls.append(requested)
                baseline = requested.endswith("gpt-current")
                return {
                    "requested_route": requested,
                    "authoritative": True,
                    "reasoning_effort": "high",
                    "controller_config_sha256": "sha256:" + "b" * 64,
                    "release_tree_sha256": "sha256:" + "c" * 64,
                    "execution_environment": {"platform": "darwin", "sandbox_backend": "sandbox-exec"},
                    "scheduled_episodes": 80,
                    "infrastructure_valid_episodes": 80,
                    "pair_ids": FULL_PAIR_IDS,
                    "repetitions": 5,
                    "deterministic_contract_completion_rate": 0.70 if baseline else 0.85,
                    "matched_pair_completion_rate": 0.60 if baseline else 0.80,
                    "pair_stability": {"min": 0.40 if baseline else 0.60},
                    "controller_usage": {"api_calls": 80, "cost_usd": 2.0},
                }

            state = run_full_stage(
                root,
                runner=full,
                max_cost_usd=10.0,
                allow_unknown_costs=False,
                max_api_calls=2720,
                max_routes=2,
                **self.signed_stage_approval(
                    root, stage="full", max_cost_usd=10.0, max_api_calls=2720,
                    max_routes=2, allow_unknown_costs=False,
                ),
            )
            self.assertEqual("completed", state["status"])
            self.assertEqual(2, len(full_calls))
            self.assertEqual(2, len(state["full_run_routes"]))
            decision = json.loads((root / "DECISION_REPORT.json").read_text(encoding="utf-8"))
            self.assertEqual("openai-codex/gpt-current", decision["current_route"])
            self.assertEqual("switch", decision["recommendation"])
            self.assertEqual("openai-codex/gpt-next", decision["recommended_route"])

    def test_qualification_refuses_to_start_route_without_full_call_allowance(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            calls: list[str] = []

            def runner(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                calls.append(str(route["requested_route"]))
                return self.qualification_report(str(route["requested_route"]))

            state = run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=33,
                max_routes=3,
                **self.signed_stage_approval(
                    root, stage="qualification", max_cost_usd=1.0, max_api_calls=33,
                    max_routes=3, allow_unknown_costs=False,
                ),
            )
            self.assertEqual([], calls)
            self.assertEqual("qualification_call_budget_exhausted", state["status"])

    def test_route_cap_prioritizes_current_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            inventory = self.inventory()
            inventory["provider"] = "xai-oauth"
            inventory["model"] = "grok-test"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=inventory,
                reasoning_effort="high",
            )
            calls: list[str] = []

            def runner(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
                requested = str(route["requested_route"])
                calls.append(requested)
                return self.qualification_report(requested)

            run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=34,
                max_routes=1,
                **self.signed_stage_approval(
                    root, stage="qualification", max_cost_usd=1.0, max_api_calls=34,
                    max_routes=1, allow_unknown_costs=False,
                ),
            )
            self.assertEqual(["xai-oauth/grok-test"], calls)

    def test_decision_declines_without_two_authoritative_comparable_routes(self) -> None:
        report = build_decision_report(
            current_route="openai-codex/gpt-current",
            expected_pair_ids=FULL_PAIR_IDS,
            expected_repetitions=5,
            expected_release_tree_sha256="sha256:" + "c" * 64,
            suite_reports=[
                {
                    "requested_route": "openai-codex/gpt-current",
                    "authoritative": False,
                    "reasoning_effort": "high",
                }
            ],
        )
        self.assertEqual("not_supportable", report["recommendation"])
        self.assertIn("fewer_than_two_authoritative_routes", report["reasons"])

    def test_decision_rejects_cross_platform_or_backend_comparison(self) -> None:
        baseline = {
            "requested_route": "openai-codex/gpt-current",
            "authoritative": True,
            "reasoning_effort": "high",
            "controller_config_sha256": "sha256:" + "b" * 64,
            "release_tree_sha256": "sha256:" + "c" * 64,
            "scheduled_episodes": 80,
            "infrastructure_valid_episodes": 80,
            "pair_ids": FULL_PAIR_IDS,
            "repetitions": 5,
            "deterministic_contract_completion_rate": 0.70,
            "matched_pair_completion_rate": 0.60,
            "pair_stability": {"min": 0.40},
            "execution_environment": {"platform": "darwin", "sandbox_backend": "sandbox-exec"},
        }
        candidate = {
            **baseline,
            "requested_route": "openai-codex/gpt-next",
            "deterministic_contract_completion_rate": 0.90,
            "execution_environment": {"platform": "linux", "sandbox_backend": "bubblewrap-libseccomp"},
        }
        report = build_decision_report(
            current_route="openai-codex/gpt-current",
            expected_pair_ids=FULL_PAIR_IDS,
            expected_repetitions=5,
            expected_release_tree_sha256="sha256:" + "c" * 64,
            suite_reports=[baseline, candidate],
        )
        self.assertEqual("not_supportable", report["recommendation"])
        self.assertIn("fewer_than_two_authoritative_routes", report["reasons"])

    def test_decision_recommends_only_strict_dominance(self) -> None:
        baseline = {
            "requested_route": "openai-codex/gpt-current",
            "authoritative": True,
            "reasoning_effort": "high",
            "controller_config_sha256": "sha256:" + "b" * 64,
            "release_tree_sha256": "sha256:" + "c" * 64,
            "execution_environment": {"platform": "darwin", "sandbox_backend": "sandbox-exec"},
            "scheduled_episodes": 80,
            "infrastructure_valid_episodes": 80,
            "pair_ids": FULL_PAIR_IDS,
            "repetitions": 5,
            "deterministic_contract_completion_rate": 0.70,
            "matched_pair_completion_rate": 0.60,
            "pair_stability": {"min": 0.40},
        }
        candidate = {
            **baseline,
            "requested_route": "openai-codex/gpt-next",
            "deterministic_contract_completion_rate": 0.85,
            "matched_pair_completion_rate": 0.80,
            "pair_stability": {"min": 0.60},
        }
        report = build_decision_report(
            current_route="openai-codex/gpt-current",
            expected_pair_ids=FULL_PAIR_IDS,
            expected_repetitions=5,
            expected_release_tree_sha256="sha256:" + "c" * 64,
            suite_reports=[baseline, candidate],
        )
        self.assertEqual("switch", report["recommendation"])
        self.assertEqual("openai-codex/gpt-next", report["recommended_route"])

    def test_decision_rejects_different_pair_grid_even_with_80_episodes(self) -> None:
        baseline = {
            "requested_route": "openai-codex/gpt-current",
            "authoritative": True,
            "reasoning_effort": "high",
            "controller_config_sha256": "sha256:" + "b" * 64,
            "release_tree_sha256": "sha256:" + "c" * 64,
            "execution_environment": {"platform": "darwin", "sandbox_backend": "sandbox-exec"},
            "scheduled_episodes": 80,
            "infrastructure_valid_episodes": 80,
            "pair_ids": FULL_PAIR_IDS,
            "repetitions": 5,
            "deterministic_contract_completion_rate": 0.70,
            "matched_pair_completion_rate": 0.60,
            "pair_stability": {"min": 0.40},
        }
        candidate = {
            **baseline,
            "requested_route": "openai-codex/gpt-next",
            "pair_ids": [f"Q{index:02d}" for index in range(1, 9)],
            "deterministic_contract_completion_rate": 0.90,
        }
        report = build_decision_report(
            current_route="openai-codex/gpt-current",
            expected_pair_ids=FULL_PAIR_IDS,
            expected_repetitions=5,
            expected_release_tree_sha256="sha256:" + "c" * 64,
            suite_reports=[baseline, candidate],
        )
        self.assertEqual("not_supportable", report["recommendation"])
        self.assertIn("fewer_than_two_authoritative_routes", report["reasons"])


if __name__ == "__main__":
    unittest.main()
