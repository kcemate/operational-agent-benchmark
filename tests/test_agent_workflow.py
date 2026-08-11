from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from typing import Mapping, cast
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import oab.agent_workflow as agent_workflow_module
from oab.agent_workflow import (
    _attempt_accounting,
    _hermes_python_command,
    _planned_stage_routes,
    _quarantine_partial_suite,
    _validate_campaign_orchestration_metadata,
    _write_attempt_event,
    build_campaign_plan,
    build_approval_preview,
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
from oab.qualification_contract import (
    QUALIFICATION_CONTRACT_ID,
    assert_quality_free,
    qualification_contract_for_route_count,
    qualification_probe_definitions,
)
from oab.full_stage_contract import (
    authoritative_full_contract_for_route_count,
    build_authoritative_stage_binding,
)
from qualification_fixtures import qualification_usage, write_qualification_suite

FULL_PAIR_IDS = [f"P{index:02d}" for index in range(1, 9)]
_REAL_INITIALIZE_CAMPAIGN = initialize_campaign


class AgentWorkflowContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self._key_tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._key_tempdir.cleanup)
        self._approval_private_key = Ed25519PrivateKey.generate()
        self._approval_public_path = Path(self._key_tempdir.name) / "approval-authority.pem"
        self._approval_public_path.write_bytes(
            self._approval_private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self._initialize_patch = patch(
            __name__ + ".initialize_campaign",
            side_effect=self._initialize_with_pinned_test_key,
        )
        self._initialize_patch.start()
        self.addCleanup(self._initialize_patch.stop)

    def _initialize_with_pinned_test_key(self, *args: object, **kwargs: object) -> dict[str, object]:
        doctor = kwargs.get("doctor")
        if isinstance(doctor, Mapping):
            kwargs["doctor"] = {
                **dict(doctor),
                "release_tree_sha256": str(
                    doctor.get("release_tree_sha256") or ("sha256:" + "e" * 64)
                ),
            }
        kwargs.setdefault("approval_authority_public_key_path", self._approval_public_path)
        return _REAL_INITIALIZE_CAMPAIGN(*args, **kwargs)

    def authoritative_decision_context(self, *route_ids: str) -> dict[str, object]:
        plan_sha256 = "sha256:" + "a" * 64
        approval_sha256 = "sha256:" + "d" * 64
        full_plan = authoritative_full_contract_for_route_count(len(route_ids))
        return {
            "authoritative_full_plan": full_plan,
            "expected_plan_sha256": plan_sha256,
            "expected_stage_approval_sha256": approval_sha256,
            "bindings": {
                route_id: build_authoritative_stage_binding(
                    plan_sha256=plan_sha256,
                    stage_approval_sha256=approval_sha256,
                    route_id=route_id,
                    output_relative_path=f"full/attempts/{index:032x}.evidence",
                    full_plan=full_plan,
                    route_count=len(route_ids),
                )
                for index, route_id in enumerate(route_ids, start=1)
            },
        }

    def test_load_campaign_rejects_substituted_symlink_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            moved = Path(td) / "moved-campaign"
            root.rename(moved)
            root.symlink_to(moved, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "campaign_internal_path_unsafe"):
                load_campaign(root)

    def test_attempt_event_write_rejects_attempts_parent_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            attempts = root / "qualification/attempts"
            attempts.rmdir()
            outside = Path(td) / "outside"
            outside.mkdir()
            attempts.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "campaign_internal_path_unsafe"):
                _write_attempt_event(
                    root,
                    "qualification",
                    "a" * 32,
                    "reserved",
                    {
                        "route_id": "route-a",
                        "requested_route": "provider/model",
                        "reserved_api_calls": 34,
                        "max_observed_cost_usd": 1.0,
                        "approval_sha256": "sha256:" + "b" * 64,
                    },
                )
            self.assertEqual([], list(outside.iterdir()))

    def test_partial_suite_quarantine_never_moves_an_unowned_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            suite = root / "qualification/suites/route-a"
            suite.mkdir()
            (suite / "partial.txt").write_text("partial", encoding="utf-8")
            outside = Path(td) / "outside"
            outside.mkdir()
            (outside / "secret.txt").write_text("outside", encoding="utf-8")
            parked = Path(td) / "parked"
            real_replace = __import__("os").replace

            def raced_replace(source: object, destination: object) -> None:
                real_replace(suite, parked)
                real_replace(outside, suite)
                real_replace(source, destination)

            with patch("oab.agent_workflow.os.replace", side_effect=raced_replace):
                with self.assertRaisesRegex(ValueError, "campaign_partial_suite_unsafe"):
                    _quarantine_partial_suite(
                        root, "qualification", "route-a", "a" * 32
                    )
            self.assertTrue(outside.exists())
            self.assertEqual(
                "outside", (outside / "secret.txt").read_text(encoding="utf-8")
            )

    def test_orchestration_metadata_rejects_unrepresentable_elapsed_integer(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "campaign_orchestration_metadata_invalid"
        ):
            _validate_campaign_orchestration_metadata(
                {
                    "campaign_suite_verified": True,
                    "campaign_elapsed_seconds": 10**1000,
                }
            )

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
        serial = len(list(root.parent.glob("test-approval-*.json")))
        receipt_path = root.parent / f"test-approval-{serial}.json"
        signature_path = root.parent / f"test-approval-{serial}.sig"
        receipt = build_stage_approval_request(
            root,
            stage=stage,
            max_cost_usd=max_cost_usd,
            max_api_calls=max_api_calls,
            max_routes=max_routes,
            allow_unknown_costs=allow_unknown_costs,
            approval_public_key_path=self._approval_public_path,
        )
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        signed_bytes = json.dumps(
            receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        signature_path.write_bytes(self._approval_private_key.sign(signed_bytes))
        return {
            "approval_path": receipt_path,
            "approval_signature_path": signature_path,
            "approval_public_key_path": self._approval_public_path,
        }

    def test_stage_approval_requires_valid_signature_and_exact_controls(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            artifacts = self.signed_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=1.0,
                max_api_calls=48,
                max_routes=3,
                allow_unknown_costs=False,
            )
            plan = json.loads((root / "PLAN.json").read_text(encoding="utf-8"))
            state = load_campaign(root)
            kwargs = {
                "expected_plan_sha256": plan["plan_sha256"],
                "expected_calibration_sha256": state["calibration_sha256"],
                "expected_stage": "qualification",
                "expected_route_ids": [item["route_id"] for item in plan["routes"]],
                "expected_max_cost_usd": 1.0,
                "expected_max_api_calls": 48,
                "expected_max_routes": 3,
                "expected_allow_unknown_costs": False,
                "public_key_path": artifacts["approval_public_key_path"],
                "signature_path": artifacts["approval_signature_path"],
                "campaign_root": root,
                "expected_plan": plan,
            }
            receipt_path = artifacts["approval_path"]
            self.assertEqual([], verify_stage_approval(receipt_path, **kwargs))
            self.assertEqual(
                ["stage_approval_invalid"],
                verify_stage_approval(
                    receipt_path,
                    **{**kwargs, "expected_calibration_sha256": "sha256:" + "d" * 64},
                ),
            )
            self.assertEqual(
                ["stage_approval_controls_mismatch"],
                verify_stage_approval(receipt_path, **{**kwargs, "expected_max_api_calls": 47}),
            )
            artifacts["approval_signature_path"].write_bytes(b"")
            self.assertEqual(["stage_approval_invalid"], verify_stage_approval(receipt_path, **kwargs))

    def test_record_calibration_accepts_current_all_pairs_schema(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                inventory_payload=self.inventory(),
                reasoning_effort="high",
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
            )
            record_calibration(
                root,
                {
                    "schema": "oab.calibration-report/v2",
                    "passed": True,
                    "pair_count": 8,
                    "case_count": 16,
                    "cases": [],
                },
            )
            receipt = json.loads((root / "CALIBRATION.json").read_text(encoding="utf-8"))
            self.assertEqual("oab.calibration-report/v2", receipt["schema"])
            self.assertTrue(load_campaign(root)["calibration_passed"])

    def test_caller_asserted_conversational_receipt_cannot_authorize_spend(self) -> None:
        """A caller-asserted conversation reference is not host-verified evidence.

        Anyone able to run the CLI can write such a receipt, so it must never reach a
        spend-capable stage. Only the externally signed stage approval qualifies.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                inventory_payload=self.inventory(),
                reasoning_effort="high",
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
            )
            record_calibration(root, {"schema": "oab.calibration-report/v1", "passed": True})
            plan = json.loads((root / "PLAN.json").read_text(encoding="utf-8"))
            state = load_campaign(root)
            _plan, routes = _planned_stage_routes(
                root, state, stage="qualification", route_cap=2
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
                    body,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            approval_path = Path(td) / "qualification-conversation.json"
            approval_path.write_text(json.dumps(body), encoding="utf-8")
            calls: list[str] = []

            def runner(route: dict[str, object], _stage: str, output: Path, _effort: str) -> dict[str, object]:
                calls.append(str(route["requested_route"]))
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            with self.assertRaisesRegex(
                ValueError, "conversation_approval_not_host_verified"
            ):
                run_qualification_stage(
                    root,
                    runner=runner,
                    approval_path=approval_path,
                    approval_signature_path=None,
                    approval_public_key_path=None,
                    max_cost_usd=5.0,
                    max_api_calls=32,
                    max_routes=2,
                    allow_unknown_costs=True,
                )
            self.assertEqual([], calls)
            spend = load_campaign(root).get("spend")
            self.assertTrue(
                not isinstance(spend, dict)
                or spend.get("qualification_approved") is not True
            )
            self.assertFalse(sorted((root / "APPROVALS").glob("*.json")))

    def test_signed_stage_approval_still_authorizes_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                inventory_payload=self.inventory(),
                reasoning_effort="high",
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
            )
            approval = self.signed_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=5.0,
                max_api_calls=32,
                max_routes=2,
                allow_unknown_costs=True,
            )
            state = run_qualification_stage(
                root,
                runner=lambda route, _stage, output, _effort: self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                ),
                max_cost_usd=5.0,
                max_api_calls=32,
                max_routes=2,
                allow_unknown_costs=True,
                **approval,
            )
            spend = state["spend"]
            assert isinstance(spend, dict)
            self.assertTrue(spend["qualification_approved"])
            self.assertEqual(
                "external_signature", spend["qualification_approval_assurance"]
            )

    def test_route_semantics_cannot_change_after_plan_and_approval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                inventory_payload=self.inventory(),
                reasoning_effort="high",
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
            )
            approval = self.signed_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=5.0,
                max_api_calls=32,
                max_routes=2,
                allow_unknown_costs=False,
            )
            discovery_path = root / "DISCOVERY.json"
            discovery = json.loads(discovery_path.read_text(encoding="utf-8"))
            discovery["routes"][0]["provider"] = "xai-oauth"
            discovery["routes"][0]["model"] = "grok-mutated"
            discovery["routes"][0]["requested_route"] = "xai-oauth/grok-mutated"
            discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
            calls: list[object] = []

            with self.assertRaisesRegex(ValueError, "campaign_discovery_plan_mismatch"):
                run_qualification_stage(
                    root,
                    runner=lambda *args: calls.append(args),
                    max_cost_usd=5.0,
                    max_api_calls=32,
                    max_routes=2,
                    allow_unknown_costs=False,
                    **approval,
                )
            self.assertEqual([], calls)

    def test_reasoning_effort_cannot_change_after_plan_and_approval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                inventory_payload=self.inventory(),
                reasoning_effort="high",
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
            )
            approval = self.signed_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=5.0,
                max_api_calls=32,
                max_routes=2,
                allow_unknown_costs=False,
            )
            campaign_path = root / "CAMPAIGN.json"
            campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
            campaign["reasoning_effort"] = "low"
            campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
            calls: list[object] = []

            with self.assertRaisesRegex(ValueError, "campaign_reasoning_effort_mismatch"):
                run_qualification_stage(
                    root,
                    runner=lambda *args: calls.append(args),
                    max_cost_usd=5.0,
                    max_api_calls=32,
                    max_routes=2,
                    allow_unknown_costs=False,
                    **approval,
                )
            self.assertEqual([], calls)

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
                {
                    "slug": "moa",
                    "authenticated": False,
                    "models": ["virtual-model"],
                },
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

    def test_inventory_api_does_not_forward_bearer_key_through_redirects(self) -> None:
        received_authorization: list[str | None] = []

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                received_authorization.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, format: str, *args: object) -> None:
                return

        target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        target_url = f"http://127.0.0.1:{target.server_address[1]}/steal"

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", target_url)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        redirect_thread = threading.Thread(target=redirect.serve_forever, daemon=True)
        redirect_thread.start()
        try:
            with self.assertRaisesRegex(RuntimeError, "hermes_inventory_api_unavailable"):
                load_hermes_inventory(
                    api_base_url=f"http://127.0.0.1:{redirect.server_address[1]}",
                    api_key="MUST-NOT-LEAK",
                )
            self.assertEqual([], received_authorization)
        finally:
            redirect.shutdown()
            target.shutdown()
            redirect.server_close()
            target.server_close()
            redirect_thread.join(timeout=2)
            target_thread.join(timeout=2)

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

    def test_hermes_python_command_resolves_one_bounded_exec_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            interpreter = root / "runtime/python3"
            interpreter.parent.mkdir()
            interpreter.write_bytes(b"python-placeholder")

            target = root / "hermes-venv/bin/hermes"
            target.parent.mkdir(parents=True)
            target.write_text(f"#!{interpreter}\n", encoding="utf-8")

            wrapper = root / "bin/hermes"
            wrapper.parent.mkdir()
            wrapper.write_text(
                "#!/usr/bin/env bash\n"
                "unset PYTHONPATH\n"
                "unset PYTHONHOME\n"
                f'exec "{target}" "$@"\n',
                encoding="utf-8",
            )

            self.assertEqual([str(interpreter)], _hermes_python_command(str(wrapper)))

    def test_hermes_python_command_rejects_unsafe_exec_wrappers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target-hermes"
            target.write_text("#!/usr/bin/python3\n", encoding="utf-8")
            target_link = root / "target-link"
            target_link.symlink_to(target)
            hardlink_source = root / "hardlink-source"
            hardlink_source.write_text("#!/usr/bin/python3\n", encoding="utf-8")
            target_hardlink = root / "target-hardlink"
            target_hardlink.hardlink_to(hardlink_source)
            nested_target = root / "nested-target"
            nested_target.write_text(
                f'#!/usr/bin/env bash\nexec "{target}" "$@"\n', encoding="utf-8"
            )

            cases = {
                "relative": '#!/usr/bin/env bash\nexec "../target-hermes" "$@"\n',
                "symlink": f'#!/usr/bin/env bash\nexec "{target_link}" "$@"\n',
                "hardlink": f'#!/usr/bin/env bash\nexec "{target_hardlink}" "$@"\n',
                "nested-wrapper": f'#!/usr/bin/env bash\nexec "{nested_target}" "$@"\n',
                "extra-command": (
                    "#!/usr/bin/env bash\n"
                    "echo unsafe\n"
                    f'exec "{target}" "$@"\n'
                ),
            }
            for name, text in cases.items():
                with self.subTest(name=name):
                    wrapper = root / f"wrapper-{name}"
                    wrapper.write_text(text, encoding="utf-8")
                    self.assertIsNone(_hermes_python_command(str(wrapper)))

    def test_hermes_python_command_rejects_symlinked_wrapper_and_target_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            interpreter = root / "runtime/python3"
            interpreter.parent.mkdir()
            interpreter.write_bytes(b"python-placeholder")
            target = root / "real-target/hermes"
            target.parent.mkdir()
            target.write_text(f"#!{interpreter}\n", encoding="utf-8")
            wrapper = root / "real-wrapper/hermes"
            wrapper.parent.mkdir()
            wrapper.write_text(
                "#!/usr/bin/env bash\n"
                "unset PYTHONPATH\n"
                "unset PYTHONHOME\n"
                f'exec "{target}" "$@"\n',
                encoding="utf-8",
            )
            wrapper_alias = root / "wrapper-alias"
            wrapper_alias.symlink_to(wrapper.parent, target_is_directory=True)
            self.assertIsNone(
                _hermes_python_command(str(wrapper_alias / wrapper.name))
            )

            target_alias = root / "target-alias"
            target_alias.symlink_to(target.parent, target_is_directory=True)
            wrapper.write_text(
                "#!/usr/bin/env bash\n"
                "unset PYTHONPATH\n"
                "unset PYTHONHOME\n"
                f'exec "{target_alias / target.name}" "$@"\n',
                encoding="utf-8",
            )
            self.assertIsNone(_hermes_python_command(str(wrapper)))

            interpreter_alias = root / "interpreter-alias"
            interpreter_alias.symlink_to(interpreter.parent, target_is_directory=True)
            target.write_text(
                f"#!{interpreter_alias / interpreter.name}\n", encoding="utf-8"
            )
            wrapper.write_text(
                "#!/usr/bin/env bash\n"
                "unset PYTHONPATH\n"
                "unset PYTHONHOME\n"
                f'exec "{target}" "$@"\n',
                encoding="utf-8",
            )
            self.assertIsNone(_hermes_python_command(str(wrapper)))

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
        plan = build_campaign_plan(
            discovery,
            reasoning_effort="high",
            release_tree_sha256="sha256:" + "e" * 64,
            approval_authority_public_key_sha256=(
                "sha256:" + hashlib.sha256(self._approval_public_path.read_bytes()).hexdigest()
            ),
        )
        self.assertEqual("oab.campaign-plan/v2", plan["schema"])
        self.assertEqual(3, plan["route_count"])
        self.assertEqual(qualification_contract_for_route_count(3), plan["qualification"])
        self.assertEqual(1, plan["qualification"]["repetitions"])
        self.assertEqual(2, plan["qualification"]["episodes_per_route"])
        self.assertEqual(6, plan["qualification"]["scheduled_episodes"])
        self.assertEqual(240, plan["full_run"]["scheduled_episodes"])
        self.assertIn("approval_authority_public_key_sha256", plan)
        self.assertIn("plan_sha256", plan)

    def test_v230_readiness_plan_tuple_and_preview_are_exactly_bound(self) -> None:
        """The signed plan, not a child default, selects readiness execution semantics."""
        discovery = sanitize_hermes_inventory(self.inventory())
        plan = build_campaign_plan(
            discovery,
            reasoning_effort="high",
            release_tree_sha256="sha256:" + "e" * 64,
            approval_authority_public_key_sha256=(
                "sha256:" + hashlib.sha256(self._approval_public_path.read_bytes()).hexdigest()
            ),
        )
        qualification = plan["qualification"]
        self.assertEqual(qualification_contract_for_route_count(3), qualification)
        self.assertEqual(
            "oab.qualification-readiness/v1",
            agent_workflow_module._qualification_execution_contract(plan),
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            record_calibration(
                root,
                {"schema": "oab.calibration-report/v1", "passed": True, "failures": []},
            )
            preview = build_approval_preview(
                root,
                stage="qualification",
                max_cost_usd=5.0,
                max_api_calls=48,
                max_routes=3,
                allow_unknown_costs=False,
            )
        self.assertEqual(2, preview["episodes_per_route"])
        self.assertEqual(6, preview["scheduled_episodes"])
        self.assertEqual(8, preview["first_attempt_api_calls_per_route"])
        self.assertEqual(16, preview["absolute_api_calls_per_route"])
        self.assertEqual(48, preview["absolute_reserved_api_calls"])

    def test_historical_legacy_report_can_be_read_but_not_used_as_v230_contract(self) -> None:
        """Historical 34-episode evidence remains readable but cannot select v2.3 execution."""
        report = {
            "requested_route": "openai-codex/gpt-current",
            "reasoning_effort": "high",
            "scheduled_episodes": 34,
            "infrastructure_valid_episodes": 34,
            "infrastructure_invalid_episodes": 0,
            "identity_source": "provider_response",
            "controller_config_sha256": "sha256:" + "a" * 64,
            "controller_usage": {"api_calls": 34, "cost_usd": 0.12},
            "campaign_suite_verified": True,
            "campaign_elapsed_seconds": 1.0,
            "observations": [
                {"runner_status": "task_failed", "reason_codes": ["model_protocol_invalid"]},
                {"runner_status": "completed", "reason_codes": []},
            ],
        }
        historical = classify_qualification(
            report,
            requested_route="openai-codex/gpt-current",
            reasoning_effort="high",
        )
        self.assertEqual("qualified", historical["status"])
        self.assertEqual(0.12, historical["observed_cost_usd"])

        v230 = classify_qualification(
            report,
            requested_route="openai-codex/gpt-current",
            reasoning_effort="high",
            execution_contract="v2.3.0",
        )
        self.assertEqual("qualification_contract_invalid", v230["status"])
        self.assertNotIn("scoreable", v230)

    def test_auth_failure_is_not_a_model_score(self) -> None:
        report = {
            "requested_route": "xai-oauth/grok-test",
            "reasoning_effort": "high",
            "scheduled_episodes": 34,
            "infrastructure_valid_episodes": 0,
            "infrastructure_invalid_episodes": 34,
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
            "scheduled_episodes": 34,
            "infrastructure_valid_episodes": 34,
            "infrastructure_invalid_episodes": 0,
            "identity_source": "provider_response",
            "controller_usage": {"api_calls": 34, "cost_usd": None},
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
                    "scheduled_episodes": 34,
                    "infrastructure_valid_episodes": 0,
                    "infrastructure_invalid_episodes": 34,
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
                    max_api_calls=16,
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

    def qualification_report(
        self,
        route: str,
        *,
        output: Path,
        contract: Mapping[str, object] | None = None,
        cost: float | None = 0.1,
        attempts: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        """Produce a real, sealed readiness suite for an execution runner mock.

        The old generic report fixture is deliberately unavailable to execution
        tests.  Every normal mock runner now returns a score-free report whose
        physical receipts and dedicated seal have already verified.
        """
        if attempts is None:
            probes = qualification_probe_definitions()
            if cost is None:
                usage = qualification_usage(
                    api_calls=4,
                    cost_usd=None,
                    known_cost_usd=0.0,
                    unknown_cost_api_calls=4,
                )
            else:
                usage = qualification_usage(
                    api_calls=4,
                    cost_usd=cost / 2,
                    known_cost_usd=cost / 2,
                    unknown_cost_api_calls=0,
                )
            attempts = [
                {"probe": probes[0], "attempt_number": 1, "telemetry": usage},
                {"probe": probes[1], "attempt_number": 1, "telemetry": usage},
            ]
        return write_qualification_suite(
            output,
            route=route,
            contract=contract or qualification_contract_for_route_count(1),
            attempts=attempts,
        )

    def readiness_report(
        self,
        route: str = "xai-oauth/grok-4.5",
        *,
        cost: float | None = 0.08,
        attempts: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        """A sealed-native report for read-only classifier tests."""
        with tempfile.TemporaryDirectory() as td:
            report = self.qualification_report(
                route,
                output=Path(td) / "qualification-suite",
                cost=cost,
                attempts=attempts,
            )
        report.pop("campaign_suite_verified")
        report.pop("campaign_elapsed_seconds")
        return report

    @staticmethod
    def legacy_generic_qualification_report(**overrides: object) -> dict[str, object]:
        """Historical generic shape: readable only, never execution authority."""
        report: dict[str, object] = {
            "requested_route": "xai-oauth/grok-4.5",
            "reasoning_effort": "high",
            "scheduled_episodes": 2,
            "infrastructure_valid_episodes": 2,
            "infrastructure_invalid_episodes": 0,
            "identity_source": "provider_response",
            "controller_usage": {
                "api_calls": 8,
                "cost_usd": 0.08,
                "known_cost_usd": 0.08,
                "unknown_cost_api_calls": 0,
            },
            "campaign_suite_verified": True,
            "campaign_elapsed_seconds": 2.5,
            "observations": [],
        }
        report.update(overrides)
        return report

    def test_v230_campaign_qualification_artifacts_are_recursively_quality_free(self) -> None:
        """Campaign receipts and QUALIFICATION.json cannot regain quality authority."""
        with self.assertRaisesRegex(ValueError, "qualification_quality_field_invalid"):
            assert_quality_free({"throughput_rate": 1})

        forbidden = (
            "score",
            "rate",
            "percentage",
            "pair_stability",
            "valid_for_scoring",
            "valid_for_calibration",
            "switch",
        )

        def scan(value: object, *, path: str) -> None:
            if isinstance(value, Mapping):
                for key, nested in value.items():
                    lowered = str(key).lower()
                    for marker in forbidden:
                        self.assertNotIn(marker, lowered, f"{path}.{key}")
                    scan(nested, path=f"{path}.{key}")
            elif isinstance(value, list):
                for index, nested in enumerate(value):
                    scan(nested, path=f"{path}[{index}]")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )

            def runner(
                route: dict[str, object], _stage: str, output: Path, _effort: str
            ) -> dict[str, object]:
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            state = run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=48,
                max_routes=3,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=1.0,
                    max_api_calls=48,
                    max_routes=3,
                    allow_unknown_costs=False,
                ),
            )
            self.assertEqual("awaiting_full_run_approval", state["status"])
            receipts = sorted((root / "qualification" / "results").glob("*.json"))
            self.assertEqual(3, len(receipts))
            for receipt in receipts:
                scan(json.loads(receipt.read_text(encoding="utf-8")), path=receipt.name)
            scan(
                json.loads((root / "QUALIFICATION.json").read_text(encoding="utf-8")),
                path="QUALIFICATION.json",
            )

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
                    probes = qualification_probe_definitions()
                    return self.qualification_report(
                        requested,
                        output=output,
                        contract=cast(Mapping[str, object], route["_qualification_contract"]),
                        attempts=[
                            {
                                "probe": probe,
                                "attempt_number": 1,
                                "status": "runner_invalid",
                                "reason_codes": ["provider_authentication_invalid"],
                                "telemetry": qualification_usage(
                                    api_calls=1,
                                    cost_usd=0.2,
                                    known_cost_usd=0.2,
                                    unknown_cost_api_calls=0,
                                ),
                            }
                            for probe in probes
                        ],
                    )
                return self.qualification_report(
                    requested,
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            state = run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=48,
                max_routes=3,
                **self.signed_stage_approval(
                    root, stage="qualification", max_cost_usd=1.0, max_api_calls=48,
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
            self.assertEqual(48, approval["max_api_calls"])
            self.assertEqual(3, approval["max_routes"])
            self.assertRegex(approval["receipt_sha256"], r"^sha256:[0-9a-f]{64}$")
            qualification = json.loads((root / "QUALIFICATION.json").read_text(encoding="utf-8"))
            # 2 qualified routes × $0.1 × (80 full episodes / 2 qual probes) = $8.0
            self.assertEqual(8.0, qualification["projected_full_run_cost_usd"])
            # Dedicated seale...[truncated]
            self.assertEqual("READY", qualification["readiness"])
            self.assertIn("plumbing", qualification["headline"].lower())
            self.assertNotIn("%", qualification["headline"])
            for route in qualification["qualified_routes"]:
                self.assertEqual("READY", route["readiness"])
            self.assertEqual("NOT READY", qualification["excluded_routes"][0]["readiness"])

    def test_infrastructure_invalid_known_cost_exhausts_signed_budget(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )

            def runner(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                    attempts=[
                        {
                            "probe": probe,
                            "attempt_number": 1,
                            "status": "runner_invalid",
                            "reason_codes": ["provider_auth_unavailable"],
                            "telemetry": qualification_usage(
                                api_calls=4,
                                cost_usd=0.3,
                                known_cost_usd=0.3,
                                unknown_cost_api_calls=0,
                            ),
                        }
                        for probe in qualification_probe_definitions()
                    ],
                )

            state = run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=0.5,
                allow_unknown_costs=False,
                max_api_calls=16,
                max_routes=1,
                **self.signed_stage_approval(
                    root, stage="qualification", max_cost_usd=0.5, max_api_calls=16,
                    max_routes=1, allow_unknown_costs=False,
                ),
            )
            self.assertEqual("qualification_budget_exhausted", state["status"])
            self.assertAlmostEqual(0.6, state["spend"]["observed_qualification_cost_usd"])
            self.assertEqual(1, len(state["excluded_routes"]))

    def test_malformed_qualification_call_count_is_conservatively_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )

            def runner(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                report = self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )
                usage = cast(dict[str, object], report["controller_usage"])
                usage["api_calls"] = 35
                return report

            state = run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=16,
                max_routes=1,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=1.0,
                    max_api_calls=16,
                    max_routes=1,
                    allow_unknown_costs=False,
                ),
            )
            self.assertEqual("blocked_unknown_api_calls", state["status"])
            self.assertEqual([], state["qualified_routes"])

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
                return self.qualification_report(
                    requested,
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                    cost=None,
                )

            first = run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=48,
                max_routes=3,
                **self.signed_stage_approval(
                    root, stage="qualification", max_cost_usd=1.0, max_api_calls=48,
                    max_routes=3, allow_unknown_costs=False,
                ),
            )
            self.assertEqual("blocked_unknown_cost", first["status"])
            self.assertEqual(1, len(calls))
            first_route = calls[0]
            # The first receipt was sealed under allow_unknown_costs=false. A later
            # approval cannot reinterpret it under a looser accounting policy.
            with self.assertRaisesRegex(
                ValueError, "campaign_stage_result_recomputation_mismatch"
            ):
                run_qualification_stage(
                    root,
                    runner=runner,
                    max_cost_usd=1.0,
                    allow_unknown_costs=True,
                    max_api_calls=48,
                    max_routes=3,
                    **self.signed_stage_approval(
                        root, stage="qualification", max_cost_usd=1.0, max_api_calls=48,
                        max_routes=3, allow_unknown_costs=True,
                    ),
                )
            self.assertEqual(1, calls.count(first_route))
            self.assertEqual(1, len(calls))

    def test_stage_rejects_symlinked_campaign_internal_directories(self) -> None:
        for relative in (
            Path("APPROVALS"),
            Path("qualification/results"),
            Path("qualification/suites"),
        ):
            with self.subTest(relative=str(relative)), tempfile.TemporaryDirectory() as td:
                root = Path(td) / "campaign"
                initialize_campaign(
                    root,
                    doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                    inventory_payload=self.inventory(),
                    reasoning_effort="high",
                )
                approval = self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=1.0,
                    max_api_calls=32,
                    max_routes=2,
                    allow_unknown_costs=False,
                )
                target = Path(td) / "outside" / relative.name
                target.mkdir(parents=True)
                path = root / relative
                if path.exists():
                    path.rmdir()
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(target, target_is_directory=True)

                with self.assertRaisesRegex(ValueError, "campaign_internal_path_unsafe"):
                    run_qualification_stage(
                        root,
                        runner=lambda *_args: self.readiness_report("unused"),
                        max_cost_usd=1.0,
                        allow_unknown_costs=False,
                        max_api_calls=32,
                        max_routes=2,
                        **approval,
                    )

    def test_interrupted_attempt_is_quarantined_and_charged_before_resume(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            calls: list[str] = []

            def interrupted(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                calls.append(str(route["requested_route"]))
                output.mkdir(parents=True)
                (output / "partial.txt").write_text("partial", encoding="utf-8")
                raise RuntimeError("campaign_controller_timeout")

            first = run_qualification_stage(
                root,
                runner=interrupted,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=32,
                max_routes=2,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=1.0,
                    max_api_calls=32,
                    max_routes=2,
                    allow_unknown_costs=False,
                ),
            )
            self.assertEqual("qualification_interrupted", first["status"])
            self.assertFalse(any((root / "qualification/suites").iterdir()))
            attempts = root / "qualification/attempts"
            self.assertTrue(list(attempts.glob("*.reserved.json")))
            self.assertTrue(list(attempts.glob("*.failed.json")))
            self.assertTrue(list(attempts.glob("*.evidence")))
            self.assertEqual(
                16,
                first["spend"]["qualification_failed_attempt_reserved_api_calls"],
            )
            self.assertTrue(first["spend"]["unknown_cost_encountered"])

            blocked_calls: list[str] = []
            blocked = run_qualification_stage(
                root,
                runner=lambda route, *_args: blocked_calls.append(str(route["route_id"])),
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=32,
                max_routes=2,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=1.0,
                    max_api_calls=32,
                    max_routes=2,
                    allow_unknown_costs=False,
                ),
            )
            self.assertEqual("blocked_unknown_cost", blocked["status"])
            self.assertEqual([], blocked_calls)

            def completed(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                calls.append(str(route["requested_route"]))
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            resumed = run_qualification_stage(
                root,
                runner=completed,
                max_cost_usd=1.0,
                allow_unknown_costs=True,
                max_api_calls=32,
                max_routes=2,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=1.0,
                    max_api_calls=32,
                    max_routes=2,
                    allow_unknown_costs=True,
                ),
            )
            self.assertEqual("comparison_not_supportable", resumed["status"])
            self.assertEqual(2, len(calls))

    def test_attempt_accounting_rejects_post_validation_attempts_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )

            def interrupted(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                output.mkdir(parents=True)
                (output / "partial.txt").write_text("partial", encoding="utf-8")
                raise RuntimeError("campaign_controller_timeout")

            first = run_qualification_stage(
                root,
                runner=interrupted,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=16,
                max_routes=1,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=1.0,
                    max_api_calls=16,
                    max_routes=1,
                    allow_unknown_costs=False,
                ),
            )
            self.assertEqual(
                16,
                first["spend"]["qualification_failed_attempt_reserved_api_calls"],
            )
            attempts = root / "qualification/attempts"
            retained = root / "qualification/retained-attempts"
            attempts.rename(retained)
            outside = Path(td) / "outside-attempts"
            outside.mkdir()
            attempts.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "campaign_internal_path_unsafe"):
                _attempt_accounting(root, "qualification", {}, require_ledger=True)

    def test_resume_rejects_regular_attempts_directory_replacement_that_erases_spend(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )

            def interrupted(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                output.mkdir(parents=True)
                raise RuntimeError("campaign_controller_timeout")

            first = run_qualification_stage(
                root,
                runner=interrupted,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=16,
                max_routes=1,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=1.0,
                    max_api_calls=16,
                    max_routes=1,
                    allow_unknown_costs=False,
                ),
            )
            self.assertEqual(
                16,
                first["spend"]["qualification_failed_attempt_reserved_api_calls"],
            )
            attempts = root / "qualification/attempts"
            attempts.rename(root / "qualification/retained-attempts")
            attempts.mkdir()
            resumed_calls: list[str] = []

            with self.assertRaisesRegex(ValueError, "campaign_attempt_ledger_invalid"):
                run_qualification_stage(
                    root,
                    runner=lambda route, *_args: resumed_calls.append(
                        str(route["route_id"])
                    ),
                    max_cost_usd=1.0,
                    allow_unknown_costs=True,
                    max_api_calls=16,
                    max_routes=1,
                    **self.signed_stage_approval(
                        root,
                        stage="qualification",
                        max_cost_usd=1.0,
                        max_api_calls=16,
                        max_routes=1,
                        allow_unknown_costs=True,
                    ),
                )
            self.assertEqual([], resumed_calls)

    def test_stage_retains_attempts_descriptor_across_post_entry_directory_swap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )

            def interrupted(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                output.mkdir(parents=True)
                raise RuntimeError("campaign_controller_timeout")

            run_qualification_stage(
                root,
                runner=interrupted,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=16,
                max_routes=1,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=1.0,
                    max_api_calls=16,
                    max_routes=1,
                    allow_unknown_costs=False,
                ),
            )
            attempts = root / "qualification/attempts"
            original_validate = agent_workflow_module._validate_campaign_layout
            swapped = False

            def validate_then_swap(path: Path, *, create: bool = False) -> None:
                nonlocal swapped
                original_validate(path, create=create)
                if not create and not swapped:
                    swapped = True
                    attempts.rename(root / "qualification/retained-attempts")
                    attempts.mkdir()

            resumed_calls: list[str] = []
            resume_approval = self.signed_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=1.0,
                max_api_calls=16,
                max_routes=1,
                allow_unknown_costs=True,
            )
            with patch(
                "oab.agent_workflow._validate_campaign_layout",
                side_effect=validate_then_swap,
            ):
                resumed = run_qualification_stage(
                    root,
                    runner=lambda route, *_args: (
                        resumed_calls.append(str(route["route_id"])),
                        (_ for _ in ()).throw(RuntimeError("campaign_controller_timeout")),
                    )[1],
                    max_cost_usd=1.0,
                    allow_unknown_costs=True,
                    max_api_calls=16,
                    max_routes=1,
                    **resume_approval,
                )
            self.assertTrue(swapped)
            self.assertEqual([], resumed_calls)
            self.assertEqual(
                16,
                resumed["spend"]["qualification_failed_attempt_reserved_api_calls"],
            )

    def test_resume_cannot_narrow_scope_around_completed_attempts(self) -> None:
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

            def runner(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=48,
                max_routes=3,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=1.0,
                    max_api_calls=48,
                    max_routes=3,
                    allow_unknown_costs=False,
                ),
            )

            with self.assertRaisesRegex(
                ValueError, "campaign_stage_result_scope_mismatch"
            ):
                run_qualification_stage(
                    root,
                    runner=runner,
                    max_cost_usd=1.0,
                    allow_unknown_costs=False,
                    max_api_calls=16,
                    max_routes=1,
                    **self.signed_stage_approval(
                        root,
                        stage="qualification",
                        max_cost_usd=1.0,
                        max_api_calls=16,
                        max_routes=1,
                        allow_unknown_costs=False,
                    ),
                )

    def test_resume_rejects_result_cost_and_unknown_telemetry_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            calls: list[str] = []

            def runner(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                requested = str(route["requested_route"])
                calls.append(requested)
                return self.qualification_report(
                    requested,
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                    cost=None,
                )

            first = run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=5.0,
                allow_unknown_costs=False,
                max_api_calls=48,
                max_routes=3,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=5.0,
                    max_api_calls=48,
                    max_routes=3,
                    allow_unknown_costs=False,
                ),
            )
            self.assertEqual("blocked_unknown_cost", first["status"])
            self.assertEqual(1, len(calls))
            result_path = next((root / "qualification" / "results").glob("*.json"))
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["classification"]["observed_cost_usd"] = 0.0
            result["classification"]["observed_known_cost_usd"] = 0.0
            result["classification"]["unknown_cost_api_calls"] = 0
            result_path.write_text(json.dumps(result), encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError, "campaign_stage_result_receipt_digest_mismatch"
            ):
                run_qualification_stage(
                    root,
                    runner=runner,
                    max_cost_usd=5.0,
                    allow_unknown_costs=True,
                    max_api_calls=48,
                    max_routes=3,
                    **self.signed_stage_approval(
                        root,
                        stage="qualification",
                        max_cost_usd=5.0,
                        max_api_calls=48,
                        max_routes=3,
                        allow_unknown_costs=True,
                    ),
                )
            self.assertEqual(1, len(calls))

    def test_resume_rejects_self_consistent_unverified_suite_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )

            def runner(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            approval = self.signed_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=1.0,
                max_api_calls=16,
                max_routes=1,
                allow_unknown_costs=False,
            )
            run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=16,
                max_routes=1,
                **approval,
            )
            result_path = next((root / "qualification" / "results").glob("*.json"))
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["campaign_suite_verified"] = False
            unsigned = dict(result)
            unsigned.pop("receipt_sha256")
            result["receipt_sha256"] = "sha256:" + hashlib.sha256(
                json.dumps(
                    unsigned,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            result_path.write_text(json.dumps(result), encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError, "campaign_orchestration_metadata_invalid"
            ):
                run_qualification_stage(
                    root,
                    runner=runner,
                    max_cost_usd=1.0,
                    allow_unknown_costs=False,
                    max_api_calls=16,
                    max_routes=1,
                    **approval,
                )

    def test_resume_rejects_numeric_type_confusion_in_classification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )

            def runner(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            approval = self.signed_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=1.0,
                max_api_calls=16,
                max_routes=1,
                allow_unknown_costs=False,
            )
            run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=16,
                max_routes=1,
                **approval,
            )
            result_path = next((root / "qualification/results").glob("*.json"))
            result = json.loads(result_path.read_text(encoding="utf-8"))
            attempt_id = str(result["attempt_id"])
            result["classification"]["observed_api_calls"] = 34.0
            unsigned = dict(result)
            unsigned.pop("receipt_sha256")
            result["receipt_sha256"] = "sha256:" + hashlib.sha256(
                json.dumps(
                    unsigned,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            result_path.write_text(json.dumps(result), encoding="utf-8")
            completion_path = (
                root / "qualification/attempts" / f"{attempt_id}.completed.json"
            )
            completion = json.loads(completion_path.read_text(encoding="utf-8"))
            completion["result_receipt_sha256"] = result["receipt_sha256"]
            unsigned_completion = dict(completion)
            unsigned_completion.pop("receipt_sha256")
            completion["receipt_sha256"] = "sha256:" + hashlib.sha256(
                json.dumps(
                    unsigned_completion,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            completion_path.write_text(json.dumps(completion), encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError, "campaign_stage_result_recomputation_mismatch"
            ):
                run_qualification_stage(
                    root,
                    runner=runner,
                    max_cost_usd=1.0,
                    allow_unknown_costs=False,
                    max_api_calls=16,
                    max_routes=1,
                    **approval,
                )

    def test_current_campaign_rejects_result_without_attempt_ledger(self) -> None:
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

            def runner(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            approval = self.signed_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=1.0,
                max_api_calls=16,
                max_routes=1,
                allow_unknown_costs=False,
            )
            run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=16,
                max_routes=1,
                **approval,
            )
            result_path = next((root / "qualification/results").glob("*.json"))
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result.pop("attempt_id")
            unsigned = dict(result)
            unsigned.pop("receipt_sha256")
            result["receipt_sha256"] = "sha256:" + hashlib.sha256(
                json.dumps(
                    unsigned,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            result_path.write_text(json.dumps(result), encoding="utf-8")
            for event in (root / "qualification/attempts").glob("*.json"):
                event.unlink()

            with self.assertRaisesRegex(ValueError, "campaign_attempt_ledger_invalid"):
                run_qualification_stage(
                    root,
                    runner=runner,
                    max_cost_usd=1.0,
                    allow_unknown_costs=False,
                    max_api_calls=16,
                    max_routes=1,
                    **approval,
                )

    def test_resume_rejects_result_without_completed_attempt_event(self) -> None:
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

            def runner(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            approval = self.signed_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=1.0,
                max_api_calls=16,
                max_routes=1,
                allow_unknown_costs=False,
            )
            run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=16,
                max_routes=1,
                **approval,
            )
            completed = next(
                (root / "qualification/attempts").glob("*.completed.json")
            )
            completed.unlink()

            with self.assertRaisesRegex(ValueError, "campaign_attempt_ledger_invalid"):
                run_qualification_stage(
                    root,
                    runner=runner,
                    max_cost_usd=1.0,
                    allow_unknown_costs=False,
                    max_api_calls=16,
                    max_routes=1,
                    **approval,
                )

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
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            run_qualification_stage(
                root,
                runner=qualify,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=48,
                max_routes=3,
                **self.signed_stage_approval(
                    root, stage="qualification", max_cost_usd=1.0, max_api_calls=48,
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
                report = {
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
                    "controller_usage": {
                        "api_calls": 80,
                        "cost_usd": 2.0,
                        "known_cost_usd": 2.0,
                        "unknown_cost_api_calls": 0,
                    },
                    "campaign_suite_verified": True,
                    "campaign_elapsed_seconds": 2.0,
                }
                report["authoritative_stage"] = build_authoritative_stage_binding(
                    plan_sha256=str(
                        json.loads((root / "PLAN.json").read_text(encoding="utf-8"))["plan_sha256"]
                    ),
                    stage_approval_sha256=str(
                        json.loads(
                            Path(str(route["_campaign_approval_path"])).read_text(encoding="utf-8")
                        )["receipt_sha256"]
                    ),
                    route_id=str(route["route_id"]),
                    output_relative_path=str(output.resolve().relative_to(root.resolve())),
                    full_plan=cast(
                        Mapping[str, object],
                        json.loads((root / "PLAN.json").read_text(encoding="utf-8"))["full_run"],
                    ),
                    route_count=3,
                )
                sealed_report = dict(report)
                sealed_report.pop("campaign_suite_verified")
                sealed_report.pop("campaign_elapsed_seconds")
                output.mkdir(parents=True, exist_ok=True)
                (output / "suite-report.json").write_text(
                    json.dumps(sealed_report), encoding="utf-8"
                )
                return report

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

            result_path = next((root / "full" / "results").glob("*.json"))
            original_result = json.loads(result_path.read_text(encoding="utf-8"))
            campaign_path = root / "CAMPAIGN.json"

            def write_result(result: dict[str, object]) -> None:
                result["suite_report_sha256"] = "sha256:" + hashlib.sha256(
                    json.dumps(
                        result["suite_report"],
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest()
                unsigned = dict(result)
                unsigned.pop("receipt_sha256", None)
                result["receipt_sha256"] = "sha256:" + hashlib.sha256(
                    json.dumps(
                        unsigned,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest()
                result_path.write_text(json.dumps(result), encoding="utf-8")
                attempt_id = result.get("attempt_id")
                if isinstance(attempt_id, str):
                    event_path = root / "full/attempts" / f"{attempt_id}.completed.json"
                    event = json.loads(event_path.read_text(encoding="utf-8"))
                    event["result_receipt_sha256"] = result["receipt_sha256"]
                    unsigned_event = dict(event)
                    unsigned_event.pop("receipt_sha256", None)
                    event["receipt_sha256"] = "sha256:" + hashlib.sha256(
                        json.dumps(
                            unsigned_event,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=False,
                            allow_nan=False,
                        ).encode("utf-8")
                    ).hexdigest()
                    event_path.write_text(json.dumps(event), encoding="utf-8")
                campaign_state = json.loads(campaign_path.read_text(encoding="utf-8"))
                campaign_state["status"] = "running_full"
                campaign_path.write_text(json.dumps(campaign_state), encoding="utf-8")

            def resume_full() -> dict[str, object]:
                return run_full_stage(
                    root,
                    runner=full,
                    max_cost_usd=10.0,
                    allow_unknown_costs=False,
                    max_api_calls=2720,
                    max_routes=2,
                    **self.signed_stage_approval(
                        root,
                        stage="full",
                        max_cost_usd=10.0,
                        max_api_calls=2720,
                        max_routes=2,
                        allow_unknown_costs=False,
                    ),
                )

            legacy_result = json.loads(json.dumps(original_result))
            legacy_report = cast(dict[str, object], legacy_result["suite_report"])
            legacy_report["campaign_suite_verified"] = legacy_result.pop(
                "campaign_suite_verified"
            )
            legacy_report["campaign_elapsed_seconds"] = legacy_result.pop(
                "campaign_elapsed_seconds"
            )
            sealed_path = Path(str(original_result["suite_output"])) / "suite-report.json"
            original_sealed_report = json.loads(sealed_path.read_text(encoding="utf-8"))
            legacy_report["release_tree_sha256"] = (
                "sha256:967445bec99f6df126ae5bbfd19cce47527f4cc50d78bd918ed8c339f8c99c68"
            )
            legacy_sealed_report = dict(original_sealed_report)
            legacy_sealed_report["release_tree_sha256"] = legacy_report[
                "release_tree_sha256"
            ]
            sealed_path.write_text(json.dumps(legacy_sealed_report), encoding="utf-8")
            write_result(legacy_result)
            with self.assertRaisesRegex(
                ValueError, "campaign_legacy_receipt_release_invalid"
            ):
                resume_full()

            unsupported_legacy = json.loads(json.dumps(original_result))
            unsupported_report = cast(
                dict[str, object], unsupported_legacy["suite_report"]
            )
            unsupported_report["campaign_suite_verified"] = unsupported_legacy.pop(
                "campaign_suite_verified"
            )
            unsupported_report["campaign_elapsed_seconds"] = unsupported_legacy.pop(
                "campaign_elapsed_seconds"
            )
            sealed_path.write_text(json.dumps(original_sealed_report), encoding="utf-8")
            write_result(unsupported_legacy)
            with self.assertRaisesRegex(
                ValueError, "campaign_legacy_receipt_release_invalid"
            ):
                resume_full()

            ambiguous_result = json.loads(json.dumps(legacy_result))
            ambiguous_result["campaign_suite_verified"] = True
            ambiguous_result["campaign_elapsed_seconds"] = 1.0
            write_result(ambiguous_result)
            with self.assertRaisesRegex(
                ValueError, "campaign_orchestration_metadata_invalid"
            ):
                resume_full()

            type_confused_result = json.loads(json.dumps(original_result))
            type_confused_report = cast(
                dict[str, object], type_confused_result["suite_report"]
            )
            type_confused_report["authoritative"] = 1
            write_result(type_confused_result)
            with self.assertRaisesRegex(
                ValueError, "campaign_stage_result_report_mismatch"
            ):
                resume_full()

            invalid_result = json.loads(json.dumps(original_result))
            invalid_result["campaign_suite_verified"] = False
            write_result(invalid_result)
            with self.assertRaisesRegex(
                ValueError, "campaign_orchestration_metadata_invalid"
            ):
                resume_full()

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
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            # A 15-call request cannot even produce a signed readiness stage proof:
            # the immutable per-route ceiling is exactly 16.
            with self.assertRaisesRegex(
                ValueError, "stage_api_call_budget_must_match_authoritative_tuple"
            ):
                run_qualification_stage(
                    root,
                    runner=runner,
                    max_cost_usd=1.0,
                    allow_unknown_costs=False,
                    max_api_calls=15,
                    max_routes=3,
                    **self.signed_stage_approval(
                        root, stage="qualification", max_cost_usd=1.0, max_api_calls=15,
                        max_routes=3, allow_unknown_costs=False,
                    ),
                )
            self.assertEqual([], calls)

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
                return self.qualification_report(
                    requested,
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=1.0,
                allow_unknown_costs=False,
                max_api_calls=16,
                max_routes=1,
                **self.signed_stage_approval(
                    root, stage="qualification", max_cost_usd=1.0, max_api_calls=16,
                    max_routes=1, allow_unknown_costs=False,
                ),
            )
            self.assertEqual(["xai-oauth/grok-test"], calls)

    def test_v230_qualification_with_completed_probes_is_ready(self) -> None:
        """Two sealed P01 primary receipts classify as readiness, not quality."""
        result = classify_qualification(
            self.readiness_report(),
            requested_route="xai-oauth/grok-4.5",
            reasoning_effort="high",
            execution_contract=QUALIFICATION_CONTRACT_ID,
        )
        self.assertNotIn("scoreable", result)
        self.assertEqual("qualified", result["status"])

    def test_v230_qualification_agent_loop_incompatible_when_model_cannot_tool_loop(self) -> None:
        """Task/loop failure is readiness INCOMPATIBLE, never a score."""
        probes = qualification_probe_definitions()
        report = self.readiness_report(
            "openai-codex/gpt-current",
            attempts=[
                {
                    "probe": probe,
                    "attempt_number": 1,
                    "status": "task_failed",
                    "reason_codes": ["controller_step_limit_exceeded"],
                    "telemetry": qualification_usage(
                        api_calls=2,
                        cost_usd=0.02,
                        known_cost_usd=0.02,
                        unknown_cost_api_calls=0,
                    ),
                }
                for probe in probes
            ],
        )
        result = classify_qualification(
            report,
            requested_route="openai-codex/gpt-current",
            reasoning_effort="high",
            execution_contract=QUALIFICATION_CONTRACT_ID,
        )
        self.assertEqual("agent_loop_incompatible", result["status"])
        self.assertNotIn("scoreable", result)

    def test_v230_qualification_infrastructure_failure_is_not_quality_score(self) -> None:
        """Retry exhaustion remains typed infrastructure readiness evidence."""
        probes = qualification_probe_definitions()
        report = self.readiness_report(
            attempts=[
                {
                    "probe": probe,
                    "attempt_number": number,
                    "status": "runner_invalid",
                    "reason_codes": ["provider_rate_limited"],
                    "telemetry": qualification_usage(
                        api_calls=1,
                        cost_usd=0.0,
                        known_cost_usd=0.0,
                        unknown_cost_api_calls=0,
                    ),
                }
                for number in (1, 2)
                for probe in probes
            ]
        )
        result = classify_qualification(
            report,
            requested_route="xai-oauth/grok-4.5",
            reasoning_effort="high",
            execution_contract=QUALIFICATION_CONTRACT_ID,
        )
        self.assertEqual("provider_rate_limited", result["status"])
        self.assertNotIn("scoreable", result)

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
        self.assertIn("authoritative_full_contract_required", report["reasons"])

    def test_v230_signed_call_ceiling_is_exact_for_selected_routes(self) -> None:
        """A stage proof binds the selected routes × 16-call readiness ceiling exactly."""
        for call_budget in (32,):
            with self.subTest(max_api_calls=call_budget), tempfile.TemporaryDirectory() as td:
                root = Path(td) / "campaign"
                initialize_campaign(
                    root,
                    doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                    inventory_payload=self.inventory(),
                    reasoning_effort="high",
                )
                route_limits: list[int] = []

                def runner(
                    route: dict[str, object], stage: str, output: Path, effort: str
                ) -> dict[str, object]:
                    route_limit = route["max_api_calls"]
                    assert isinstance(route_limit, int) and not isinstance(route_limit, bool)
                    route_limits.append(route_limit)
                    probes = qualification_probe_definitions()
                    attempts = [
                        {
                            "probe": probe,
                            "attempt_number": number,
                            "status": "runner_invalid" if number == 1 else "completed",
                            "reason_codes": ["provider_unavailable"] if number == 1 else [],
                            "telemetry": qualification_usage(
                                api_calls=4,
                                cost_usd=0.0,
                                known_cost_usd=0.0,
                                unknown_cost_api_calls=0,
                            ),
                        }
                        for number in (1, 2)
                        for probe in probes
                    ]
                    return self.qualification_report(
                        str(route["requested_route"]),
                        output=output,
                        contract=cast(Mapping[str, object], route["_qualification_contract"]),
                        attempts=attempts,
                    )

                approval = self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=10.0,
                    max_api_calls=call_budget,
                    max_routes=2,
                    allow_unknown_costs=False,
                )
                state = run_qualification_stage(
                    root,
                    runner=runner,
                    max_cost_usd=10.0,
                    allow_unknown_costs=False,
                    max_api_calls=call_budget,
                    max_routes=2,
                    **approval,
                )

                self.assertEqual([16, 16], route_limits)
                self.assertEqual("awaiting_full_run_approval", state["status"])

    def test_v230_signed_call_ceiling_rejects_headroom_or_shortfall(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            for call_budget in (16, 48):
                with self.subTest(max_api_calls=call_budget):
                    with self.assertRaisesRegex(
                        ValueError, "stage_api_call_budget_must_match_authoritative_tuple"
                    ):
                        self.signed_stage_approval(
                            root,
                            stage="qualification",
                            max_cost_usd=10.0,
                            max_api_calls=call_budget,
                            max_routes=2,
                            allow_unknown_costs=False,
                        )

    def test_v230_plan_rejects_legacy_shaped_qualification_report(self) -> None:
        """A report cannot replace the signed two-probe execution contract."""
        for scheduled_episodes in (34, 34.0):
            with self.subTest(scheduled_episodes=scheduled_episodes), tempfile.TemporaryDirectory() as td:
                root = Path(td) / "campaign"
                initialize_campaign(
                    root,
                    doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                    inventory_payload=self.inventory(),
                    reasoning_effort="high",
                )
                route_limits: list[int] = []
                calls: list[str] = []

                def runner(
                    route: dict[str, object], stage: str, output: Path, effort: str
                ) -> dict[str, object]:
                    route_limit = route["max_api_calls"]
                    assert isinstance(route_limit, int) and not isinstance(route_limit, bool)
                    route_limits.append(route_limit)
                    calls.append(str(route["requested_route"]))
                    return self.legacy_generic_qualification_report(
                        requested_route=str(route["requested_route"]),
                        scheduled_episodes=scheduled_episodes,
                        infrastructure_valid_episodes=34,
                        infrastructure_invalid_episodes=0,
                        controller_usage={
                            "api_calls": 34,
                            "cost_usd": 0.0,
                            "known_cost_usd": 0.0,
                            "unknown_cost_api_calls": 0,
                        },
                    )

                approval = self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=10.0,
                    max_api_calls=32,
                    max_routes=2,
                    allow_unknown_costs=False,
                )
                state = run_qualification_stage(
                    root,
                    runner=runner,
                    max_cost_usd=10.0,
                    allow_unknown_costs=False,
                    max_api_calls=32,
                    max_routes=2,
                    **approval,
                )

                self.assertEqual([16], route_limits)
                self.assertEqual([], state["qualified_routes"])
                self.assertEqual(1, len(calls))

    def test_v230_first_route_overrun_is_terminal(self) -> None:
        """A route that exceeds its 16-call allowance cannot be retried or promoted."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={
                    "schema": "oab.doctor/v1",
                    "ready": True,
                    "checks": [],
                    "release_tree_sha256": "sha256:" + "a" * 64,
                },
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            route_limits: list[int] = []
            calls: list[str] = []

            def overrun_runner(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                route_limit = route["max_api_calls"]
                assert isinstance(route_limit, int) and not isinstance(route_limit, bool)
                route_limits.append(route_limit)
                calls.append(str(route["requested_route"]))
                report = self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                    cost=0.0,
                )
                report["controller_usage"] = {
                    "api_calls": 34,
                    "cost_usd": 0.0,
                    "known_cost_usd": 0.0,
                    "unknown_cost_api_calls": 0,
                }
                return report

            first_approval = self.signed_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=10.0,
                max_api_calls=32,
                max_routes=2,
                allow_unknown_costs=False,
            )
            first = run_qualification_stage(
                root,
                runner=overrun_runner,
                max_cost_usd=10.0,
                allow_unknown_costs=False,
                max_api_calls=32,
                max_routes=2,
                **first_approval,
            )
            self.assertEqual([16], route_limits)
            self.assertEqual(1, len(calls))
            self.assertEqual("blocked_unknown_api_calls", first["status"])
            self.assertEqual([], first["qualified_routes"])

            resumed_calls: list[str] = []
            resumed_approval = self.signed_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=10.0,
                max_api_calls=32,
                max_routes=2,
                allow_unknown_costs=False,
            )
            resumed = run_qualification_stage(
                root,
                runner=lambda route, *_args: resumed_calls.append(
                    str(route["requested_route"])
                ) or {},
                max_cost_usd=10.0,
                allow_unknown_costs=False,
                max_api_calls=32,
                max_routes=2,
                **resumed_approval,
            )
            self.assertEqual("blocked_unknown_cost", resumed["status"])
            self.assertEqual([], resumed_calls)

            full_calls: list[str] = []
            with self.assertRaisesRegex(ValueError, "campaign_not_ready_for_full_run"):
                run_full_stage(
                    root,
                    runner=lambda *_args: full_calls.append("called") or {},
                    max_cost_usd=10.0,
                    allow_unknown_costs=False,
                    max_api_calls=2720,
                    max_routes=2,
                    approval_path=root / "missing-full-approval.json",
                    approval_signature_path=None,
                    approval_public_key_path=None,
                )
            self.assertEqual([], full_calls)

    def test_full_stage_requires_bound_qualification_receipts(self) -> None:
        """Mutable campaign state cannot promote routes without v2.3 qualification evidence."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={
                    "schema": "oab.doctor/v1",
                    "ready": True,
                    "checks": [],
                    "release_tree_sha256": "sha256:" + "a" * 64,
                },
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            discovery = json.loads((root / "DISCOVERY.json").read_text(encoding="utf-8"))
            selected = discovery["routes"][:2]
            state_path = root / "CAMPAIGN.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["qualified_routes"] = [
                {
                    "route_id": route["route_id"],
                    "requested_route": route["requested_route"],
                }
                for route in selected
            ]
            state_path.write_text(json.dumps(state), encoding="utf-8")
            approval = self.signed_stage_approval(
                root,
                stage="full",
                max_cost_usd=10.0,
                max_api_calls=2720,
                max_routes=2,
                allow_unknown_costs=False,
            )
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["status"] = "awaiting_full_run_approval"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            full_calls: list[str] = []

            def full_runner(
                route: dict[str, object], _stage: str, output: Path, _effort: str
            ) -> dict[str, object]:
                full_calls.append(str(route["requested_route"]))
                report: dict[str, object] = {
                    "requested_route": route["requested_route"],
                    "reasoning_effort": "high",
                    "controller_config_sha256": "sha256:" + "b" * 64,
                    "release_tree_sha256": "sha256:" + "a" * 64,
                    "execution_environment": {
                        "platform": "darwin",
                        "sandbox_backend": "sandbox-exec",
                    },
                    "scheduled_episodes": 80,
                    "infrastructure_valid_episodes": 80,
                    "pair_ids": FULL_PAIR_IDS,
                    "repetitions": 5,
                    "controller_usage": {
                        "api_calls": 80,
                        "cost_usd": 0.0,
                        "known_cost_usd": 0.0,
                        "unknown_cost_api_calls": 0,
                    },
                    "campaign_suite_verified": True,
                    "campaign_elapsed_seconds": 1.0,
                }
                sealed_report = dict(report)
                sealed_report.pop("campaign_suite_verified")
                sealed_report.pop("campaign_elapsed_seconds")
                output.mkdir(parents=True, exist_ok=False)
                (output / "suite-report.json").write_text(
                    json.dumps(sealed_report, sort_keys=True) + "\n", encoding="utf-8"
                )
                return report

            with self.assertRaisesRegex(ValueError, "campaign_qualification_result_missing"):
                run_full_stage(
                    root,
                    runner=full_runner,
                    max_cost_usd=10.0,
                    allow_unknown_costs=False,
                    max_api_calls=2720,
                    max_routes=2,
                    **approval,
                )
            self.assertEqual([], full_calls)

    def test_v230_interrupted_route_cannot_reuse_16_call_reserve(self) -> None:
        """An unaccounted interrupted route consumes its full route reserve."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )

            def interrupted(
                _route: dict[str, object], _stage: str, output: Path, _effort: str
            ) -> dict[str, object]:
                output.mkdir(parents=True, exist_ok=False)
                raise RuntimeError("campaign_controller_timeout")

            first = run_qualification_stage(
                root,
                runner=interrupted,
                max_cost_usd=10.0,
                allow_unknown_costs=False,
                max_api_calls=16,
                max_routes=1,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=10.0,
                    max_api_calls=16,
                    max_routes=1,
                    allow_unknown_costs=False,
                ),
            )
            self.assertEqual(
                16,
                first["spend"]["qualification_failed_attempt_reserved_api_calls"],
            )

            resumed_calls: list[str] = []

            def resumed_runner(
                route: dict[str, object], _stage: str, output: Path, _effort: str
            ) -> dict[str, object]:
                resumed_calls.append(str(route["requested_route"]))
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                )

            run_qualification_stage(
                root,
                runner=resumed_runner,
                max_cost_usd=10.0,
                allow_unknown_costs=True,
                max_api_calls=16,
                max_routes=1,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=10.0,
                    max_api_calls=16,
                    max_routes=1,
                    allow_unknown_costs=True,
                ),
            )
            self.assertEqual([], resumed_calls)

    def test_v230_missing_unknown_cost_count_blocks_stage(self) -> None:
        """Partial dollar telemetry cannot silently claim zero unknown-cost calls."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            calls: list[str] = []

            def runner(
                route: dict[str, object], stage: str, output: Path, effort: str
            ) -> dict[str, object]:
                calls.append(str(route["requested_route"]))
                report = self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                    cost=0.25,
                )
                report["controller_usage"] = {
                    "api_calls": 8,
                    "cost_usd": 0.25,
                    "known_cost_usd": 0.10,
                }
                return report

            approval = self.signed_stage_approval(
                root,
                stage="qualification",
                max_cost_usd=10.0,
                max_api_calls=32,
                max_routes=2,
                allow_unknown_costs=False,
            )
            state = run_qualification_stage(
                root,
                runner=runner,
                max_cost_usd=10.0,
                allow_unknown_costs=False,
                max_api_calls=32,
                max_routes=2,
                **approval,
            )

            self.assertEqual("blocked_unknown_api_calls", state["status"])
            self.assertEqual(1, len(calls))
            self.assertTrue(state["spend"]["unknown_cost_encountered"])

    def test_v230_total_cost_does_not_substitute_for_missing_known_cost(self) -> None:
        """Dedicated receipts reject a missing known-cost lower bound."""
        for label, usage in (
            (
                "missing",
                {
                    "api_calls": 8,
                    "cost_usd": 0.25,
                    "unknown_cost_api_calls": 0,
                },
            ),
            (
                "null",
                {
                    "api_calls": 8,
                    "cost_usd": 0.25,
                    "known_cost_usd": None,
                    "unknown_cost_api_calls": 0,
                },
            ),
        ):
            with self.subTest(known_cost_usd=label):
                report = self.readiness_report()
                report["controller_usage"] = usage
                result = classify_qualification(
                    report,
                    requested_route="xai-oauth/grok-4.5",
                    reasoning_effort="high",
                    execution_contract=QUALIFICATION_CONTRACT_ID,
                )
                self.assertEqual("qualification_contract_invalid", result["status"])

    def test_v230_explicit_zero_cost_is_known_and_not_unknown(self) -> None:
        """An explicitly reported zero remains distinct from absent cost telemetry."""
        result = classify_qualification(
            self.readiness_report(cost=0.0),
            requested_route="xai-oauth/grok-4.5",
            reasoning_effort="high",
            execution_contract=QUALIFICATION_CONTRACT_ID,
        )
        self.assertEqual("qualified", result["status"])
        self.assertEqual(0.0, result["observed_cost_usd"])
        self.assertEqual(0.0, result["observed_known_cost_usd"])
        self.assertEqual(0, result["unknown_cost_api_calls"])

    def test_v230_api_call_count_must_be_a_json_integer(self) -> None:
        """Absent, null, floating, string, and boolean call counts cannot qualify."""
        cases: tuple[tuple[str, dict[str, object]], ...] = (
            ("missing", {}),
            ("null", {"api_calls": None}),
            ("float", {"api_calls": 8.0}),
            ("string", {"api_calls": "8"}),
            ("boolean", {"api_calls": True}),
        )
        for label, api_calls in cases:
            with self.subTest(api_calls=label):
                usage: dict[str, object] = {
                    "cost_usd": 0.08,
                    "known_cost_usd": 0.08,
                    "unknown_cost_api_calls": 0,
                }
                usage.update(api_calls)
                report = self.readiness_report()
                report["controller_usage"] = usage
                result = classify_qualification(
                    report,
                    requested_route="xai-oauth/grok-4.5",
                    reasoning_effort="high",
                    execution_contract=QUALIFICATION_CONTRACT_ID,
                )
                self.assertEqual("qualification_contract_invalid", result["status"])
                self.assertNotIn("scoreable", result)

    def test_v230_invalid_api_calls_receipt_is_terminal_on_signed_resume(self) -> None:
        """A sealed null call count cannot be bypassed by a later signed resume."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={
                    "schema": "oab.doctor/v1",
                    "ready": True,
                    "checks": [],
                    "release_tree_sha256": "sha256:" + "a" * 64,
                },
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            first_calls: list[str] = []

            def invalid_runner(
                route: dict[str, object], _stage: str, output: Path, _effort: str
            ) -> dict[str, object]:
                first_calls.append(str(route["requested_route"]))
                report = self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                    cost=0.0,
                )
                usage = cast(dict[str, object], report["controller_usage"])
                usage["api_calls"] = None
                return report

            first = run_qualification_stage(
                root,
                runner=invalid_runner,
                max_cost_usd=10.0,
                allow_unknown_costs=False,
                max_api_calls=32,
                max_routes=2,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=10.0,
                    max_api_calls=32,
                    max_routes=2,
                    allow_unknown_costs=False,
                ),
            )
            self.assertEqual("blocked_unknown_api_calls", first["status"])
            self.assertEqual(1, len(first_calls))

            resumed_calls: list[str] = []

            def later_runner(
                route: dict[str, object], _stage: str, output: Path, _effort: str
            ) -> dict[str, object]:
                resumed_calls.append(str(route["requested_route"]))
                return self.qualification_report(
                    str(route["requested_route"]),
                    output=output,
                    contract=cast(Mapping[str, object], route["_qualification_contract"]),
                    cost=0.0,
                )

            resumed = run_qualification_stage(
                root,
                runner=later_runner,
                max_cost_usd=10.0,
                allow_unknown_costs=False,
                max_api_calls=32,
                max_routes=2,
                **self.signed_stage_approval(
                    root,
                    stage="qualification",
                    max_cost_usd=10.0,
                    max_api_calls=32,
                    max_routes=2,
                    allow_unknown_costs=False,
                ),
            )
            self.assertEqual("blocked_unknown_cost", resumed["status"])
            self.assertEqual([], resumed_calls)
            self.assertEqual([], resumed["qualified_routes"])

            full_calls: list[str] = []
            with self.assertRaisesRegex(ValueError, "campaign_not_ready_for_full_run"):
                run_full_stage(
                    root,
                    runner=lambda route, *_args: full_calls.append(
                        str(route["requested_route"])
                    )
                    or {},
                    max_cost_usd=10.0,
                    allow_unknown_costs=False,
                    max_api_calls=2720,
                    max_routes=2,
                    approval_path=root / "unreachable-full-approval.json",
                    approval_signature_path=None,
                    approval_public_key_path=None,
                )
            self.assertEqual([], full_calls)

    def test_v230_missing_or_malformed_unknown_cost_count_is_never_zero(self) -> None:
        """Only a literal JSON integer zero may certify zero unknown-cost calls."""
        cases: tuple[tuple[str, dict[str, object]], ...] = (
            ("missing", {}),
            ("null", {"unknown_cost_api_calls": None}),
            ("float", {"unknown_cost_api_calls": 0.0}),
            ("string", {"unknown_cost_api_calls": "0"}),
            ("boolean", {"unknown_cost_api_calls": True}),
            ("negative", {"unknown_cost_api_calls": -1}),
        )
        for label, unknown_cost_calls in cases:
            with self.subTest(unknown_cost_api_calls=label):
                usage: dict[str, object] = {
                    "api_calls": 8,
                    "cost_usd": 0.25,
                    "known_cost_usd": 0.10,
                }
                usage.update(unknown_cost_calls)
                report = self.readiness_report()
                report["controller_usage"] = usage
                result = classify_qualification(
                    report,
                    requested_route="xai-oauth/grok-4.5",
                    reasoning_effort="high",
                    execution_contract=QUALIFICATION_CONTRACT_ID,
                )
                self.assertEqual("qualification_contract_invalid", result["status"])

    def test_v230_api_calls_above_absolute_route_reserve_is_invalid(self) -> None:
        """Absolute reserve is 16 calls/route; more than that cannot be a valid probe pair."""
        report = self.readiness_report()
        report["controller_usage"] = {
            "api_calls": 17,
            "cost_usd": 0.2,
            "known_cost_usd": 0.2,
            "unknown_cost_api_calls": 0,
        }
        result = classify_qualification(
            report,
            requested_route="xai-oauth/grok-4.5",
            reasoning_effort="high",
            execution_contract=QUALIFICATION_CONTRACT_ID,
        )
        self.assertEqual("qualification_contract_invalid", result["status"])

    def test_v230_unknown_cost_is_not_ready_and_stays_null_never_zero(self) -> None:
        report = self.readiness_report(cost=None)
        result = classify_qualification(
            report,
            requested_route="xai-oauth/grok-4.5",
            reasoning_effort="high",
            execution_contract=QUALIFICATION_CONTRACT_ID,
        )
        self.assertEqual("cost_telemetry_unknown", result["status"])
        self.assertEqual(0.0, result["observed_known_cost_usd"])
        self.assertIsNone(result["observed_cost_usd"])
        self.assertEqual(8, result["unknown_cost_api_calls"])

    def test_v230_qualification_output_carries_no_quality_metric(self) -> None:
        result = classify_qualification(
            self.readiness_report(),
            requested_route="xai-oauth/grok-4.5",
            reasoning_effort="high",
            execution_contract=QUALIFICATION_CONTRACT_ID,
        )
        forbidden = {
            "scoreable",
            "completion_rate",
            "matched_pair_completion_rate",
            "pair_stability",
            "diagnostic_gate_pass_rate",
            "contract_completion_rate",
        }
        self.assertEqual(set(), forbidden & set(result))

    def test_v230_route_mismatch_is_infrastructure_not_quality(self) -> None:
        result = classify_qualification(
            self.readiness_report("xai-oauth/other"),
            requested_route="xai-oauth/grok-4.5",
            reasoning_effort="high",
            execution_contract=QUALIFICATION_CONTRACT_ID,
        )
        self.assertEqual("route_mismatch", result["status"])
        self.assertNotIn("scoreable", result)

    def test_qualification_preview_binds_plumbing_only_2_probe_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            record_calibration(
                root, {"schema": "oab.calibration-report/v1", "passed": True, "failures": []}
            )
            preview = build_approval_preview(
                root,
                stage="qualification",
                max_cost_usd=25.0,
                max_api_calls=32,
                max_routes=2,
                allow_unknown_costs=False,
            )
            self.assertEqual(2, preview["episodes_per_route"])
            self.assertEqual(4, preview["max_api_calls_per_episode"])
            self.assertEqual(8, preview["first_attempt_api_calls_per_route"])
            self.assertEqual(16, preview["absolute_api_calls_per_route"])
            self.assertEqual(16, preview["minimum_required_api_calls"])
            self.assertEqual(32, preview["absolute_reserved_api_calls"])
            self.assertTrue(preview["call_ceiling_sufficient"])
            self.assertIn("Plumbing-only", str(preview["stage_purpose"]))
            self.assertIn("No model-quality score", str(preview["stage_purpose"]))
            serialized = json.dumps(preview)
            self.assertNotIn("completion_rate", serialized)
            self.assertNotIn("%", serialized)

    def test_qualification_preview_rejects_ceiling_below_absolute_reserve(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "campaign"
            initialize_campaign(
                root,
                doctor={"schema": "oab.doctor/v1", "ready": True, "checks": []},
                inventory_payload=self.inventory(),
                reasoning_effort="high",
            )
            record_calibration(
                root, {"schema": "oab.calibration-report/v1", "passed": True, "failures": []}
            )
            preview = build_approval_preview(
                root,
                stage="qualification",
                max_cost_usd=25.0,
                max_api_calls=31,
                max_routes=2,
                allow_unknown_costs=False,
            )
            self.assertFalse(preview["call_ceiling_sufficient"])

    def test_legacy_generic_cost_telemetry_is_read_only_not_execution_authority(self) -> None:
        """Old generic shapes remain readable only and cannot authorize readiness."""
        report = self.legacy_generic_qualification_report(
            controller_usage={"api_calls": 8}
        )
        result = classify_qualification(
            report,
            requested_route="xai-oauth/grok-4.5",
            reasoning_effort="high",
            execution_contract=QUALIFICATION_CONTRACT_ID,
        )
        self.assertEqual("qualification_contract_invalid", result["status"])

    def test_legacy_generic_unknown_cost_shape_is_read_only_not_execution_authority(self) -> None:
        report = self.legacy_generic_qualification_report(
            controller_usage={"api_calls": 8, "cost_usd": None}
        )
        result = classify_qualification(
            report,
            requested_route="xai-oauth/grok-4.5",
            reasoning_effort="high",
            execution_contract=QUALIFICATION_CONTRACT_ID,
        )
        self.assertEqual("qualification_contract_invalid", result["status"])

    def test_decision_rejects_cross_platform_or_backend_comparison(self) -> None:
        context = self.authoritative_decision_context("route-current", "route-next")
        bindings = cast(Mapping[str, object], context["bindings"])
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
            "controller_usage": {"api_calls": 80},
            "authoritative_stage": bindings["route-current"],
        }
        candidate = {
            **baseline,
            "requested_route": "openai-codex/gpt-next",
            "deterministic_contract_completion_rate": 0.90,
            "execution_environment": {"platform": "linux", "sandbox_backend": "bubblewrap-libseccomp"},
            "authoritative_stage": bindings["route-next"],
        }
        report = build_decision_report(
            current_route="openai-codex/gpt-current",
            expected_pair_ids=FULL_PAIR_IDS,
            expected_repetitions=5,
            expected_release_tree_sha256="sha256:" + "c" * 64,
            authoritative_full_plan=cast(Mapping[str, object], context["authoritative_full_plan"]),
            expected_plan_sha256=cast(str, context["expected_plan_sha256"]),
            expected_stage_approval_sha256=cast(str, context["expected_stage_approval_sha256"]),
            suite_reports=[baseline, candidate],
        )
        self.assertEqual("not_supportable", report["recommendation"])
        self.assertIn("fewer_than_two_authoritative_routes", report["reasons"])

    def test_decision_is_invariant_to_diagnostic_gate_pass_rate(self) -> None:
        """diagnostic_gate_pass_rate must never influence a switch decision.

        It exists to break 0%-vs-0% ties for a human reader. If it ever reached
        the decision path, a route could be recommended on partial gate credit
        without completing a single contract.
        """
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
            "deterministic_contract_completion_rate": 0.90,
            "matched_pair_completion_rate": 0.80,
            "pair_stability": {"min": 0.60},
        }
        kwargs = {
            "current_route": "openai-codex/gpt-current",
            "expected_pair_ids": FULL_PAIR_IDS,
            "expected_repetitions": 5,
            "expected_release_tree_sha256": "sha256:" + "c" * 64,
        }
        without = build_decision_report(suite_reports=[baseline, candidate], **kwargs)

        # Invert the diagnostic signal: the losing route gets a perfect gate
        # pass rate, the winning route gets zero.
        baseline_with = {**baseline, "diagnostic_gate_pass_rate": 1.0}
        candidate_with = {**candidate, "diagnostic_gate_pass_rate": 0.0}
        with_diagnostic = build_decision_report(
            suite_reports=[baseline_with, candidate_with], **kwargs
        )

        for key in ("recommendation", "recommended_route", "reasons", "comparable_routes"):
            self.assertEqual(without[key], with_diagnostic[key], key)

    def test_decision_recommends_only_strict_dominance(self) -> None:
        context = self.authoritative_decision_context("route-current", "route-next")
        bindings = cast(Mapping[str, object], context["bindings"])
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
            "controller_usage": {"api_calls": 80},
            "authoritative_stage": bindings["route-current"],
        }
        candidate = {
            **baseline,
            "requested_route": "openai-codex/gpt-next",
            "deterministic_contract_completion_rate": 0.85,
            "matched_pair_completion_rate": 0.80,
            "pair_stability": {"min": 0.60},
            "authoritative_stage": bindings["route-next"],
        }
        report = build_decision_report(
            current_route="openai-codex/gpt-current",
            expected_pair_ids=FULL_PAIR_IDS,
            expected_repetitions=5,
            expected_release_tree_sha256="sha256:" + "c" * 64,
            authoritative_full_plan=cast(Mapping[str, object], context["authoritative_full_plan"]),
            expected_plan_sha256=cast(str, context["expected_plan_sha256"]),
            expected_stage_approval_sha256=cast(str, context["expected_stage_approval_sha256"]),
            suite_reports=[baseline, candidate],
        )
        self.assertEqual("switch", report["recommendation"])
        self.assertEqual("openai-codex/gpt-next", report["recommended_route"])

    def test_decision_rejects_different_pair_grid_even_with_80_episodes(self) -> None:
        context = self.authoritative_decision_context("route-current", "route-next")
        bindings = cast(Mapping[str, object], context["bindings"])
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
            "controller_usage": {"api_calls": 80},
            "authoritative_stage": bindings["route-current"],
        }
        candidate = {
            **baseline,
            "requested_route": "openai-codex/gpt-next",
            "pair_ids": [f"Q{index:02d}" for index in range(1, 9)],
            "deterministic_contract_completion_rate": 0.90,
            "authoritative_stage": bindings["route-next"],
        }
        report = build_decision_report(
            current_route="openai-codex/gpt-current",
            expected_pair_ids=FULL_PAIR_IDS,
            expected_repetitions=5,
            expected_release_tree_sha256="sha256:" + "c" * 64,
            authoritative_full_plan=cast(Mapping[str, object], context["authoritative_full_plan"]),
            expected_plan_sha256=cast(str, context["expected_plan_sha256"]),
            expected_stage_approval_sha256=cast(str, context["expected_stage_approval_sha256"]),
            suite_reports=[baseline, candidate],
        )
        self.assertEqual("not_supportable", report["recommendation"])
        self.assertIn("fewer_than_two_authoritative_routes", report["reasons"])


if __name__ == "__main__":
    unittest.main()
