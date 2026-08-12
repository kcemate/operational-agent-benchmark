from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from typing import Mapping, cast
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oab.campaign_authorization import (
    campaign_plan_sha256,
    canonical_bytes,
    canonical_sha256,
    encode_child_authorization_envelope,
)
from oab.full_stage_contract import (
    AUTHORITATIVE_FULL_PAIR_IDS,
    FULL_REPETITIONS,
    authoritative_full_contract_for_route_count,
)
from oab.qualification_contract import (
    QUALIFICATION_CONTRACT_ID,
    qualification_contract_for_route_count,
)
from oab.suite_seal import verify_suite_seal
from tools.agent_workflow import _production_suite_runner
from tools import run_suite


class CampaignChildAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name) / "campaign"
        self.root.mkdir(mode=0o700)
        self.output_parent = self.root / "qualification" / "attempts"
        self.output_parent.mkdir(mode=0o700, parents=True)
        self.redirected_output_parent = Path(self.tempdir.name) / "redirected-outputs"
        self.redirected_output_parent.mkdir(mode=0o700)
        self.output_name = "a" * 32 + ".evidence"
        manifest = json.loads((run_suite.ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
        self.release_tree = str(manifest["tree_sha256"])
        self.private = Ed25519PrivateKey.generate()
        self.public_bytes = self.private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_digest = "sha256:" + hashlib.sha256(self.public_bytes).hexdigest()
        self._write_signed_campaign()

    def _write_signed_campaign(self) -> None:
        calibration = {"schema": "oab.calibration/v1", "result": "passed"}
        calibration_digest = canonical_sha256(calibration)
        (self.root / "CALIBRATION.json").write_bytes(canonical_bytes(calibration))
        plan: dict[str, object] = {
            "schema": "oab.campaign-plan/v2",
            "created_at": "2026-08-11T00:00:00+00:00",
            "campaign_id": "campaign-child-test",
            "routes": [{"route_id": "route-1", "requested_route": "offline/test"}],
            "route_count": 1,
            "baseline_route": "offline/test",
            "reasoning_effort": "high",
            "qualification": qualification_contract_for_route_count(1),
            "full_run": authoritative_full_contract_for_route_count(1),
            "release_tree_sha256": self.release_tree,
            "approval_authority_public_key_sha256": self.public_digest,
        }
        plan["plan_sha256"] = campaign_plan_sha256(plan)
        (self.root / "PLAN.json").write_bytes(canonical_bytes(plan))
        context = {
            "schema": "oab.stage-execution-context/v1",
            "campaign_root_context_sha256": "sha256:"
            + hashlib.sha256(str(self.root.resolve()).encode("utf-8")).hexdigest(),
            "stage": "qualification",
            "routes": [
                {
                    "route_id": "route-1",
                    "requested_route": "offline/test",
                    "output_relative_path": f"qualification/attempts/{self.output_name}",
                }
            ],
        }
        receipt: dict[str, object] = {
            "schema": "oab.stage-approval/v5",
            "created_at": "2026-08-11T00:00:00+00:00",
            "stage": "qualification",
            "plan_sha256": str(plan["plan_sha256"]),
            "calibration_sha256": calibration_digest,
            "route_ids": ["route-1"],
            "observed_cost_stop_usd": 1.0,
            "cost_control_mode": "post_provider_call_observed_known_cost_stop",
            "max_cost_overshoot_api_calls": 1,
            "max_api_calls": 16,
            "max_routes": 1,
            "allow_unknown_costs": False,
            "approval_public_key_sha256": self.public_digest,
            "qualification_contract": plan["qualification"],
            "qualification_contract_sha256": canonical_sha256(plan["qualification"]),
            "execution_context": context,
        }
        receipt["receipt_sha256"] = canonical_sha256(receipt)
        signature = self.private.sign(canonical_bytes(receipt))
        self.envelope = encode_child_authorization_envelope(
            approval_receipt=receipt,
            signature=signature,
            public_key_pem=self.public_bytes,
        )

    @contextlib.contextmanager
    def _fake_runtime(self):
        yield SimpleNamespace(home=Path(self.tempdir.name), config_sha256="sha256:" + "8" * 64)

    def _invoke(
        self,
        *,
        envelope: bytes | None = None,
        provider: str = "offline",
        model: str = "test",
        effort: str = "high",
        max_api_calls: int = 16,
        max_cost: float = 1.0,
        allow_unknown_costs: bool = False,
        output_name: str | None = None,
        output_parent: Path | None = None,
    ) -> tuple[int, list[str]]:
        saved_cwd_fd = os.open(".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        selected_output_parent = output_parent or self.output_parent
        output_fd = os.open(selected_output_parent, os.O_RDONLY | os.O_DIRECTORY)
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        calls: list[str] = []
        with tempfile.TemporaryFile() as transport:
            if envelope is not None:
                transport.write(envelope)
                transport.flush()
                transport.seek(0)
            args = [
                "--provider", provider,
                "--model", model,
                "--reasoning-effort", effort,
                "--output-root", str(selected_output_parent / str(output_name or self.output_name)),
                "--output-parent-fd", str(output_fd),
                "--output-name", str(output_name or self.output_name),
                "--qualification-readiness-v1",
                "--campaign-root-path", str(self.root.resolve()),
                "--campaign-root-fd", str(root_fd),
                "--campaign-authorization-fd", str(transport.fileno()),
                "--max-api-calls", str(max_api_calls),
                "--max-observed-cost-usd", str(max_cost),
            ]
            if allow_unknown_costs:
                args.append("--allow-unknown-costs")
            with patch.object(run_suite, "verify_release_manifest", return_value=[]), patch.object(
                run_suite, "pinned_hermes_runtime", lambda *args, **kwargs: self._fake_runtime()
            ), patch.object(
                run_suite,
                "_run_qualification_readiness",
                side_effect=lambda **_: calls.append("controller") or {"status": "offline-ok"},
            ):
                try:
                    status = run_suite.main(args)
                finally:
                    os.fchdir(saved_cwd_fd)
                    os.close(output_fd)
                    os.close(root_fd)
                    os.close(saved_cwd_fd)
        return status, calls

    def test_unsigned_direct_child_reaches_zero_controller_construction(self) -> None:
        with self.assertRaisesRegex(SystemExit, "campaign_child_authorization_required"):
            self._invoke(envelope=None)

    def test_exact_externally_signed_child_reaches_offline_controller_once(self) -> None:
        status, calls = self._invoke(envelope=self.envelope)

        self.assertEqual(0, status)
        self.assertEqual(["controller"], calls)

    def test_signed_output_name_cannot_be_redirected_through_another_parent_fd(self) -> None:
        with self.assertRaisesRegex(SystemExit, "campaign_child_output_parent_invalid"):
            self._invoke(
                envelope=self.envelope,
                output_parent=self.redirected_output_parent,
            )
        self.assertFalse((self.redirected_output_parent / self.output_name).exists())

    def test_tampered_route_effort_plan_key_cost_or_output_is_rejected_before_controller(self) -> None:
        alternate_private = Ed25519PrivateKey.generate()
        alternate_public = alternate_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        tampered_key_envelope = encode_child_authorization_envelope(
            approval_receipt=json.loads(self.envelope.decode("utf-8"))["approval_receipt"],
            signature=base64.b64decode(json.loads(self.envelope.decode("utf-8"))["signature_base64"]),
            public_key_pem=alternate_public,
        )
        cases = (
            ("route", {"provider": "offline", "model": "other"}),
            ("effort", {"effort": "low"}),
            ("cost", {"max_cost": 1.01}),
            ("output", {"output_name": "b" * 32 + ".evidence"}),
            ("key", {"envelope": tampered_key_envelope}),
        )
        for label, kwargs in cases:
            with self.subTest(label=label):
                invocation = {"envelope": self.envelope, **kwargs}
                with self.assertRaises(SystemExit):
                    self._invoke(**invocation)
        plan = json.loads((self.root / "PLAN.json").read_text(encoding="utf-8"))
        plan["reasoning_effort"] = "low"
        (self.root / "PLAN.json").write_bytes(canonical_bytes(plan))
        with self.assertRaises(SystemExit):
            self._invoke(envelope=self.envelope)
class ParentCreatedChildAuthorizationSubprocessTests(unittest.TestCase):
    """Exercise the real parent subprocess and descriptor proof boundary offline."""

    def setUp(self) -> None:
        self._real_python = sys.executable
        self._repository_root = Path(__file__).resolve().parents[1]
        self._harness = self._repository_root / "tests" / "parent_child_subprocess_harness.py"

    @staticmethod
    def _canonical_file_digest(path: Path) -> str:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    @contextlib.contextmanager
    def _campaign(self, *, stage: str):
        with tempfile.TemporaryDirectory() as td:
            temporary_root = Path(td)
            root = temporary_root / "campaign"
            root.mkdir(mode=0o700)
            (root / stage / "attempts").mkdir(parents=True, mode=0o700)
            approvals = root / "APPROVALS"
            approvals.mkdir(mode=0o700)
            output_name = "f" * 32 + ".evidence"
            private = Ed25519PrivateKey.generate()
            public_bytes = private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            public_digest = "sha256:" + hashlib.sha256(public_bytes).hexdigest()
            release_tree = str(
                json.loads(
                    (run_suite.ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8")
                )["tree_sha256"]
            )
            calibration = {"schema": "oab.calibration-report/v2", "passed": True, "cases": []}
            (root / "CALIBRATION.json").write_bytes(canonical_bytes(calibration))
            plan: dict[str, object] = {
                "schema": "oab.campaign-plan/v2",
                "created_at": "2026-08-11T00:00:00+00:00",
                "campaign_id": "parent-child-subprocess-test",
                "routes": [{"route_id": "route-1", "requested_route": "offline/test"}],
                "route_count": 1,
                "baseline_route": "offline/test",
                "reasoning_effort": "high",
                "qualification": qualification_contract_for_route_count(1),
                "full_run": authoritative_full_contract_for_route_count(1),
                "release_tree_sha256": release_tree,
                "approval_authority_public_key_sha256": public_digest,
            }
            plan["plan_sha256"] = campaign_plan_sha256(plan)
            (root / "PLAN.json").write_bytes(canonical_bytes(plan))
            context = {
                "schema": "oab.stage-execution-context/v1",
                "campaign_root_context_sha256": "sha256:"
                + hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest(),
                "stage": stage,
                "routes": [
                    {
                        "route_id": "route-1",
                        "requested_route": "offline/test",
                        "output_relative_path": f"{stage}/attempts/{output_name}",
                    }
                ],
            }
            contract_key = "qualification_contract" if stage == "qualification" else "full_contract"
            contract = plan["qualification"] if stage == "qualification" else plan["full_run"]
            receipt: dict[str, object] = {
                "schema": "oab.stage-approval/v5",
                "created_at": "2026-08-11T00:00:00+00:00",
                "stage": stage,
                "plan_sha256": plan["plan_sha256"],
                "calibration_sha256": canonical_sha256(calibration),
                "route_ids": ["route-1"],
                "observed_cost_stop_usd": 1.0,
                "cost_control_mode": "post_provider_call_observed_known_cost_stop",
                "max_cost_overshoot_api_calls": 1,
                "max_api_calls": 16 if stage == "qualification" else 1360,
                "max_routes": 1,
                "allow_unknown_costs": False,
                "approval_public_key_sha256": public_digest,
                contract_key: contract,
                f"{contract_key}_sha256": canonical_sha256(cast(Mapping[str, object], contract)),
                "execution_context": context,
            }
            receipt["receipt_sha256"] = canonical_sha256(receipt)
            approval_path = approvals / f"{stage}.json"
            signature_path = approvals / f"{stage}.sig"
            public_path = approvals / "approval-public.pem"
            approval_path.write_bytes(canonical_bytes(receipt))
            signature_path.write_bytes(private.sign(canonical_bytes(receipt)))
            public_path.write_bytes(public_bytes)
            release_approval_path = temporary_root / "release-approval.json"
            release_approval_path.write_text(
                json.dumps(
                    {
                        "schema": "oab.release-approval/v1",
                        "release_tree_sha256": release_tree,
                        "reviews": [
                            {
                                "role": "security",
                                "reviewer": "offline-security-review",
                                "decision": "APPROVE",
                                "reviewed_tree_sha256": release_tree,
                                "claim_limitations_acknowledged": True,
                            },
                            {
                                "role": "product",
                                "reviewer": "offline-product-review",
                                "decision": "APPROVE",
                                "reviewed_tree_sha256": release_tree,
                                "claim_limitations_acknowledged": True,
                            },
                        ],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            output = root / stage / "attempts" / output_name
            route: dict[str, object] = {
                "route_id": "route-1",
                "requested_route": "offline/test",
                "provider": "offline",
                "model": "test",
                "max_api_calls": 16 if stage == "qualification" else 1360,
                "max_observed_cost_usd": 1.0,
                "allow_unknown_costs": False,
                "_campaign_root_path": str(root.resolve()),
                "_campaign_output_relative_path": f"{stage}/attempts/{output_name}",
                "_campaign_approval_path": str(approval_path),
                "_campaign_approval_signature_path": str(signature_path),
                "_campaign_approval_public_key_path": str(public_path),
            }
            if stage == "qualification":
                route["_qualification_contract_version"] = QUALIFICATION_CONTRACT_ID
                route["_qualification_contract"] = plan["qualification"]
            child_marker = temporary_root / "child-entered"
            controller_marker = temporary_root / "controller-constructed"
            wrapper = temporary_root / "offline-child-wrapper.py"
            wrapper.write_text(
                "#!" + self._real_python + "\n"
                "import os, sys\n"
                "target = os.environ['OAB_TEST_REAL_PYTHON']\n"
                "os.execv(target, [target, os.environ['OAB_TEST_HARNESS'], *sys.argv[1:]])\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            yield {
                "root": root,
                "route": route,
                "output": output,
                "approval_public_path": public_path,
                "release_approval_path": release_approval_path,
                "release_approval_sha256": self._canonical_file_digest(release_approval_path),
                "child_marker": child_marker,
                "controller_marker": controller_marker,
                "wrapper": wrapper,
                "temporary_root": temporary_root,
            }

    def _runner(
        self, context: Mapping[str, object], *, stage: str, timeout_seconds: float = 20
    ):
        release_path = context["release_approval_path"] if stage == "full" else None
        release_sha = context["release_approval_sha256"] if stage == "full" else None
        return _production_suite_runner(
            source_hermes_home=None,
            release_approval=cast(Path | None, release_path),
            expected_release_approval_sha256=cast(str | None, release_sha),
            timeout_seconds=timeout_seconds,
        )

    @contextlib.contextmanager
    def _subprocess_environment(self, context: Mapping[str, object]):
        temporary_root = cast(Path, context["temporary_root"])
        environment = {
            "OAB_TEST_REPOSITORY_ROOT": str(self._repository_root),
            "OAB_TEST_HARNESS": str(self._harness),
            "OAB_TEST_REAL_PYTHON": self._real_python,
            "OAB_TEST_CHILD_MARKER": str(context["child_marker"]),
            "OAB_TEST_CONTROLLER_MARKER": str(context["controller_marker"]),
            "OAB_TEST_STAGE_ROOT": str(temporary_root / "harness-staging"),
        }
        with patch.dict(os.environ, environment, clear=False), patch(
            "tools.agent_workflow.sys.executable", str(context["wrapper"])
        ):
            yield

    @contextlib.contextmanager
    def _public_child_environment(self, context: Mapping[str, object]):
        """Inject an offline test module without altering product CLI behavior.

        The real parent still launches its normal ``sys.executable -m
        tools.run_suite`` command and passes its real descriptor FDs.  A temporary
        ``sitecustomize`` bootstrap exists only on this test subprocess's
        PYTHONPATH; no public CLI argument or production environment switch can
        select the test seam.
        """

        temporary_root = cast(Path, context["temporary_root"])
        bootstrap = temporary_root / "public-child-bootstrap"
        bootstrap.mkdir(mode=0o700)
        (bootstrap / "sitecustomize.py").write_text(
            "from public_full_child_test_seam import install\ninstall()\n",
            encoding="utf-8",
        )
        config_path = temporary_root / "public-child-seam.json"
        config_path.write_text(
            json.dumps(
                {
                    "child_marker": str(cast(Path, context["child_marker"])),
                    "controller_marker": str(cast(Path, context["controller_marker"])),
                    "runtime_home": str(temporary_root / "public-child-runtime"),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        existing_pythonpath = os.environ.get("PYTHONPATH", "")
        # The child must import this exact working-tree candidate, not an older
        # installed ``tools`` package that may also exist in the test venv.
        pythonpath_parts = [
            str(bootstrap),
            str(self._repository_root),
            str(self._repository_root / "tests"),
        ]
        if existing_pythonpath:
            pythonpath_parts.append(existing_pythonpath)
        environment = {
            "OAB_TEST_PUBLIC_FULL_CHILD_SEAM": "1",
            "OAB_TEST_PUBLIC_FULL_CHILD_CONFIG": str(config_path),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join(pythonpath_parts),
        }
        with patch.dict(os.environ, environment, clear=False):
            yield

    @staticmethod
    def _jsonl_records(path: Path) -> list[dict[str, object]]:
        if not path.exists():
            return []
        values = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        if not all(isinstance(value, dict) for value in values):
            raise AssertionError("test_marker_record_invalid")
        return [cast(dict[str, object], value) for value in values]

    def _assert_public_child_rejected_before_controller(self, *, tamper: str) -> None:
        with self.subTest(tamper=tamper), self._campaign(stage="full") as context:
            route = cast(dict[str, object], context["route"])
            output = cast(Path, context["output"])
            root = cast(Path, context["root"])
            if tamper == "plan":
                plan_path = root / "PLAN.json"
                plan = json.loads(plan_path.read_text(encoding="utf-8"))
                plan["reasoning_effort"] = "low"
                plan_path.write_bytes(canonical_bytes(plan))
            elif tamper == "route":
                route["model"] = "other"
            elif tamper == "output":
                output = output.with_name("e" * 32 + ".evidence")
            else:
                raise AssertionError(f"unknown_public_child_tamper:{tamper}")
            runner = self._runner(context, stage="full", timeout_seconds=30)
            with self._public_child_environment(context):
                with self.assertRaises(RuntimeError):
                    runner(route, "full", output, "high")
            records = self._jsonl_records(cast(Path, context["child_marker"]))
            endpoint_records = [
                record
                for record in records
                if record.get("event") == "public_child_bootstrap"
                and "tools.run_suite" in cast(list[object], record.get("orig_argv", []))
            ]
            self.assertEqual(1, len(endpoint_records))
            self.assertFalse(cast(Path, context["controller_marker"]).exists())
            self.assertFalse(output.exists())

    def _run_happy_child(self, context: Mapping[str, object], *, stage: str) -> dict[str, object]:
        runner = self._runner(context, stage=stage)
        route = dict(cast(Mapping[str, object], context["route"]))
        output = cast(Path, context["output"])
        with self._subprocess_environment(context), patch(
            "tools.agent_workflow.verify_suite_seal", return_value=[]
        ):
            report = runner(route, stage, output, "high")
        self.assertTrue(cast(Path, context["child_marker"]).exists())
        marker = cast(Path, context["child_marker"]).read_text(encoding="utf-8").strip()
        self.assertNotEqual(str(os.getpid()), marker)
        self.assertTrue(cast(Path, context["controller_marker"]).exists())
        return report

    def _assert_rejected_before_controller(self, *, stage: str, tamper: str) -> None:
        with self.subTest(stage=stage, tamper=tamper), self._campaign(stage=stage) as context:
            route = cast(dict[str, object], context["route"])
            output = cast(Path, context["output"])
            root = cast(Path, context["root"])
            effort = "high"
            if tamper == "route":
                route["model"] = "other"
            elif tamper == "effort":
                effort = "low"
            elif tamper == "plan":
                plan_path = root / "PLAN.json"
                plan = json.loads(plan_path.read_text(encoding="utf-8"))
                plan["reasoning_effort"] = "low"
                plan_path.write_bytes(canonical_bytes(plan))
            elif tamper == "key":
                alternate = Ed25519PrivateKey.generate().public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                cast(Path, context["approval_public_path"]).write_bytes(alternate)
            elif tamper == "cost":
                route["max_observed_cost_usd"] = 1.01
            elif tamper == "output":
                output = output.with_name("e" * 32 + ".evidence")
            else:
                raise AssertionError(f"unknown_tamper:{tamper}")
            runner = self._runner(context, stage=stage)
            with self._subprocess_environment(context), patch(
                "tools.agent_workflow.verify_suite_seal", return_value=[]
            ):
                with self.assertRaises(RuntimeError):
                    runner(route, stage, output, effort)
            self.assertTrue(cast(Path, context["child_marker"]).exists())
            self.assertFalse(cast(Path, context["controller_marker"]).exists())
            self.assertFalse(output.exists())

    def test_parent_created_proof_qualification_subprocess_accepts_and_rejects_tampering(self) -> None:
        with self._campaign(stage="qualification") as context:
            report = self._run_happy_child(context, stage="qualification")
            self.assertEqual("oab.qualification-suite-report/v1", report["schema"])
            self.assertEqual("READY", report["readiness"])
            self.assertEqual(8, cast(Mapping[str, object], report["controller_usage"])["api_calls"])
        for tamper in ("route", "effort", "plan", "key", "cost", "output"):
            self._assert_rejected_before_controller(stage="qualification", tamper=tamper)

    def test_parent_created_proof_full_subprocess_accepts_and_rejects_tampering(self) -> None:
        with self._campaign(stage="full") as context:
            report = self._run_happy_child(context, stage="full")
            self.assertEqual("oab.suite-report/v1", report["schema"])
            self.assertEqual(80, report["scheduled_episodes"])
            self.assertEqual(1360, cast(Mapping[str, object], report["controller_usage"])["api_calls"])
            binding = cast(Mapping[str, object], report["authoritative_stage"])
            self.assertEqual("full", binding["stage"])
            full_contract = cast(Mapping[str, object], binding["full_contract"])
            pair_ids = cast(list[object], full_contract["pair_ids"])
            self.assertEqual(
                list(range(1, 9)),
                [int(str(pair).removeprefix("P")) for pair in pair_ids],
            )
        for tamper in ("route", "effort", "plan", "key", "cost", "output"):
            self._assert_rejected_before_controller(stage="full", tamper=tamper)

    def test_parent_created_proof_full_public_run_suite_child_accepts_and_seals(self) -> None:
        """Run the actual protected CLI child through the parent FD handoff.

        This intentionally does not replace the child executable with the legacy
        subprocess harness.  The temporary test-only bootstrap supplies a
        no-network controller and deterministic positive-control artifacts; every
        authorization, full-grid, aggregation, report, and seal path remains the
        production implementation.
        """

        public_child_source = (self._repository_root / "tools" / "run_suite.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("OAB_TEST_PUBLIC_FULL_CHILD", public_child_source)
        self.assertNotIn("public_full_child_test_seam", public_child_source)
        with self._campaign(stage="full") as context:
            route = dict(cast(Mapping[str, object], context["route"]))
            output = cast(Path, context["output"])
            runner = self._runner(context, stage="full", timeout_seconds=180)
            with self._public_child_environment(context):
                report = runner(route, "full", output, "high")

            records = self._jsonl_records(cast(Path, context["child_marker"]))
            endpoint_records = [
                record
                for record in records
                if record.get("event") == "public_child_bootstrap"
                and "tools.run_suite" in cast(list[object], record.get("orig_argv", []))
            ]
            self.assertEqual(1, len(endpoint_records))
            endpoint_argv = cast(list[object], endpoint_records[0]["orig_argv"])
            self.assertIn("-m", endpoint_argv)
            self.assertIn("tools.run_suite", endpoint_argv)
            self.assertIn("--authoritative-full-v1", endpoint_argv)
            self.assertIn("--output-parent-fd", endpoint_argv)
            self.assertIn("--campaign-root-fd", endpoint_argv)
            self.assertIn("--campaign-authorization-fd", endpoint_argv)
            self.assertNotIn("parent_child_subprocess_harness.py", endpoint_argv)

            controller_records = self._jsonl_records(cast(Path, context["controller_marker"]))
            self.assertEqual(80, len(controller_records))
            self.assertEqual(
                {17}, {record.get("max_api_calls") for record in controller_records}
            )
            self.assertEqual(
                {"offline"}, {record.get("provider") for record in controller_records}
            )
            self.assertEqual({"test"}, {record.get("model") for record in controller_records})

            self.assertTrue(report["campaign_suite_verified"])
            self.assertEqual("oab.suite-report/v1", report["schema"])
            self.assertTrue(report["authoritative"])
            self.assertTrue(report["release_authorized"])
            self.assertEqual(80, report["scheduled_episodes"])
            self.assertEqual(1360, cast(Mapping[str, object], report["controller_usage"])["api_calls"])
            observations = cast(list[Mapping[str, object]], report["observations"])
            self.assertEqual(80, len(observations))
            expected_grid = {
                (pair_id, variant, repetition)
                for pair_id in AUTHORITATIVE_FULL_PAIR_IDS
                for variant in ("approved", "prohibited")
                for repetition in range(1, FULL_REPETITIONS + 1)
            }
            observed_grid = {
                (
                    str(observation["pair_id"]),
                    str(observation["variant"]),
                    int(cast(int | str, observation["repetition"])),
                )
                for observation in observations
            }
            self.assertEqual(expected_grid, observed_grid)
            self.assertTrue(
                all(
                    cast(Mapping[str, object], observation["controller_usage"])["api_calls"] == 17
                    for observation in observations
                )
            )
            binding = cast(Mapping[str, object], report["authoritative_stage"])
            self.assertEqual("full", binding["stage"])
            self.assertEqual(
                str(route["_campaign_output_relative_path"]), binding["output_relative_path"]
            )
            self.assertTrue((output / "suite-report.json").is_file())
            self.assertTrue((output / "SUITE_SEAL.json").is_file())
            self.assertTrue((output / "RELEASE_APPROVAL.json").is_file())
            self.assertEqual([], verify_suite_seal(output))

        for tamper in ("plan", "route", "output"):
            self._assert_public_child_rejected_before_controller(tamper=tamper)


if __name__ == "__main__":
    unittest.main()
