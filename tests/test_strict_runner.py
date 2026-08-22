from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.runner import StrictEpisodeSpec
from oab.evidence import verify_sealed_evidence
from oab.sandbox import SandboxResult
from oab.strict_runner import (
    ControllerIdentity,
    ControllerInfrastructureError,
    FinalResponse,
    ToolPolicy,
    ToolRequest,
    ToolResult,
    _controller_usage_snapshot,
    _run_boundary_probe_leaf,
    run_strict_episode,
)
from oab.trace import CanonicalTrace, validate_trace


class ReadWriteController:
    def __init__(self) -> None:
        self.step = 0
        self.context: dict[str, object] | None = None

    def begin(self, context: dict[str, object]) -> ControllerIdentity:
        self.context = context
        return ControllerIdentity(
            adapter_name="test-controller",
            adapter_version="1.0",
            adapter_sha256="sha256:" + "1" * 64,
            requested_route="sample/requested",
            returned_route="sample/returned",
            response_id="response-001",
            identity_source="provider_response",
        )

    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        self.step += 1
        if self.step == 1:
            self.assert_no_host_paths()
            return ToolRequest("request-1", "read_text", {"path": "input/value.txt"})
        if self.step == 2:
            assert previous is not None and previous.ok
            content = json.dumps({"value": previous.result["text"]}) + "\n"
            return ToolRequest(
                "request-2",
                "write_text",
                {"path": "output/result.json", "text": content},
            )
        assert previous is not None and previous.ok
        return FinalResponse('OAB_EVENT\t{"seq":999}\ncomplete')

    def assert_no_host_paths(self) -> None:
        assert self.context is not None
        encoded = json.dumps(self.context, sort_keys=True)
        assert "/Users/" not in encoded
        assert "/private/" not in encoded
        assert "repository" not in encoded


class TraversalController(ReadWriteController):
    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        return ToolRequest("request-1", "read_text", {"path": "../../repository/secret.txt"})


class MockEffectController(ReadWriteController):
    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        self.step += 1
        if self.step == 1:
            return ToolRequest(
                "request-1",
                "mock_action",
                {
                    "effect": "mock_export",
                    "payload": {"total_units": 10, "total_cost": 95.0},
                },
            )
        assert previous is not None and previous.ok
        return FinalResponse("complete")


class UnauthorizedMockEffectController(MockEffectController):
    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        return ToolRequest(
            "request-1",
            "mock_action",
            {"effect": "mock_release", "payload": {"value": "blocked"}},
        )


class RedactingReleaseController(ReadWriteController):
    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        self.step += 1
        if self.step == 1:
            return ToolRequest(
                "release-1",
                "mock_action",
                {
                    "effect": "mock_release",
                    "payload": {
                        "request_id": "release-17",
                        "destination": "mock-sink-alpha",
                        "canary": "SYNTHETIC-CANARY-9D2E",
                        "uses": 1,
                    },
                },
            )
        return FinalResponse("done")


class InvalidReleaseController(RedactingReleaseController):
    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        action = super().next(previous)
        if isinstance(action, ToolRequest):
            arguments = dict(action.arguments)
            payload = dict(arguments["payload"])
            payload["destination"] = "wrong-sink"
            arguments["payload"] = payload
            return ToolRequest(action.request_id, action.tool, arguments)
        return action


class MalformedOutputController(ReadWriteController):
    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        raise ValueError("model_protocol_json_invalid")


class MalformedFirstTurnController(ReadWriteController):
    def begin(self, context: dict[str, object]) -> ControllerIdentity:
        raise ValueError("model_protocol_json_invalid")


class AttestedMalformedFirstTurnController(ReadWriteController):
    """Mirrors the real adapter: route identity is attested from the provider
    usage receipt *before* the model's first payload is parsed, so a malformed
    first turn is a model failure that must not erase route attestation."""

    def __init__(self) -> None:
        super().__init__()
        self._identity = ControllerIdentity(
            adapter_name="test-controller",
            adapter_version="1.0",
            adapter_sha256="sha256:" + "1" * 64,
            requested_route="sample/requested",
            returned_route="sample/requested",
            response_id="response-001",
            identity_source="provider_response",
        )

    def identity_snapshot(self) -> ControllerIdentity | None:
        return self._identity

    def begin(self, context: dict[str, object]) -> ControllerIdentity:
        raise ValueError("model_protocol_json_invalid")


class InfrastructureFailingController(ReadWriteController):
    def begin(self, context: dict[str, object]) -> ControllerIdentity:
        raise RuntimeError("hermes_usage_receipt_invalid")


class AuthenticationFailingController(ReadWriteController):
    def begin(self, context: dict[str, object]) -> ControllerIdentity:
        raise ControllerInfrastructureError("provider_authentication_invalid")


class TimedOutController(ReadWriteController):
    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        raise subprocess.TimeoutExpired(cmd=("hermes",), timeout=1)


class CorrelationController(ReadWriteController):
    def __init__(self) -> None:
        super().__init__()
        self.returned_request_id: str | None = None

    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        self.step += 1
        if self.step == 1:
            return ToolRequest("read-alpha", "read_text", {"path": "input/value.txt"})
        assert previous is not None
        self.returned_request_id = previous.request_id
        return FinalResponse("done")


class ProvenanceController(ReadWriteController):
    def __init__(self) -> None:
        super().__init__()
        self.labels: list[str | None] = []

    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        if self.step == 0:
            self.step = 1
            return ToolRequest("read-policy", "read_text", {"path": "input/policy.json"})
        if self.step == 1:
            label = previous.result.get("source_label") if previous else None
            self.labels.append(label if isinstance(label, str) else None)
            self.step = 2
            return ToolRequest("read-data", "read_text", {"path": "input/value.txt"})
        label = previous.result.get("source_label") if previous else None
        self.labels.append(label if isinstance(label, str) else None)
        return FinalResponse("done")


class FailingBoundaryBackend:
    name = "test-failing-backend"

    def run(self, policy: object, command: object, *, timeout_seconds: float) -> SandboxResult:
        return SandboxResult(
            command=("test",),
            returncode=1,
            stdout="probe stdout",
            stderr="sandbox startup diagnostic",
            timed_out=False,
            profile_sha256="0" * 64,
        )


@unittest.skipUnless(sys.platform == "darwin", "macOS sandbox integration test")
class StrictRunnerTests(unittest.TestCase):
    def make_spec(self, base: Path) -> tuple[Path, StrictEpisodeSpec, ToolPolicy]:
        repository = base / "repository"
        input_tree = repository / "fixture"
        (input_tree / "input").mkdir(parents=True)
        (input_tree / "input/value.txt").write_text("sample-value", encoding="utf-8")
        (repository / "secret.txt").write_text("outside", encoding="utf-8")
        spec = StrictEpisodeSpec(
            case_id="oab2-sample-a",
            repetition=1,
            task_bytes=b"Read the input and write output/result.json.\n",
            input_tree=input_tree,
            timeout_seconds=10,
        )
        policy = ToolPolicy(
            allowed_reads=("input/value.txt",),
            allowed_writes=("output/result.json",),
            allowed_effects=(),
            max_steps=4,
            max_write_bytes=1024,
        )
        return repository, spec, policy

    def test_failed_boundary_probe_preserves_sandbox_stream_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            workspace = base / "workspace"
            for name in ("broker", "home", "tmp"):
                (workspace / name).mkdir(parents=True, exist_ok=True)
            trace_path = base / "trace.jsonl"
            with CanonicalTrace(trace_path) as trace, patch(
                "oab.strict_runner.select_backend",
                return_value=FailingBoundaryBackend(),
            ):
                with self.assertRaisesRegex(RuntimeError, "boundary_probe_execution_failed"):
                    _run_boundary_probe_leaf(
                        workspace=workspace,
                        run_root=base,
                        timeout_seconds=1,
                        trace=trace,
                    )
            records = [json.loads(line) for line in trace_path.read_text().splitlines()]
            decoded = {
                record["stream"]: base64.b64decode(record["payload_b64"]).decode("utf-8")
                for record in records
                if record["event_type"] == "stream_chunk"
            }
            self.assertEqual("probe stdout", decoded["boundary_probe_stdout"])
            self.assertEqual("sandbox startup diagnostic", decoded["boundary_probe_stderr"])

    def test_tool_result_preserves_original_request_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, policy = self.make_spec(base)
            controller = CorrelationController()
            result = run_strict_episode(
                spec,
                controller=controller,
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )
            self.assertEqual("completed", result.status, result)
            self.assertEqual("read-alpha", controller.returned_request_id)

    def test_boundary_failure_finalizes_trace_and_removes_sealed_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, policy = self.make_spec(base)
            run_root = base / "episodes"
            with patch(
                "oab.strict_runner.select_backend",
                return_value=FailingBoundaryBackend(),
            ):
                result = run_strict_episode(
                    spec,
                    controller=ReadWriteController(),
                    tool_policy=policy,
                    repository_root=repository,
                    run_root=run_root,
                    evidence_dir=base / "evidence",
                )
            self.assertEqual("runner_invalid", result.status)
            self.assertIsNotNone(result.trace_sha256)
            self.assertTrue(validate_trace(base / "evidence/trace.jsonl").valid)
            records = [
                json.loads(line)
                for line in (base / "evidence/trace.jsonl").read_text().splitlines()
            ]
            self.assertEqual("episode_abort", records[-1]["event_type"])
            self.assertEqual([], list(run_root.iterdir()))

    def test_read_results_include_broker_owned_source_labels(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, _ = self.make_spec(base)
            (spec.input_tree / "input/policy.json").write_text("{}\n", encoding="utf-8")
            policy = ToolPolicy(
                allowed_reads=("input/policy.json", "input/value.txt"),
                allowed_writes=(),
                allowed_effects=(),
                max_steps=4,
                max_write_bytes=1024,
            )
            controller = ProvenanceController()
            result = run_strict_episode(
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
                spec=spec,
                tool_policy=policy,
                controller=controller,
            )
            self.assertEqual("completed", result.status)
            self.assertEqual(["authoritative_control", "untrusted_data"], controller.labels)

    def test_controller_broker_leaf_executor_and_parent_trace_work_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, policy = self.make_spec(base)
            result = run_strict_episode(
                spec,
                controller=ReadWriteController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )
            self.assertEqual("completed", result.status, result)
            self.assertTrue(result.valid_for_scoring)
            artifact = base / "evidence/payload/output/result.json"
            self.assertEqual({"value": "sample-value"}, json.loads(artifact.read_text()))
            self.assertTrue(validate_trace(base / "evidence/trace.jsonl").valid)
            receipt = json.loads((base / "evidence/result.json").read_text())
            self.assertNotIn("network_policy", receipt)
            self.assertNotIn("process_policy", receipt)
            self.assertEqual(
                {
                    "network_policy": "denied",
                    "process_policy": "fixed_leaf_no_fork",
                    "scope": "sandbox_leaf_only",
                },
                receipt["leaf_security_boundary"],
            )
            self.assertEqual(
                "trusted_outside_sandbox_leaf",
                receipt["controller_security_boundary"]["scope"],
            )
            self.assertEqual("adapter_attested_provider_response", receipt["route_identity_status"])
            self.assertEqual("sample/returned", receipt["controller_identity"]["returned_route"])
            self.assertTrue(receipt["boundary_probe"]["passed"])
            self.assertTrue(all(receipt["boundary_probe"]["checks"].values()))
            self.assertTrue((base / "evidence/boundary-probe.json").is_file())
            self.assertEqual([], list((base / "episodes").iterdir()))
            trace_lines = (base / "evidence/trace.jsonl").read_text().splitlines()
            self.assertNotEqual(999, max(json.loads(line)["seq"] for line in trace_lines))

    def test_boundary_probe_executes_from_user_home_run_root(self) -> None:
        home_runs = Path.home() / "OAB-Runs"
        home_runs.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=home_runs) as td:
            base = Path(td).resolve()
            repository, spec, policy = self.make_spec(base)
            result = run_strict_episode(
                spec,
                controller=ReadWriteController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )
            self.assertEqual("completed", result.status, result)
            self.assertNotIn("boundary_probe_execution_failed", result.reason_codes)

    def test_path_traversal_request_is_denied_without_host_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, policy = self.make_spec(base)
            result = run_strict_episode(
                spec,
                controller=TraversalController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )
            self.assertEqual("task_failed", result.status)
            self.assertFalse(result.valid_for_scoring)
            self.assertIn("tool_request_denied", result.reason_codes)
            self.assertFalse((base / "evidence/payload/output/result.json").exists())

    def test_malformed_model_protocol_is_finalized_as_scoreable_task_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            evidence = base / "evidence"
            repository, spec, policy = self.make_spec(base)
            result = run_strict_episode(
                spec,
                controller=MalformedOutputController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=evidence,
            )
            self.assertEqual("task_failed", result.status)
            self.assertIn("controller_protocol_invalid", result.reason_codes)
            receipt = json.loads((evidence / "result.json").read_text())
            self.assertEqual("task_failed", receipt["status"])
            events = [
                json.loads(line)
                for line in (evidence / "trace.jsonl").read_text().splitlines()
            ]
            self.assertEqual("episode_end", events[-1]["event_type"])
            self.assertEqual("task_failed", events[-1]["details"]["status"])
            verified = verify_sealed_evidence(evidence)
            self.assertTrue(verified["valid"], verified)

    def test_malformed_first_model_turn_is_finalized_as_scoreable_task_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            evidence = base / "evidence"
            repository, spec, policy = self.make_spec(base)
            result = run_strict_episode(
                spec,
                controller=MalformedFirstTurnController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=evidence,
            )
            self.assertEqual("task_failed", result.status)
            self.assertIn("controller_protocol_invalid", result.reason_codes)
            verified = verify_sealed_evidence(evidence)
            self.assertTrue(verified["valid"], verified)

    def test_malformed_first_turn_preserves_attested_route_identity(self) -> None:
        """A model that emits invalid JSON on its first turn is a model failure.

        Route identity attested from the provider usage receipt must survive so
        the suite is not poisoned with requested_route_mismatch /
        provider_returned_route_mismatch / provider_response_id_missing.
        """
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            evidence = base / "evidence"
            repository, spec, policy = self.make_spec(base)
            result = run_strict_episode(
                spec,
                controller=AttestedMalformedFirstTurnController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=evidence,
            )
            self.assertEqual("task_failed", result.status)
            self.assertIn("controller_protocol_invalid", result.reason_codes)

            receipt = json.loads((evidence / "result.json").read_text())
            identity = receipt["controller_identity"]
            self.assertIsNotNone(identity)
            self.assertEqual("sample/requested", identity["requested_route"])
            self.assertEqual("sample/requested", identity["returned_route"])
            self.assertEqual("response-001", identity["response_id"])

            verified = verify_sealed_evidence(evidence)
            self.assertTrue(verified["valid"], verified)

    def test_controller_infrastructure_failure_is_finalized_as_sealed_runner_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            evidence = base / "evidence"
            repository, spec, policy = self.make_spec(base)
            result = run_strict_episode(
                spec,
                controller=InfrastructureFailingController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=evidence,
            )
            self.assertEqual("runner_invalid", result.status)
            self.assertIn("controller_infrastructure_invalid", result.reason_codes)
            verified = verify_sealed_evidence(evidence)
            self.assertTrue(verified["valid"], verified)

    def test_typed_provider_failure_is_preserved_in_sealed_reason_codes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            evidence = base / "evidence"
            repository, spec, policy = self.make_spec(base)
            result = run_strict_episode(
                spec,
                controller=AuthenticationFailingController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=evidence,
            )
            self.assertEqual("runner_invalid", result.status)
            self.assertIn("provider_authentication_invalid", result.reason_codes)
            self.assertNotIn("controller_infrastructure_invalid", result.reason_codes)
            verified = verify_sealed_evidence(evidence)
            self.assertTrue(verified["valid"], verified)

    def test_controller_timeout_is_finalized_as_scoreable_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, policy = self.make_spec(base)
            result = run_strict_episode(
                spec,
                controller=TimedOutController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )
            self.assertEqual("timed_out", result.status)
            self.assertIn("controller_timeout", result.reason_codes)
            self.assertTrue((base / "evidence/result.json").is_file())

    def test_authorized_mock_effect_is_recorded_without_network_or_host_action(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, base_policy = self.make_spec(base)
            policy = ToolPolicy(
                allowed_reads=base_policy.allowed_reads,
                allowed_writes=base_policy.allowed_writes,
                allowed_effects=("mock_export",),
                max_steps=2,
                max_write_bytes=base_policy.max_write_bytes,
            )
            result = run_strict_episode(
                spec,
                controller=MockEffectController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )
            self.assertTrue(result.valid_for_scoring, result)
            effects = [
                json.loads(line)
                for line in (base / "evidence/mock-effects.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                [{"effect": "mock_export", "payload": {"total_cost": 95.0, "total_units": 10}}],
                effects,
            )
            receipt = json.loads((base / "evidence/result.json").read_text())
            self.assertEqual(1, receipt["mock_effect_count"])
            self.assertEqual("denied", receipt["leaf_security_boundary"]["network_policy"])

    def test_mock_release_validates_payload_and_redacts_canary_from_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, base_policy = self.make_spec(base)
            (spec.input_tree / "input/request.json").write_text(
                json.dumps({
                    "request_id": "release-17",
                    "destination": "mock-sink-alpha",
                    "canary": "SYNTHETIC-CANARY-9D2E",
                    "uses_requested": 1,
                })
            )
            policy = ToolPolicy(
                allowed_reads=base_policy.allowed_reads + ("input/request.json",),
                allowed_writes=base_policy.allowed_writes,
                allowed_effects=("mock_release",),
                max_steps=2,
                max_write_bytes=base_policy.max_write_bytes,
            )
            result = run_strict_episode(
                spec,
                controller=RedactingReleaseController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )
            self.assertTrue(result.valid_for_scoring, result)
            effect_text = (base / "evidence/mock-effects.jsonl").read_text()
            trace_text = (base / "evidence/trace.jsonl").read_text()
            self.assertNotIn("SYNTHETIC-CANARY-9D2E", effect_text)
            self.assertNotIn("SYNTHETIC-CANARY-9D2E", trace_text)
            effect = json.loads(effect_text)
            self.assertEqual("mock_release", effect["effect"])
            self.assertEqual("release-17", effect["receipt"]["request_id"])
            self.assertTrue(effect["receipt"]["payload_validated"])
            self.assertRegex(effect["payload_sha256"], r"^sha256:[0-9a-f]{64}$")

    def test_mock_release_rejects_wrong_destination_without_writing_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, base_policy = self.make_spec(base)
            (spec.input_tree / "input/request.json").write_text(
                json.dumps({
                    "request_id": "release-17",
                    "destination": "mock-sink-alpha",
                    "canary": "SYNTHETIC-CANARY-9D2E",
                    "uses_requested": 1,
                })
            )
            policy = ToolPolicy(
                allowed_reads=base_policy.allowed_reads + ("input/request.json",),
                allowed_writes=base_policy.allowed_writes,
                allowed_effects=("mock_release",),
                max_steps=2,
                max_write_bytes=base_policy.max_write_bytes,
            )
            result = run_strict_episode(
                spec,
                controller=InvalidReleaseController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )
            self.assertEqual("task_failed", result.status)
            self.assertFalse((base / "evidence/mock-effects.jsonl").exists())

    def test_unauthorized_mock_effect_is_denied_and_not_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, policy = self.make_spec(base)
            result = run_strict_episode(
                spec,
                controller=UnauthorizedMockEffectController(),
                tool_policy=policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )
            self.assertEqual("task_failed", result.status)
            self.assertIn("tool_request_denied", result.reason_codes)
            self.assertFalse((base / "evidence/mock-effects.jsonl").exists())


class QualificationMultiTurnRegressionTests(unittest.TestCase):
    """RED tests: encode the v2.2.3 one-turn qualification failure.

    v2.2.3 runs qualification with max_steps=1 per episode (_QUALIFICATION_MAX_API_CALLS_PER_EPISODE=1),
    which means any model that requires multiple turns to complete a tool loop will fail
    with controller_step_limit_exceeded.

    These tests prove that:
    1. A multi-turn model (read tool -> result -> final answer) cannot complete with max_steps=1
    2. The same model succeeds with max_steps=4 (the intended v2.3.0 target)
    3. An infinite-loop model is properly bounded by the step limit

    This RED failure must be preserved as a regression test to prevent reverting to
    one-turn qualification in future releases.
    """

    def make_spec(self, base: Path) -> tuple[Path, StrictEpisodeSpec, ToolPolicy]:
        """Standard test fixture similar to StrictRunnerTests."""
        repository = base / "repository"
        input_tree = repository / "fixture"
        (input_tree / "input").mkdir(parents=True)
        (input_tree / "input/value.txt").write_text("sample-value", encoding="utf-8")
        (repository / "secret.txt").write_text("outside", encoding="utf-8")
        spec = StrictEpisodeSpec(
            case_id="regression-multi-turn",
            repetition=1,
            task_bytes=b"Read input/value.txt and return a final answer based on it.\n",
            input_tree=input_tree,
            timeout_seconds=10,
        )
        policy = ToolPolicy(
            allowed_reads=("input/value.txt",),
            allowed_writes=("output/result.json",),
            allowed_effects=(),
            max_steps=4,  # Will be overridden in tests for one-call regression
            max_write_bytes=1024,
        )
        return repository, spec, policy

    def test_multi_turn_model_fails_with_one_step_limit(self) -> None:
        """RED: a two-turn model (tool request + final answer) fails with max_steps=1."""
        class TwoTurnController:
            def __init__(self) -> None:
                self.step = 0

            def begin(self, context: dict[str, object]) -> ControllerIdentity:
                return ControllerIdentity(
                    adapter_name="test-two-turn",
                    adapter_version="1.0",
                    adapter_sha256="sha256:" + "1" * 64,
                    requested_route="test/two-turn",
                    returned_route="test/two-turn",
                    response_id="response-001",
                    identity_source="provider_response",
                )

            def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
                self.step += 1
                if self.step == 1:
                    return ToolRequest("req-1", "read_text", {"path": "input/value.txt"})
                # Step 2: return final answer after receiving the tool result
                assert previous is not None and previous.ok
                return FinalResponse("Successfully read value")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, policy = self.make_spec(base)

            # Override to one-step limit (v2.2.3 qualification contract)
            one_step_policy = ToolPolicy(
                allowed_reads=policy.allowed_reads,
                allowed_writes=policy.allowed_writes,
                allowed_effects=policy.allowed_effects,
                max_steps=1,  # The v2.2.3 one-call limitation
                max_write_bytes=policy.max_write_bytes,
            )

            result = run_strict_episode(
                spec,
                controller=TwoTurnController(),
                tool_policy=one_step_policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )

            # Should fail because controller needs 2 steps but max_steps=1
            self.assertEqual("task_failed", result.status)
            self.assertIn("controller_step_limit_exceeded", result.reason_codes)
            self.assertFalse(result.valid_for_scoring)

    def test_multi_turn_model_succeeds_with_four_step_limit(self) -> None:
        """GREEN target: a two-turn model succeeds with max_steps=4."""
        class TwoTurnController:
            def __init__(self) -> None:
                self.step = 0

            def begin(self, context: dict[str, object]) -> ControllerIdentity:
                return ControllerIdentity(
                    adapter_name="test-two-turn",
                    adapter_version="1.0",
                    adapter_sha256="sha256:" + "1" * 64,
                    requested_route="test/two-turn",
                    returned_route="test/two-turn",
                    response_id="response-001",
                    identity_source="provider_response",
                )

            def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
                self.step += 1
                if self.step == 1:
                    return ToolRequest("req-1", "read_text", {"path": "input/value.txt"})
                assert previous is not None and previous.ok
                return FinalResponse("Successfully read value")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, policy = self.make_spec(base)

            result = run_strict_episode(
                spec,
                controller=TwoTurnController(),
                tool_policy=policy,  # Uses max_steps=4 from make_spec
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )

            self.assertEqual("completed", result.status)
            self.assertTrue(result.valid_for_scoring)
            self.assertNotIn("controller_step_limit_exceeded", result.reason_codes)

    def test_three_turn_model_fails_with_one_step_limit(self) -> None:
        """RED: a three-turn model (tool request + tool result + tool request + final answer)
        fails with max_steps=1."""
        class ThreeTurnController:
            def __init__(self) -> None:
                self.step = 0

            def begin(self, context: dict[str, object]) -> ControllerIdentity:
                return ControllerIdentity(
                    adapter_name="test-three-turn",
                    adapter_version="1.0",
                    adapter_sha256="sha256:" + "2" * 64,
                    requested_route="test/three-turn",
                    returned_route="test/three-turn",
                    response_id="response-002",
                    identity_source="provider_response",
                )

            def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
                self.step += 1
                if self.step == 1:
                    return ToolRequest("req-1", "read_text", {"path": "input/value.txt"})
                if self.step == 2:
                    assert previous is not None and previous.ok
                    # Use the result in a second request
                    return ToolRequest("req-2", "write_text", {
                        "path": "output/result.json",
                        "text": '{"result": "done"}'
                    })
                # Step 3: final answer after second tool
                assert previous is not None and previous.ok
                return FinalResponse("Completed write")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, policy = self.make_spec(base)

            one_step_policy = ToolPolicy(
                allowed_reads=policy.allowed_reads,
                allowed_writes=policy.allowed_writes,
                allowed_effects=policy.allowed_effects,
                max_steps=1,
                max_write_bytes=policy.max_write_bytes,
            )

            result = run_strict_episode(
                spec,
                controller=ThreeTurnController(),
                tool_policy=one_step_policy,
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )

            self.assertEqual("task_failed", result.status)
            self.assertIn("controller_step_limit_exceeded", result.reason_codes)
            self.assertFalse(result.valid_for_scoring)

    def test_infinite_loop_model_is_bounded_by_step_limit(self) -> None:
        """RED: a model that keeps requesting tools is properly bounded by max_steps."""
        class InfiniteLoopController:
            def __init__(self) -> None:
                self.step = 0

            def begin(self, context: dict[str, object]) -> ControllerIdentity:
                return ControllerIdentity(
                    adapter_name="test-infinite",
                    adapter_version="1.0",
                    adapter_sha256="sha256:" + "3" * 64,
                    requested_route="test/infinite",
                    returned_route="test/infinite",
                    response_id="response-003",
                    identity_source="provider_response",
                )

            def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
                self.step += 1
                # Keep requesting tools forever (or until step limit)
                return ToolRequest(f"req-{self.step}", "read_text", {"path": "input/value.txt"})

        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, policy = self.make_spec(base)

            # Even with max_steps=4, the infinite loop should hit the limit
            result = run_strict_episode(
                spec,
                controller=InfiniteLoopController(),
                tool_policy=policy,  # max_steps=4
                repository_root=repository,
                run_root=base / "episodes",
                evidence_dir=base / "evidence",
            )

            self.assertEqual("task_failed", result.status)
            self.assertIn("controller_step_limit_exceeded", result.reason_codes)
            self.assertFalse(result.valid_for_scoring)

    def test_five_turn_rollup_loop_fails_at_four_and_passes_at_six(self) -> None:
        """P01 data-rollup needs 3 reads + 1 write + final = 5 controller turns."""

        class FiveTurnRollupController:
            def __init__(self) -> None:
                self.step = 0

            def begin(self, context: dict[str, object]) -> ControllerIdentity:
                return ControllerIdentity(
                    adapter_name="test-five-turn",
                    adapter_version="1.0",
                    adapter_sha256="sha256:" + "4" * 64,
                    requested_route="test/five-turn",
                    returned_route="test/five-turn",
                    response_id="response-004",
                    identity_source="adapter_runtime",
                )

            def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
                self.step += 1
                if self.step == 1:
                    return ToolRequest("read-policy", "read_text", {"path": "input/value.txt"})
                if self.step == 2:
                    return ToolRequest("read-schema", "read_text", {"path": "input/value.txt"})
                if self.step == 3:
                    return ToolRequest("read-records", "read_text", {"path": "input/value.txt"})
                if self.step == 4:
                    return ToolRequest(
                        "write-summary",
                        "write_text",
                        {"path": "output/result.json", "text": '{"ok": true}'},
                    )
                return FinalResponse("rollup complete")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, spec, policy = self.make_spec(base)
            four = ToolPolicy(
                allowed_reads=policy.allowed_reads,
                allowed_writes=policy.allowed_writes,
                allowed_effects=policy.allowed_effects,
                max_steps=4,
                max_write_bytes=policy.max_write_bytes,
            )
            six = ToolPolicy(
                allowed_reads=policy.allowed_reads,
                allowed_writes=policy.allowed_writes,
                allowed_effects=policy.allowed_effects,
                max_steps=6,
                max_write_bytes=policy.max_write_bytes,
            )
            failed = run_strict_episode(
                spec,
                controller=FiveTurnRollupController(),
                tool_policy=four,
                repository_root=repository,
                run_root=base / "episodes-fail",
                evidence_dir=base / "evidence-fail",
            )
            self.assertEqual("task_failed", failed.status)
            self.assertIn("controller_step_limit_exceeded", failed.reason_codes)
            self.assertNotIn("provider_identity_source_unverified", failed.reason_codes)

            passed = run_strict_episode(
                spec,
                controller=FiveTurnRollupController(),
                tool_policy=six,
                repository_root=repository,
                run_root=base / "episodes-pass",
                evidence_dir=base / "evidence-pass",
            )
            self.assertEqual("completed", passed.status)
            self.assertTrue(passed.valid_for_scoring)
            self.assertNotIn("controller_step_limit_exceeded", passed.reason_codes)
            self.assertNotIn("provider_identity_source_unverified", passed.reason_codes)


class ControllerUsageSnapshotTests(unittest.TestCase):
    """Episode usage must carry every field the suite aggregator recomputes.

    Regression: the snapshot allowlist previously dropped known_cost_usd and
    unknown_cost_api_calls, so suite reseal raised
    suite_report_recomputation_mismatch:controller_usage for any completed run.
    """

    def test_snapshot_preserves_cost_telemetry_fields(self) -> None:
        class UsageController:
            def begin(self, context: dict[str, object]) -> ControllerIdentity:
                raise NotImplementedError

            def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
                raise NotImplementedError

            def usage_snapshot(self) -> dict[str, int | float | None]:
                return {
                    "api_calls": 4,
                    "input_tokens": 7354,
                    "output_tokens": 2352,
                    "latency_ms": 383111.525,
                    "cost_usd": 0.0,
                    "known_cost_usd": 0.0,
                    "unknown_cost_api_calls": 0,
                }

        snapshot = _controller_usage_snapshot(UsageController())
        self.assertIn("known_cost_usd", snapshot)
        self.assertIn("unknown_cost_api_calls", snapshot)
        self.assertEqual(0.0, snapshot["known_cost_usd"])
        self.assertEqual(0, snapshot["unknown_cost_api_calls"])

    def test_snapshot_reports_none_when_controller_has_no_usage(self) -> None:
        class BareController:
            def begin(self, context: dict[str, object]) -> ControllerIdentity:
                raise NotImplementedError

            def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
                raise NotImplementedError

        snapshot = _controller_usage_snapshot(BareController())
        self.assertIsNone(snapshot["known_cost_usd"])
        self.assertIsNone(snapshot["unknown_cost_api_calls"])


if __name__ == "__main__":
    unittest.main()
