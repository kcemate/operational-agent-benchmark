from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from oab.evidence import verify_sealed_evidence
from oab.qualification_contract import qualification_contract_for_route_count
from oab.strict_runner import StrictEpisodeResult, ToolPolicy
from oab.suite_seal import verify_suite_seal
from qualification_fixtures import write_probe_evidence
from tools import run_suite
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

    def test_observations_carry_protocol_normalization_count(self) -> None:
        """The suite runner builds observations by hand.

        Any receipt field the seal recomputes must be copied here too, or
        `write_suite_seal` fails with suite_report_recomputation_mismatch on
        every real run while unit tests that construct observations directly
        stay green. Caught live on a granite3.3 run.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "fixture").mkdir()
            (root / "task.txt").write_text("opaque", encoding="utf-8")

            class FenceUsingController:
                controller_config_sha256 = "sha256:" + "a" * 64
                protocol_normalized_turns = 3

                def __init__(self, **kwargs: object) -> None:
                    pass

                def usage_snapshot(self) -> dict[str, object]:
                    return {
                        "api_calls": 1,
                        "cost_usd": 0.0,
                        "known_cost_usd": 0.0,
                        "unknown_cost_api_calls": 0,
                    }

            args = argparse.Namespace(
                repetitions=1,
                max_observed_cost_usd=None,
                model="model",
                provider="provider",
                timeout_seconds=1.0,
                reasoning_effort="high",
                allow_unknown_costs=True,
                max_api_calls=None,
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
                status="completed",
                valid_for_scoring=True,
                reason_codes=(),
                trace_sha256="sha256:" + "b" * 64,
                output_tree_sha256="sha256:" + "c" * 64,
            )
            with (
                patch("tools.run_suite.ROOT", root),
                patch("tools.run_suite.HermesCliController", FenceUsingController),
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

            self.assertEqual(3, observations[0]["protocol_normalized_turns"])


class QualificationReadinessModeTests(unittest.TestCase):
    def _authorized_output(self, root: Path) -> Path:
        parent = root / "outputs"
        parent.mkdir(mode=0o700, exist_ok=True)
        return parent / ("a" * 32 + ".evidence")

    @contextlib.contextmanager
    def _authorized_qualification_command(
        self,
        *,
        root: Path,
        output: Path,
        route: str,
        allow_unknown_costs: bool = False,
    ):
        provider, model = route.split("/", 1)
        output_parent = output.parent
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        output_parent_fd = os.open(output_parent, os.O_RDONLY | os.O_DIRECTORY)
        transport_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        manifest = json.loads((run_suite.ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
        authorization = {
            "stage": "qualification",
            "contract": qualification_contract_for_route_count(1),
            "release_tree_sha256": manifest["tree_sha256"],
        }
        command = [
            "run_suite",
            "--provider", provider,
            "--model", model,
            "--reasoning-effort", "high",
            "--output-root", str(output),
            "--output-parent-fd", str(output_parent_fd),
            "--output-name", output.name,
            "--qualification-readiness-v1",
            "--campaign-root-path", str(root),
            "--campaign-root-fd", str(root_fd),
            "--max-api-calls", "24",
            "--max-observed-cost-usd", "1.0",
        ]
        if allow_unknown_costs:
            command.append("--allow-unknown-costs")
        try:
            with patch("tools.run_suite.verify_campaign_child_contract", return_value=authorization):
                yield command
        finally:
            os.close(transport_fd)
            os.close(output_parent_fd)
            os.close(root_fd)

    def _write_probe_evidence(
        self,
        evidence: Path,
        *,
        case_id: str,
        repetition: int,
        route: str,
        usage: dict[str, object],
        status: str = "completed",
        reason_codes: list[str] | None = None,
    ) -> StrictEpisodeResult:
        receipt = write_probe_evidence(
            evidence,
            case_id=case_id,
            repetition=repetition,
            route=route,
            status=status,
            reason_codes=reason_codes or [],
            telemetry=usage,
        )
        return StrictEpisodeResult(
            case_id=str(receipt["case_id"]),
            repetition=cast(int, receipt["repetition"]),
            status=str(receipt["status"]),
            valid_for_scoring=bool(receipt["readiness_evidence"]),
            reason_codes=tuple(
                str(code) for code in cast(list[object], receipt["reason_codes"])
            ),
            evidence_dir=evidence,
            trace_sha256=str(receipt["trace_sha256"]),
            output_tree_sha256=str(receipt["output_tree_sha256"]),
        )

    def test_v230_unknown_cost_primary_is_never_retried_even_when_disclosed(self) -> None:
        """Unknown dollars stay disclosed; they cannot open a retry spend hole."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            output = self._authorized_output(root)
            route = "offline/unknown-cost"
            invocations: list[tuple[str, int]] = []

            class OfflineController:
                controller_config_sha256 = "sha256:" + "b" * 64

                def __init__(self, **_kwargs: object) -> None:
                    return None

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
                artifact_profile: str = "standard",
                **_kwargs: object,
            ) -> StrictEpisodeResult:
                case_id = str(getattr(spec, "case_id"))
                attempt_number = len(
                    [item for item in invocations if item[0] == case_id]
                ) + 1
                invocations.append((case_id, attempt_number))
                self.assertEqual("qualification_readiness", artifact_profile)
                if case_id == "oab2-data-rollup-a":
                    return self._write_probe_evidence(
                        evidence_dir,
                        case_id=case_id,
                        repetition=1,
                        route=route,
                        status="runner_invalid",
                        reason_codes=["provider_unavailable"],
                        usage={
                            "api_calls": 2,
                            "input_tokens": 1,
                            "output_tokens": 1,
                            "latency_ms": 1.0,
                            "cost_usd": None,
                            "known_cost_usd": 0.0,
                            "unknown_cost_api_calls": 2,
                        },
                    )
                return self._write_probe_evidence(
                    evidence_dir,
                    case_id=case_id,
                    repetition=1,
                    route=route,
                    usage={
                        "api_calls": 2,
                        "input_tokens": 1,
                        "output_tokens": 1,
                        "latency_ms": 1.0,
                        "cost_usd": 0.0,
                        "known_cost_usd": 0.0,
                        "unknown_cost_api_calls": 0,
                    },
                )

            with (
                self._authorized_qualification_command(
                    root=root,
                    output=output,
                    route=route,
                    allow_unknown_costs=True,
                ) as command,
                patch.object(sys, "argv", command),
                patch("tools.run_suite.verify_release_manifest", return_value=[]),
                patch("tools.run_suite.pinned_hermes_runtime", return_value=OfflineRuntime()),
                patch("tools.run_suite.HermesCliController", OfflineController),
                patch("tools.run_suite.run_strict_episode", side_effect=fake_episode),
                patch("tools.run_suite.verify_case", return_value=[]),
                patch("oab.suite_seal.verify_case", return_value=[]),
            ):
                self.assertEqual(0, run_suite.main())

            self.assertEqual(
                [("oab2-data-rollup-a", 1), ("oab2-data-rollup-p", 1)], invocations
            )
            report = json.loads((output / "suite-report.json").read_text(encoding="utf-8"))
            self.assertEqual(2, len(report["attempts"]))
            self.assertIsNone(report["controller_usage"]["cost_usd"])
            self.assertEqual(2, report["controller_usage"]["unknown_cost_api_calls"])

    def test_v230_malformed_and_nonretryable_primary_receipts_never_open_retry(self) -> None:
        """Malformed telemetry and non-transient failures remain terminal child outcomes."""
        scenarios: tuple[
            tuple[str, str, list[str], dict[str, object], list[tuple[str, int]]], ...
        ] = (
            (
                "malformed-telemetry",
                "completed",
                [],
                {
                    "api_calls": None,
                    "input_tokens": 1,
                    "output_tokens": 1,
                    "latency_ms": 1.0,
                    "cost_usd": 0.0,
                    "known_cost_usd": 0.0,
                    "unknown_cost_api_calls": 0,
                },
                [("oab2-data-rollup-a", 1)],
            ),
            (
                "nonretryable-auth",
                "runner_invalid",
                ["provider_authentication_invalid"],
                {
                    "api_calls": 2,
                    "input_tokens": 1,
                    "output_tokens": 1,
                    "latency_ms": 1.0,
                    "cost_usd": 0.0,
                    "known_cost_usd": 0.0,
                    "unknown_cost_api_calls": 0,
                },
                [("oab2-data-rollup-a", 1), ("oab2-data-rollup-p", 1)],
            ),
        )
        for label, first_status, first_reasons, first_usage, expected in scenarios:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as td:
                root = Path(td).resolve()
                output = self._authorized_output(root)
                route = f"offline/{label}"
                invocations: list[tuple[str, int]] = []
                controller_budgets: list[object] = []

                class OfflineController:
                    controller_config_sha256 = "sha256:" + "b" * 64

                    def __init__(self, **kwargs: object) -> None:
                        controller_budgets.append(kwargs.get("max_api_calls"))

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
                    artifact_profile: str = "standard",
                    **_kwargs: object,
                ) -> StrictEpisodeResult:
                    case_id = str(getattr(spec, "case_id"))
                    attempt_number = len(
                        [item for item in invocations if item[0] == case_id]
                    ) + 1
                    invocations.append((case_id, attempt_number))
                    self.assertEqual("qualification_readiness", artifact_profile)
                    if case_id == "oab2-data-rollup-a":
                        return self._write_probe_evidence(
                            evidence_dir,
                            case_id=case_id,
                            repetition=int(getattr(spec, "repetition")),
                            route=route,
                            status=first_status,
                            reason_codes=first_reasons,
                            usage=first_usage,
                        )
                    return self._write_probe_evidence(
                        evidence_dir,
                        case_id=case_id,
                        repetition=int(getattr(spec, "repetition")),
                        route=route,
                        usage={
                            "api_calls": 2,
                            "input_tokens": 1,
                            "output_tokens": 1,
                            "latency_ms": 1.0,
                            "cost_usd": 0.0,
                            "known_cost_usd": 0.0,
                            "unknown_cost_api_calls": 0,
                        },
                    )

                with (
                    self._authorized_qualification_command(
                        root=root,
                        output=output,
                        route=route,
                    ) as command,
                    patch.object(sys, "argv", command),
                    patch("tools.run_suite.verify_release_manifest", return_value=[]),
                    patch("tools.run_suite.pinned_hermes_runtime", return_value=OfflineRuntime()),
                    patch("tools.run_suite.HermesCliController", OfflineController),
                    patch("tools.run_suite.run_strict_episode", side_effect=fake_episode),
                    patch("tools.run_suite.verify_case", return_value=[]),
                    patch("oab.suite_seal.verify_case", return_value=[]),
                ):
                    self.assertEqual(0, run_suite.main())

                self.assertEqual(expected, invocations)
                self.assertEqual([6] * len(expected), controller_budgets)
                report = json.loads((output / "suite-report.json").read_text(encoding="utf-8"))
                self.assertEqual("NOT_READY", report["readiness"])
                self.assertEqual(len(expected), len(report["attempts"]))
                self.assertFalse(
                    any(attempt["attempt_number"] == 2 for attempt in report["attempts"])
                )
                self.assertEqual([], verify_suite_seal(output))

    def test_v230_no_retry_child_runs_exactly_two_first_attempts_and_seals_them(self) -> None:
        """A healthy readiness child executes the two first probes once, then seals both."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            output = self._authorized_output(root)
            route = "offline/no-retry"
            invocations: list[tuple[str, int]] = []
            controller_budgets: list[object] = []

            class OfflineController:
                controller_config_sha256 = "sha256:" + "b" * 64

                def __init__(self, **kwargs: object) -> None:
                    controller_budgets.append(kwargs.get("max_api_calls"))

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
                artifact_profile: str = "standard",
                **_kwargs: object,
            ) -> StrictEpisodeResult:
                case_id = str(getattr(spec, "case_id"))
                attempt_number = len(
                    [item for item in invocations if item[0] == case_id]
                ) + 1
                invocations.append((case_id, attempt_number))
                self.assertEqual("qualification_readiness", artifact_profile)
                return self._write_probe_evidence(
                    evidence_dir,
                    case_id=case_id,
                    repetition=int(getattr(spec, "repetition")),
                    route=route,
                    usage={
                        "api_calls": 4,
                        "input_tokens": 1,
                        "output_tokens": 1,
                        "latency_ms": 1.0,
                        "cost_usd": 0.0,
                        "known_cost_usd": 0.0,
                        "unknown_cost_api_calls": 0,
                    },
                )

            with (
                self._authorized_qualification_command(
                    root=root,
                    output=output,
                    route=route,
                ) as command,
                patch.object(sys, "argv", command),
                patch("tools.run_suite.verify_release_manifest", return_value=[]),
                patch("tools.run_suite.pinned_hermes_runtime", return_value=OfflineRuntime()),
                patch("tools.run_suite.HermesCliController", OfflineController),
                patch("tools.run_suite.run_strict_episode", side_effect=fake_episode),
                patch("tools.run_suite.verify_case", return_value=[]),
                patch("oab.suite_seal.verify_case", return_value=[]),
            ):
                self.assertEqual(0, run_suite.main())

            self.assertEqual(
                [("oab2-data-rollup-a", 1), ("oab2-data-rollup-p", 1)], invocations
            )
            self.assertEqual([6, 6], controller_budgets)
            report = json.loads((output / "suite-report.json").read_text(encoding="utf-8"))
            self.assertEqual("READY", report["readiness"])
            self.assertEqual(2, len(report["attempts"]))
            self.assertEqual(8, report["controller_usage"]["api_calls"])
            self.assertLessEqual(report["controller_usage"]["api_calls"], 12)
            for attempt in report["attempts"]:
                evidence = output / str(attempt["evidence_dir"])
                self.assertTrue(verify_sealed_evidence(evidence)["valid"])
            self.assertEqual([], verify_suite_seal(output))

    def test_v230_selective_transient_retry_runs_only_affected_probe_and_seals_usage(self) -> None:
        """One typed transient first failure gets one charged retry after both primaries."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            output = self._authorized_output(root)
            route = "offline/selective-retry"
            invocations: list[tuple[str, int]] = []
            controller_budgets: list[object] = []

            class OfflineController:
                controller_config_sha256 = "sha256:" + "b" * 64

                def __init__(self, **kwargs: object) -> None:
                    controller_budgets.append(kwargs.get("max_api_calls"))

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
                artifact_profile: str = "standard",
                **_kwargs: object,
            ) -> StrictEpisodeResult:
                case_id = str(getattr(spec, "case_id"))
                attempt_number = len(
                    [item for item in invocations if item[0] == case_id]
                ) + 1
                invocations.append((case_id, attempt_number))
                self.assertEqual("qualification_readiness", artifact_profile)
                status = "completed"
                reasons: list[str] = []
                if case_id == "oab2-data-rollup-a" and attempt_number == 1:
                    status = "runner_invalid"
                    reasons = ["provider_unavailable"]
                return self._write_probe_evidence(
                    evidence_dir,
                    case_id=case_id,
                    repetition=int(getattr(spec, "repetition")),
                    route=route,
                    status=status,
                    reason_codes=reasons,
                    usage={
                        "api_calls": 2,
                        "input_tokens": 1,
                        "output_tokens": 1,
                        "latency_ms": 1.0,
                        "cost_usd": 0.01,
                        "known_cost_usd": 0.01,
                        "unknown_cost_api_calls": 0,
                    },
                )

            with (
                self._authorized_qualification_command(
                    root=root,
                    output=output,
                    route=route,
                ) as command,
                patch.object(sys, "argv", command),
                patch("tools.run_suite.verify_release_manifest", return_value=[]),
                patch("tools.run_suite.pinned_hermes_runtime", return_value=OfflineRuntime()),
                patch("tools.run_suite.HermesCliController", OfflineController),
                patch("tools.run_suite.run_strict_episode", side_effect=fake_episode),
                patch("tools.run_suite.verify_case", return_value=[]),
                patch("oab.suite_seal.verify_case", return_value=[]),
            ):
                self.assertEqual(0, run_suite.main())

            self.assertEqual(
                [
                    ("oab2-data-rollup-a", 1),
                    ("oab2-data-rollup-p", 1),
                    ("oab2-data-rollup-a", 2),
                ],
                invocations,
            )
            self.assertEqual([6, 6, 6], controller_budgets)
            report = json.loads((output / "suite-report.json").read_text(encoding="utf-8"))
            self.assertEqual("READY", report["readiness"])
            self.assertEqual(3, len(report["attempts"]))
            self.assertEqual(6, report["controller_usage"]["api_calls"])
            self.assertEqual(0.03, report["controller_usage"]["known_cost_usd"])
            self.assertEqual(
                ["P01-approved-attempt-02", "P01-prohibited-attempt-01"],
                [probe["selected_attempt"] for probe in report["probes"]],
            )
            for attempt in report["attempts"]:
                evidence = output / str(attempt["evidence_dir"])
                self.assertTrue(verify_sealed_evidence(evidence)["valid"])
            seal = json.loads((output / "SUITE_SEAL.json").read_text(encoding="utf-8"))
            self.assertEqual(3, len(seal["physical_attempts"]))
            self.assertEqual(2, len(seal["selected_attempts"]))
            self.assertEqual([], verify_suite_seal(output))

    def test_v230_qualification_child_stdout_report_and_seal_are_quality_free(self) -> None:
        """The production-safe child has one score-free output boundary, not redaction."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            output = self._authorized_output(root)
            route = "offline/qualification-probe"
            created_controller_budgets: list[object] = []

            class OfflineController:
                controller_config_sha256 = "sha256:" + "b" * 64
                protocol_normalized_turns = 0

                def __init__(self, **kwargs: object) -> None:
                    created_controller_budgets.append(kwargs.get("max_api_calls"))

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
                tool_policy: ToolPolicy,
                artifact_profile: str = "standard",
                **_kwargs: object,
            ) -> StrictEpisodeResult:
                self.assertEqual("qualification_readiness", artifact_profile)
                self.assertEqual(6, tool_policy.max_steps)
                return self._write_probe_evidence(
                    evidence_dir,
                    case_id=str(getattr(spec, "case_id")),
                    repetition=int(getattr(spec, "repetition")),
                    route=route,
                    usage={
                        "api_calls": 4,
                        "input_tokens": 1,
                        "output_tokens": 1,
                        "latency_ms": 1.0,
                        "cost_usd": 0.0,
                        "known_cost_usd": 0.0,
                        "unknown_cost_api_calls": 0,
                    },
                )

            with (
                self._authorized_qualification_command(
                    root=root,
                    output=output,
                    route=route,
                ) as command,
                patch.object(sys, "argv", command),
                patch("tools.run_suite.verify_release_manifest", return_value=[]),
                patch("tools.run_suite.pinned_hermes_runtime", return_value=OfflineRuntime()),
                patch("tools.run_suite.HermesCliController", OfflineController),
                patch("tools.run_suite.run_strict_episode", side_effect=fake_episode),
                patch("tools.run_suite.verify_case", return_value=[]),
                patch("oab.suite_seal.verify_case", return_value=[]),
                patch("tools.run_suite.aggregate_suite_observations") as aggregate,
            ):
                from io import StringIO

                with patch("sys.stdout", new_callable=StringIO) as stdout:
                    self.assertEqual(0, run_suite.main())
                lines = [line for line in stdout.getvalue().splitlines() if line]
            aggregate.assert_not_called()
            self.assertEqual(1, len(lines))
            child = json.loads(lines[0])
            self.assertEqual(
                {
                    "schema",
                    "readiness",
                    "reason_codes",
                    "controller_usage",
                    "suite_report_path",
                    "suite_seal_path",
                    "suite_seal_sha256",
                },
                set(child),
            )
            report = json.loads((output / "suite-report.json").read_text(encoding="utf-8"))
            seal = json.loads((output / "SUITE_SEAL.json").read_text(encoding="utf-8"))

            def assert_quality_free(value: object) -> None:
                if isinstance(value, dict):
                    for key, nested in value.items():
                        lowered = str(key).lower()
                        for forbidden in (
                            "score",
                            "rate",
                            "percentage",
                            "pair_stability",
                            "valid_for_scoring",
                            "valid_for_calibration",
                            "switch",
                            "_rate",
                        ):
                            self.assertNotIn(forbidden, lowered)
                        assert_quality_free(nested)
                elif isinstance(value, list):
                    for nested in value:
                        assert_quality_free(nested)

            assert_quality_free(report)
            assert_quality_free(seal)
            assert_quality_free(child)
            headline = (output / "HEADLINE.txt").read_text(encoding="utf-8")
            for forbidden in (
                "score",
                "rate",
                "percentage",
                "pair_stability",
                "valid_for_scoring",
                "valid_for_calibration",
                "switch",
            ):
                self.assertNotIn(forbidden, headline.lower())
            self.assertNotIn("%", headline)
            self.assertNotIn("/", headline.split("route=", 1)[0])
            self.assertEqual([6, 6], created_controller_budgets)


if __name__ == "__main__":
    unittest.main()