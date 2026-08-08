from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, cast

from oab.agent_workflow import (
    _canonical_sha256,
    _known_cost_from_report,
    _plan_bound_routes,
    _plan_reasoning_effort,
    _unknown_cost_api_calls_from_report,
    build_approval_preview,
    build_conversational_stage_approval,
    build_evidence_posture,
    build_stage_approval_request,
    build_decision_report,
    doctor_environment,
    initialize_campaign,
    load_campaign,
    load_hermes_inventory,
    record_calibration,
    run_full_stage,
    run_qualification_stage,
    sanitize_hermes_inventory,
    stage_approval_signing_payload,
    verify_campaign_plan,
    verify_conversational_stage_approval,
    verify_stage_approval,
)
from oab.explain import explain_episode, format_explanation
from oab.paths import benchmark_root
from oab.suite_seal import verify_suite_seal
from tools.run_calibration import run_calibration

ROOT = benchmark_root()


def _json_print(payload: Mapping[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True, ensure_ascii=False, allow_nan=False), flush=True)


def _classify_route_failure(diagnostic: str) -> str:
    """Map bounded child diagnostics to stable codes without persisting raw text."""
    lowered = diagnostic.lower()
    patterns = (
        (("release approval",), "campaign_release_approval_invalid"),
        (("release manifest",), "campaign_release_manifest_invalid"),
        (("runtime profile", "hermes home"), "campaign_runtime_profile_invalid"),
        (("fileexistserror", "already exists", "output root"), "campaign_output_exists"),
        (("bubblewrap", "sandbox-exec", "containment", "libseccomp"), "campaign_containment_unavailable"),
        (("hermes_usage", "controller_usage"), "campaign_controller_telemetry_invalid"),
        (("provider_auth", "authentication"), "campaign_provider_auth_unavailable"),
        (("rate_limit", "rate limit"), "campaign_provider_rate_limited"),
        (("provider_unavailable",), "campaign_provider_unavailable"),
    )
    for needles, code in patterns:
        if any(needle in lowered for needle in needles):
            return code
    return "campaign_route_process_failed"


def _campaign_exit_code(state: Mapping[str, object]) -> int:
    status = state.get("status")
    if status in {"awaiting_qualification_approval", "awaiting_full_run_approval", "completed"}:
        return 0
    if status == "blocked_environment":
        return 2
    return 3


def _run_route_process(
    command: Sequence[str], *, timeout_seconds: int | float
) -> dict[str, object]:
    """Run one route in an isolated process group and return sanitized status."""

    with tempfile.TemporaryFile() as diagnostic_stream:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=diagnostic_stream,
            start_new_session=os.name == "posix",
        )
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            returncode = process.wait()
        diagnostic_stream.seek(0)
        diagnostic_sample = diagnostic_stream.read(64 * 1024).decode("utf-8", errors="replace")
        diagnostic_stream.seek(0)
        digest = hashlib.sha256()
        while True:
            chunk = diagnostic_stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return {
        "returncode": returncode,
        "timed_out": timed_out,
        "diagnostic_sha256": "sha256:" + digest.hexdigest(),
        "error_code": _classify_route_failure(diagnostic_sample),
    }


def _load_json_object(path: Path) -> dict[str, object]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("json_input_invalid") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.is_symlink():
        raise ValueError("json_input_file_unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("json_input_invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("json_input_invalid")
    return value


def _production_suite_runner(
    *,
    source_hermes_home: Path | None,
    release_approval: Path | None,
    expected_release_approval_sha256: str | None,
    timeout_seconds: float,
) -> Callable[[dict[str, object], str, Path, str], dict[str, object]]:
    if (release_approval is None) != (expected_release_approval_sha256 is None):
        raise ValueError("release_approval_and_digest_required_together")

    def run(route: dict[str, object], stage: str, output: Path, effort: str) -> dict[str, object]:
        provider = str(route.get("provider") or "")
        model = str(route.get("model") or "")
        requested_route = str(route.get("requested_route") or "")
        scheduled = 34 if stage == "qualification" else 80
        command = [
            sys.executable,
            "-m",
            "tools.run_suite",
            "--provider",
            provider,
            "--model",
            model,
            "--reasoning-effort",
            effort,
            "--output-root",
            str(output),
        ]
        if stage == "qualification":
            command.extend(
                [
                    "--pairs",
                    "P01",
                    "--repetitions",
                    "17",
                    "--max-steps-per-episode",
                    "1",
                ]
            )
        route_call_budget = route.get("max_api_calls")
        if (
            isinstance(route_call_budget, int)
            and not isinstance(route_call_budget, bool)
            and route_call_budget >= 0
        ):
            command.extend(["--max-api-calls", str(route_call_budget)])
        if source_hermes_home is not None:
            command.extend(["--source-hermes-home", str(source_hermes_home)])
        max_observed_cost = route.get("max_observed_cost_usd")
        if (
            isinstance(max_observed_cost, (int, float))
            and not isinstance(max_observed_cost, bool)
            and float(max_observed_cost) >= 0
        ):
            command.extend(["--max-observed-cost-usd", str(float(max_observed_cost))])
        if route.get("allow_unknown_costs") is True:
            command.append("--allow-unknown-costs")
        if release_approval is not None and expected_release_approval_sha256 is not None:
            command.extend(
                [
                    "--release-approval",
                    str(release_approval),
                    "--expected-release-approval-sha256",
                    expected_release_approval_sha256,
                ]
            )
        started = time.monotonic()
        execution = _run_route_process(command, timeout_seconds=timeout_seconds)
        if execution["timed_out"] is True:
            return {
                "requested_route": requested_route,
                "reasoning_effort": effort,
                "scheduled_episodes": scheduled,
                "infrastructure_valid_episodes": 0,
                "infrastructure_invalid_episodes": scheduled,
                "identity_source": None,
                "controller_usage": {"api_calls": None, "cost_usd": None},
                "diagnostic_sha256": execution["diagnostic_sha256"],
                "observations": [
                    {"runner_status": "runner_invalid", "reason_codes": ["campaign_route_timeout"]}
                ],
            }
        report_path = output / "suite-report.json"
        if execution["returncode"] not in {0, 2} or not report_path.is_file():
            return {
                "requested_route": requested_route,
                "reasoning_effort": effort,
                "scheduled_episodes": scheduled,
                "infrastructure_valid_episodes": 0,
                "infrastructure_invalid_episodes": scheduled,
                "identity_source": None,
                "controller_usage": {"api_calls": None, "cost_usd": None},
                "diagnostic_sha256": execution["diagnostic_sha256"],
                "observations": [
                    {"runner_status": "runner_invalid", "reason_codes": [execution["error_code"]]}
                ],
            }
        errors = verify_suite_seal(output)
        if errors:
            return {
                "requested_route": requested_route,
                "reasoning_effort": effort,
                "scheduled_episodes": scheduled,
                "infrastructure_valid_episodes": 0,
                "infrastructure_invalid_episodes": scheduled,
                "identity_source": None,
                "controller_usage": {"api_calls": None, "cost_usd": None},
                "observations": [
                    {"runner_status": "runner_invalid", "reason_codes": ["campaign_suite_verification_failed"]}
                ],
            }
        report = _load_json_object(report_path)
        report["campaign_suite_verified"] = True
        report["campaign_elapsed_seconds"] = round(time.monotonic() - started, 3)
        return report

    return run


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oab",
        description="Agent-native Operational Agent Benchmark campaign orchestrator.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="Check release, Hermes, and containment readiness")
    doctor.add_argument("--json", action="store_true")
    doctor.add_argument("--expected-release-tree-sha256", default=None)

    discover = subparsers.add_parser("discover", help="List configured Hermes route candidates safely")
    discover.add_argument("--inventory-json", type=Path, default=None)
    discover.add_argument("--hermes-api-url", default=None)
    discover.add_argument("--json", action="store_true")

    benchmark = subparsers.add_parser("benchmark", help="Create a no-spend all-accessible campaign plan")
    benchmark.add_argument("--all-accessible", action="store_true", required=True)
    benchmark.add_argument("--output-root", type=Path, required=True)
    benchmark.add_argument(
        "--reasoning-effort",
        required=True,
        choices=("none", "minimal", "low", "medium", "high", "xhigh"),
    )
    benchmark.add_argument("--inventory-json", type=Path, default=None)
    benchmark.add_argument("--expected-release-tree-sha256", default=None)
    benchmark.add_argument("--hermes-api-url", default=None)

    preview = subparsers.add_parser(
        "approval-preview",
        help="Print an exact no-spend stage preview before requesting human approval",
    )
    preview.add_argument("output_root", type=Path)
    preview.add_argument("--stage", required=True, choices=("qualification", "full"))
    preview.add_argument(
        "--observed-cost-stop-usd",
        "--max-cost-usd",
        dest="max_cost_usd",
        type=float,
        required=True,
        help=(
            "Known billed-cost stop threshold. Enforcement occurs after each provider "
            "call, so the revealing call may overshoot once."
        ),
    )
    preview.add_argument("--max-api-calls", type=int, required=True)
    preview.add_argument("--max-routes", type=int, required=True)
    preview.add_argument("--allow-unknown-costs", action="store_true")

    approval = subparsers.add_parser(
        "approval-request", help="Create an exact conversational or externally signed stage approval"
    )
    approval.add_argument("output_root", type=Path)
    approval.add_argument("--stage", required=True, choices=("qualification", "full"))
    approval.add_argument(
        "--observed-cost-stop-usd",
        "--max-cost-usd",
        dest="max_cost_usd",
        type=float,
        required=True,
        help=(
            "Known billed-cost stop threshold. Enforcement occurs after each provider "
            "call, so the revealing call may overshoot once."
        ),
    )
    approval.add_argument("--max-api-calls", type=int, required=True)
    approval.add_argument("--max-routes", type=int, required=True)
    approval.add_argument("--allow-unknown-costs", action="store_true")
    approval_mode = approval.add_mutually_exclusive_group(required=True)
    approval_mode.add_argument("--approval-public-key", type=Path)
    approval_mode.add_argument("--conversation-approval-reference")
    approval.add_argument("--output", type=Path, required=True)

    resume = subparsers.add_parser("resume", help="Resume a campaign with an exact stage approval")
    resume.add_argument("output_root", type=Path)
    gate = resume.add_mutually_exclusive_group()
    gate.add_argument("--qualification-approval", type=Path)
    gate.add_argument("--full-approval", type=Path)
    resume.add_argument("--approval-signature", type=Path, default=None)
    resume.add_argument("--approval-public-key", type=Path, default=None)
    resume.add_argument(
        "--observed-cost-stop-usd",
        "--max-cost-usd",
        dest="max_cost_usd",
        type=float,
        default=None,
        help="Known billed-cost stop threshold; the revealing provider call may overshoot once",
    )
    resume.add_argument("--max-api-calls", type=int, default=None)
    resume.add_argument("--max-routes", type=int, default=None)
    resume.add_argument("--allow-unknown-costs", action="store_true")
    resume.add_argument("--source-hermes-home", type=Path, default=None)
    resume.add_argument("--release-approval", type=Path, default=None)
    resume.add_argument("--expected-release-approval-sha256", default=None)
    resume.add_argument("--stage-timeout-seconds", type=float, default=36000.0)

    report = subparsers.add_parser("report", help="Print campaign status or final decision")
    report.add_argument("output_root", type=Path)

    verify = subparsers.add_parser("verify", help="Verify every completed campaign suite")
    verify.add_argument("output_root", type=Path)

    explain = subparsers.add_parser(
        "explain", help="Explain why one episode passed or failed"
    )
    explain.add_argument("evidence_dir", type=Path)
    explain.add_argument("--json", action="store_true", dest="as_json")

    return parser


def _decision_semantics(report: Mapping[str, object]) -> dict[str, object]:
    comparable = report.get("comparable_routes")
    routes = sorted(str(route) for route in comparable) if isinstance(comparable, list) else []
    return {
        "schema": report.get("schema"),
        "current_route": report.get("current_route"),
        "expected_pair_ids": report.get("expected_pair_ids"),
        "expected_repetitions": report.get("expected_repetitions"),
        "expected_release_tree_sha256": report.get("expected_release_tree_sha256"),
        "recommendation": report.get("recommendation"),
        "recommended_route": report.get("recommended_route"),
        "reasons": report.get("reasons"),
        "claim_scope": report.get("claim_scope"),
        "comparable_routes": routes,
    }


def _verify_campaign(
    root: Path,
    *,
    suite_verifier: Callable[[Path], list[str]] = verify_suite_seal,
) -> dict[str, object]:
    root = root.expanduser().resolve(strict=True)
    state = load_campaign(root)
    errors: list[str] = []
    checked = 0
    checked_approvals = 0
    plan = _load_json_object(root / "PLAN.json")
    errors.extend(verify_campaign_plan(plan))
    try:
        _plan_bound_routes(root, plan)
    except ValueError as exc:
        errors.append(str(exc))
    try:
        _plan_reasoning_effort(plan, state)
    except ValueError as exc:
        errors.append(str(exc))
    plan_sha256 = plan.get("plan_sha256")
    calibration_sha256 = state.get("calibration_sha256")
    try:
        calibration = _load_json_object(root / "CALIBRATION.json")
    except ValueError:
        errors.append("calibration_receipt_missing_or_invalid")
    else:
        if calibration.get("schema") not in {
            "oab.calibration-report/v1",
            "oab.calibration-report/v2",
        } or calibration.get("passed") is not True:
            errors.append("calibration_receipt_failed_or_invalid")
        observed_calibration_sha256 = "sha256:" + hashlib.sha256(
            json.dumps(
                calibration,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        if calibration_sha256 != observed_calibration_sha256:
            errors.append("calibration_receipt_digest_mismatch")
    spend = state.get("spend")
    spend_map = spend if isinstance(spend, Mapping) else {}
    full_reports: list[dict[str, object]] = []

    for stage in ("qualification", "full"):
        results_root = root / stage / "results"
        if not results_root.is_dir():
            continue
        prefix = "qualification" if stage == "qualification" else "full_run"
        approval_path_value = spend_map.get(f"{prefix}_approval_path")
        signature_path_value = spend_map.get(f"{prefix}_approval_signature_path")
        public_key_path_value = spend_map.get(f"{prefix}_approval_public_key_path")
        approval_assurance = spend_map.get(
            f"{prefix}_approval_assurance", "external_signature"
        )
        approval_sha_value = spend_map.get(f"{prefix}_approval_sha256")
        approved_route_ids = spend_map.get(f"{prefix}_approved_route_ids")
        max_cost_value = spend_map.get(f"{prefix}_max_cost_usd")
        max_calls_value = spend_map.get(f"{prefix}_max_api_calls")
        max_routes_value = spend_map.get(f"{prefix}_max_routes")
        allow_unknown_value = spend_map.get(
            "allow_unknown_costs" if stage == "qualification" else "allow_unknown_full_costs"
        )
        conversational = approval_assurance == "conversation_attested"
        approval_values_valid = (
            isinstance(approval_path_value, str)
            and isinstance(plan_sha256, str)
            and isinstance(calibration_sha256, str)
            and isinstance(approved_route_ids, list)
            and all(isinstance(route_id, str) for route_id in approved_route_ids)
            and isinstance(max_cost_value, (int, float))
            and not isinstance(max_cost_value, bool)
            and isinstance(max_calls_value, int)
            and not isinstance(max_calls_value, bool)
            and isinstance(max_routes_value, int)
            and not isinstance(max_routes_value, bool)
            and isinstance(allow_unknown_value, bool)
            and (
                (conversational and signature_path_value is None and public_key_path_value is None)
                or (
                    approval_assurance == "external_signature"
                    and isinstance(signature_path_value, str)
                    and isinstance(public_key_path_value, str)
                )
            )
        )
        if not approval_values_valid:
            errors.append(f"{stage}:stage_approval_missing_or_state_invalid")
        else:
            approval_path = Path(cast(str, approval_path_value)).expanduser().resolve()
            checked_plan_sha256 = cast(str, plan_sha256)
            checked_route_ids = cast(list[str], approved_route_ids)
            checked_max_cost = float(cast(int | float, max_cost_value))
            checked_max_calls = cast(int, max_calls_value)
            checked_max_routes = cast(int, max_routes_value)
            checked_allow_unknown = cast(bool, allow_unknown_value)
            approvals_root = (root / "APPROVALS").resolve()
            artifact_paths = [approval_path]
            if not conversational:
                artifact_paths.extend(
                    [
                        Path(cast(str, signature_path_value)).expanduser().resolve(),
                        Path(cast(str, public_key_path_value)).expanduser().resolve(),
                    ]
                )
            if any(not candidate.is_relative_to(approvals_root) for candidate in artifact_paths):
                errors.append(f"{stage}:stage_approval_path_outside_campaign")
            else:
                if conversational:
                    approval_errors = verify_conversational_stage_approval(
                        approval_path,
                        expected_plan_sha256=checked_plan_sha256,
                        expected_calibration_sha256=cast(str, calibration_sha256),
                        expected_stage=stage,
                        expected_route_ids=checked_route_ids,
                        expected_max_cost_usd=checked_max_cost,
                        expected_max_api_calls=checked_max_calls,
                        expected_max_routes=checked_max_routes,
                        expected_allow_unknown_costs=checked_allow_unknown,
                    )
                else:
                    signature_path = artifact_paths[1]
                    public_key_path = artifact_paths[2]
                    approval_errors = verify_stage_approval(
                        approval_path,
                        expected_plan_sha256=checked_plan_sha256,
                        expected_calibration_sha256=cast(str, calibration_sha256),
                        expected_stage=stage,
                        expected_route_ids=checked_route_ids,
                        expected_max_cost_usd=checked_max_cost,
                        expected_max_api_calls=checked_max_calls,
                        expected_max_routes=checked_max_routes,
                        expected_allow_unknown_costs=checked_allow_unknown,
                        public_key_path=public_key_path,
                        signature_path=signature_path,
                    )
                checked_approvals += 1
                errors.extend(f"{stage}:{code}" for code in approval_errors)
                if not approval_errors:
                    approval = _load_json_object(approval_path)
                    if approval.get("receipt_sha256") != approval_sha_value:
                        errors.append(f"{stage}:stage_approval_state_digest_mismatch")

        expected_suites_root = (root / stage / "suites").resolve()
        seen_route_ids: list[str] = []
        observed_calls_total = 0
        observed_cost_total = 0.0
        unknown_cost_seen = False
        for result_path in sorted(results_root.glob("*.json")):
            result = _load_json_object(result_path)
            unsigned_result = dict(result)
            recorded_result_digest = unsigned_result.pop("receipt_sha256", None)
            if recorded_result_digest != _canonical_sha256(unsigned_result):
                errors.append(f"{stage}:{result_path.stem}:result_receipt_digest_mismatch")
            embedded_report = result.get("suite_report")
            if not isinstance(embedded_report, Mapping) or result.get(
                "suite_report_sha256"
            ) != _canonical_sha256(embedded_report):
                errors.append(f"{stage}:{result_path.stem}:result_report_digest_mismatch")
            result_route_id = result.get("route_id")
            if not isinstance(result_route_id, str) or result_route_id != result_path.stem:
                errors.append(f"{stage}:{result_path.stem}:result_route_id_invalid")
            else:
                seen_route_ids.append(result_route_id)
            if stage == "qualification":
                classification = result.get("classification")
                usage_source = classification if isinstance(classification, Mapping) else {}
            else:
                usage_source = result
            observed_calls = usage_source.get("observed_api_calls")
            if not isinstance(observed_calls, int) or isinstance(observed_calls, bool) or observed_calls < 0:
                errors.append(f"{stage}:{result_path.stem}:observed_api_calls_invalid")
            else:
                observed_calls_total += observed_calls
            observed_cost = usage_source.get("observed_cost_usd")
            if isinstance(observed_cost, (int, float)) and not isinstance(observed_cost, bool) and observed_cost >= 0:
                observed_cost_total += float(observed_cost)
            elif observed_cost is None:
                unknown_cost_seen = True
            else:
                errors.append(f"{stage}:{result_path.stem}:observed_cost_invalid")
            suite_output = result.get("suite_output")
            if not isinstance(suite_output, str):
                errors.append(f"{stage}:suite_output_missing")
                continue
            output = Path(suite_output).expanduser().resolve()
            if not output.is_relative_to(expected_suites_root):
                errors.append(f"{stage}:{result_path.stem}:suite_output_outside_campaign")
                continue
            suite_errors = suite_verifier(output)
            checked += 1
            errors.extend(f"{stage}:{result_path.stem}:{code}" for code in suite_errors)
            if suite_errors:
                continue
            try:
                suite_report = _load_json_object(output / "suite-report.json")
            except ValueError:
                errors.append(f"{stage}:{result_path.stem}:suite_report_invalid")
                continue
            if suite_report.get("requested_route") != result.get("requested_route"):
                errors.append(f"{stage}:{result_path.stem}:suite_report_route_mismatch")
                continue
            if not isinstance(embedded_report, Mapping) or dict(embedded_report) != suite_report:
                errors.append(f"{stage}:{result_path.stem}:result_report_mismatch")
            report_usage = suite_report.get("controller_usage")
            report_usage_map = report_usage if isinstance(report_usage, Mapping) else {}
            if usage_source.get("observed_api_calls") != report_usage_map.get("api_calls"):
                errors.append(f"{stage}:{result_path.stem}:result_api_calls_mismatch")
            if usage_source.get("observed_cost_usd") != report_usage_map.get("cost_usd"):
                errors.append(f"{stage}:{result_path.stem}:result_cost_mismatch")
            expected_known_cost = _known_cost_from_report(suite_report)
            if usage_source.get("observed_known_cost_usd") != expected_known_cost:
                errors.append(f"{stage}:{result_path.stem}:result_known_cost_mismatch")
            expected_unknown_calls = _unknown_cost_api_calls_from_report(suite_report)
            if usage_source.get("unknown_cost_api_calls") != expected_unknown_calls:
                errors.append(f"{stage}:{result_path.stem}:result_unknown_cost_calls_mismatch")
            if stage == "full":
                full_reports.append(suite_report)

        if approval_values_valid:
            expected_route_set = set(cast(list[str], approved_route_ids))
            if len(seen_route_ids) != len(set(seen_route_ids)):
                errors.append(f"{stage}:result_route_duplicate")
            if set(seen_route_ids) != expected_route_set:
                errors.append(f"{stage}:result_route_set_mismatch")
            if observed_calls_total > cast(int, max_calls_value):
                errors.append(f"{stage}:observed_api_call_limit_exceeded")
            if observed_cost_total > float(cast(int | float, max_cost_value)):
                errors.append(f"{stage}:observed_cost_limit_exceeded")
            if unknown_cost_seen and cast(bool, allow_unknown_value) is False:
                errors.append(f"{stage}:unknown_cost_not_approved")

    decision_for_posture: Mapping[str, object] | None = None
    if state.get("status") == "completed":
        decision_path = root / "DECISION_REPORT.json"
        try:
            stored_decision = _load_json_object(decision_path)
        except ValueError:
            errors.append("decision_report_missing_or_invalid")
        else:
            decision_for_posture = stored_decision
            full_plan = plan.get("full_run")
            baseline_route = plan.get("baseline_route")
            release_tree_sha256 = plan.get("release_tree_sha256")
            if (
                not isinstance(full_plan, Mapping)
                or not isinstance(full_plan.get("pair_ids"), list)
                or not isinstance(full_plan.get("repetitions"), int)
                or isinstance(full_plan.get("repetitions"), bool)
                or not isinstance(baseline_route, str)
                or not baseline_route
                or not isinstance(release_tree_sha256, str)
                or not release_tree_sha256
            ):
                errors.append("decision_plan_binding_invalid")
            else:
                recomputed = build_decision_report(
                    current_route=baseline_route,
                    expected_pair_ids=[str(item) for item in full_plan["pair_ids"]],
                    expected_repetitions=int(full_plan["repetitions"]),
                    expected_release_tree_sha256=release_tree_sha256,
                    suite_reports=full_reports,
                )
                if _decision_semantics(stored_decision) != _decision_semantics(recomputed):
                    errors.append("decision_report_recomputation_mismatch")

    recomputed_posture = build_evidence_posture(
        full_reports,
        decision=decision_for_posture,
    )
    posture_fields = (
        "evidence_posture",
        "release_authorized",
        "authority_blockers",
        "route_authority",
        "authority_remediation",
    )
    if any(state.get(field) != recomputed_posture.get(field) for field in posture_fields):
        errors.append("campaign_evidence_posture_mismatch")

    return {
        "schema": "oab.campaign-verification/v1",
        "valid": not errors,
        "campaign_status": state.get("status"),
        **recomputed_posture,
        "checked_suites": checked,
        "checked_approvals": checked_approvals,
        "errors": errors,
        "claim": "internal suite consistency; externally pin release and suite digests for coordinated-rewrite detection",
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    doctor_fn: Any = None,
    inventory_loader: Any = None,
    calibration_runner: Any = None,
    suite_runner: Any = None,
    suite_verifier: Any = None,
) -> int:
    args = _parser().parse_args(argv)
    doctor_fn = doctor_fn or doctor_environment
    inventory_loader = inventory_loader or load_hermes_inventory
    calibration_runner = calibration_runner or run_calibration
    suite_verifier = suite_verifier or verify_suite_seal
    try:
        if args.command == "doctor":
            doctor_kwargs: dict[str, object] = {"benchmark_root": ROOT}
            if args.expected_release_tree_sha256 is not None:
                doctor_kwargs["expected_release_tree_sha256"] = args.expected_release_tree_sha256
            report = doctor_fn(**doctor_kwargs)
            _json_print(report)
            return 0 if report.get("ready") is True else 2

        if args.command == "discover":
            inventory = (
                _load_json_object(args.inventory_json)
                if args.inventory_json
                else inventory_loader(api_base_url=args.hermes_api_url)
                if args.hermes_api_url
                else inventory_loader()
            )
            report = sanitize_hermes_inventory(inventory)
            _json_print(report)
            return 0

        if args.command == "benchmark":
            doctor_kwargs = {"benchmark_root": ROOT}
            if args.expected_release_tree_sha256 is not None:
                doctor_kwargs["expected_release_tree_sha256"] = args.expected_release_tree_sha256
            doctor_report = doctor_fn(**doctor_kwargs)
            if doctor_report.get("ready") is not True:
                _json_print(doctor_report)
                return 2
            inventory = (
                _load_json_object(args.inventory_json)
                if args.inventory_json
                else inventory_loader(api_base_url=args.hermes_api_url)
                if args.hermes_api_url
                else inventory_loader()
            )
            state = initialize_campaign(
                args.output_root,
                doctor=doctor_report,
                inventory_payload=inventory,
                reasoning_effort=args.reasoning_effort,
            )
            if doctor_report.get("ready") is True:
                calibration = calibration_runner(args.output_root.resolve() / "calibration")
                state = record_calibration(args.output_root, calibration)
            _json_print(state)
            return _campaign_exit_code(state)

        if args.command == "approval-preview":
            preview = build_approval_preview(
                args.output_root,
                stage=args.stage,
                max_cost_usd=args.max_cost_usd,
                max_api_calls=args.max_api_calls,
                max_routes=args.max_routes,
                allow_unknown_costs=args.allow_unknown_costs,
            )
            _json_print(preview)
            return 0 if preview.get("call_ceiling_sufficient") is True else 2

        if args.command == "approval-request":
            preview = build_approval_preview(
                args.output_root,
                stage=args.stage,
                max_cost_usd=args.max_cost_usd,
                max_api_calls=args.max_api_calls,
                max_routes=args.max_routes,
                allow_unknown_costs=args.allow_unknown_costs,
            )
            if preview.get("call_ceiling_sufficient") is not True:
                raise ValueError("stage_api_call_ceiling_insufficient")
            if args.conversation_approval_reference is not None:
                request = build_conversational_stage_approval(
                    args.output_root,
                    stage=args.stage,
                    max_cost_usd=args.max_cost_usd,
                    max_api_calls=args.max_api_calls,
                    max_routes=args.max_routes,
                    allow_unknown_costs=args.allow_unknown_costs,
                    user_approval_reference=args.conversation_approval_reference,
                )
            else:
                request = build_stage_approval_request(
                    args.output_root,
                    stage=args.stage,
                    max_cost_usd=args.max_cost_usd,
                    max_api_calls=args.max_api_calls,
                    max_routes=args.max_routes,
                    allow_unknown_costs=args.allow_unknown_costs,
                    approval_public_key_path=args.approval_public_key,
                )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as handle:
                json.dump(request, handle, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
                handle.write("\n")
            signing_payload_path = None
            if args.conversation_approval_reference is None:
                signing_payload_path = Path(str(args.output) + ".signing-payload")
                with signing_payload_path.open("xb") as handle:
                    handle.write(stage_approval_signing_payload(request))
            _json_print(
                {
                    "schema": "oab.approval-request-created/v1",
                    "path": str(args.output.resolve()),
                    "receipt_sha256": request["receipt_sha256"],
                    "stage": args.stage,
                    "approval_assurance": request.get(
                        "approval_assurance", "external_signature"
                    ),
                    "signing_payload_path": (
                        str(signing_payload_path.resolve()) if signing_payload_path else None
                    ),
                }
            )
            return 0

        if args.command == "resume":
            approval_path = args.qualification_approval or args.full_approval
            if approval_path is None:
                _json_print(load_campaign(args.output_root))
                return 0
            approval_receipt = _load_json_object(approval_path)
            conversational = (
                approval_receipt.get("schema") == "oab.conversational-stage-approval/v2"
            )
            if conversational:
                if args.approval_signature is not None or args.approval_public_key is not None:
                    _json_print({"error": "conversation_approval_rejects_key_artifacts"})
                    return 2
            elif args.approval_signature is None or args.approval_public_key is None:
                _json_print({"error": "signed_stage_approval_required"})
                return 2
            if args.max_cost_usd is None or args.max_cost_usd <= 0:
                _json_print({"error": "positive_max_cost_usd_required"})
                return 2
            if args.max_api_calls is None or args.max_api_calls <= 0:
                _json_print({"error": "positive_max_api_calls_required"})
                return 2
            if args.max_routes is None or args.max_routes <= 0:
                _json_print({"error": "positive_max_routes_required"})
                return 2
            runner = suite_runner or _production_suite_runner(
                source_hermes_home=args.source_hermes_home,
                release_approval=args.release_approval,
                expected_release_approval_sha256=args.expected_release_approval_sha256,
                timeout_seconds=args.stage_timeout_seconds,
            )
            common = {
                "runner": runner,
                "max_cost_usd": args.max_cost_usd,
                "allow_unknown_costs": args.allow_unknown_costs,
                "max_api_calls": args.max_api_calls,
                "max_routes": args.max_routes,
                "approval_path": approval_path,
                "approval_signature_path": args.approval_signature,
                "approval_public_key_path": args.approval_public_key,
            }
            if args.qualification_approval is not None:
                state = run_qualification_stage(args.output_root, **common)
            else:
                state = run_full_stage(args.output_root, **common)
            _json_print(state)
            return _campaign_exit_code(state)

        if args.command == "report":
            state = load_campaign(args.output_root)
            decision_path = args.output_root.resolve() / "DECISION_REPORT.json"
            payload = dict(state)
            if decision_path.is_file():
                final_decision = _load_json_object(decision_path)
                payload["decision"] = final_decision
                payload["recommendation"] = final_decision.get("recommendation")
                payload["recommended_route"] = final_decision.get("recommended_route")
            _json_print(payload)
            return 0

        if args.command == "verify":
            result = _verify_campaign(args.output_root.resolve(), suite_verifier=suite_verifier)
            _json_print(result)
            return 0 if result["valid"] is True else 2

        if args.command == "explain":
            explanation = explain_episode(args.evidence_dir)
            if args.as_json:
                _json_print(explanation)
            else:
                sys.stdout.write(format_explanation(explanation))
            # A failed episode is a valid explanation, not a command error.
            return 0

    except (RuntimeError, ValueError, OSError) as exc:
        _json_print({"error": str(exc)})
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
