from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, cast

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from oab.agent_workflow import (
    LEGACY_V221_RELEASE_TREE_SHA256,
    _attempt_accounting,
    _canonical_sha256,
    _known_cost_from_report,
    _open_directory_fd,
    _plan_bound_routes,
    _plan_reasoning_effort,
    _unknown_cost_api_calls_from_report,
    _validate_campaign_orchestration_metadata,
    build_evidence_posture,
    build_decision_report,
    doctor_environment,
    initialize_campaign,
    load_campaign,
    load_hermes_inventory,
    project_test_model_state,
    record_calibration,
    run_full_stage,
    run_qualification_stage,
    sanitize_hermes_inventory,
    select_model_comparison_inventory,
    verify_campaign_plan,
)
from oab.full_stage_contract import validate_authoritative_full_stage_plan

from oab.explain import explain_episode, format_explanation
from oab.paths import benchmark_root
from oab.qualification_contract import (
    ABSOLUTE_API_CALL_CEILING_PER_ROUTE,
    QUALIFICATION_CONTRACT_ID,
    QUALIFICATION_REPORT_SCHEMA,
    canonical_bytes as qualification_canonical_bytes,
    validate_qualification_contract,
    validate_qualification_report,
)
from oab.suite_seal import verify_suite_seal
if __package__:
    from .run_calibration import run_calibration
else:
    from tools.run_calibration import run_calibration

ROOT = benchmark_root()


def _default_test_model_output_root() -> Path:
    return Path.home() / "OAB-Runs" / f"oab-test-{int(time.time())}-{secrets.token_hex(4)}"


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
    if status in {"ready_for_qualification", "qualification_complete", "completed"}:
        return 0
    if status == "blocked_environment":
        return 2
    return 3


def _run_route_process(
    command: Sequence[str],
    *,
    timeout_seconds: int | float,
    pass_fds: Sequence[int] = (),
) -> dict[str, object]:
    """Run one route in an isolated process group and return sanitized status."""

    with tempfile.TemporaryFile() as diagnostic_stream:
        if os.name == "posix":
            process = subprocess.Popen(
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=diagnostic_stream,
                start_new_session=True,
                pass_fds=tuple(pass_fds),
            )
        else:
            process = subprocess.Popen(
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=diagnostic_stream,
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


def _read_regular_bytes_at(
    directory_fd: int, name: str, *, max_bytes: int = 16 * 1024 * 1024
) -> bytes:
    if name in {"", ".", ".."} or "/" in name or "\\" in name:
        raise ValueError("json_input_file_unsafe")

    def identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("json_input_invalid") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("json_input_file_unsafe")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise ValueError("json_input_invalid") from exc
    try:
        opened = os.fstat(descriptor)
        if identity(opened) != identity(before):
            raise ValueError("json_input_file_race")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > max_bytes:
                raise ValueError("json_input_too_large")
        after_read = os.fstat(descriptor)
        after_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if identity(after_read) != identity(opened) or identity(after_entry) != identity(opened):
            raise ValueError("json_input_file_race")
        return bytes(payload)
    finally:
        os.close(descriptor)


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
        if output.name in {"", ".", ".."} or "/" in output.name or "\\" in output.name:
            raise ValueError("campaign_suite_output_invalid")
        route_call_budget = route.get("max_api_calls")
        qualification_contract: dict[str, object] | None = None
        if stage == "qualification":
            tuple_value = route.get("_qualification_contract")
            if (
                route.get("_qualification_contract_version") != QUALIFICATION_CONTRACT_ID
                or not isinstance(route_call_budget, int)
                or isinstance(route_call_budget, bool)
                or route_call_budget != ABSOLUTE_API_CALL_CEILING_PER_ROUTE
            ):
                raise ValueError("qualification_execution_contract_invalid")
            try:
                qualification_contract = validate_qualification_contract(tuple_value)
            except ValueError as exc:
                raise ValueError("qualification_execution_contract_invalid") from exc
        elif stage == "full":
            if (
                not isinstance(route_call_budget, int)
                or isinstance(route_call_budget, bool)
                or route_call_budget != 1360
            ):
                raise ValueError("authoritative_full_execution_contract_invalid")
        try:
            output_parent_fd = _open_directory_fd(output.parent.expanduser().absolute())
        except (OSError, ValueError) as exc:
            raise ValueError("campaign_internal_path_unsafe") from exc

        suite_module = (
            f"{__package__}.run_suite"
            if __package__ in {"tools", "oab_tools"}
            else "tools.run_suite"
        )
        command = [
            sys.executable,
            "-m",
            suite_module,
            "--provider",
            provider,
            "--model",
            model,
            "--reasoning-effort",
            effort,
            "--output-root",
            str(output),
        ]
        if os.name == "posix":
            command.extend(
                [
                    "--output-parent-fd",
                    str(output_parent_fd),
                    "--output-name",
                    output.name,
                ]
            )
        campaign_root_fd = -1
        if stage in {"qualification", "full"}:
            root_value = route.get("_campaign_root_path")
            if not isinstance(root_value, str) or not root_value:
                os.close(output_parent_fd)
                raise ValueError("campaign_child_contract_missing")
            campaign_root = Path(root_value).expanduser().resolve()
            try:
                campaign_root_fd = _open_directory_fd(campaign_root)
            except Exception:
                os.close(output_parent_fd)
                raise ValueError("campaign_child_contract_missing") from None
            command.extend(
                [
                    "--campaign-root-path",
                    str(campaign_root),
                    "--campaign-root-fd",
                    str(campaign_root_fd),
                ]
            )
        if stage == "qualification":
            # The child owns the exact P01 approved/prohibited first-attempt phase
            # and any typed retry. Generic pair/repetition/step selectors are never
            # passed to qualification readiness mode.
            command.append("--qualification-readiness-v1")
        elif stage == "full":
            command.append("--authoritative-full-v1")
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
        if (
            stage != "qualification"
            and release_approval is not None
            and expected_release_approval_sha256 is not None
        ):
            command.extend(
                [
                    "--release-approval",
                    str(release_approval),
                    "--expected-release-approval-sha256",
                    expected_release_approval_sha256,
                ]
            )
        started = time.monotonic()
        output_fd = -1
        saved_cwd_fd = -1
        try:
            execution = _run_route_process(
                command,
                timeout_seconds=timeout_seconds,
                pass_fds=tuple(
                    descriptor
                    for descriptor in (
                        output_parent_fd,
                        campaign_root_fd,
                    )
                    if descriptor >= 0
                ),
            )
            if execution["timed_out"] is True:
                raise RuntimeError("campaign_route_timeout")
            if execution["returncode"] not in {0, 2}:
                raise RuntimeError(str(execution["error_code"]))
            try:
                output_fd = os.open(
                    output.name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=output_parent_fd,
                )
                report_bytes = _read_regular_bytes_at(output_fd, "suite-report.json")
                seal_bytes = _read_regular_bytes_at(output_fd, "SUITE_SEAL.json")
                saved_cwd_fd = os.open(
                    ".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                )
                os.fchdir(output_fd)
            except (OSError, ValueError) as exc:
                raise RuntimeError("campaign_suite_verification_failed") from exc
            errors = verify_suite_seal(
                Path("."), seal_bytes=seal_bytes, report_bytes=report_bytes
            )
            if errors:
                raise RuntimeError("campaign_suite_verification_failed")
            try:
                report_value = json.loads(report_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("campaign_suite_verification_failed") from exc
            if not isinstance(report_value, dict):
                raise RuntimeError("campaign_suite_verification_failed")
            if stage == "qualification":
                try:
                    validated = validate_qualification_report(report_value)
                except ValueError as exc:
                    raise RuntimeError("campaign_suite_verification_failed") from exc
                if validated.get("qualification_contract") != qualification_contract:
                    raise RuntimeError("campaign_suite_verification_failed")
            report = report_value
        finally:
            if saved_cwd_fd >= 0:
                os.fchdir(saved_cwd_fd)
                os.close(saved_cwd_fd)
            if output_fd >= 0:
                os.close(output_fd)
            if campaign_root_fd >= 0:
                os.close(campaign_root_fd)
            os.close(output_parent_fd)
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

    benchmark = subparsers.add_parser("benchmark", help="Create a bounded all-accessible campaign plan")
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
    benchmark.add_argument("--qualification-cost-stop-usd", type=float, default=5.0)
    benchmark.add_argument("--qualification-max-routes", type=int, default=None)
    benchmark.add_argument("--allow-unknown-costs", action="store_true")
    benchmark.add_argument("--full-cost-stop-usd", type=float, default=50.0)
    benchmark.add_argument("--full-max-routes", type=int, default=None)
    benchmark.add_argument("--allow-unknown-full-costs", action="store_true")

    test_model = subparsers.add_parser(
        "test-model",
        help="Run a bounded two-route candidate-vs-current test",
    )
    test_model.add_argument("candidate_route")
    test_model.add_argument("--output-root", type=Path, default=None)
    test_model.add_argument(
        "--reasoning-effort",
        default="high",
        choices=("none", "minimal", "low", "medium", "high", "xhigh"),
    )
    test_model.add_argument("--qualification-cost-stop-usd", type=float, default=5.0)
    test_model.add_argument("--allow-unknown-costs", action="store_true")
    test_model.add_argument("--hermes-api-url", default=None)

    test_model_status = subparsers.add_parser(
        "test-model-status",
        help="Project a campaign into its running, blocked, or verdict state",
    )
    test_model_status.add_argument("output_root", type=Path)

    resume = subparsers.add_parser("resume", help="Run or resume one bounded campaign stage")
    resume.add_argument("output_root", type=Path)
    resume.add_argument("--stage", required=True, choices=("qualification", "full"))
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
    errors: list[str] = []
    try:
        state = load_campaign(root)
    except ValueError as exc:
        return {
            "schema": "oab.campaign-verification/v1",
            "valid": False,
            "campaign_status": None,
            "evidence_posture": "exploratory",
            "release_authorized": False,
            "authority_blockers": ["campaign_internal_path_unsafe"],
            "route_authority": [],
            "authority_remediation": None,
            "checked_suites": 0,
            "checked_approvals": 0,
            "errors": [str(exc)],
            "claim": "campaign layout rejected before artifact traversal",
        }
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
    campaign_release_tree_sha256 = plan.get("release_tree_sha256")
    full_reports: list[dict[str, object]] = []

    for stage in ("qualification", "full"):
        results_root = root / stage / "results"
        if not results_root.is_dir():
            continue
        max_cost_value = spend_map.get(f"{'qualification' if stage == 'qualification' else 'full_run'}_max_cost_usd")
        max_calls_value = spend_map.get(f"{'qualification' if stage == 'qualification' else 'full_run'}_max_api_calls")
        max_routes_value = spend_map.get(f"{'qualification' if stage == 'qualification' else 'full_run'}_max_routes")
        allow_unknown_value = spend_map.get("allow_unknown_costs" if stage == "qualification" else "allow_unknown_full_costs")
        limits_valid = (isinstance(max_cost_value, (int, float)) and not isinstance(max_cost_value, bool) and isinstance(max_calls_value, int) and not isinstance(max_calls_value, bool) and isinstance(max_routes_value, int) and not isinstance(max_routes_value, bool) and isinstance(allow_unknown_value, bool))

        seen_route_ids: list[str] = []
        attempt_results: dict[str, dict[str, object]] = {}
        observed_calls_total = 0
        observed_cost_total = 0.0
        unknown_cost_seen = False
        for result_path in sorted(results_root.glob("*.json")):
            result = _load_json_object(result_path)
            attempt_results[result_path.stem] = result
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
            attempt_id = result.get("attempt_id")
            if (
                isinstance(attempt_id, str)
                and re.fullmatch(r"[0-9a-f]{32}", attempt_id) is not None
            ):
                expected_output = root / stage / "attempts" / f"{attempt_id}.evidence"
            elif campaign_release_tree_sha256 == LEGACY_V221_RELEASE_TREE_SHA256:
                expected_output = root / stage / "suites" / result_path.stem
            else:
                errors.append(f"{stage}:{result_path.stem}:campaign_attempt_ledger_invalid")
                continue
            if suite_output != str(expected_output):
                errors.append(f"{stage}:{result_path.stem}:suite_output_outside_campaign")
                continue
            output = expected_output
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
            comparable_report = dict(embedded_report) if isinstance(embedded_report, Mapping) else None
            legacy_metadata = comparable_report is not None and any(
                key in comparable_report
                for key in ("campaign_suite_verified", "campaign_elapsed_seconds")
            )
            top_level_metadata = any(
                key in result
                for key in ("campaign_suite_verified", "campaign_elapsed_seconds")
            )
            if legacy_metadata:
                assert comparable_report is not None
                if top_level_metadata:
                    errors.append(
                        f"{stage}:{result_path.stem}:campaign_metadata_layout_invalid"
                    )
                try:
                    _validate_campaign_orchestration_metadata(comparable_report)
                except ValueError:
                    errors.append(f"{stage}:{result_path.stem}:legacy_campaign_metadata_invalid")
                if (
                    comparable_report.get("release_tree_sha256")
                    != LEGACY_V221_RELEASE_TREE_SHA256
                    or campaign_release_tree_sha256
                    != LEGACY_V221_RELEASE_TREE_SHA256
                ):
                    errors.append(
                        f"{stage}:{result_path.stem}:legacy_campaign_release_invalid"
                    )
                comparable_report.pop("campaign_suite_verified", None)
                comparable_report.pop("campaign_elapsed_seconds", None)
            else:
                try:
                    _validate_campaign_orchestration_metadata(result)
                except ValueError:
                    errors.append(f"{stage}:{result_path.stem}:campaign_metadata_invalid")
            if comparable_report is None or _canonical_sha256(
                comparable_report
            ) != _canonical_sha256(suite_report):
                errors.append(f"{stage}:{result_path.stem}:result_report_mismatch")
            report_usage = suite_report.get("controller_usage")
            report_usage_map = report_usage if isinstance(report_usage, Mapping) else {}
            if usage_source.get("observed_api_calls") != report_usage_map.get("api_calls"):
                errors.append(f"{stage}:{result_path.stem}:result_api_calls_mismatch")
            if usage_source.get("observed_cost_usd") != report_usage_map.get("cost_usd"):
                errors.append(f"{stage}:{result_path.stem}:result_cost_mismatch")
            expected_known_cost = _known_cost_from_report(suite_report)
            observed_known = usage_source.get("observed_known_cost_usd")
            if observed_known != expected_known_cost:
                if not (observed_known is None and expected_known_cost == 0.0):
                    errors.append(f"{stage}:{result_path.stem}:result_known_cost_mismatch")
            expected_unknown_calls = _unknown_cost_api_calls_from_report(suite_report)
            if usage_source.get("unknown_cost_api_calls") != expected_unknown_calls:
                errors.append(f"{stage}:{result_path.stem}:result_unknown_cost_calls_mismatch")
            if stage == "full":
                full_reports.append(suite_report)

        try:
            attempt_accounting = _attempt_accounting(
                root,
                stage,
                attempt_results,
                require_ledger=(
                    campaign_release_tree_sha256
                    != LEGACY_V221_RELEASE_TREE_SHA256
                ),
            )
        except ValueError as exc:
            errors.append(f"{stage}:{exc}")
        else:
            failed_calls = attempt_accounting.get("failed_reserved_api_calls")
            failed_attempts = attempt_accounting.get("failed_attempts")
            if not isinstance(failed_calls, int) or not isinstance(failed_attempts, int):
                errors.append(f"{stage}:campaign_attempt_ledger_invalid")
            else:
                observed_calls_total += failed_calls
                unknown_cost_seen = unknown_cost_seen or bool(
                    attempt_accounting.get("unknown_cost_encountered")
                )
                failed_calls_field = (
                    "qualification_failed_attempt_reserved_api_calls"
                    if stage == "qualification"
                    else "full_failed_attempt_reserved_api_calls"
                )
                failed_attempts_field = (
                    "qualification_failed_attempts"
                    if stage == "qualification"
                    else "full_failed_attempts"
                )
                if list((root / stage / "attempts").glob("*.json")) and (
                    spend_map.get(failed_calls_field) != failed_calls
                    or spend_map.get(failed_attempts_field) != failed_attempts
                ):
                    errors.append(f"{stage}:campaign_attempt_state_mismatch")

        if len(seen_route_ids) != len(set(seen_route_ids)):
            errors.append(f"{stage}:result_route_duplicate")
        if limits_valid:
            if observed_calls_total > cast(int, max_calls_value):
                errors.append(f"{stage}:observed_api_call_limit_exceeded")
            if observed_cost_total > float(cast(int | float, max_cost_value)):
                errors.append(f"{stage}:observed_cost_limit_exceeded")
            if unknown_cost_seen and cast(bool, allow_unknown_value) is False:
                errors.append(f"{stage}:unknown_cost_not_allowed")

    decision_for_posture: Mapping[str, object] | None = None
    if state.get("status") == "completed":
        decision_path = root / "DECISION_REPORT.json"
        try:
            stored_decision = _load_json_object(decision_path)
        except ValueError:
            errors.append("decision_report_missing_or_invalid")
        else:
            decision_for_posture = stored_decision
            raw_full_plan = plan.get("full_run")
            baseline_route = plan.get("baseline_route")
            release_tree_sha256 = plan.get("release_tree_sha256")
            route_count = plan.get("route_count")
            execution_contract_sha256 = plan_sha256
            try:
                if (
                    not isinstance(baseline_route, str)
                    or not baseline_route
                    or not isinstance(release_tree_sha256, str)
                    or not release_tree_sha256
                    or not isinstance(route_count, int)
                    or isinstance(route_count, bool)
                    or not isinstance(execution_contract_sha256, str)
                    or not execution_contract_sha256
                ):
                    raise ValueError("decision_plan_binding_invalid")
                full_plan = validate_authoritative_full_stage_plan(
                    raw_full_plan, route_count=route_count
                )
                recomputed = build_decision_report(
                    current_route=baseline_route,
                    expected_release_tree_sha256=release_tree_sha256,
                    suite_reports=full_reports,
                    authoritative_full_plan=full_plan,
                    expected_plan_sha256=str(plan_sha256),
                    expected_execution_contract_sha256=execution_contract_sha256,
                )
            except (TypeError, ValueError):
                errors.append("decision_plan_binding_invalid")
            else:
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
        "checked_approvals": 0,
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
    trusted_test_model_context_loader: Any = None,
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
                qualification_known_cost_stop_usd=args.qualification_cost_stop_usd,
                qualification_allow_unknown_costs=args.allow_unknown_costs,
                qualification_max_routes=args.qualification_max_routes,
                full_known_cost_stop_usd=args.full_cost_stop_usd,
                full_allow_unknown_costs=args.allow_unknown_full_costs,
                full_max_routes=args.full_max_routes,
            )
            if doctor_report.get("ready") is True:
                calibration = calibration_runner(args.output_root.resolve() / "calibration")
                state = record_calibration(args.output_root, calibration)
            _json_print(state)
            return _campaign_exit_code(state)

        if args.command == "test-model":
            output_root = args.output_root or _default_test_model_output_root()
            if trusted_test_model_context_loader is not None:
                trusted_context = trusted_test_model_context_loader()
                release_tree_sha256 = trusted_context.get("release_tree_sha256")
            else:
                manifest = _load_json_object(ROOT / "RELEASE_MANIFEST.json")
                release_tree_sha256 = manifest.get("tree_sha256")
            if not isinstance(release_tree_sha256, str) or not release_tree_sha256:
                raise ValueError("trusted_release_pin_unavailable")
            doctor_kwargs = {
                "benchmark_root": ROOT,
                "expected_release_tree_sha256": release_tree_sha256,
            }
            doctor_report = doctor_fn(**doctor_kwargs)
            if doctor_report.get("ready") is not True:
                _json_print(doctor_report)
                return 2
            if doctor_report.get("release_tree_sha256") != release_tree_sha256:
                raise ValueError("trusted_release_pin_mismatch")
            inventory = (
                inventory_loader(api_base_url=args.hermes_api_url)
                if args.hermes_api_url
                else inventory_loader()
            )
            selected_inventory = select_model_comparison_inventory(
                inventory, candidate_route=args.candidate_route
            )
            initialize_campaign(
                output_root,
                doctor=doctor_report,
                inventory_payload=selected_inventory,
                reasoning_effort=args.reasoning_effort,
                qualification_known_cost_stop_usd=args.qualification_cost_stop_usd,
                qualification_allow_unknown_costs=args.allow_unknown_costs,
                qualification_max_routes=2,
                full_allow_unknown_costs=args.allow_unknown_costs,
                full_max_routes=2,
            )
            calibration = calibration_runner(output_root.resolve() / "calibration")
            record_calibration(output_root, calibration)
            routes = [
                str(item.get("requested_route"))
                for item in sanitize_hermes_inventory(selected_inventory)["routes"]
                if isinstance(item, Mapping)
            ]
            baseline = sanitize_hermes_inventory(selected_inventory)["current_route"]
            candidate = next(route for route in routes if route != baseline)
            runner = suite_runner or _production_suite_runner(
                source_hermes_home=None,
                release_approval=None,
                expected_release_approval_sha256=None,
                timeout_seconds=36000.0,
            )
            state = run_qualification_stage(
                output_root,
                runner=runner,
                max_cost_usd=args.qualification_cost_stop_usd,
                allow_unknown_costs=args.allow_unknown_costs,
                max_api_calls=2 * ABSOLUTE_API_CALL_CEILING_PER_ROUTE,
                max_routes=2,
            )
            _json_print(
                {
                    "schema": "oab.test-model-result/v1",
                    "campaign_root": str(output_root.resolve()),
                    "baseline": baseline,
                    "candidate": candidate,
                    "stage": "qualification",
                    "maximum_api_calls": 2 * ABSOLUTE_API_CALL_CEILING_PER_ROUTE,
                    "observed_known_billed_cost_stop_usd": args.qualification_cost_stop_usd,
                    "allow_unknown_costs": args.allow_unknown_costs,
                    "routes": routes,
                    "campaign_status": state.get("status"),
                    "next_action": "review_qualification_before_full_stage",
                }
            )
            return _campaign_exit_code(state)

        if args.command == "test-model-status":
            root = args.output_root.resolve()
            campaign = load_campaign(root)
            qualification_path = root / "QUALIFICATION.json"
            decision_path = root / "DECISION_REPORT.json"
            qualification = (
                _load_json_object(qualification_path) if qualification_path.is_file() else None
            )
            decision = _load_json_object(decision_path) if decision_path.is_file() else None
            _json_print(
                project_test_model_state(
                    campaign,
                    qualification=qualification,
                    decision=decision,
                )
            )
            return 0

        if args.command == "resume":
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
            }
            state = (
                run_qualification_stage(args.output_root, **common)
                if args.stage == "qualification"
                else run_full_stage(args.output_root, **common)
            )
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
