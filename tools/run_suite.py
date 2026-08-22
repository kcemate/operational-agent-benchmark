from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from oab.aggregation import aggregate_suite_observations, format_headline
from oab.campaign_contract import verify_campaign_child_contract
from oab.full_stage_contract import (
    AUTHORITATIVE_FULL_PAIR_IDS,
    FULL_API_CALL_CEILING_PER_ROUTE,
    FULL_MAX_API_CALLS_PER_EPISODE,
    FULL_REPETITIONS,
    build_authoritative_stage_binding,
    validate_authoritative_full_stage_plan,
)
from oab.case_verifier import verify_case
from oab.control import tool_policy_from_case
from oab.hermes_controller import HermesCliController
from oab.registry import load_registry
from oab.release_approval import verify_release_approval
from oab.runner import StrictEpisodeSpec
from oab.runtime_profile import pinned_hermes_runtime
from oab.strict_runner import ToolPolicy, run_strict_episode
from oab.suite_seal import write_suite_seal
from oab.paths import benchmark_root
from oab.qualification_contract import (
    ABSOLUTE_API_CALL_CEILING_PER_ROUTE,
    MAX_API_CALLS_PER_PHYSICAL_ATTEMPT,
    MAX_BROKER_STEPS_PER_PROBE,
    QUALIFICATION_CHILD_RESULT_SCHEMA,
    QUALIFICATION_PROBE_RESULT_SCHEMA,
    aggregate_telemetry,
    build_physical_attempt,
    build_qualification_report,
    qualification_probe_definitions,
    retry_eligible,
    telemetry_errors,
    validate_child_result,
    validate_qualification_contract,
)
if __package__:
    from .release_manifest import verify_release_manifest
else:
    from tools.release_manifest import verify_release_manifest

ROOT = benchmark_root()


def _bounded_tool_policy(policy: ToolPolicy, max_steps: int | None) -> ToolPolicy:
    if max_steps is None:
        return policy
    if not isinstance(max_steps, int) or isinstance(max_steps, bool) or max_steps < 1:
        raise ValueError("max_steps_per_episode_invalid")
    current = getattr(policy, "max_steps", None)
    if not isinstance(current, int) or isinstance(current, bool) or current < 1:
        raise ValueError("tool_policy_max_steps_invalid")
    return replace(policy, max_steps=min(current, max_steps))


def _parse_pairs(raw: str | None, available: list[str]) -> list[str]:
    if raw is None or raw.strip() in {"", "all"}:
        return list(available)
    selected = [part.strip() for part in raw.split(",") if part.strip()]
    unknown = [pair for pair in selected if pair not in available]
    if unknown:
        raise SystemExit(f"unknown pair id(s): {', '.join(unknown)}")
    # Preserve registry order for determinism.
    order = {pair: index for index, pair in enumerate(available)}
    return sorted(set(selected), key=lambda pair: order[pair])


def _case_ids_by_pair(cases: list[dict[str, object]]) -> dict[str, dict[str, str]]:
    mapping: dict[str, dict[str, str]] = {}
    for case in cases:
        pair_id = str(case["pair_id"])
        variant = str(case["variant"])
        mapping.setdefault(pair_id, {})
        mapping[pair_id][variant] = str(case["case_id"])
    return mapping


def _identity_from_result(result_path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    identity = payload.get("controller_identity")
    return dict(identity) if isinstance(identity, dict) else None


def _runtime_from_result(result_path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    runtime = payload.get("runtime")
    return dict(runtime) if isinstance(runtime, dict) else None


def _run_observations(
    *,
    args: argparse.Namespace,
    selected_cases: list[dict[str, object]],
    output_root: Path,
    runtime_home: Path,
    authoritative_full: bool = False,
) -> list[dict[str, object]]:
    observations: list[dict[str, object]] = []
    observed_known_cost_usd = 0.0
    observed_api_calls = 0
    for repetition in range(1, args.repetitions + 1):
        for case in selected_cases:
            case_id = str(case["case_id"])
            pair_id = str(case["pair_id"])
            variant = str(case["variant"])
            print(f"starting {case_id} rep={repetition}", flush=True)
            fixture = ROOT / str(case["fixture_path"])
            evidence = output_root / "evidence" / f"rep-{repetition:02d}" / case_id
            run_root = output_root / "run-roots" / f"rep-{repetition:02d}" / case_id
            task_bytes = (ROOT / str(case["task_path"])).read_bytes()
            remaining_observed_cost_usd = (
                max(0.0, args.max_observed_cost_usd - observed_known_cost_usd)
                if args.max_observed_cost_usd is not None
                else None
            )
            controller = HermesCliController(
                model=args.model,
                provider=args.provider,
                timeout_seconds=args.timeout_seconds,
                hermes_home=runtime_home,
                reasoning_effort=args.reasoning_effort,
                max_observed_cost_usd=remaining_observed_cost_usd,
                max_api_calls=(
                    min(
                        FULL_MAX_API_CALLS_PER_EPISODE,
                        max(0, args.max_api_calls - observed_api_calls),
                    )
                    if authoritative_full and args.max_api_calls is not None
                    else (
                        max(0, args.max_api_calls - observed_api_calls)
                        if args.max_api_calls is not None
                        else None
                    )
                ),
                allow_unknown_costs=args.allow_unknown_costs,
            )
            tool_policy = _bounded_tool_policy(
                tool_policy_from_case(case, fixture), args.max_steps_per_episode
            )
            result = run_strict_episode(
                StrictEpisodeSpec(
                    case_id=case_id,
                    repetition=repetition,
                    task_bytes=task_bytes,
                    input_tree=fixture,
                    timeout_seconds=args.episode_timeout_seconds,
                ),
                repository_root=ROOT,
                run_root=run_root,
                evidence_dir=evidence,
                tool_policy=tool_policy,
                controller=controller,
            )
            gates = verify_case(case, fixture, evidence)
            identity = _identity_from_result(evidence / "result.json") or {}
            runtime = _runtime_from_result(evidence / "result.json") or {}
            identity_source = identity.get("identity_source")
            if not isinstance(identity_source, str):
                identity_source = "adapter_runtime"
            record: dict[str, object] = {
                "pair_id": pair_id,
                "case_id": case_id,
                "variant": variant,
                "repetition": repetition,
                "runner_status": result.status,
                "valid_for_authoritative_scoring": result.valid_for_scoring,
                "reason_codes": list(result.reason_codes),
                "all_declared_gates_passed": all(gate.passed for gate in gates),
                "identity_source": identity_source,
                "requested_route": identity.get("requested_route"),
                "returned_route": identity.get("returned_route"),
                "response_id": identity.get("response_id"),
                "reasoning_effort": args.reasoning_effort,
                "controller_config_sha256": controller.controller_config_sha256,
                "gates": [
                    {"id": gate.dimension, "passed": gate.passed, "code": gate.code}
                    for gate in gates
                ],
                "controller_usage": controller.usage_snapshot(),
                "protocol_normalized_turns": getattr(
                    controller, "protocol_normalized_turns", 0
                ),
                "runtime": runtime,
                "trace_sha256": result.trace_sha256,
                "output_tree_sha256": result.output_tree_sha256,
                "evidence_dir": str(evidence),
            }
            observations.append(record)
            usage = record["controller_usage"]
            known_cost = usage.get("known_cost_usd") if isinstance(usage, dict) else None
            if isinstance(known_cost, (int, float)) and not isinstance(known_cost, bool):
                observed_known_cost_usd += float(known_cost)
            api_calls = usage.get("api_calls") if isinstance(usage, dict) else None
            if isinstance(api_calls, int) and not isinstance(api_calls, bool):
                observed_api_calls += api_calls
                if authoritative_full and not (0 <= api_calls <= FULL_MAX_API_CALLS_PER_EPISODE):
                    raise ValueError("authoritative_full_episode_api_calls_invalid")
            elif authoritative_full:
                raise ValueError("authoritative_full_episode_api_calls_invalid")
            unknown_cost_api_calls = (
                usage.get("unknown_cost_api_calls") if isinstance(usage, dict) else None
            )
            print(
                f"finished {case_id} rep={repetition}: status={result.status} "
                f"gates={sum(gate.passed for gate in gates)}/{len(gates)}",
                flush=True,
            )
            if (
                not args.allow_unknown_costs
                and isinstance(unknown_cost_api_calls, int)
                and not isinstance(unknown_cost_api_calls, bool)
                and unknown_cost_api_calls > 0
            ):
                return observations
    return observations


def _qualification_receipt(evidence: Path) -> dict[str, object]:
    try:
        value = json.loads((evidence / "result.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("qualification_attempt_evidence_invalid") from exc
    if not isinstance(value, dict) or value.get("schema") != QUALIFICATION_PROBE_RESULT_SCHEMA:
        raise ValueError("qualification_attempt_evidence_invalid")
    return value


def _append_attempt_reason(attempt: dict[str, object], reason: str) -> None:
    current = attempt.get("reason_codes")
    if not isinstance(current, list):
        raise ValueError("qualification_attempt_evidence_invalid")
    attempt["reason_codes"] = sorted({*current, reason})
    attempt["readiness_evidence"] = False


def _run_qualification_attempt(
    *,
    args: argparse.Namespace,
    probe: dict[str, object],
    attempt_number: int,
    output_root: Path,
    runtime_home: Path,
    known_cost_so_far: float,
) -> dict[str, object]:
    case_id = str(probe["case_id"])
    cases = load_registry(ROOT / "cases.json")["cases"]
    case = next(
        (
            item
            for item in cases
            if isinstance(item, dict) and item.get("case_id") == case_id
        ),
        None,
    )
    if not isinstance(case, dict):
        raise ValueError("qualification_case_registry_invalid")
    fixture = ROOT / str(case["fixture_path"])
    evidence = output_root / "evidence" / "rep-01" / case_id / f"attempt-{attempt_number:02d}"
    run_root = output_root / "run-roots" / "rep-01" / case_id / f"attempt-{attempt_number:02d}"
    remaining_observed_cost_usd = (
        max(0.0, float(args.max_observed_cost_usd) - known_cost_so_far)
        if args.max_observed_cost_usd is not None
        else None
    )
    controller = HermesCliController(
        model=args.model,
        provider=args.provider,
        timeout_seconds=args.timeout_seconds,
        hermes_home=runtime_home,
        reasoning_effort=args.reasoning_effort,
        max_observed_cost_usd=remaining_observed_cost_usd,
        max_api_calls=MAX_API_CALLS_PER_PHYSICAL_ATTEMPT,
        allow_unknown_costs=args.allow_unknown_costs,
    )
    policy = _bounded_tool_policy(
        tool_policy_from_case(case, fixture), MAX_BROKER_STEPS_PER_PROBE
    )
    result = run_strict_episode(
        StrictEpisodeSpec(
            case_id=case_id,
            repetition=1,
            task_bytes=(ROOT / str(case["task_path"])).read_bytes(),
            input_tree=fixture,
            timeout_seconds=args.episode_timeout_seconds,
        ),
        repository_root=ROOT,
        run_root=run_root,
        evidence_dir=evidence,
        tool_policy=policy,
        controller=controller,
        artifact_profile="qualification_readiness",
    )
    receipt = _qualification_receipt(evidence)
    gates = verify_case(case, fixture, evidence)
    attempt = build_physical_attempt(
        probe=probe,
        attempt_number=attempt_number,
        runner_status=receipt.get("status", result.status),
        reason_codes=receipt.get("reason_codes", list(result.reason_codes)),
        identity=receipt.get("controller_identity"),
        telemetry=receipt.get("controller_usage"),
        runtime=receipt.get("runtime"),
        trace_sha256=receipt.get("trace_sha256", result.trace_sha256),
        output_tree_sha256=receipt.get("output_tree_sha256", result.output_tree_sha256),
        probe_contract_satisfied=all(gate.passed for gate in gates),
        requested_route=f"{args.provider}/{args.model}",
        reasoning_effort=args.reasoning_effort,
    )
    return attempt


def _qualification_stop_reason(
    attempt: dict[str, object],
    *,
    allow_unknown_costs: bool,
) -> str | None:
    telemetry = attempt.get("telemetry")
    if telemetry_errors(telemetry, per_attempt=True):
        return "qualification_stopped_invalid_telemetry"
    unknown = telemetry.get("unknown_cost_api_calls") if isinstance(telemetry, dict) else None
    if (
        not allow_unknown_costs
        and isinstance(unknown, int)
        and not isinstance(unknown, bool)
        and unknown > 0
    ):
        _append_attempt_reason(attempt, "controller_cost_telemetry_unknown")
        return "qualification_stopped_unknown_cost"
    return None


def _known_cost(attempts: list[dict[str, object]]) -> float:
    usage = aggregate_telemetry(attempts)
    value = usage.get("known_cost_usd")
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0


def _run_qualification_readiness(
    *,
    args: argparse.Namespace,
    output_root: Path,
    runtime_home: Path,
    release_tree_sha256: str | None,
    controller_config_sha256: str | None,
    qualification_contract: Mapping[str, object],
) -> dict[str, object]:
    """Run the dedicated, two-probe readiness state machine without aggregation."""
    if (
        args.pairs is not None
        or args.repetitions is not None
        or args.max_steps_per_episode is not None
        or args.release_approval is not None
        or args.expected_release_approval_sha256 is not None
        or args.max_api_calls != ABSOLUTE_API_CALL_CEILING_PER_ROUTE
    ):
        raise ValueError("qualification_readiness_arguments_invalid")
    try:
        contract = validate_qualification_contract(qualification_contract)
    except ValueError as exc:
        raise ValueError("qualification_execution_contract_invalid") from exc
    registry = load_registry(ROOT / "cases.json")
    registry_cases = {
        str(case.get("case_id")): case
        for case in registry["cases"]
        if isinstance(case, dict)
    }
    for probe in qualification_probe_definitions():
        case = registry_cases.get(str(probe["case_id"]))
        if not isinstance(case, dict) or (
            case.get("pair_id") != probe["pair_id"]
            or case.get("variant") != probe["variant"]
        ):
            raise ValueError("qualification_case_registry_invalid")

    attempts: list[dict[str, object]] = []
    stopped_before_probe: str | None = None
    probes = qualification_probe_definitions()
    # First-attempt phase is deliberately complete before retry selection.
    for probe in probes:
        attempt = _run_qualification_attempt(
            args=args,
            probe=probe,
            attempt_number=1,
            output_root=output_root,
            runtime_home=runtime_home,
            known_cost_so_far=_known_cost(attempts),
        )
        attempts.append(attempt)
        stopped_before_probe = _qualification_stop_reason(
            attempt, allow_unknown_costs=args.allow_unknown_costs
        )
        if stopped_before_probe is not None:
            break
    # Never revisit a completed/healthy probe. A second attempt is legal only
    # when its own sealed first attempt has an exact typed transient reason.
    if stopped_before_probe is None and len(attempts) == len(probes):
        first_by_probe = {str(row["probe_id"]): row for row in attempts}
        for probe in probes:
            first = first_by_probe[str(probe["probe_id"])]
            if not retry_eligible(first):
                continue
            retry = _run_qualification_attempt(
                args=args,
                probe=probe,
                attempt_number=2,
                output_root=output_root,
                runtime_home=runtime_home,
                known_cost_so_far=_known_cost(attempts),
            )
            attempts.append(retry)
            stopped_before_probe = _qualification_stop_reason(
                retry, allow_unknown_costs=args.allow_unknown_costs
            )
            if stopped_before_probe is not None:
                break
    report = build_qualification_report(
        qualification_contract=contract,
        requested_route=f"{args.provider}/{args.model}",
        reasoning_effort=args.reasoning_effort,
        release_tree_sha256=release_tree_sha256,
        controller_config_sha256=controller_config_sha256,
        created_at=datetime.now(timezone.utc).isoformat(),
        attempts=attempts,
        stopped_before_probe=stopped_before_probe,
    )
    report_path = output_root / "suite-report.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    headline_path = output_root / "HEADLINE.txt"
    headline_path.write_text(str(report["headline"]) + "\n", encoding="utf-8")
    seal_path, seal_sha256 = write_suite_seal(
        output_root,
        release_manifest=ROOT / "RELEASE_MANIFEST.json",
    )
    child_result: dict[str, object] = {
        "schema": QUALIFICATION_CHILD_RESULT_SCHEMA,
        "readiness": report["readiness"],
        "reason_codes": report["reason_codes"],
        "controller_usage": report["controller_usage"],
        "suite_report_path": str(report_path),
        "suite_seal_path": str(seal_path),
        "suite_seal_sha256": seal_sha256,
    }
    return validate_child_result(child_result)


def _run_authoritative_full_stage(
    *,
    args: argparse.Namespace,
    output_root: Path,
    runtime_home: Path,
    release_tree_sha256: str,
    release_approval_sha256: str | None,
    release_authorized: bool,
    authorization: Mapping[str, object],
) -> int:
    """Execute the sole full-stage authority tuple reconstructed from PLAN."""
    if (
        args.pairs is not None
        or args.repetitions is not None
        or args.max_steps_per_episode is not None
        or args.max_api_calls != FULL_API_CALL_CEILING_PER_ROUTE
    ):
        raise ValueError("authoritative_full_arguments_invalid")
    contract_value = authorization.get("contract")
    if not isinstance(contract_value, Mapping):
        raise ValueError("authoritative_full_execution_contract_invalid")
    planned_count = contract_value.get("planned_route_count")
    if not isinstance(planned_count, int) or isinstance(planned_count, bool):
        raise ValueError("authoritative_full_execution_contract_invalid")
    try:
        full_plan = validate_authoritative_full_stage_plan(
            contract_value, route_count=planned_count
        )
    except ValueError as exc:
        raise ValueError("authoritative_full_execution_contract_invalid") from exc
    registry = load_registry(ROOT / "cases.json")
    all_cases = [case for case in registry["cases"] if isinstance(case, dict)]
    selected_cases = [
        case for case in all_cases if str(case.get("pair_id")) in AUTHORITATIVE_FULL_PAIR_IDS
    ]
    selected_cases.sort(
        key=lambda case: (
            AUTHORITATIVE_FULL_PAIR_IDS.index(str(case["pair_id"])),
            0 if case["variant"] == "approved" else 1,
            str(case["case_id"]),
        )
    )
    expected_case_shape = [
        (pair_id, variant)
        for pair_id in AUTHORITATIVE_FULL_PAIR_IDS
        for variant in ("approved", "prohibited")
    ]
    if [
        (str(case.get("pair_id")), str(case.get("variant"))) for case in selected_cases
    ] != expected_case_shape:
        raise ValueError("authoritative_full_case_registry_invalid")
    args.repetitions = FULL_REPETITIONS
    observations = _run_observations(
        args=args,
        selected_cases=selected_cases,
        output_root=output_root,
        runtime_home=runtime_home,
        authoritative_full=True,
    )
    route_id = authorization.get("route_id")
    output_relative_path = authorization.get("output_relative_path")
    plan_sha256 = authorization.get("plan_sha256")
    execution_contract_sha256 = authorization.get("execution_contract_sha256")
    if not all(
        isinstance(value, str) and value
        for value in (route_id, output_relative_path, plan_sha256, execution_contract_sha256)
    ):
        raise ValueError("authoritative_full_execution_contract_invalid")
    binding = build_authoritative_stage_binding(
        plan_sha256=str(plan_sha256),
        execution_contract_sha256=str(execution_contract_sha256),
        route_id=str(route_id),
        output_relative_path=str(output_relative_path),
        full_plan=full_plan,
        route_count=planned_count,
    )
    report = aggregate_suite_observations(
        observations,
        requested_route=f"{args.provider}/{args.model}",
        reasoning_effort=args.reasoning_effort,
        controller_config_sha256=(
            str(observations[0].get("controller_config_sha256")) if observations else None
        ),
        release_tree_sha256=release_tree_sha256,
        release_approval_sha256=release_approval_sha256,
        release_authorized=bool(release_authorized),
        repetitions=FULL_REPETITIONS,
        pair_ids=list(AUTHORITATIVE_FULL_PAIR_IDS),
        case_ids_by_pair=_case_ids_by_pair(selected_cases),
        authoritative_stage=binding,
    )
    report["created_at"] = datetime.now(timezone.utc).isoformat()
    report["output_root"] = str(output_root)
    report_path = output_root / "suite-report.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    (output_root / "HEADLINE.txt").write_text(str(report["headline"]) + "\n", encoding="utf-8")
    seal_path, seal_sha256 = write_suite_seal(
        output_root,
        release_manifest=ROOT / "RELEASE_MANIFEST.json",
    )
    print(str(report_path), flush=True)
    print(str(report["headline"]), flush=True)
    print(f"SUITE_SEAL={seal_path}", flush=True)
    print(f"SUITE_SEAL_SHA256={seal_sha256}", flush=True)
    return 0 if len(observations) == 80 else 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run OAB v2 multi-rep matched-pair suite for one provider/model into an "
            "external output root and write suite-report.json."
        )
    )
    parser.add_argument("--model", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument(
        "--reasoning-effort",
        required=True,
        choices=("none", "minimal", "low", "medium", "high", "xhigh"),
        help="Pin and attest the Hermes reasoning effort for every model turn",
    )
    parser.add_argument(
        "--source-hermes-home",
        type=Path,
        default=None,
        help="Hermes home providing config/auth (default: HERMES_HOME or ~/.hermes)",
    )
    parser.add_argument(
        "--pairs",
        default=None,
        help="Comma-separated pair ids (default: all registry pairs)",
    )
    parser.add_argument(
        "--repetitions",
        type=int,
        default=None,
        help="Repetitions per case (default: registry default_repetitions, usually 5)",
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--output-parent-fd", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--output-name", default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--max-observed-cost-usd",
        type=float,
        default=None,
        help=(
            "Stop before the next provider turn once known billed cost reaches this "
            "threshold; a charge revealed only after a call can overshoot by that one call"
        ),
    )
    parser.add_argument(
        "--allow-unknown-costs",
        action="store_true",
        help="Continue after unpriced calls; otherwise stop after the first unpriced call",
    )
    parser.add_argument(
        "--release-approval",
        type=Path,
        default=None,
        help="Externally reviewed oab.release-approval/v1 receipt",
    )
    parser.add_argument(
        "--expected-release-approval-sha256",
        default=None,
        help="Externally published sha256: digest of --release-approval",
    )
    parser.add_argument("--timeout-seconds", type=float, default=240.0)
    parser.add_argument("--episode-timeout-seconds", type=float, default=30.0)
    parser.add_argument(
        "--max-steps-per-episode",
        type=int,
        default=None,
        help="Never allow more than this many broker/controller steps in one episode",
    )
    parser.add_argument(
        "--max-api-calls",
        type=int,
        default=None,
        help="Hard ceiling on provider calls across this suite",
    )
    parser.add_argument(
        "--qualification-readiness-v1",
        action="store_true",
        help="Run the locked score-free oab.qualification-readiness/v1 child mode",
    )
    parser.add_argument(
        "--qualification-contract-json",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--authoritative-full-v1", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--campaign-root-path", type=Path, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--campaign-root-fd", type=int, default=None, help=argparse.SUPPRESS)

    args = parser.parse_args(argv)

    protected_stage: str | None = None
    if args.qualification_readiness_v1 and args.authoritative_full_v1:
        raise SystemExit("campaign_child_mode_ambiguous")
    if args.qualification_readiness_v1:
        protected_stage = "qualification"
    elif args.authoritative_full_v1:
        protected_stage = "full"

    if args.qualification_readiness_v1 and (
        args.release_approval is not None
        or args.expected_release_approval_sha256 is not None
    ):
        raise SystemExit("qualification readiness mode does not accept release approval")
    if protected_stage is not None:
        if args.qualification_contract_json is not None:
            raise SystemExit("campaign_child_contract_argv_refused")
        if (
            args.campaign_root_path is None
            or args.campaign_root_fd is None
            or args.output_parent_fd is None
            or args.output_name is None
        ):
            raise SystemExit("campaign_child_contract_required")
        if protected_stage == "full" and (
            args.pairs is not None
            or args.repetitions is not None
            or args.max_steps_per_episode is not None
        ):
            raise SystemExit("authoritative_full_arguments_invalid")
        try:
            child_authorization = verify_campaign_child_contract(
                stage=protected_stage,
                campaign_root_path=args.campaign_root_path,
                campaign_root_fd=args.campaign_root_fd,

                output_parent_fd=args.output_parent_fd,
                requested_route=f"{args.provider}/{args.model}",
                reasoning_effort=args.reasoning_effort,
                output_name=str(args.output_name),
                max_api_calls=args.max_api_calls,
                max_observed_cost_usd=args.max_observed_cost_usd,
                allow_unknown_costs=args.allow_unknown_costs,
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    else:
        child_authorization = None

    # The protected child has now reconstructed its signed campaign authority.
    # Only after that boundary may it inspect repository release state or create
    # output directories; no controller/runtime is constructed above this point.
    release_manifest_path = ROOT / "RELEASE_MANIFEST.json"
    release_errors = verify_release_manifest(ROOT, release_manifest_path)
    if release_errors:
        raise SystemExit(
            "release manifest verification failed: " + ",".join(release_errors)
        )
    release_tree_sha256 = json.loads(
        release_manifest_path.read_text(encoding="utf-8")
    ).get("tree_sha256")
    if (
        child_authorization is not None
        and child_authorization.get("release_tree_sha256") != release_tree_sha256
    ):
        raise SystemExit("campaign_child_release_tree_invalid")
    approval_args = (
        args.release_approval is not None,
        args.expected_release_approval_sha256 is not None,
    )
    if approval_args[0] != approval_args[1]:
        raise SystemExit(
            "--release-approval and --expected-release-approval-sha256 are required together"
        )
    release_approval_sha256: str | None = None
    release_authorized = False
    if args.release_approval is not None:
        if not isinstance(release_tree_sha256, str):
            raise SystemExit("release manifest tree digest is invalid")
        approval = verify_release_approval(
            args.release_approval,
            expected_release_tree_sha256=release_tree_sha256,
            expected_file_sha256=args.expected_release_approval_sha256,
        )
        if approval.get("valid") is not True:
            errors = approval.get("errors")
            rendered = (
                ",".join(str(code) for code in errors)
                if isinstance(errors, list)
                else "invalid"
            )
            raise SystemExit("release approval verification failed: " + rendered)
        release_approval_sha256 = str(approval["file_sha256"])
        release_authorized = True
    if protected_stage == "full" and not release_authorized:
        # Exploratory full may run without a release approval. Decision/switch
        # authority still requires an independently pinned release approval.
        pass

    if (args.output_parent_fd is None) != (args.output_name is None):
        raise SystemExit("internal output descriptor and name are required together")
    if args.output_parent_fd is not None:
        if os.name != "posix":
            raise SystemExit("descriptor-bound output is unavailable on this platform")
        output_name = str(args.output_name)
        if (
            not re.fullmatch(r"[0-9a-f]{32}\.evidence", output_name)
            or args.output_parent_fd < 0
        ):
            raise SystemExit("descriptor-bound output name is invalid")
        try:
            parent_info = os.fstat(args.output_parent_fd)
            if not stat.S_ISDIR(parent_info.st_mode):
                raise OSError("output parent is not a directory")
            os.fchdir(args.output_parent_fd)
            parent_path = Path.cwd().resolve()
            if (
                parent_path == ROOT
                or parent_path.is_relative_to(ROOT)
                or ROOT.is_relative_to(parent_path)
            ):
                raise SystemExit(
                    "output root and benchmark repository must be fully disjoint"
                )
            os.mkdir(output_name, 0o700, dir_fd=args.output_parent_fd)
            output_fd = os.open(
                output_name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=args.output_parent_fd,
            )
            os.fchdir(output_fd)
            os.close(output_fd)
        except OSError as exc:
            raise SystemExit("descriptor-bound output creation failed") from exc
        output_root = Path(".")
    else:
        output_root = args.output_root.resolve()
        if output_root == ROOT or output_root.is_relative_to(ROOT) or ROOT.is_relative_to(output_root):
            raise SystemExit("output root and benchmark repository must be fully disjoint")
        output_root.mkdir(parents=True, exist_ok=False)
    if release_authorized and args.release_approval is not None:
        shutil.copyfile(args.release_approval, output_root / "RELEASE_APPROVAL.json")

    if args.qualification_readiness_v1:
        if not isinstance(release_tree_sha256, str):
            raise SystemExit("release manifest tree digest is invalid")
        try:
            with pinned_hermes_runtime(
                args.reasoning_effort,
                source_home=args.source_hermes_home,
            ) as runtime:
                child_result = _run_qualification_readiness(
                    args=args,
                    output_root=output_root,
                    runtime_home=runtime.home,
                    release_tree_sha256=release_tree_sha256,
                    controller_config_sha256=runtime.config_sha256,
                    qualification_contract=(
                        child_authorization["contract"]
                        if child_authorization is not None
                        and isinstance(child_authorization.get("contract"), Mapping)
                        else {}
                    ),
                )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        # One machine-readable, score-free output boundary. No progress or generic
        # aggregation text is emitted by this mode.
        print(json.dumps(child_result, sort_keys=True, separators=(",", ":")), flush=True)
        return 0

    if args.authoritative_full_v1:
        if (
            not isinstance(release_tree_sha256, str)
            or child_authorization is None
        ):
            raise SystemExit("authoritative_full_execution_contract_invalid")
        try:
            with pinned_hermes_runtime(
                args.reasoning_effort,
                source_home=args.source_hermes_home,
            ) as runtime:
                return _run_authoritative_full_stage(
                    args=args,
                    output_root=output_root,
                    runtime_home=runtime.home,
                    release_tree_sha256=release_tree_sha256,
                    release_approval_sha256=release_approval_sha256,
                    release_authorized=release_authorized,
                    authorization=child_authorization,
                )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc

    registry = load_registry(ROOT / "cases.json")
    all_cases = list(registry["cases"])
    available_pairs = sorted({str(case["pair_id"]) for case in all_cases})
    pair_ids = _parse_pairs(args.pairs, available_pairs)
    repetitions = args.repetitions
    if repetitions is None:
        repetitions = int(registry["benchmark"]["default_repetitions"])
    if repetitions < 1:
        raise SystemExit("repetitions must be >= 1")

    selected_cases = [case for case in all_cases if str(case["pair_id"]) in set(pair_ids)]
    # Stable order: pair registry order, approved before prohibited, then case_id.
    selected_cases.sort(
        key=lambda case: (
            pair_ids.index(str(case["pair_id"])),
            0 if case["variant"] == "approved" else 1,
            str(case["case_id"]),
        )
    )
    args.repetitions = repetitions
    case_map = _case_ids_by_pair(selected_cases)

    with pinned_hermes_runtime(
        args.reasoning_effort,
        source_home=args.source_hermes_home,
    ) as runtime:
        observations = _run_observations(
            args=args,
            selected_cases=selected_cases,
            output_root=output_root,
            runtime_home=runtime.home,
        )
        runtime_config_sha256 = runtime.config_sha256

    report = aggregate_suite_observations(
        observations,
        requested_route=f"{args.provider}/{args.model}",
        reasoning_effort=args.reasoning_effort,
        controller_config_sha256=runtime_config_sha256,
        release_tree_sha256=(
            release_tree_sha256 if isinstance(release_tree_sha256, str) else None
        ),
        release_approval_sha256=release_approval_sha256,
        release_authorized=release_authorized,
        repetitions=repetitions,
        pair_ids=pair_ids,
        case_ids_by_pair=case_map,
    )
    report["created_at"] = datetime.now(timezone.utc).isoformat()
    report["output_root"] = str(output_root)


    report_path = output_root / "suite-report.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    headline_path = output_root / "HEADLINE.txt"
    headline_path.write_text(str(report["headline"]) + "\n", encoding="utf-8")
    seal_path, seal_sha256 = write_suite_seal(
        output_root,
        release_manifest=release_manifest_path,
    )
    print(str(report_path), flush=True)
    print(str(report["headline"]), flush=True)
    print(f"SUITE_SEAL={seal_path}", flush=True)
    print(f"SUITE_SEAL_SHA256={seal_sha256}", flush=True)

    # Exit status reflects benchmark infrastructure coverage, never model quality.
    if int(report["infrastructure_valid_episodes"]) != int(report["scheduled_episodes"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
