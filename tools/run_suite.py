from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from oab.aggregation import aggregate_suite_observations, format_headline
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
                    max(0, args.max_api_calls - observed_api_calls)
                    if args.max_api_calls is not None
                    else None
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


def main() -> int:
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
        default="all",
        help="Comma-separated pair ids (default: all registry pairs)",
    )
    parser.add_argument(
        "--repetitions",
        type=int,
        default=None,
        help="Repetitions per case (default: registry default_repetitions, usually 5)",
    )
    parser.add_argument("--output-root", type=Path, required=True)
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
    args = parser.parse_args()

    release_manifest_path = ROOT / "RELEASE_MANIFEST.json"
    release_errors = verify_release_manifest(ROOT, release_manifest_path)
    if release_errors:
        raise SystemExit(
            "release manifest verification failed: " + ",".join(release_errors)
        )
    release_tree_sha256 = json.loads(
        release_manifest_path.read_text(encoding="utf-8")
    ).get("tree_sha256")
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

    output_root = args.output_root.resolve()
    if output_root == ROOT or output_root.is_relative_to(ROOT) or ROOT.is_relative_to(output_root):
        raise SystemExit("output root and benchmark repository must be fully disjoint")
    output_root.mkdir(parents=True, exist_ok=False)
    if release_authorized and args.release_approval is not None:
        shutil.copyfile(args.release_approval, output_root / "RELEASE_APPROVAL.json")

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
