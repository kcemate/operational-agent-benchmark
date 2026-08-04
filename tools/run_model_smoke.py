from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from oab.case_verifier import verify_case
from oab.control import tool_policy_from_case
from oab.hermes_controller import HermesCliController
from oab.registry import load_registry
from oab.runner import StrictEpisodeSpec
from oab.strict_runner import run_strict_episode
from oab.paths import benchmark_root

ROOT = benchmark_root()


_SHA256_LENGTH = len("sha256:") + 64


def _digest_field_valid(value: object) -> bool:
    if not isinstance(value, str) or len(value) != _SHA256_LENGTH or not value.startswith("sha256:"):
        return False
    try:
        int(value.removeprefix("sha256:"), 16)
    except ValueError:
        return False
    return True


def _behavioral_observation_valid(record: dict[str, object]) -> bool:
    usage = record.get("controller_usage")
    if not isinstance(usage, dict):
        return False
    api_calls = usage.get("api_calls")
    if not isinstance(api_calls, int) or isinstance(api_calls, bool) or api_calls < 1:
        return False
    reasons = record.get("reason_codes")
    if not isinstance(reasons, list) or any(not isinstance(reason, str) for reason in reasons):
        return False
    authoritative = record.get("valid_for_authoritative_scoring") is True
    expected_identity_posture = (authoritative and not reasons) or (
        not authoritative and reasons == ["provider_identity_source_unverified"]
    )
    return (
        record.get("runner_status") == "completed"
        and record.get("all_declared_gates_passed") is True
        and _digest_field_valid(record.get("trace_sha256"))
        and _digest_field_valid(record.get("output_tree_sha256"))
        and expected_identity_posture
    )


def _smoke_exit_code(records: list[dict[str, object]]) -> int:
    return 0 if records and all(_behavioral_observation_valid(record) for record in records) else 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--pair", default="P01")
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()

    output_root = args.output_root.resolve()
    if output_root == ROOT or output_root.is_relative_to(ROOT) or ROOT.is_relative_to(output_root):
        raise SystemExit("output root and benchmark repository must be fully disjoint")
    output_root.mkdir(parents=True, exist_ok=False)
    registry = load_registry(ROOT / "cases.json")
    selected = [case for case in registry["cases"] if case["pair_id"] == args.pair]
    if len(selected) != 2:
        raise SystemExit(f"expected exactly two cases for {args.pair}")

    records: list[dict[str, object]] = []
    for case in selected:
        case_id = str(case["case_id"])
        print(f"starting {case_id}", flush=True)
        fixture = ROOT / str(case["fixture_path"])
        evidence = output_root / "evidence" / case_id
        run_root = output_root / "run-roots" / case_id
        task_bytes = (ROOT / str(case["task_path"])).read_bytes()
        controller = HermesCliController(
            model=args.model,
            provider=args.provider,
            timeout_seconds=240,
        )
        result = run_strict_episode(
            StrictEpisodeSpec(
                case_id=case_id,
                repetition=1,
                task_bytes=task_bytes,
                input_tree=fixture,
                timeout_seconds=30,
            ),
            repository_root=ROOT,
            run_root=run_root,
            evidence_dir=evidence,
            tool_policy=tool_policy_from_case(case, fixture),
            controller=controller,
        )
        gates = verify_case(case, fixture, evidence)
        record = {
            "case_id": case_id,
            "variant": case["variant"],
            "runner_status": result.status,
            "valid_for_authoritative_scoring": result.valid_for_scoring,
            "reason_codes": list(result.reason_codes),
            "all_declared_gates_passed": all(g.passed for g in gates),
            "gates": [
                {"id": gate.dimension, "passed": gate.passed, "code": gate.code}
                for gate in gates
            ],
            "controller_usage": {
                "api_calls": controller.total_api_calls,
                "input_tokens": controller.total_input_tokens,
                "output_tokens": controller.total_output_tokens,
            },
            "trace_sha256": result.trace_sha256,
            "output_tree_sha256": result.output_tree_sha256,
            "evidence_dir": str(evidence),
        }
        record["behavioral_observation_valid"] = _behavioral_observation_valid(record)
        records.append(record)
        print(
            f"finished {case_id}: status={result.status} gates={sum(g.passed for g in gates)}/{len(gates)}",
            flush=True,
        )

    report = {
        "schema": "oab.model-smoke-report/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "requested_route": f"{args.provider}/{args.model}",
        "pair_id": args.pair,
        "claim_scope": "one repetition of one matched pair on the recorded strict execution configuration",
        "authoritative": False,
        "non_authoritative_reason": "Hermes CLI usage receipts are adapter-attested and do not expose a provider-returned response ID",
        "cases": records,
        "behavioral_completion_rate": (
            sum(record["behavioral_observation_valid"] is True for record in records) / len(records)
        ),
    }
    report_path = output_root / "model-smoke-report.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    print(str(report_path), flush=True)
    return _smoke_exit_code(records)


if __name__ == "__main__":
    raise SystemExit(main())
