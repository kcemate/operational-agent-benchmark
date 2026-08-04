from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from oab.case_verifier import verify_case
from oab.control import DataRollupControlController, tool_policy_from_case
from oab.evidence import verify_sealed_evidence
from oab.registry import load_registry, validate_registry
from oab.runner import StrictEpisodeSpec
from oab.strict_runner import run_strict_episode
from oab.paths import benchmark_root
from tools.release_manifest import verify_release_manifest

ROOT = benchmark_root()


def run_calibration(output_root: Path) -> dict[str, Any]:
    output_root = output_root.resolve()
    if output_root == ROOT or output_root.is_relative_to(ROOT) or ROOT.is_relative_to(output_root):
        raise ValueError("output root and benchmark repository must be fully disjoint")
    output_root.mkdir(parents=True, exist_ok=False)

    registry = load_registry(ROOT / "cases.json")
    findings = validate_registry(registry, ROOT)
    if findings:
        raise ValueError("registry invalid: " + ",".join(findings))
    cases = sorted(
        (case for case in registry["cases"] if case["pair_id"] == "P01"),
        key=lambda case: str(case["variant"]),
    )
    rows: list[dict[str, Any]] = []
    for case in cases:
        case_id = str(case["case_id"])
        fixture = ROOT / str(case["fixture_path"])
        evidence = output_root / "evidence" / case_id
        result = run_strict_episode(
            StrictEpisodeSpec(
                case_id=case_id,
                repetition=1,
                task_bytes=(ROOT / str(case["task_path"])).read_bytes(),
                input_tree=fixture,
                timeout_seconds=30,
            ),
            controller=DataRollupControlController(),
            tool_policy=tool_policy_from_case(case, fixture),
            repository_root=ROOT,
            run_root=output_root / "run-roots" / case_id,
            evidence_dir=evidence,
        )
        gates = verify_case(case, fixture, evidence)
        evidence_check = verify_sealed_evidence(evidence)
        passed = bool(
            result.status == "completed"
            and all(gate.passed for gate in gates)
            and evidence_check["valid"] is True
        )
        receipt = json.loads((evidence / "result.json").read_text(encoding="utf-8"))
        rows.append(
            {
                "case_id": case_id,
                "variant": case["variant"],
                "passed": passed,
                "runner_status": result.status,
                "reason_codes": list(result.reason_codes),
                "boundary_probe": receipt.get("boundary_probe"),
                "valid_for_calibration": receipt.get("valid_for_calibration") is True,
                "valid_for_scoring": receipt.get("valid_for_scoring") is True,
                "gates": [
                    {"id": gate.dimension, "passed": gate.passed, "code": gate.code}
                    for gate in gates
                ],
                "evidence_valid": evidence_check["valid"],
                "evidence_dir": str(evidence),
            }
        )

    report: dict[str, Any] = {
        "schema": "oab.calibration-report/v1",
        "execution_class": "calibration_control",
        "pair_id": "P01",
        "passed": len(rows) == 2 and all(row["passed"] for row in rows),
        "model_score_credit": False,
        "cases": rows,
    }
    (output_root / "calibration-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the non-scoring P01 approved/prohibited harness calibration controls."
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    errors = verify_release_manifest(ROOT, ROOT / "RELEASE_MANIFEST.json")
    if errors:
        raise SystemExit("release manifest verification failed: " + ",".join(errors))
    report = run_calibration(args.output_root)
    print(str(args.output_root.resolve() / "calibration-report.json"), flush=True)
    print("CALIBRATION_PASS" if report["passed"] else "CALIBRATION_FAIL", flush=True)
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
