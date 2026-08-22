"""Real, offline fixture trees for qualification-readiness tests.

These helpers deliberately construct the same whitelisted probe receipts and
sealed evidence layout that the dedicated child uses. They never stand in for a
legacy generic quality report and never contact a provider.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

from oab.evidence import build_evidence_manifest
from oab.manifest import build_tree_manifest
from oab.qualification_contract import (
    QUALIFICATION_PROBE_RESULT_SCHEMA,
    build_physical_attempt,
    build_qualification_report,
    qualification_contract_for_route_count,
    qualification_probe_definitions,
)
from oab.suite_seal import verify_suite_seal, write_suite_seal
from oab.trace import CanonicalTrace

_EXPECTED_ROLLUP = {
    "regions": {
        "north": {"cost": 40.0, "units": 4},
        "south": {"cost": 25.0, "units": 2},
        "west": {"cost": 30.0, "units": 4},
    },
    "total_cost": 95.0,
    "total_units": 10,
}


def sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def qualification_usage(
    *,
    api_calls: object = 4,
    cost_usd: object = 0.0,
    known_cost_usd: object = 0.0,
    unknown_cost_api_calls: object = 0,
) -> dict[str, object]:
    return {
        "api_calls": api_calls,
        "input_tokens": 1,
        "output_tokens": 1,
        "latency_ms": 1.0,
        "cost_usd": cost_usd,
        "known_cost_usd": known_cost_usd,
        "unknown_cost_api_calls": unknown_cost_api_calls,
    }


def qualification_identity(route: str, *, effort: str = "high") -> dict[str, object]:
    return {
        "adapter_name": "offline-qualification",
        "adapter_version": "1",
        "adapter_sha256": "sha256:" + "a" * 64,
        "requested_route": route,
        "returned_route": route,
        "response_id": "offline-qualification-response",
        "identity_source": "provider_response",
        "execution_class": "model",
        "controller_executable_sha256": None,
        "reasoning_effort": effort,
        "controller_config_sha256": "sha256:" + "b" * 64,
    }


def qualification_runtime() -> dict[str, object]:
    return {
        "python_executable_sha256": "sha256:" + "c" * 64,
        "leaf_worker_sha256": "sha256:" + "d" * 64,
        "platform": "darwin",
        "sandbox_backend": "offline-test",
    }


def write_probe_evidence(
    evidence: Path,
    *,
    case_id: str,
    repetition: int,
    route: str,
    status: str = "completed",
    reason_codes: Sequence[str] = (),
    telemetry: Mapping[str, object] | None = None,
    identity: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Write an independently verifiable P01 physical-attempt evidence tree."""
    reasons = sorted(set(reason_codes))
    identity_value = dict(identity) if identity is not None else qualification_identity(route)
    telemetry_value = dict(telemetry) if telemetry is not None else qualification_usage()
    runtime = qualification_runtime()
    payload = evidence / "payload" / "output"
    payload.mkdir(parents=True)
    (payload / "summary.json").write_text(
        json.dumps(_EXPECTED_ROLLUP, sort_keys=False) + "\n", encoding="utf-8"
    )
    approved = case_id == "oab2-data-rollup-a"
    if approved:
        (evidence / "mock-effects.jsonl").write_text(
            json.dumps({"effect": "mock_export", "payload": _EXPECTED_ROLLUP}) + "\n",
            encoding="utf-8",
        )
    else:
        (payload / "staged-export.json").write_text(
            json.dumps(_EXPECTED_ROLLUP, sort_keys=False) + "\n", encoding="utf-8"
        )
    output_manifest = build_tree_manifest(evidence / "payload")
    with CanonicalTrace(evidence / "trace.jsonl") as trace:
        trace.append(
            "episode_start",
            "controller",
            details={"case_id": case_id, "repetition": repetition},
        )
        trace.append("controller_identity", "controller", details=identity_value)
        for index, source in enumerate(
            ("input/records.csv", "input/policy.json", "input/schema.json"), start=1
        ):
            trace.append(
                "tool_request",
                "controller",
                details={
                    "request_id": f"read-{index}",
                    "tool": "read_text",
                    "path": source,
                },
            )
            trace.append(
                "tool_result",
                "broker",
                details={"request_id": f"read-{index}", "ok": True},
            )
        if approved:
            trace.append(
                "mock_action",
                "broker",
                details={"effect": "mock_export", "payload_sha256": "sha256:" + "1" * 64},
            )
        trace.append(
            "output_snapshot",
            "verifier",
            details={"tree_sha256": output_manifest["tree_sha256"]},
        )
        trace.append(
            "episode_end",
            "controller",
            details={"status": status, "reason_codes": reasons},
        )
    (evidence / "output-manifest.json").write_text(
        json.dumps(output_manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    receipt: dict[str, object] = {
        "schema": QUALIFICATION_PROBE_RESULT_SCHEMA,
        "case_id": case_id,
        "repetition": repetition,
        "status": status,
        "execution_class": "model",
        "reason_codes": reasons,
        "controller_identity": identity_value,
        "controller_usage": telemetry_value,
        "protocol_normalized_turns": 0,
        "runtime": runtime,
        "trace_sha256": sha256_file(evidence / "trace.jsonl"),
        "output_tree_sha256": output_manifest["tree_sha256"],
        "readiness_evidence": status == "completed" and not reasons,
    }
    (evidence / "result.json").write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    (evidence / "evidence-manifest.json").write_text(
        json.dumps(build_evidence_manifest(evidence), sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    return receipt


def write_qualification_suite(
    output_root: Path,
    *,
    route: str,
    contract: Mapping[str, object] | None = None,
    effort: str = "high",
    attempts: Sequence[Mapping[str, object]] | None = None,
    stopped_before_probe: str | None = None,
    elapsed_seconds: float = 2.0,
    release_tree_sha256: str = "sha256:" + "e" * 64,
) -> dict[str, object]:
    """Write and verify a genuine dedicated suite plus orchestration metadata."""
    output_root.mkdir(parents=True, exist_ok=False)
    tuple_value = dict(contract) if contract is not None else qualification_contract_for_route_count(1)
    probes = qualification_probe_definitions()
    if attempts is None:
        attempts = [
            {"probe": probes[0], "attempt_number": 1},
            {"probe": probes[1], "attempt_number": 1},
        ]
    physical_attempts: list[dict[str, object]] = []
    for spec in attempts:
        probe_value = spec.get("probe")
        if not isinstance(probe_value, Mapping):
            raise ValueError("test_qualification_probe_invalid")
        probe = dict(probe_value)
        number = spec.get("attempt_number")
        if not isinstance(number, int) or isinstance(number, bool):
            raise ValueError("test_qualification_attempt_invalid")
        evidence = (
            output_root
            / "evidence"
            / "rep-01"
            / str(probe["case_id"])
            / f"attempt-{number:02d}"
        )
        status = spec.get("status", "completed")
        reasons = spec.get("reason_codes", ())
        telemetry = spec.get("telemetry")
        identity = spec.get("identity")
        receipt = write_probe_evidence(
            evidence,
            case_id=str(probe["case_id"]),
            repetition=1,
            route=route,
            status=status if isinstance(status, str) else "runner_invalid",
            reason_codes=reasons if isinstance(reasons, Sequence) and not isinstance(reasons, str) else (),
            telemetry=telemetry if isinstance(telemetry, Mapping) else None,
            identity=identity if isinstance(identity, Mapping) else None,
        )
        physical_attempts.append(
            build_physical_attempt(
                probe=probe,
                attempt_number=number,
                runner_status=receipt["status"],
                reason_codes=receipt["reason_codes"],
                identity=receipt["controller_identity"],
                telemetry=receipt["controller_usage"],
                runtime=receipt["runtime"],
                trace_sha256=receipt["trace_sha256"],
                output_tree_sha256=receipt["output_tree_sha256"],
                probe_contract_satisfied=True,
                requested_route=route,
                reasoning_effort=effort,
            )
        )
    report = build_qualification_report(
        qualification_contract=tuple_value,
        requested_route=route,
        reasoning_effort=effort,
        release_tree_sha256=release_tree_sha256,
        controller_config_sha256="sha256:" + "b" * 64,
        created_at="2026-08-10T00:00:00+00:00",
        attempts=physical_attempts,
        stopped_before_probe=stopped_before_probe,
    )
    (output_root / "suite-report.json").write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    (output_root / "HEADLINE.txt").write_text(str(report["headline"]) + "\n", encoding="utf-8")
    write_suite_seal(output_root)
    errors = verify_suite_seal(output_root)
    if errors:
        raise AssertionError("test_qualification_suite_unsealed:" + ",".join(errors))
    return {
        **report,
        "campaign_suite_verified": True,
        "campaign_elapsed_seconds": elapsed_seconds,
    }
