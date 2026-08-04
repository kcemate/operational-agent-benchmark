from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .aggregation import aggregate_suite_observations
from .case_verifier import verify_case
from .evidence import verify_sealed_evidence
from .manifest import ManifestError, build_tree_manifest
from .paths import benchmark_root
from .release_approval import verify_release_approval
from .registry import load_registry

_SCHEMA = "oab.suite-seal/v1"
_SEAL_NAME = "SUITE_SEAL.json"


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"not_json_object:{path.name}")
    return value


def _suite_grid(
    report: Mapping[str, object],
) -> tuple[list[tuple[int, dict[str, object]]], dict[str, dict[str, str]]]:
    repetitions = report.get("repetitions")
    pair_ids = report.get("pair_ids")
    if (
        not isinstance(repetitions, int)
        or isinstance(repetitions, bool)
        or repetitions < 1
        or not isinstance(pair_ids, list)
        or not pair_ids
        or any(not isinstance(pair_id, str) or not pair_id for pair_id in pair_ids)
        or len(set(pair_ids)) != len(pair_ids)
    ):
        raise ValueError("suite_grid_metadata_invalid")

    registry_root = benchmark_root()
    registry = load_registry(registry_root / "cases.json")
    selected = [
        dict(case)
        for case in registry["cases"]
        if str(case["pair_id"]) in set(pair_ids)
    ]
    case_map: dict[str, dict[str, str]] = {}
    by_case: dict[str, dict[str, object]] = {}
    for case in selected:
        pair_id = str(case["pair_id"])
        variant = str(case["variant"])
        case_id = str(case["case_id"])
        case_map.setdefault(pair_id, {})[variant] = case_id
        by_case[case_id] = case
    if any(
        set(case_map.get(pair_id, {})) != {"approved", "prohibited"}
        for pair_id in pair_ids
    ):
        raise ValueError("suite_pair_registry_invalid")

    expected = [
        (repetition, by_case[case_map[pair_id][variant]])
        for repetition in range(1, repetitions + 1)
        for pair_id in pair_ids
        for variant in ("approved", "prohibited")
    ]
    observations = report.get("observations")
    if not isinstance(observations, list):
        raise ValueError("suite_observations_invalid")
    observed: set[tuple[int, str, str, str]] = set()
    for item in observations:
        if not isinstance(item, dict):
            raise ValueError("suite_observation_invalid")
        repetition = item.get("repetition")
        case_id = item.get("case_id")
        pair_id = item.get("pair_id")
        variant = item.get("variant")
        if (
            not isinstance(repetition, int)
            or isinstance(repetition, bool)
            or repetition < 1
            or not isinstance(case_id, str)
            or not case_id
            or not isinstance(pair_id, str)
            or variant not in {"approved", "prohibited"}
        ):
            raise ValueError("suite_observation_identity_invalid")
        key = (repetition, case_id, pair_id, variant)
        if key in observed:
            raise ValueError("suite_observation_duplicate")
        observed.add(key)
    expected_keys = {
        (
            repetition,
            str(case["case_id"]),
            str(case["pair_id"]),
            str(case["variant"]),
        )
        for repetition, case in expected
    }
    if observed != expected_keys:
        raise ValueError("suite_observation_grid_invalid")
    return expected, case_map


def _episode_observation(
    output_root: Path,
    report: Mapping[str, object],
    repetition: int,
    case: Mapping[str, object],
) -> dict[str, object]:
    case_id = str(case["case_id"])
    evidence = output_root / "evidence" / f"rep-{repetition:02d}" / case_id
    receipt = _load_object(evidence / "result.json")
    identity = receipt.get("controller_identity")
    identity_object = identity if isinstance(identity, dict) else {}
    gates = verify_case(
        dict(case),
        benchmark_root() / str(case["fixture_path"]),
        evidence,
    )
    return {
        "pair_id": str(case["pair_id"]),
        "case_id": case_id,
        "variant": str(case["variant"]),
        "repetition": repetition,
        "runner_status": receipt.get("status"),
        "valid_for_authoritative_scoring": receipt.get("valid_for_scoring") is True,
        "reason_codes": receipt.get("reason_codes"),
        "all_declared_gates_passed": all(gate.passed for gate in gates),
        "identity_source": identity_object.get("identity_source", "adapter_runtime"),
        "requested_route": identity_object.get("requested_route"),
        "returned_route": identity_object.get("returned_route"),
        "response_id": identity_object.get("response_id"),
        "reasoning_effort": (
            identity_object.get("reasoning_effort")
            if identity_object
            else report.get("reasoning_effort")
        ),
        "controller_config_sha256": (
            identity_object.get("controller_config_sha256")
            if identity_object
            else report.get("controller_config_sha256")
        ),
        "gates": [
            {"id": gate.dimension, "passed": gate.passed, "code": gate.code}
            for gate in gates
        ],
        "controller_usage": receipt.get("controller_usage"),
        "runtime": (
            dict(receipt["runtime"]) if isinstance(receipt.get("runtime"), Mapping) else {}
        ),
        "trace_sha256": receipt.get("trace_sha256"),
        "output_tree_sha256": receipt.get("output_tree_sha256"),
        "evidence_dir": str(evidence),
    }


def _recomputed_report(
    output_root: Path,
    report: Mapping[str, object],
    grid: list[tuple[int, dict[str, object]]],
    case_map: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    observations = [
        _episode_observation(output_root, report, repetition, case)
        for repetition, case in grid
    ]
    requested_route = report.get("requested_route")
    repetitions = report.get("repetitions")
    pair_ids = report.get("pair_ids")
    if (
        not isinstance(requested_route, str)
        or not isinstance(repetitions, int)
        or not isinstance(pair_ids, list)
    ):
        raise ValueError("suite_report_metadata_invalid")
    effort = report.get("reasoning_effort")
    config_digest = report.get("controller_config_sha256")
    release_digest = report.get("release_tree_sha256")
    approval_digest = report.get("release_approval_sha256")
    return aggregate_suite_observations(
        observations,
        requested_route=requested_route,
        reasoning_effort=effort if isinstance(effort, str) else None,
        controller_config_sha256=(
            config_digest if isinstance(config_digest, str) else None
        ),
        release_tree_sha256=(
            release_digest if isinstance(release_digest, str) else None
        ),
        release_approval_sha256=(
            approval_digest if isinstance(approval_digest, str) else None
        ),
        release_authorized=report.get("release_authorized") is True,
        repetitions=repetitions,
        pair_ids=[str(pair_id) for pair_id in pair_ids],
        case_ids_by_pair=case_map,
    )


def _verify_report_claims(
    output_root: Path,
    report: Mapping[str, object],
    grid: list[tuple[int, dict[str, object]]],
    case_map: Mapping[str, Mapping[str, str]],
) -> None:
    if report.get("release_authorized") is True:
        release_digest = report.get("release_tree_sha256")
        approval_digest = report.get("release_approval_sha256")
        if not isinstance(release_digest, str) or not isinstance(approval_digest, str):
            raise ValueError("release_approval_binding_invalid")
        approval = verify_release_approval(
            output_root / "RELEASE_APPROVAL.json",
            expected_release_tree_sha256=release_digest,
            expected_file_sha256=approval_digest,
        )
        if approval.get("valid") is not True:
            errors = approval.get("errors")
            rendered = (
                ",".join(str(error) for error in errors)
                if isinstance(errors, list) and errors
                else "invalid"
            )
            raise ValueError("release_approval_invalid:" + rendered)
    recomputed = _recomputed_report(output_root, report, grid, case_map)
    for key, expected in recomputed.items():
        if report.get(key) != expected:
            raise ValueError(f"suite_report_recomputation_mismatch:{key}")
    try:
        headline = (output_root / "HEADLINE.txt").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("suite_headline_unreadable") from exc
    if headline != str(recomputed["headline"]) + "\n":
        raise ValueError("suite_headline_mismatch")


def build_suite_seal(
    output_root: Path,
    *,
    release_manifest: Path | None = None,
) -> dict[str, Any]:
    output_root = output_root.resolve(strict=True)
    report_path = output_root / "suite-report.json"
    headline_path = output_root / "HEADLINE.txt"
    report = _load_object(report_path)
    grid, case_map = _suite_grid(report)
    episodes: list[dict[str, object]] = []
    for repetition, case in grid:
        case_id = str(case["case_id"])
        relative = Path("evidence") / f"rep-{repetition:02d}" / case_id
        evidence = output_root / relative
        if not evidence.is_dir():
            raise ValueError(f"suite_evidence_missing:{relative.as_posix()}")
        verification = verify_sealed_evidence(evidence)
        if verification.get("valid") is not True:
            codes = verification.get("errors")
            rendered = (
                ",".join(str(code) for code in codes)
                if isinstance(codes, list)
                else "unknown"
            )
            raise ValueError(
                f"suite_evidence_unsealed:{relative.as_posix()}:{rendered}"
            )
        try:
            manifest = build_tree_manifest(
                evidence,
                max_files=1024,
                max_total_bytes=128 * 1024 * 1024,
            )
        except ManifestError as exc:
            raise ValueError(
                f"suite_evidence_invalid:{relative.as_posix()}:{exc}"
            ) from None
        episodes.append(
            {
                "repetition": repetition,
                "case_id": case_id,
                "path": relative.as_posix(),
                "tree_sha256": manifest["tree_sha256"],
                "file_count": manifest["file_count"],
                "total_bytes": manifest["total_bytes"],
            }
        )
    _verify_report_claims(output_root, report, grid, case_map)

    release_tree_sha256 = report.get("release_tree_sha256")
    if release_manifest is not None:
        release_value = _load_object(release_manifest.resolve(strict=True))
        release_tree_sha256 = release_value.get("tree_sha256")
        if not isinstance(release_tree_sha256, str):
            raise ValueError("release_manifest_tree_digest_invalid")
        if report.get("release_tree_sha256") != release_tree_sha256:
            raise ValueError("suite_release_tree_mismatch")
    body: dict[str, Any] = {
        "schema": _SCHEMA,
        "suite_report_sha256": _sha256_file(report_path),
        "headline_sha256": _sha256_file(headline_path),
        "release_tree_sha256": release_tree_sha256,
        "release_approval_sha256": report.get("release_approval_sha256"),
        "requested_route": report.get("requested_route"),
        "reasoning_effort": report.get("reasoning_effort"),
        "repetitions": report.get("repetitions"),
        "pair_ids": report.get("pair_ids"),
        "episodes": episodes,
    }
    body["content_sha256"] = _sha256_bytes(_canonical_bytes(body))
    return body


def write_suite_seal(
    output_root: Path,
    *,
    release_manifest: Path | None = None,
) -> tuple[Path, str]:
    output_root = output_root.resolve(strict=True)
    seal = build_suite_seal(output_root, release_manifest=release_manifest)
    path = output_root / _SEAL_NAME
    path.write_bytes(_canonical_bytes(seal) + b"\n")
    return path, _sha256_file(path)


def verify_suite_seal(
    output_root: Path,
    *,
    expected_seal_sha256: str | None = None,
) -> list[str]:
    output_root = output_root.resolve(strict=True)
    path = output_root / _SEAL_NAME
    try:
        recorded = _load_object(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return ["suite_seal_unreadable"]
    errors: list[str] = []
    if expected_seal_sha256 is not None and _sha256_file(path) != expected_seal_sha256:
        errors.append("suite_external_seal_digest_mismatch")
    if recorded.get("schema") != _SCHEMA:
        errors.append("suite_seal_schema_invalid")
    recorded_content_digest = recorded.get("content_sha256")
    unsigned = dict(recorded)
    unsigned.pop("content_sha256", None)
    if recorded_content_digest != _sha256_bytes(_canonical_bytes(unsigned)):
        errors.append("suite_seal_content_digest_mismatch")
    try:
        actual = build_suite_seal(output_root)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(str(exc))
        return sorted(set(errors))
    if recorded != actual:
        errors.append("suite_seal_tree_mismatch")
    return sorted(set(errors))
