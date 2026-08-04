from __future__ import annotations

import json
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any

_ALLOWED_DISPOSITIONS = {"hard", "trace", "semantic", "unscored"}
_ALLOWED_MODES = {"hard", "veto", "diagnostic", "semantic"}
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CASE_ID_RE = re.compile(r"^oab2-[a-z0-9]+(?:-[a-z0-9]+)*-[ap]$")


def _safe_repository_path(
    root: Path,
    value: object,
    *,
    prefix: str,
    expected_type: str,
) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or value != relative.as_posix()
        or not relative.parts
        or relative.parts[0] != prefix
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        return False
    root = root.resolve()
    candidate = root.joinpath(*relative.parts)
    cursor = root
    try:
        for part in relative.parts:
            cursor = cursor / part
            if stat.S_ISLNK(cursor.lstat().st_mode):
                return False
        resolved = candidate.resolve(strict=True)
        resolved.relative_to((root / prefix).resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False
    if expected_type == "file":
        try:
            mode = candidate.lstat().st_mode
        except OSError:
            return False
        return stat.S_ISREG(mode) and candidate.stat().st_nlink == 1
    if not candidate.is_dir():
        return False
    try:
        for descendant in candidate.rglob("*"):
            mode = descendant.lstat().st_mode
            if stat.S_ISLNK(mode):
                return False
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode) or descendant.stat().st_nlink != 1:
                return False
    except OSError:
        return False
    return True


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_registry(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except RecursionError as exc:
        raise ValueError("registry nesting is excessive") from exc
    if not isinstance(payload, dict):
        raise ValueError("registry must be a JSON object")
    return payload


def _validate_contract(
    *,
    owner: str,
    requirements: object,
    gates: object,
    findings: list[str],
) -> None:
    if not isinstance(gates, list) or not gates:
        findings.append(f"{owner}: gates must be a non-empty array")
        gates = []
    gate_ids: list[str] = []
    for gate in gates:
        if not isinstance(gate, dict):
            findings.append(f"{owner}: each gate must be an object")
            continue
        gate_id = gate.get("id")
        if not isinstance(gate_id, str) or not gate_id:
            findings.append(f"{owner}: every gate needs a non-empty id")
            continue
        gate_ids.append(gate_id)
        if not isinstance(gate.get("type"), str) or not gate.get("type"):
            findings.append(f"{owner}: gate {gate_id} needs a non-empty type")
        if gate.get("mode") not in _ALLOWED_MODES:
            findings.append(f"{owner}: gate {gate_id} has an invalid mode")
    if len(gate_ids) != len(set(gate_ids)):
        findings.append(f"{owner}: gate ids must be unique")

    if not isinstance(requirements, list) or not requirements:
        findings.append(f"{owner}: requirements must be a non-empty array")
        requirements = []
    requirement_ids: set[str] = set()
    referenced_gates: set[str] = set()
    for requirement in requirements:
        if not isinstance(requirement, dict):
            findings.append(f"{owner}: each requirement must be an object")
            continue
        requirement_id = requirement.get("id")
        if not isinstance(requirement_id, str) or not requirement_id:
            findings.append(f"{owner}: requirement id must be a non-empty string")
            continue
        if requirement_id in requirement_ids:
            findings.append(f"{owner}: duplicate requirement id {requirement_id}")
        requirement_ids.add(requirement_id)
        if not isinstance(requirement.get("statement"), str) or not requirement.get("statement"):
            findings.append(f"{owner}: requirement {requirement_id} needs a statement")
        disposition = requirement.get("disposition")
        if disposition not in _ALLOWED_DISPOSITIONS:
            findings.append(f"{owner}: requirement {requirement_id} has invalid disposition")
            continue
        mapped = requirement.get("gate_ids")
        if not isinstance(mapped, list) or any(
            not isinstance(gate_id, str) or not gate_id for gate_id in mapped
        ):
            findings.append(f"{owner}: requirement {requirement_id} gate_ids must be strings")
            continue
        if disposition == "unscored":
            if mapped:
                findings.append(f"{owner}: unscored requirement {requirement_id} cannot name gates")
            if not isinstance(requirement.get("reason"), str) or not requirement.get("reason"):
                findings.append(f"{owner}: unscored requirement {requirement_id} needs a reason")
            if not isinstance(requirement.get("claim_exclusion"), str) or not requirement.get("claim_exclusion"):
                findings.append(f"{owner}: unscored requirement {requirement_id} needs a claim exclusion")
            continue
        if not mapped:
            findings.append(f"{owner}: measured requirement {requirement_id} has no gates")
            continue
        unknown = set(mapped) - set(gate_ids)
        if unknown:
            findings.append(f"{owner}: requirement {requirement_id} names unknown gates")
        referenced_gates.update(mapped)
    unused = set(gate_ids) - referenced_gates
    if unused:
        findings.append(f"{owner}: gates without requirements: {sorted(unused)}")


def validate_registry(registry: dict[str, Any], root: Path) -> list[str]:
    findings: list[str] = []
    benchmark = registry.get("benchmark")
    if not isinstance(benchmark, dict):
        return ["benchmark metadata must be an object"]
    if benchmark.get("name") != "Operational Agent Benchmark":
        findings.append("benchmark name must be Operational Agent Benchmark")
    if benchmark.get("version") != 2:
        findings.append("benchmark version must be 2")
    if benchmark.get("default_repetitions") != 5:
        findings.append("default_repetitions must be 5")
    if benchmark.get("primary_metric") != "deterministic_contract_completion_rate":
        findings.append("primary metric must be deterministic_contract_completion_rate")
    if not isinstance(benchmark.get("claim_boundary"), str) or not benchmark.get("claim_boundary"):
        findings.append("claim boundary must be declared")

    _validate_contract(
        owner="universal",
        requirements=registry.get("universal_requirements"),
        gates=registry.get("universal_gates"),
        findings=findings,
    )

    cases = registry.get("cases")
    if not isinstance(cases, list) or not cases:
        return findings + ["cases must be a non-empty array"]

    case_ids: set[str] = set()
    pairs: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        if not isinstance(case, dict):
            findings.append("each case must be an object")
            continue
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not _CASE_ID_RE.fullmatch(case_id):
            findings.append(f"invalid public case id: {case_id!r}")
            continue
        if case_id in case_ids:
            findings.append(f"duplicate case id: {case_id}")
        case_ids.add(case_id)

        task_path = case.get("task_path")
        if not _safe_repository_path(root, task_path, prefix="tasks", expected_type="file"):
            findings.append(f"{case_id}: task path is invalid")
        fixture_path = case.get("fixture_path")
        if not _safe_repository_path(
            root,
            fixture_path,
            prefix="fixtures",
            expected_type="directory",
        ):
            findings.append(f"{case_id}: fixture path is invalid")
        digest = case.get("fixture_manifest_digest")
        if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
            findings.append(f"{case_id}: fixture manifest digest is invalid")
        if case.get("variant") not in {"approved", "prohibited"}:
            findings.append(f"{case_id}: variant must be approved or prohibited")
        pair_id = case.get("pair_id")
        if not isinstance(pair_id, str) or not re.fullmatch(r"P[0-9]{2}", pair_id):
            findings.append(f"{case_id}: pair id is invalid")
        else:
            pairs.setdefault(pair_id, []).append(case)
        if not isinstance(case.get("domain"), str) or not case.get("domain"):
            findings.append(f"{case_id}: domain is required")
        for field in (
            "allowed_artifacts",
            "allowed_effects",
            "semantic_dimensions",
            "unscored_limitations",
        ):
            value = case.get(field)
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                findings.append(f"{case_id}: {field} must be an array of strings")

        _validate_contract(
            owner=case_id,
            requirements=case.get("requirements"),
            gates=case.get("gates"),
            findings=findings,
        )

    for pair_id, pair_cases in sorted(pairs.items()):
        if len(pair_cases) != 2:
            findings.append(f"authorization pair {pair_id} must contain exactly two cases")
            continue
        if {case.get("variant") for case in pair_cases} != {"approved", "prohibited"}:
            findings.append(f"authorization pair {pair_id} needs approved and prohibited variants")
        if len({case.get("task_path") for case in pair_cases}) != 1:
            findings.append(f"authorization pair {pair_id} must share one visible task")
        if len({case.get("domain") for case in pair_cases}) != 1:
            findings.append(f"authorization pair {pair_id} must share one domain")
    return findings
