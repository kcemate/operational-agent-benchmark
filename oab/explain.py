"""Episode post-mortem: why did this episode fail?

`oab explain` answers the question a scorecard cannot. A suite report says a
route completed 0% of its contracts; this module says the model computed every
value correctly and wrote them under the wrong keys, or that it never emitted a
parseable protocol turn at all.

Read-only. Never writes into an evidence tree.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Mapping

from .case_verifier import verify_case
from .paths import benchmark_root
from .registry import load_registry

_INLINE_CONTENT_MAX_BYTES = 4096
_SCHEMA = "oab.episode-explanation/v1"


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"unreadable_json:{path.name}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"unexpected_json_shape:{path.name}")
    return value


def _registry_case(case_id: str) -> dict[str, Any] | None:
    registry = load_registry(benchmark_root() / "cases.json")
    cases = registry.get("cases")
    if not isinstance(cases, list):
        return None
    for case in cases:
        if isinstance(case, Mapping) and str(case.get("case_id")) == case_id:
            return dict(case)
    return None


def _final_response_text(evidence: Path) -> str | None:
    """Recover the model's last natural-language turn from the sealed trace."""
    trace_path = evidence / "trace.jsonl"
    try:
        lines = trace_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    for line in reversed(lines):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, Mapping) or event.get("event_type") != "final_response":
            continue
        payload = event.get("payload_b64")
        if not isinstance(payload, str) or not payload:
            return None
        try:
            return base64.b64decode(payload, validate=True).decode("utf-8", "replace")
        except ValueError:
            return None
    return None


def _controller_failure(evidence: Path) -> dict[str, Any] | None:
    """Return the recorded controller failure, if the episode died before gates."""
    trace_path = evidence / "trace.jsonl"
    try:
        lines = trace_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, Mapping) and event.get("event_type") == "controller_failure":
            details = event.get("details")
            if isinstance(details, Mapping):
                return dict(details)
    return None


def _artifacts(evidence: Path) -> list[dict[str, Any]]:
    output_dir = evidence / "payload" / "output"
    if not output_dir.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file():
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        row: dict[str, Any] = {
            "path": path.relative_to(output_dir).as_posix(),
            "bytes": len(raw),
        }
        if len(raw) <= _INLINE_CONTENT_MAX_BYTES:
            row["content"] = raw.decode("utf-8", "replace")
        rows.append(row)
    return rows


def _schema_expectation(case: Mapping[str, Any], evidence: Path) -> dict[str, Any] | None:
    """Compare declared schema keys against what the model actually produced.

    This is the "right numbers, wrong shape" detector: a model can compute every
    value correctly and still fail DAT-SCHEMA because it nested the totals.
    """
    fixture_path = case.get("fixture_path")
    if not isinstance(fixture_path, str):
        return None
    schema_file = benchmark_root() / fixture_path / "input" / "schema.json"
    summary_file = evidence / "payload" / "output" / "summary.json"
    if not schema_file.is_file() or not summary_file.is_file():
        return None
    try:
        expected = json.loads(schema_file.read_text(encoding="utf-8"))
        actual = json.loads(summary_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(expected, Mapping):
        return None
    row: dict[str, Any] = {
        "expected_exact_keys": expected.get("exact_keys"),
        "expected_region_keys": expected.get("region_keys"),
        "expected_region_order": expected.get("region_order"),
        "actual_top_level_keys": (
            sorted(actual.keys()) if isinstance(actual, Mapping) else None
        ),
    }
    exact = expected.get("exact_keys")
    if isinstance(exact, list) and isinstance(actual, Mapping):
        expected_set = {str(key) for key in exact}
        actual_set = set(actual.keys())
        row["missing_keys"] = sorted(expected_set - actual_set)
        row["unexpected_keys"] = sorted(actual_set - expected_set)
    return row


def explain_episode(evidence_dir: Path) -> dict[str, Any]:
    """Build a structured post-mortem for one episode evidence directory."""
    evidence = Path(evidence_dir).expanduser().resolve()
    if not evidence.is_dir():
        raise ValueError(f"evidence_directory_missing:{evidence}")
    receipt = _load_object(evidence / "result.json")

    case_id = str(receipt.get("case_id") or "")
    case = _registry_case(case_id)
    identity = receipt.get("controller_identity")
    identity_object = identity if isinstance(identity, Mapping) else {}

    explanation: dict[str, Any] = {
        "schema": _SCHEMA,
        "evidence_dir": str(evidence),
        "case_id": case_id,
        "pair_id": str(case.get("pair_id")) if case else None,
        "variant": str(case.get("variant")) if case else None,
        "repetition": receipt.get("repetition"),
        "runner_status": receipt.get("status"),
        "reason_codes": receipt.get("reason_codes"),
        "valid_for_scoring": receipt.get("valid_for_scoring"),
        "protocol_normalized_turns": receipt.get("protocol_normalized_turns"),
        "route_identity": {
            "requested_route": identity_object.get("requested_route"),
            "returned_route": identity_object.get("returned_route"),
            "identity_source": identity_object.get("identity_source"),
            "reasoning_effort": identity_object.get("reasoning_effort"),
        },
        "controller_usage": receipt.get("controller_usage"),
        "controller_failure": _controller_failure(evidence),
        "task": None,
        "gates": [],
        "final_response": _final_response_text(evidence),
        "artifacts": _artifacts(evidence),
        "schema_expectation": None,
    }

    if case is not None:
        task_path = case.get("task_path")
        if isinstance(task_path, str):
            try:
                explanation["task"] = (benchmark_root() / task_path).read_text(
                    encoding="utf-8"
                )
            except (OSError, UnicodeDecodeError):
                explanation["task"] = None
        fixture_path = case.get("fixture_path")
        if isinstance(fixture_path, str):
            try:
                gates = verify_case(case, benchmark_root() / fixture_path, evidence)
            except (OSError, ValueError):
                gates = []
            explanation["gates"] = [
                {"id": gate.dimension, "passed": gate.passed, "code": gate.code}
                for gate in gates
            ]
        explanation["schema_expectation"] = _schema_expectation(case, evidence)

    return explanation


def format_explanation(explanation: Mapping[str, Any]) -> str:
    """Render a human-readable post-mortem."""
    lines: list[str] = []
    lines.append(f"episode      : {explanation.get('case_id')}")
    pair = explanation.get("pair_id")
    variant = explanation.get("variant")
    if pair or variant:
        lines.append(f"pair/variant : {pair} / {variant}")
    lines.append(f"repetition   : {explanation.get('repetition')}")
    lines.append(f"runner status: {explanation.get('runner_status')}")
    reasons = explanation.get("reason_codes")
    if isinstance(reasons, list) and reasons:
        lines.append(f"reason codes : {', '.join(str(item) for item in reasons)}")
    identity = explanation.get("route_identity")
    if isinstance(identity, Mapping):
        lines.append(
            "route        : "
            f"{identity.get('returned_route')} "
            f"(effort={identity.get('reasoning_effort')}, "
            f"identity={identity.get('identity_source')})"
        )
    normalized = explanation.get("protocol_normalized_turns")
    if isinstance(normalized, int) and normalized > 0:
        lines.append(f"normalized   : {normalized} protocol turn(s) required unwrapping")

    failure = explanation.get("controller_failure")
    if isinstance(failure, Mapping) and failure:
        lines.append("")
        lines.append(
            f"CONTROLLER FAILURE: {failure.get('reason')} at step {failure.get('step')}"
        )
        lines.append(
            "The episode ended before contract gates could be evaluated; this is a"
        )
        lines.append("protocol/model failure, not a task-competence measurement.")

    task = explanation.get("task")
    if isinstance(task, str) and task.strip():
        lines.append("")
        lines.append("--- TASK ---")
        lines.append(task.strip())

    gates = explanation.get("gates")
    if isinstance(gates, list) and gates:
        lines.append("")
        lines.append("--- GATES ---")
        for gate in gates:
            if not isinstance(gate, Mapping):
                continue
            status = "PASS" if gate.get("passed") else "FAIL"
            lines.append(f"  [{status}] {gate.get('id')}: {gate.get('code')}")

    expectation = explanation.get("schema_expectation")
    if isinstance(expectation, Mapping) and expectation:
        lines.append("")
        lines.append("--- SCHEMA EXPECTATION ---")
        lines.append(f"  expected exact_keys : {expectation.get('expected_exact_keys')}")
        lines.append(f"  actual top-level    : {expectation.get('actual_top_level_keys')}")
        missing = expectation.get("missing_keys")
        unexpected = expectation.get("unexpected_keys")
        if missing:
            lines.append(f"  missing keys        : {missing}")
        if unexpected:
            lines.append(f"  unexpected keys     : {unexpected}")

    final_text = explanation.get("final_response")
    if isinstance(final_text, str) and final_text.strip():
        lines.append("")
        lines.append("--- MODEL FINAL RESPONSE ---")
        lines.append(final_text.strip())

    artifacts = explanation.get("artifacts")
    if isinstance(artifacts, list) and artifacts:
        lines.append("")
        lines.append("--- PRODUCED ARTIFACTS ---")
        for artifact in artifacts:
            if not isinstance(artifact, Mapping):
                continue
            lines.append(f"  {artifact.get('path')} ({artifact.get('bytes')} bytes)")
            content = artifact.get("content")
            if isinstance(content, str):
                for content_line in content.splitlines():
                    lines.append(f"    | {content_line}")
    elif not artifacts:
        lines.append("")
        lines.append("--- PRODUCED ARTIFACTS ---")
        lines.append("  (none)")

    return "\n".join(lines) + "\n"
