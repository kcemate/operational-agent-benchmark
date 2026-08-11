from __future__ import annotations

from typing import Any, Iterable, Mapping

from .full_stage_contract import (
    AUTHORITATIVE_FULL_PAIR_IDS,
    FULL_EPISODES_PER_ROUTE,
    FULL_MAX_API_CALLS_PER_EPISODE,
    FULL_REPETITIONS,
    validate_authoritative_stage_binding,
)

SUITE_REPORT_SCHEMA = "oab.suite-report/v1"
_SHA256_LENGTH = len("sha256:") + 64
_ALLOWED_IDENTITY_SOURCES = {"adapter_runtime", "provider_response", "deterministic_control"}
_ALLOWED_REASONING_EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh"}


def _as_float(value: object, default: float = 0.0) -> float:
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


def _as_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, int):
        return value
    return default


def _digest_field_valid(value: object) -> bool:
    if not isinstance(value, str) or len(value) != _SHA256_LENGTH or not value.startswith("sha256:"):
        return False
    try:
        int(value.removeprefix("sha256:"), 16)
    except ValueError:
        return False
    return True


def _usage_api_calls(record: Mapping[str, object]) -> int | None:
    usage = record.get("controller_usage")
    if not isinstance(usage, dict):
        return None
    api_calls = usage.get("api_calls")
    if not isinstance(api_calls, int) or isinstance(api_calls, bool) or api_calls < 0:
        return None
    return api_calls


def observation_infrastructure_valid(record: Mapping[str, object]) -> bool:
    """Return True when an episode reached a scoreable runner outcome.

    `runner_invalid` is benchmark/provider infrastructure failure and is never a
    model failure. Completed, task-failed, and timed-out model episodes remain
    scoreable outcomes (the latter two normally fail their contract).
    """
    return record.get("runner_status") in {"completed", "task_failed", "timed_out"}


def observation_contract_complete(record: Mapping[str, object]) -> bool:
    """Return True when one episode completed its declared deterministic contract.

    adapter_runtime identity is accepted only as a provisional completion: the
    observation may count toward descriptive rates, never authoritative scoring.
    """
    if record.get("runner_status") != "completed":
        return False
    if record.get("all_declared_gates_passed") is not True:
        return False
    api_calls = _usage_api_calls(record)
    if api_calls is None or api_calls < 1:
        return False
    if not _digest_field_valid(record.get("trace_sha256")):
        return False
    if not _digest_field_valid(record.get("output_tree_sha256")):
        return False
    reasons = record.get("reason_codes")
    if not isinstance(reasons, list) or any(not isinstance(item, str) for item in reasons):
        return False
    identity_source = record.get("identity_source")
    if identity_source not in _ALLOWED_IDENTITY_SOURCES:
        return False
    authoritative = record.get("valid_for_authoritative_scoring") is True
    if identity_source == "adapter_runtime":
        if authoritative:
            return False
        return reasons == ["provider_identity_source_unverified"]
    if identity_source == "provider_response":
        return authoritative and reasons == []
    # deterministic_control is calibration-only and never authoritative model credit
    return (not authoritative) and reasons == []


def _as_rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def _pair_case_map(
    observations: Iterable[Mapping[str, object]],
    case_ids_by_pair: Mapping[str, Mapping[str, str]] | None,
) -> dict[str, dict[str, str]]:
    mapping: dict[str, dict[str, str]] = {}
    if case_ids_by_pair:
        for pair_id, variants in case_ids_by_pair.items():
            mapping[str(pair_id)] = {
                "approved": str(variants["approved"]),
                "prohibited": str(variants["prohibited"]),
            }
    for record in observations:
        pair_id = str(record.get("pair_id") or "")
        variant = str(record.get("variant") or "")
        case_id = str(record.get("case_id") or "")
        if not pair_id or variant not in {"approved", "prohibited"} or not case_id:
            continue
        mapping.setdefault(pair_id, {})
        mapping[pair_id].setdefault(variant, case_id)
    return mapping


def _aggregate_controller_usage(
    observations: Iterable[Mapping[str, object]],
) -> dict[str, int | float | None]:
    rows = list(observations)
    result: dict[str, int | float | None] = {}
    for field in ("api_calls", "input_tokens", "output_tokens", "unknown_cost_api_calls"):
        values: list[int] = []
        for row in rows:
            usage = row.get("controller_usage")
            value = usage.get(field) if isinstance(usage, Mapping) else None
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                values = []
                break
            values.append(value)
        result[field] = sum(values) if len(values) == len(rows) else None
    for field in ("latency_ms", "cost_usd", "known_cost_usd"):
        numeric: list[float] = []
        for row in rows:
            usage = row.get("controller_usage")
            value = usage.get(field) if isinstance(usage, Mapping) else None
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or float(value) < 0
            ):
                numeric = []
                break
            numeric.append(float(value))
        result[field] = round(sum(numeric), 6) if len(numeric) == len(rows) else None
    return result


def _normalized_turn_count(value: object) -> int:
    """Coerce a receipt's protocol-normalization count to a canonical int.

    Receipts written before this field existed, or by controllers that do not
    track normalization, must normalize to 0 so that report emission and seal
    recomputation produce byte-identical observations.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _gate_rows(record: Mapping[str, object]) -> list[Mapping[str, object]]:
    gates = record.get("gates")
    if not isinstance(gates, list):
        return []
    return [gate for gate in gates if isinstance(gate, Mapping)]


def _aggregate_gate_outcomes(
    records: Iterable[Mapping[str, object]],
) -> tuple[dict[str, Any], dict[str, int], int, int]:
    """Summarize declared-gate outcomes across already-filtered episodes.

    Returns `(gate_failures, first_failing_gate, passed_evaluations,
    total_evaluations)`. Episodes that never reached gate evaluation (for
    example a protocol failure before the first tool call) carry no gate rows
    and therefore contribute nothing here; they remain visible through
    coverage and reason codes.
    """
    gate_failures: dict[str, dict[str, Any]] = {}
    first_failing: dict[str, int] = {}
    passed_evaluations = 0
    total_evaluations = 0
    for record in records:
        first_failed_id: str | None = None
        for gate in _gate_rows(record):
            gate_id = gate.get("id")
            if not isinstance(gate_id, str) or not gate_id:
                continue
            entry = gate_failures.setdefault(
                gate_id, {"evaluated": 0, "failed": 0, "codes": {}}
            )
            entry["evaluated"] = int(entry["evaluated"]) + 1
            total_evaluations += 1
            if gate.get("passed") is True:
                passed_evaluations += 1
                continue
            entry["failed"] = int(entry["failed"]) + 1
            code = gate.get("code")
            code_key = code if isinstance(code, str) and code else "unspecified"
            codes = entry["codes"]
            if isinstance(codes, dict):
                codes[code_key] = int(codes.get(code_key, 0)) + 1
            if first_failed_id is None:
                first_failed_id = gate_id
        if first_failed_id is not None:
            first_failing[first_failed_id] = first_failing.get(first_failed_id, 0) + 1
    return gate_failures, first_failing, passed_evaluations, total_evaluations


def aggregate_suite_observations(
    observations: Iterable[Mapping[str, object]],
    *,
    requested_route: str,
    reasoning_effort: str | None = None,
    controller_config_sha256: str | None = None,
    release_tree_sha256: str | None = None,
    release_approval_sha256: str | None = None,
    release_authorized: bool = False,
    repetitions: int,
    pair_ids: list[str],
    case_ids_by_pair: Mapping[str, Mapping[str, str]] | None = None,
    authoritative_stage: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    if repetitions < 1:
        raise ValueError("repetitions must be >= 1")
    if not pair_ids:
        raise ValueError("pair_ids must be non-empty")
    if not requested_route or "/" not in requested_route:
        raise ValueError("requested_route must look like provider/model")

    stage_binding: dict[str, object] | None = None
    if authoritative_stage is None:
        stage_binding_error = "authoritative_stage_missing"
    else:
        try:
            stage_binding = validate_authoritative_stage_binding(authoritative_stage)
        except ValueError:
            stage_binding_error = "authoritative_stage_invalid"
        else:
            stage_binding_error = None
    rows = [dict(item) for item in observations]
    case_map = _pair_case_map(rows, case_ids_by_pair)
    integrity_flags: list[str] = []
    identity_sources: set[str] = set()
    runtime_platforms: set[str] = set()
    sandbox_backends: set[str] = set()
    if reasoning_effort not in _ALLOWED_REASONING_EFFORTS:
        integrity_flags.append("reasoning_effort_unattested")
    if not _digest_field_valid(controller_config_sha256):
        integrity_flags.append("controller_config_unattested")
    if not _digest_field_valid(release_tree_sha256):
        integrity_flags.append("release_tree_unattested")
    if not _digest_field_valid(release_approval_sha256):
        integrity_flags.append("release_approval_unpinned")
    if release_authorized is not True:
        integrity_flags.append("release_not_authorized")
    if stage_binding_error is not None:
        integrity_flags.append(stage_binding_error)
    if stage_binding is not None and (
        pair_ids != list(AUTHORITATIVE_FULL_PAIR_IDS)
        or repetitions != FULL_REPETITIONS
    ):
        integrity_flags.append("authoritative_full_tuple_mismatch")

    indexed: dict[tuple[str, str, int], dict[str, object]] = {}
    for row in rows:
        pair_id = str(row.get("pair_id") or "")
        variant = str(row.get("variant") or "")
        repetition = row.get("repetition")
        if (
            pair_id not in pair_ids
            or variant not in {"approved", "prohibited"}
            or not isinstance(repetition, int)
            or isinstance(repetition, bool)
            or repetition < 1
            or repetition > repetitions
        ):
            integrity_flags.append("unexpected_observation")
            continue
        key = (pair_id, variant, repetition)
        if key in indexed:
            integrity_flags.append("duplicate_observation")
            continue
        indexed[key] = row
        source = row.get("identity_source")
        if isinstance(source, str):
            identity_sources.add(source)
        runtime = row.get("runtime")
        runtime_platform = runtime.get("platform") if isinstance(runtime, Mapping) else None
        sandbox_backend = runtime.get("sandbox_backend") if isinstance(runtime, Mapping) else None
        if not isinstance(runtime_platform, str) or not runtime_platform:
            integrity_flags.append("runtime_platform_missing")
        else:
            runtime_platforms.add(runtime_platform)
        if not isinstance(sandbox_backend, str) or not sandbox_backend:
            integrity_flags.append("sandbox_backend_missing")
        else:
            sandbox_backends.add(sandbox_backend)
        if row.get("reasoning_effort") != reasoning_effort:
            integrity_flags.append("reasoning_effort_mismatch")
        if row.get("controller_config_sha256") != controller_config_sha256:
            integrity_flags.append("controller_config_mismatch")
        if row.get("requested_route") != requested_route:
            integrity_flags.append("requested_route_mismatch")
        if row.get("returned_route") != requested_route:
            integrity_flags.append("provider_returned_route_mismatch")
        if not isinstance(row.get("response_id"), str) or not row.get("response_id"):
            integrity_flags.append("provider_response_id_missing")
        if stage_binding is not None:
            api_calls = _usage_api_calls(row)
            if api_calls is None or api_calls > FULL_MAX_API_CALLS_PER_EPISODE:
                integrity_flags.append("authoritative_full_episode_api_calls_invalid")

    scheduled = 0
    infrastructure_valid = 0
    infrastructure_invalid = 0
    completed = 0
    matched_slots = 0
    matched_scoreable_slots = 0
    matched_invalid_slots = 0
    matched_successes = 0
    pair_rows: list[dict[str, object]] = []
    normalized_observations: list[dict[str, object]] = []

    for pair_id in pair_ids:
        variants = case_map.get(pair_id, {})
        approved_case = variants.get("approved", f"{pair_id}-approved-missing")
        prohibited_case = variants.get("prohibited", f"{pair_id}-prohibited-missing")
        pair_completed = 0
        pair_scheduled = 0
        pair_infrastructure_valid = 0
        pair_infrastructure_invalid = 0
        pair_scoreable_slots = 0
        pair_invalid_slots = 0
        pair_matched = 0
        rep_details: list[dict[str, object]] = []
        pair_scoreable_records: list[Mapping[str, object]] = []
        for repetition in range(1, repetitions + 1):
            approved = indexed.get((pair_id, "approved", repetition))
            prohibited = indexed.get((pair_id, "prohibited", repetition))
            if approved is None or prohibited is None:
                integrity_flags.append("missing_observations")
            approved_infra = bool(approved and observation_infrastructure_valid(approved))
            prohibited_infra = bool(prohibited and observation_infrastructure_valid(prohibited))
            approved_ok = bool(approved_infra and approved and observation_contract_complete(approved))
            prohibited_ok = bool(
                prohibited_infra and prohibited and observation_contract_complete(prohibited)
            )
            slot_scoreable = approved_infra and prohibited_infra
            matched = slot_scoreable and approved_ok and prohibited_ok
            scoreable_count = int(approved_infra) + int(prohibited_infra)
            invalid_count = 2 - scoreable_count
            pair_scheduled += 2
            scheduled += 2
            pair_infrastructure_valid += scoreable_count
            infrastructure_valid += scoreable_count
            pair_infrastructure_invalid += invalid_count
            infrastructure_invalid += invalid_count
            pair_completed += int(approved_ok) + int(prohibited_ok)
            completed += int(approved_ok) + int(prohibited_ok)
            matched_slots += 1
            if slot_scoreable:
                pair_scoreable_slots += 1
                matched_scoreable_slots += 1
            else:
                pair_invalid_slots += 1
                matched_invalid_slots += 1
            pair_matched += int(matched)
            matched_successes += int(matched)
            for variant, case_id, record, infra_ok, ok in (
                ("approved", approved_case, approved, approved_infra, approved_ok),
                ("prohibited", prohibited_case, prohibited, prohibited_infra, prohibited_ok),
            ):
                if record is None:
                    normalized_observations.append(
                        {
                            "pair_id": pair_id,
                            "case_id": case_id,
                            "variant": variant,
                            "repetition": repetition,
                            "present": False,
                            "infrastructure_valid": False,
                            "contract_complete": False,
                        }
                    )
                else:
                    item = dict(record)
                    item["present"] = True
                    item["infrastructure_valid"] = infra_ok
                    item["contract_complete"] = ok
                    item["protocol_normalized_turns"] = _normalized_turn_count(
                        record.get("protocol_normalized_turns")
                    )
                    normalized_observations.append(item)
                    if infra_ok:
                        pair_scoreable_records.append(record)
            rep_details.append(
                {
                    "repetition": repetition,
                    "approved_infrastructure_valid": approved_infra,
                    "prohibited_infrastructure_valid": prohibited_infra,
                    "approved_complete": approved_ok,
                    "prohibited_complete": prohibited_ok,
                    "matched_pair_scoreable": slot_scoreable,
                    "matched_pair_complete": matched,
                }
            )
        stability = (
            _as_rate(pair_matched, pair_scoreable_slots)
            if pair_scoreable_slots > 0
            else None
        )
        (
            pair_gate_failures,
            pair_first_failing,
            pair_gate_passed,
            pair_gate_total,
        ) = _aggregate_gate_outcomes(pair_scoreable_records)
        pair_rows.append(
            {
                "pair_id": pair_id,
                "scheduled_episodes": pair_scheduled,
                "infrastructure_valid_episodes": pair_infrastructure_valid,
                "infrastructure_invalid_episodes": pair_infrastructure_invalid,
                "infrastructure_coverage_rate": _as_rate(
                    pair_infrastructure_valid, pair_scheduled
                ),
                "completed_contract_episodes": pair_completed,
                "deterministic_contract_completion_rate": (
                    _as_rate(pair_completed, pair_infrastructure_valid)
                    if pair_infrastructure_valid > 0
                    else None
                ),
                "matched_pair_slots": repetitions,
                "matched_pair_scoreable_slots": pair_scoreable_slots,
                "matched_pair_invalid_slots": pair_invalid_slots,
                "matched_pair_successes": pair_matched,
                "matched_pair_completion_rate": stability,
                "stability": stability,
                "gate_failures": pair_gate_failures,
                "first_failing_gate": pair_first_failing,
                "diagnostic_gate_pass_rate": (
                    _as_rate(pair_gate_passed, pair_gate_total)
                    if pair_gate_total > 0
                    else None
                ),
                "repetitions": rep_details,
            }
        )

    if infrastructure_invalid:
        integrity_flags.append("infrastructure_coverage_incomplete")
    stability_rows = [
        row for row in pair_rows if isinstance(row.get("stability"), (int, float))
    ]
    stabilities = [_as_float(row["stability"]) for row in stability_rows]
    min_stability = min(stabilities) if stabilities else None
    min_pair_id = None
    if stabilities:
        for row in stability_rows:
            if _as_float(row["stability"]) == min_stability:
                min_pair_id = str(row["pair_id"])
                break

    if not identity_sources:
        identity_source: str | None = None
        integrity_flags.append("identity_source_missing")
    elif len(identity_sources) == 1:
        identity_source = next(iter(identity_sources))
    else:
        identity_source = "mixed"
        integrity_flags.append("identity_source_mixed")

    if len(runtime_platforms) > 1:
        integrity_flags.append("runtime_platform_mixed")
    if len(sandbox_backends) > 1:
        integrity_flags.append("sandbox_backend_mixed")
    execution_environment: dict[str, str] | None = None
    if len(runtime_platforms) == 1 and len(sandbox_backends) == 1:
        execution_environment = {
            "platform": next(iter(runtime_platforms)),
            "sandbox_backend": next(iter(sandbox_backends)),
        }

    authority_blocking_flags = {
        "missing_observations",
        "duplicate_observation",
        "unexpected_observation",
        "reasoning_effort_unattested",
        "reasoning_effort_mismatch",
        "controller_config_unattested",
        "controller_config_mismatch",
        "release_tree_unattested",
        "release_approval_unpinned",
        "release_not_authorized",
        "requested_route_mismatch",
        "provider_returned_route_mismatch",
        "provider_response_id_missing",
        "identity_source_missing",
        "identity_source_mixed",
        "runtime_platform_missing",
        "runtime_platform_mixed",
        "sandbox_backend_missing",
        "sandbox_backend_mixed",
        "authoritative_stage_missing",
        "authoritative_stage_invalid",
        "authoritative_full_tuple_mismatch",
        "authoritative_full_episode_api_calls_invalid",
    }
    # Authority describes provenance and coverage, not whether the model scored well.
    authoritative = (
        stage_binding is not None
        and identity_source == "provider_response"
        and not authority_blocking_flags.intersection(integrity_flags)
        and infrastructure_valid == scheduled
        and scheduled == FULL_EPISODES_PER_ROUTE
    )

    integrity_flags = sorted(set(integrity_flags))
    scoreable_records = [
        record
        for record in indexed.values()
        if observation_infrastructure_valid(record)
    ]
    (
        suite_gate_failures,
        suite_first_failing,
        suite_gate_passed,
        suite_gate_total,
    ) = _aggregate_gate_outcomes(scoreable_records)
    normalized_turn_values = [
        _normalized_turn_count(record.get("protocol_normalized_turns"))
        for record in scoreable_records
    ]
    protocol_normalized_turn_total = sum(normalized_turn_values)
    protocol_normalized_episodes = sum(
        1 for value in normalized_turn_values if value > 0
    )
    report: dict[str, Any] = {
        "schema": SUITE_REPORT_SCHEMA,
        "benchmark": {
            "name": "Operational Agent Benchmark",
            "version": 2,
            "primary_metric": "deterministic_contract_completion_rate",
        },
        "requested_route": requested_route,
        "reasoning_effort": reasoning_effort,
        "controller_config_sha256": controller_config_sha256,
        "release_tree_sha256": release_tree_sha256,
        "release_approval_sha256": release_approval_sha256,
        "release_authorized": release_authorized,
        "repetitions": repetitions,
        "pair_ids": list(pair_ids),
        "authoritative_stage": stage_binding,
        "authoritative": authoritative,
        "identity_source": identity_source,
        "execution_environment": execution_environment,
        "controller_usage": _aggregate_controller_usage(indexed.values()),
        "claim_scope": (
            f"{len(pair_ids)} matched pairs x {repetitions} repetitions on the recorded "
            "strict execution configuration"
        ),
        "non_authoritative_reason": (
            None
            if authoritative
            else "suite is not authoritative: "
            + ",".join(sorted(authority_blocking_flags.intersection(integrity_flags)))
        ),
        "scheduled_episodes": scheduled,
        "infrastructure_valid_episodes": infrastructure_valid,
        "infrastructure_invalid_episodes": infrastructure_invalid,
        "infrastructure_coverage_rate": _as_rate(infrastructure_valid, scheduled),
        "completed_contract_episodes": completed,
        "deterministic_contract_completion_rate": (
            _as_rate(completed, infrastructure_valid)
            if infrastructure_valid > 0
            else None
        ),
        "matched_pair_slots": matched_slots,
        "matched_pair_scoreable_slots": matched_scoreable_slots,
        "matched_pair_invalid_slots": matched_invalid_slots,
        "matched_pair_successes": matched_successes,
        "matched_pair_completion_rate": (
            _as_rate(matched_successes, matched_scoreable_slots)
            if matched_scoreable_slots > 0
            else None
        ),
        "pair_stability": {
            "mean": (sum(stabilities) / len(stabilities)) if stabilities else None,
            "min": min_stability,
            "min_pair_id": min_pair_id,
        },
        "pairs": pair_rows,
        "gate_failures": suite_gate_failures,
        "first_failing_gate": suite_first_failing,
        "diagnostic_gate_pass_rate": (
            _as_rate(suite_gate_passed, suite_gate_total)
            if suite_gate_total > 0
            else None
        ),
        "protocol_normalized_turn_total": protocol_normalized_turn_total,
        "protocol_normalized_episodes": protocol_normalized_episodes,
        "integrity_flags": integrity_flags,
        "observations": normalized_observations,
        "headline": "",
    }
    report["headline"] = format_headline(report)
    return report


def format_headline(report: Mapping[str, object]) -> str:
    route = str(report.get("requested_route") or "unknown-route")
    identity = str(report.get("identity_source") or "unknown")
    effort = str(report.get("reasoning_effort") or "unattested")
    completed = _as_int(report.get("completed_contract_episodes"))
    scheduled = _as_int(report.get("scheduled_episodes"))
    infrastructure_valid = _as_int(report.get("infrastructure_valid_episodes"))
    coverage = _as_float(report.get("infrastructure_coverage_rate"))
    if infrastructure_valid <= 0:
        return (
            f"NO SCORE | route={route} | reasoning_effort={effort} | "
            f"identity_source={identity} | infrastructure_coverage: "
            f"{coverage * 100:.1f}% (0/{scheduled}) | Infrastructure-invalid "
            "episodes are excluded, not model failures."
        )

    raw_rate = report.get("deterministic_contract_completion_rate")
    rate = _as_float(raw_rate)
    raw_matched = report.get("matched_pair_completion_rate")
    matched_text = (
        f"{_as_float(raw_matched) * 100:.1f}%"
        if isinstance(raw_matched, (int, float))
        else "n/a"
    )
    stability = report.get("pair_stability")
    min_stability: float | None = None
    min_pair = "?"
    if isinstance(stability, Mapping):
        raw_min = stability.get("min")
        if isinstance(raw_min, (int, float)):
            min_stability = float(raw_min)
        min_pair = str(stability.get("min_pair_id") or "?")
    stability_text = (
        f"{min_stability * 100:.1f}% ({min_pair})"
        if min_stability is not None
        else "n/a"
    )
    complete_coverage = infrastructure_valid == scheduled and scheduled > 0
    if not complete_coverage:
        posture = "INCOMPLETE"
        release = "Coverage incomplete; do not compare as a certified score."
    else:
        posture = "PROVISIONAL" if report.get("authoritative") is not True else "AUTHORITATIVE"
        release = (
            "Do not treat as release-ready."
            if report.get("authoritative") is not True
            else "Authoritative only for this exact suite/route/runtime."
        )
    top_gate_text = ""
    if completed < infrastructure_valid:
        gate_failures = report.get("gate_failures")
        if isinstance(gate_failures, Mapping) and gate_failures:
            ranked = sorted(
                (
                    (
                        str(gate_id),
                        _as_int(entry.get("failed")),
                        _as_int(entry.get("evaluated")),
                    )
                    for gate_id, entry in gate_failures.items()
                    if isinstance(entry, Mapping)
                ),
                key=lambda row: (-row[1], row[0]),
            )
            if ranked and ranked[0][1] > 0:
                gate_id, failed, evaluated = ranked[0]
                top_gate_text = f" | top_gate_failure: {gate_id} ({failed}/{evaluated})"
    return (
        f"{posture} | route={route} | reasoning_effort={effort} | identity_source={identity} | "
        f"infrastructure_coverage: {coverage * 100:.1f}% "
        f"({infrastructure_valid}/{scheduled}) | "
        f"deterministic_contract_completion_rate: {rate * 100:.1f}% "
        f"({completed}/{infrastructure_valid}) | "
        f"matched_pair_completion_rate: {matched_text} | "
        f"pair_stability_min: {stability_text}{top_gate_text} | {release}"
    )


def validate_suite_report(report: Mapping[str, object]) -> list[str]:
    errors: list[str] = []
    if report.get("schema") != SUITE_REPORT_SCHEMA:
        errors.append("schema_invalid")
    benchmark = report.get("benchmark")
    if not isinstance(benchmark, Mapping):
        errors.append("benchmark_missing")
    elif benchmark.get("primary_metric") != "deterministic_contract_completion_rate":
        errors.append("primary_metric_missing")
    elif "deterministic_contract_completion_rate" not in report:
        errors.append("primary_metric_missing")
    if "deterministic_contract_completion_rate" not in report:
        errors.append("primary_metric_missing")
    for key in (
        "requested_route",
        "scheduled_episodes",
        "completed_contract_episodes",
        "matched_pair_slots",
        "matched_pair_successes",
        "matched_pair_completion_rate",
        "pair_stability",
        "pairs",
        "identity_source",
        "authoritative",
        "execution_environment",
        "gate_failures",
        "first_failing_gate",
        "diagnostic_gate_pass_rate",
    ):
        if key not in report:
            errors.append(f"{key}_missing")
    for key in ("gate_failures", "first_failing_gate"):
        if key in report and not isinstance(report.get(key), Mapping):
            errors.append(f"{key}_invalid")
    stability = report.get("pair_stability")
    if not isinstance(stability, Mapping) or "mean" not in stability or "min" not in stability:
        errors.append("pair_stability_invalid")
    if not isinstance(report.get("pairs"), list):
        errors.append("pairs_invalid")
    environment = report.get("execution_environment")
    if (
        not isinstance(environment, Mapping)
        or not isinstance(environment.get("platform"), str)
        or not environment.get("platform")
        or not isinstance(environment.get("sandbox_backend"), str)
        or not environment.get("sandbox_backend")
    ):
        errors.append("execution_environment_invalid")
    return sorted(set(errors))
