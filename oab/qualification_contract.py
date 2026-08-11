"""The explicit, score-free OAB qualification-readiness/v1 contract.

The module owns the signed tuple and the pure report/retry/accounting rules used
by the campaign orchestrator, the isolated child runner, and the qualification
seal verifier.  It deliberately contains no provider or model identity branch.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any, Mapping, Sequence

QUALIFICATION_CONTRACT_ID = "oab.qualification-readiness/v1"
QUALIFICATION_REPORT_SCHEMA = "oab.qualification-suite-report/v1"
QUALIFICATION_PROBE_RESULT_SCHEMA = "oab.qualification-probe-result/v1"
QUALIFICATION_CHILD_RESULT_SCHEMA = "oab.qualification-child-result/v1"
QUALIFICATION_EXECUTION_MODE = "qualification_readiness_v1"
QUALIFICATION_SEAL_MODE = "qualification_readiness_v1"

PAIR_ID = "P01"
APPROVED_CASE_ID = "oab2-data-rollup-a"
PROHIBITED_CASE_ID = "oab2-data-rollup-p"
REPETITIONS = 1
LOGICAL_PROBES_PER_ROUTE = 2
MAX_BROKER_STEPS_PER_PROBE = 4
MAX_API_CALLS_PER_PHYSICAL_ATTEMPT = 4
MIN_API_CALLS_PER_READY_PHYSICAL_PROBE = 2
FIRST_ATTEMPT_API_CALL_CEILING_PER_ROUTE = 8
MAX_INFRASTRUCTURE_RETRIES_PER_PROBE = 1
MAX_PHYSICAL_ATTEMPTS_PER_ROUTE = 4
ABSOLUTE_API_CALL_CEILING_PER_ROUTE = 16

TRANSIENT_INFRASTRUCTURE_REASONS = frozenset(
    {
        "provider_rate_limited",
        "provider_unavailable",
        "controller_infrastructure_invalid",
    }
)

TELEMETRY_FIELDS = (
    "api_calls",
    "input_tokens",
    "output_tokens",
    "latency_ms",
    "cost_usd",
    "known_cost_usd",
    "unknown_cost_api_calls",
)
IDENTITY_FIELDS = (
    "adapter_name",
    "adapter_version",
    "adapter_sha256",
    "requested_route",
    "returned_route",
    "response_id",
    "identity_source",
    "execution_class",
    "controller_executable_sha256",
    "reasoning_effort",
    "controller_config_sha256",
)
RUNTIME_FIELDS = (
    "python_executable_sha256",
    "leaf_worker_sha256",
    "platform",
    "sandbox_backend",
)
REPORT_FIELDS = frozenset(
    {
        "schema",
        "execution_mode",
        "qualification_contract",
        "requested_route",
        "reasoning_effort",
        "release_tree_sha256",
        "controller_config_sha256",
        "created_at",
        "readiness",
        "reason_codes",
        "probes",
        "attempts",
        "controller_usage",
        "headline",
    }
)
PROBE_FIELDS = frozenset(
    {
        "probe_id",
        "pair_id",
        "case_id",
        "variant",
        "repetition",
        "selected_attempt",
        "readiness",
        "reason_codes",
    }
)
ATTEMPT_FIELDS = frozenset(
    {
        "attempt_id",
        "probe_id",
        "attempt_number",
        "attempt_kind",
        "retry_trigger",
        "runner_status",
        "readiness_evidence",
        "reason_codes",
        "identity",
        "telemetry",
        "runtime",
        "trace_sha256",
        "output_tree_sha256",
        "evidence_dir",
    }
)
CHILD_RESULT_FIELDS = frozenset(
    {
        "schema",
        "readiness",
        "reason_codes",
        "controller_usage",
        "suite_report_path",
        "suite_seal_path",
        "suite_seal_sha256",
    }
)
PROBE_RESULT_FIELDS = frozenset(
    {
        "schema",
        "case_id",
        "repetition",
        "status",
        "execution_class",
        "reason_codes",
        "controller_identity",
        "controller_usage",
        "protocol_normalized_turns",
        "runtime",
        "trace_sha256",
        "output_tree_sha256",
        "readiness_evidence",
    }
)
QUALIFICATION_SEAL_FIELDS = frozenset(
    {
        "schema",
        "execution_mode",
        "suite_report_sha256",
        "headline_sha256",
        "release_tree_sha256",
        "qualification_contract",
        "requested_route",
        "reasoning_effort",
        "physical_attempts",
        "selected_attempts",
        "content_sha256",
    }
)

# Positive schemas are the primary boundary. This extra recursive tripwire keeps
# future additions from accidentally reintroducing a generic evaluation field.
_FORBIDDEN_FIELD_FRAGMENTS = (
    "score",
    "_rate",
    "percentage",
    "pair_stability",
    "valid_for_scoring",
    "valid_for_calibration",
    "switch",
)
_FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "rate",
        "deterministic_contract_completion_rate",
        "matched_pair_completion_rate",
        "completion_rate",
        "gate_pass_rate",
        "infrastructure_valid_episodes",
        "infrastructure_invalid_episodes",
        "observations",
        "valid_for_authoritative_scoring",
        "release_authorized",
    }
)


PROBE_DEFINITIONS: tuple[dict[str, object], ...] = (
    {
        "probe_id": "P01-approved-r1",
        "pair_id": PAIR_ID,
        "case_id": APPROVED_CASE_ID,
        "variant": "approved",
        "repetition": REPETITIONS,
    },
    {
        "probe_id": "P01-prohibited-r1",
        "pair_id": PAIR_ID,
        "case_id": PROHIBITED_CASE_ID,
        "variant": "prohibited",
        "repetition": REPETITIONS,
    },
)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json_int(value: object, *, minimum: int, maximum: int | None = None) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        return None
    if maximum is not None and value > maximum:
        return None
    return value


def _finite_number(value: object, *, minimum: float = 0.0) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        return None
    return result


def _digest_or_none(value: object) -> bool:
    return value is None or (
        isinstance(value, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def qualification_contract_for_route_count(route_count: int) -> dict[str, object]:
    """Return the exact tuple covered by a campaign PLAN digest."""
    if _json_int(route_count, minimum=1) is None:
        raise ValueError("qualification_execution_contract_invalid")
    return {
        "contract_id": QUALIFICATION_CONTRACT_ID,
        "pair_ids": [PAIR_ID],
        "repetitions": REPETITIONS,
        "case_ids_by_pair": {
            PAIR_ID: {
                "approved": APPROVED_CASE_ID,
                "prohibited": PROHIBITED_CASE_ID,
            }
        },
        "logical_probes_per_route": LOGICAL_PROBES_PER_ROUTE,
        "episodes_per_route": LOGICAL_PROBES_PER_ROUTE,
        "scheduled_episodes": route_count * LOGICAL_PROBES_PER_ROUTE,
        "max_broker_steps_per_probe": MAX_BROKER_STEPS_PER_PROBE,
        "max_api_calls_per_physical_attempt": MAX_API_CALLS_PER_PHYSICAL_ATTEMPT,
        "min_api_calls_per_ready_physical_attempt": (
            MIN_API_CALLS_PER_READY_PHYSICAL_PROBE
        ),
        "first_attempt_api_call_ceiling_per_route": (
            FIRST_ATTEMPT_API_CALL_CEILING_PER_ROUTE
        ),
        "max_infrastructure_retries_per_probe": (
            MAX_INFRASTRUCTURE_RETRIES_PER_PROBE
        ),
        "max_physical_attempts_per_route": MAX_PHYSICAL_ATTEMPTS_PER_ROUTE,
        "absolute_api_call_ceiling_per_route": ABSOLUTE_API_CALL_CEILING_PER_ROUTE,
    }


def validate_qualification_contract(
    value: object,
    *,
    route_count: int | None = None,
) -> dict[str, object]:
    """Return an exact contract copy or reject omission, drift, and extension."""
    if not isinstance(value, Mapping):
        raise ValueError("qualification_execution_contract_invalid")
    scheduled = _json_int(value.get("scheduled_episodes"), minimum=LOGICAL_PROBES_PER_ROUTE)
    if scheduled is None or scheduled % LOGICAL_PROBES_PER_ROUTE:
        raise ValueError("qualification_execution_contract_invalid")
    inferred_route_count = scheduled // LOGICAL_PROBES_PER_ROUTE
    if route_count is not None:
        if _json_int(route_count, minimum=1) is None or route_count != inferred_route_count:
            raise ValueError("qualification_execution_contract_invalid")
    expected = qualification_contract_for_route_count(
        route_count if route_count is not None else inferred_route_count
    )
    if dict(value) != expected:
        raise ValueError("qualification_execution_contract_invalid")
    return expected


def qualification_probe_definitions() -> list[dict[str, object]]:
    """Return independent copies in fixed approved-then-prohibited order."""
    return [dict(probe) for probe in PROBE_DEFINITIONS]


def telemetry_projection(value: object) -> dict[str, object]:
    raw = value if isinstance(value, Mapping) else {}
    return {field: raw.get(field) for field in TELEMETRY_FIELDS}


def telemetry_errors(
    telemetry: object,
    *,
    per_attempt: bool = True,
) -> list[str]:
    if not isinstance(telemetry, Mapping) or set(telemetry) != set(TELEMETRY_FIELDS):
        return ["controller_usage_invalid"]
    api_calls = _json_int(
        telemetry.get("api_calls"),
        minimum=0,
        maximum=MAX_API_CALLS_PER_PHYSICAL_ATTEMPT if per_attempt else None,
    )
    input_tokens = _json_int(telemetry.get("input_tokens"), minimum=0)
    output_tokens = _json_int(telemetry.get("output_tokens"), minimum=0)
    latency = _finite_number(telemetry.get("latency_ms"))
    cost_value = telemetry.get("cost_usd")
    cost = None if cost_value is None else _finite_number(cost_value)
    known = _finite_number(telemetry.get("known_cost_usd"))
    unknown = _json_int(telemetry.get("unknown_cost_api_calls"), minimum=0)
    if (
        api_calls is None
        or input_tokens is None
        or output_tokens is None
        or latency is None
        or (cost_value is not None and cost is None)
        or known is None
        or unknown is None
    ):
        return ["controller_usage_invalid"]
    assert api_calls is not None
    assert known is not None
    assert unknown is not None
    # Telemetry has exactly two valid accounting states.  A numeric total is a
    # fully priced receipt and must equal the known-cost subtotal at canonical
    # money precision.  A null total is not a zero: it is valid only when one
    # or more provider calls are explicitly declared unpriced.
    if cost_value is None:
        if not (api_calls >= 1 and 1 <= unknown <= api_calls):
            return ["controller_usage_invalid"]
    else:
        assert cost is not None
        if unknown != 0 or round(cost, 12) != round(known, 12):
            return ["controller_usage_invalid"]
        if api_calls == 0 and (round(cost, 12) != 0.0 or round(known, 12) != 0.0):
            return ["controller_usage_invalid"]
    return []


def aggregate_telemetry(attempts: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Aggregate all physical attempts without zero-coercing missing telemetry."""
    rows = [telemetry_projection(attempt.get("telemetry")) for attempt in attempts]

    def sum_int(field: str) -> int | None:
        values = [_json_int(row.get(field), minimum=0) for row in rows]
        return sum(values) if all(value is not None for value in values) else None

    def sum_number(field: str, *, nullable: bool = False) -> float | None:
        values: list[float | None] = []
        for row in rows:
            raw = row.get(field)
            if nullable and raw is None:
                return None
            values.append(_finite_number(raw))
        return round(sum(value for value in values if value is not None), 12) if all(
            value is not None for value in values
        ) else None

    return {
        "api_calls": sum_int("api_calls"),
        "input_tokens": sum_int("input_tokens"),
        "output_tokens": sum_int("output_tokens"),
        "latency_ms": sum_number("latency_ms"),
        "cost_usd": sum_number("cost_usd", nullable=True),
        "known_cost_usd": sum_number("known_cost_usd"),
        "unknown_cost_api_calls": sum_int("unknown_cost_api_calls"),
    }


def identity_projection(value: object) -> dict[str, object]:
    raw = value if isinstance(value, Mapping) else {}
    return {field: raw.get(field) for field in IDENTITY_FIELDS}


def runtime_projection(value: object) -> dict[str, object]:
    raw = value if isinstance(value, Mapping) else {}
    return {field: raw.get(field) for field in RUNTIME_FIELDS}


def _identity_ready(identity: object, *, route: str, effort: str) -> bool:
    if not isinstance(identity, Mapping) or set(identity) != set(IDENTITY_FIELDS):
        return False
    required = (
        "adapter_name",
        "adapter_version",
        "adapter_sha256",
        "requested_route",
        "returned_route",
        "response_id",
        "identity_source",
        "execution_class",
        "reasoning_effort",
        "controller_config_sha256",
    )
    if any(not isinstance(identity.get(field), str) or not identity.get(field) for field in required):
        return False
    return (
        identity.get("requested_route") == route
        and identity.get("returned_route") == route
        and identity.get("reasoning_effort") == effort
        and identity.get("execution_class") == "model"
        and identity.get("identity_source") in {"provider_response", "adapter_runtime"}
        and _digest_or_none(identity.get("adapter_sha256"))
        and _digest_or_none(identity.get("controller_config_sha256"))
        and (
            identity.get("controller_executable_sha256") is None
            or _digest_or_none(identity.get("controller_executable_sha256"))
        )
    )


def _sorted_reason_codes(value: object) -> list[str] | None:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        return None
    if value != sorted(set(value)):
        return None
    return list(value)


def retry_eligible(attempt: Mapping[str, object]) -> bool:
    """Return the typed, adapter-neutral one-retry predicate."""
    reasons = _sorted_reason_codes(attempt.get("reason_codes"))
    telemetry = attempt.get("telemetry")
    unknown_cost_calls = (
        _json_int(telemetry.get("unknown_cost_api_calls"), minimum=0)
        if isinstance(telemetry, Mapping)
        else None
    )
    return (
        attempt.get("attempt_number") == 1
        and attempt.get("runner_status") == "runner_invalid"
        and reasons is not None
        and bool(reasons)
        and set(reasons).issubset(TRANSIENT_INFRASTRUCTURE_REASONS)
        and not telemetry_errors(telemetry, per_attempt=True)
        # A signed policy may permit later independent calls with unknown dollars,
        # but an unpriced failed attempt can never authorize a retry of itself.
        and unknown_cost_calls == 0
    )


def attempt_id_for(probe: Mapping[str, object], attempt_number: int) -> str:
    variant = probe.get("variant")
    if variant not in {"approved", "prohibited"} or attempt_number not in {1, 2}:
        raise ValueError("qualification_attempt_invalid")
    return f"P01-{variant}-attempt-{attempt_number:02d}"


def evidence_dir_for(probe: Mapping[str, object], attempt_number: int) -> str:
    case_id = probe.get("case_id")
    if not isinstance(case_id, str) or attempt_number not in {1, 2}:
        raise ValueError("qualification_attempt_invalid")
    return f"evidence/rep-01/{case_id}/attempt-{attempt_number:02d}"


def attempt_readiness(
    *,
    runner_status: str,
    reason_codes: Sequence[str],
    identity: Mapping[str, object],
    telemetry: Mapping[str, object],
    probe_contract_satisfied: bool,
    requested_route: str,
    reasoning_effort: str,
) -> bool:
    api_calls = (
        _json_int(
            telemetry.get("api_calls"),
            minimum=MIN_API_CALLS_PER_READY_PHYSICAL_PROBE,
            maximum=MAX_API_CALLS_PER_PHYSICAL_ATTEMPT,
        )
        if isinstance(telemetry, Mapping)
        else None
    )
    return (
        runner_status == "completed"
        and not reason_codes
        and probe_contract_satisfied
        and _identity_ready(identity, route=requested_route, effort=reasoning_effort)
        and not telemetry_errors(telemetry, per_attempt=True)
        and api_calls is not None
    )


def build_physical_attempt(
    *,
    probe: Mapping[str, object],
    attempt_number: int,
    runner_status: object,
    reason_codes: object,
    identity: object,
    telemetry: object,
    runtime: object,
    trace_sha256: object,
    output_tree_sha256: object,
    probe_contract_satisfied: bool,
    requested_route: str,
    reasoning_effort: str,
) -> dict[str, object]:
    """Construct one canonical physical-attempt descriptor from raw strict evidence."""
    if not isinstance(runner_status, str):
        raise ValueError("qualification_attempt_evidence_invalid")
    raw_reasons = _sorted_reason_codes(reason_codes)
    if raw_reasons is None:
        raise ValueError("qualification_attempt_evidence_invalid")
    identity_value = identity_projection(identity)
    telemetry_value = telemetry_projection(telemetry)
    runtime_value = runtime_projection(runtime)
    reasons = set(raw_reasons)
    if telemetry_errors(telemetry_value, per_attempt=True):
        reasons.add("controller_usage_invalid")
    api_calls = _json_int(
        telemetry_value.get("api_calls"),
        minimum=0,
        maximum=MAX_API_CALLS_PER_PHYSICAL_ATTEMPT,
    )
    if (
        runner_status == "completed"
        and api_calls is not None
        and api_calls < MIN_API_CALLS_PER_READY_PHYSICAL_PROBE
    ):
        # A completed P01 probe must independently prove a real two-turn tool
        # loop.  Aggregate route spend cannot mask a zero- or one-call row.
        reasons.add("qualification_probe_calls_insufficient")
    if not probe_contract_satisfied:
        reasons.add("probe_contract_unsatisfied")
    sorted_reasons = sorted(reasons)
    readiness = attempt_readiness(
        runner_status=runner_status,
        reason_codes=sorted_reasons,
        identity=identity_value,
        telemetry=telemetry_value,
        probe_contract_satisfied=probe_contract_satisfied,
        requested_route=requested_route,
        reasoning_effort=reasoning_effort,
    )
    return {
        "attempt_id": attempt_id_for(probe, attempt_number),
        "probe_id": probe["probe_id"],
        "attempt_number": attempt_number,
        "attempt_kind": "primary" if attempt_number == 1 else "infrastructure_retry",
        "retry_trigger": None if attempt_number == 1 else attempt_id_for(probe, 1),
        "runner_status": runner_status,
        "readiness_evidence": readiness,
        "reason_codes": sorted_reasons,
        "identity": identity_value,
        "telemetry": telemetry_value,
        "runtime": runtime_value,
        "trace_sha256": trace_sha256 if _digest_or_none(trace_sha256) else None,
        "output_tree_sha256": output_tree_sha256 if _digest_or_none(output_tree_sha256) else None,
        "evidence_dir": evidence_dir_for(probe, attempt_number),
    }


def _probe_outcome(attempt: Mapping[str, object]) -> tuple[str, list[str]]:
    reasons = _sorted_reason_codes(attempt.get("reason_codes")) or []
    if attempt.get("readiness_evidence") is True:
        return "READY", []
    if "controller_step_limit_exceeded" in reasons:
        return "INCOMPATIBLE", reasons
    return "NOT_READY", reasons or ["probe_contract_unsatisfied"]


def _quality_free(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError("qualification_quality_field_invalid")
            lowered = key.lower()
            if key in _FORBIDDEN_FIELD_NAMES or any(
                fragment in lowered for fragment in _FORBIDDEN_FIELD_FRAGMENTS
            ):
                raise ValueError("qualification_quality_field_invalid")
            _quality_free(nested)
    elif isinstance(value, list):
        for nested in value:
            _quality_free(nested)


def assert_quality_free(value: object) -> None:
    """Raise when a prospective readiness artifact has a generic-quality field."""
    _quality_free(value)


def _validate_attempt_shape(
    attempt: object,
    *,
    probe: Mapping[str, object],
    requested_route: str,
    reasoning_effort: str,
) -> dict[str, object]:
    if not isinstance(attempt, Mapping) or set(attempt) != ATTEMPT_FIELDS:
        raise ValueError("qualification_attempt_fields_invalid")
    attempt_value = dict(attempt)
    number = _json_int(attempt_value.get("attempt_number"), minimum=1, maximum=2)
    if (
        number is None
        or attempt_value.get("probe_id") != probe["probe_id"]
        or attempt_value.get("attempt_id") != attempt_id_for(probe, number)
        or attempt_value.get("evidence_dir") != evidence_dir_for(probe, number)
        or not isinstance(attempt_value.get("runner_status"), str)
        or not isinstance(attempt_value.get("readiness_evidence"), bool)
        or not _digest_or_none(attempt_value.get("trace_sha256"))
        or not _digest_or_none(attempt_value.get("output_tree_sha256"))
    ):
        raise ValueError("qualification_attempt_identity_invalid")
    if number == 1:
        if attempt_value.get("attempt_kind") != "primary" or attempt_value.get("retry_trigger") is not None:
            raise ValueError("qualification_attempt_retry_invalid")
    else:
        if (
            attempt_value.get("attempt_kind") != "infrastructure_retry"
            or attempt_value.get("retry_trigger") != attempt_id_for(probe, 1)
        ):
            raise ValueError("qualification_attempt_retry_invalid")
    reasons = _sorted_reason_codes(attempt_value.get("reason_codes"))
    if reasons is None:
        raise ValueError("qualification_attempt_reasons_invalid")
    identity = attempt_value.get("identity")
    runtime = attempt_value.get("runtime")
    if not isinstance(identity, Mapping) or set(identity) != set(IDENTITY_FIELDS):
        raise ValueError("qualification_attempt_identity_invalid")
    if not isinstance(runtime, Mapping) or set(runtime) != set(RUNTIME_FIELDS):
        raise ValueError("qualification_attempt_runtime_invalid")
    if not isinstance(attempt_value.get("telemetry"), Mapping) or set(
        attempt_value["telemetry"]
    ) != set(TELEMETRY_FIELDS):
        raise ValueError("qualification_attempt_telemetry_invalid")
    # The claimed boolean must be an honest projection of the raw fields. A
    # false value may reflect a failed deterministic probe gate, hence only the
    # true direction is fully recomputable at this pure boundary.
    if attempt_value["readiness_evidence"] is True and not attempt_readiness(
        runner_status=str(attempt_value["runner_status"]),
        reason_codes=reasons,
        identity=dict(identity),
        telemetry=dict(attempt_value["telemetry"]),
        probe_contract_satisfied=True,
        requested_route=requested_route,
        reasoning_effort=reasoning_effort,
    ):
        raise ValueError("qualification_attempt_readiness_invalid")
    return attempt_value


def _partial_stop_reason(attempt: Mapping[str, object]) -> str | None:
    reasons = _sorted_reason_codes(attempt.get("reason_codes")) or []
    if "controller_cost_telemetry_unknown" in reasons:
        return "qualification_stopped_unknown_cost"
    if telemetry_errors(attempt.get("telemetry"), per_attempt=True):
        return "qualification_stopped_invalid_telemetry"
    return None


def format_qualification_headline(report: Mapping[str, object]) -> str:
    usage = report.get("controller_usage")
    api_calls = usage.get("api_calls") if isinstance(usage, Mapping) else None
    call_text = str(api_calls) if _json_int(api_calls, minimum=0) is not None else "unknown"
    attempts = report.get("attempts")
    physical_count = len(attempts) if isinstance(attempts, list) else "unknown"
    return (
        "QUALIFICATION_READINESS"
        f" | route={report.get('requested_route')}"
        f" | readiness={report.get('readiness')}"
        f" | physical_attempts={physical_count}"
        f" | provider_calls={call_text}"
    )


def build_qualification_report(
    *,
    qualification_contract: Mapping[str, object],
    requested_route: str,
    reasoning_effort: str,
    release_tree_sha256: str | None,
    controller_config_sha256: str | None,
    created_at: str,
    attempts: Sequence[Mapping[str, object]],
    stopped_before_probe: str | None = None,
) -> dict[str, object]:
    """Construct a positive-whitelist readiness report from all physical attempts."""
    contract = validate_qualification_contract(qualification_contract)
    rows = [dict(attempt) for attempt in attempts]
    by_probe: dict[str, list[dict[str, object]]] = {
        str(probe["probe_id"]): [] for probe in PROBE_DEFINITIONS
    }
    for row in rows:
        probe_id = row.get("probe_id")
        if isinstance(probe_id, str) and probe_id in by_probe:
            by_probe[probe_id].append(row)
    probes: list[dict[str, object]] = []
    for probe in PROBE_DEFINITIONS:
        probe_id = str(probe["probe_id"])
        physical = by_probe[probe_id]
        if physical:
            selected = physical[-1]
            readiness, reasons = _probe_outcome(selected)
            selected_attempt: str | None = str(selected.get("attempt_id"))
        else:
            selected_attempt = None
            readiness = "NOT_READY"
            reasons = [stopped_before_probe or "qualification_not_started"]
        probes.append(
            {
                **probe,
                "selected_attempt": selected_attempt,
                "readiness": readiness,
                "reason_codes": sorted(set(reasons)),
            }
        )
    route_reasons = sorted(
        {
            reason
            for probe in probes
            for reason in probe["reason_codes"]
            if isinstance(reason, str)
        }
    )
    usage = aggregate_telemetry(rows)
    selected_ready = all(probe["readiness"] == "READY" for probe in probes)
    all_selected = all(probe["selected_attempt"] is not None for probe in probes)
    api_calls = usage.get("api_calls")
    if (
        selected_ready
        and all_selected
        and _json_int(api_calls, minimum=0, maximum=ABSOLUTE_API_CALL_CEILING_PER_ROUTE)
        is not None
        and not telemetry_errors(usage, per_attempt=False)
    ):
        readiness = "READY"
    elif all(probe["readiness"] == "INCOMPATIBLE" for probe in probes if probe["selected_attempt"]):
        readiness = "INCOMPATIBLE"
    else:
        readiness = "NOT_READY"
    report: dict[str, object] = {
        "schema": QUALIFICATION_REPORT_SCHEMA,
        "execution_mode": QUALIFICATION_EXECUTION_MODE,
        "qualification_contract": contract,
        "requested_route": requested_route,
        "reasoning_effort": reasoning_effort,
        "release_tree_sha256": release_tree_sha256,
        "controller_config_sha256": controller_config_sha256,
        "created_at": created_at,
        "readiness": readiness,
        "reason_codes": route_reasons,
        "probes": probes,
        "attempts": rows,
        "controller_usage": usage,
        "headline": "",
    }
    report["headline"] = format_qualification_headline(report)
    validate_qualification_report(report)
    return report


def validate_qualification_report(report: object) -> dict[str, object]:
    """Validate all report/retry/accounting invariants without generic aggregation."""
    if not isinstance(report, Mapping) or set(report) != REPORT_FIELDS:
        raise ValueError("qualification_report_fields_invalid")
    value = dict(report)
    if (
        value.get("schema") != QUALIFICATION_REPORT_SCHEMA
        or value.get("execution_mode") != QUALIFICATION_EXECUTION_MODE
        or not isinstance(value.get("requested_route"), str)
        or not value.get("requested_route")
        or not isinstance(value.get("reasoning_effort"), str)
        or not value.get("reasoning_effort")
        or not isinstance(value.get("created_at"), str)
        or not value.get("created_at")
        or value.get("readiness") not in {"READY", "NOT_READY", "INCOMPATIBLE"}
        or not _digest_or_none(value.get("release_tree_sha256"))
        or not _digest_or_none(value.get("controller_config_sha256"))
    ):
        raise ValueError("qualification_report_metadata_invalid")
    contract = validate_qualification_contract(value.get("qualification_contract"))
    del contract
    report_reasons = _sorted_reason_codes(value.get("reason_codes"))
    if report_reasons is None:
        raise ValueError("qualification_report_reasons_invalid")
    raw_probes = value.get("probes")
    raw_attempts = value.get("attempts")
    if not isinstance(raw_probes, list) or not isinstance(raw_attempts, list):
        raise ValueError("qualification_report_shape_invalid")
    if len(raw_probes) != LOGICAL_PROBES_PER_ROUTE or len(raw_attempts) > MAX_PHYSICAL_ATTEMPTS_PER_ROUTE:
        raise ValueError("qualification_report_shape_invalid")
    if not raw_attempts:
        raise ValueError("qualification_report_shape_invalid")
    expected_probes = qualification_probe_definitions()
    probes_by_id: dict[str, dict[str, object]] = {}
    for expected, raw_probe in zip(expected_probes, raw_probes):
        if not isinstance(raw_probe, Mapping) or set(raw_probe) != PROBE_FIELDS:
            raise ValueError("qualification_probe_fields_invalid")
        probe = dict(raw_probe)
        fixed = {key: probe.get(key) for key in expected}
        if fixed != expected or probe.get("readiness") not in {"READY", "NOT_READY", "INCOMPATIBLE"}:
            raise ValueError("qualification_probe_identity_invalid")
        selected = probe.get("selected_attempt")
        if selected is not None and not isinstance(selected, str):
            raise ValueError("qualification_probe_selection_invalid")
        if _sorted_reason_codes(probe.get("reason_codes")) is None:
            raise ValueError("qualification_probe_reasons_invalid")
        probes_by_id[str(expected["probe_id"])] = probe

    attempts_by_probe: dict[str, list[dict[str, object]]] = {
        str(probe["probe_id"]): [] for probe in expected_probes
    }
    normalized_attempts: list[dict[str, object]] = []
    for raw_attempt in raw_attempts:
        probe_id = raw_attempt.get("probe_id") if isinstance(raw_attempt, Mapping) else None
        probe = next((item for item in expected_probes if item["probe_id"] == probe_id), None)
        if probe is None:
            raise ValueError("qualification_attempt_probe_invalid")
        attempt = _validate_attempt_shape(
            raw_attempt,
            probe=probe,
            requested_route=str(value["requested_route"]),
            reasoning_effort=str(value["reasoning_effort"]),
        )
        attempts_by_probe[str(probe_id)].append(attempt)
        normalized_attempts.append(attempt)

    # Primaries are a distinct phase: never retry one probe before the other has
    # had its first physical attempt. A genuine unknown/invalid telemetry stop is
    # the only permitted incomplete primary phase.
    approved, prohibited = expected_probes
    primary_order = [
        attempt_id_for(approved, 1),
        attempt_id_for(prohibited, 1),
    ]
    observed_order = [str(item["attempt_id"]) for item in normalized_attempts]
    if observed_order[: min(2, len(observed_order))] != primary_order[: min(2, len(observed_order))]:
        raise ValueError("qualification_attempt_order_invalid")
    if len(normalized_attempts) == 1:
        if _partial_stop_reason(normalized_attempts[0]) is None:
            raise ValueError("qualification_primary_phase_incomplete")
    else:
        for probe in expected_probes:
            rows = attempts_by_probe[str(probe["probe_id"])]
            if not rows or rows[0].get("attempt_number") != 1 or len(rows) > 2:
                raise ValueError("qualification_attempt_grid_invalid")
            if len(rows) == 2 and not retry_eligible(rows[0]):
                raise ValueError("qualification_retry_illegal")
        retry_order = [
            attempt_id_for(probe, 2)
            for probe in expected_probes
            if len(attempts_by_probe[str(probe["probe_id"])]) == 2
        ]
        if observed_order[2:] != retry_order:
            raise ValueError("qualification_attempt_order_invalid")

    expected_route_reasons: set[str] = set()
    selected_attempts: list[dict[str, object]] = []
    for probe in expected_probes:
        probe_id = str(probe["probe_id"])
        declared = probes_by_id[probe_id]
        physical = attempts_by_probe[probe_id]
        if physical:
            selected = physical[-1]
            expected_readiness, expected_reasons = _probe_outcome(selected)
            if (
                declared.get("selected_attempt") != selected.get("attempt_id")
                or declared.get("readiness") != expected_readiness
                or declared.get("reason_codes") != expected_reasons
            ):
                raise ValueError("qualification_probe_selection_invalid")
            selected_attempts.append(selected)
            expected_route_reasons.update(expected_reasons)
        else:
            if len(normalized_attempts) != 1:
                raise ValueError("qualification_attempt_grid_invalid")
            stop_reason = _partial_stop_reason(normalized_attempts[0])
            if stop_reason is None or (
                declared.get("selected_attempt") is not None
                or declared.get("readiness") != "NOT_READY"
                or declared.get("reason_codes") != [stop_reason]
            ):
                raise ValueError("qualification_probe_selection_invalid")
            expected_route_reasons.add(stop_reason)

    if report_reasons != sorted(expected_route_reasons):
        raise ValueError("qualification_report_reasons_invalid")
    expected_usage = aggregate_telemetry(normalized_attempts)
    if value.get("controller_usage") != expected_usage:
        raise ValueError("qualification_report_telemetry_mismatch")
    api_calls = expected_usage.get("api_calls")
    if api_calls is not None and (
        _json_int(api_calls, minimum=0, maximum=ABSOLUTE_API_CALL_CEILING_PER_ROUTE) is None
    ):
        raise ValueError("qualification_report_api_call_ceiling_invalid")

    all_selected_ready = (
        len(selected_attempts) == LOGICAL_PROBES_PER_ROUTE
        and all(item.get("readiness_evidence") is True for item in selected_attempts)
    )
    aggregate_telemetry_valid = not telemetry_errors(expected_usage, per_attempt=False)
    if all_selected_ready and api_calls is not None and aggregate_telemetry_valid:
        expected_readiness = "READY"
    elif selected_attempts and all(
        "controller_step_limit_exceeded" in (_sorted_reason_codes(item.get("reason_codes")) or [])
        for item in selected_attempts
    ):
        expected_readiness = "INCOMPATIBLE"
    else:
        expected_readiness = "NOT_READY"
    if value.get("readiness") != expected_readiness:
        raise ValueError("qualification_report_readiness_invalid")
    if value.get("headline") != format_qualification_headline(value):
        raise ValueError("qualification_headline_mismatch")
    if "%" in str(value.get("headline")):
        raise ValueError("qualification_headline_invalid")
    assert_quality_free(value)
    return value


def validate_child_result(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != CHILD_RESULT_FIELDS:
        raise ValueError("qualification_child_result_fields_invalid")
    result = dict(value)
    if (
        result.get("schema") != QUALIFICATION_CHILD_RESULT_SCHEMA
        or result.get("readiness") not in {"READY", "NOT_READY", "INCOMPATIBLE"}
        or _sorted_reason_codes(result.get("reason_codes")) is None
        or not isinstance(result.get("suite_report_path"), str)
        or not isinstance(result.get("suite_seal_path"), str)
        or not _digest_or_none(result.get("suite_seal_sha256"))
    ):
        raise ValueError("qualification_child_result_invalid")
    usage = result.get("controller_usage")
    if not isinstance(usage, Mapping) or set(usage) != set(TELEMETRY_FIELDS):
        raise ValueError("qualification_child_result_invalid")
    assert_quality_free(result)
    return result
