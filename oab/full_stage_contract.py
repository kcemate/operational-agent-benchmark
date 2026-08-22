"""Immutable authority tuple for OAB v2.3 full comparison campaigns.

Generic ``oab-run`` remains useful for exploratory/manual experiments.  This
module deliberately describes the only tuple that may carry campaign decision
or switch authority: eight ordered pairs, five repetitions, two variants per
pair, eighty episodes per route, at most seventeen provider calls per episode,
and at most 1,360 calls per route.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

FULL_STAGE_CONTRACT_SCHEMA = "oab.full-stage-contract/v1"
AUTHORITATIVE_STAGE_BINDING_SCHEMA = "oab.authoritative-stage-binding/v1"
AUTHORITATIVE_FULL_PAIR_IDS = tuple(f"P{number:02d}" for number in range(1, 9))
FULL_REPETITIONS = 5
FULL_VARIANTS_PER_PAIR = 2
FULL_EPISODES_PER_ROUTE = 80
FULL_MAX_API_CALLS_PER_EPISODE = 17
FULL_API_CALL_CEILING_PER_ROUTE = 1360

_FULL_CONTRACT_FIELDS = frozenset(
    {
        "schema",
        "pair_ids",
        "repetitions",
        "variants_per_pair",
        "episodes_per_route",
        "max_api_calls_per_episode",
        "api_call_ceiling_per_route",
    }
)
_FULL_PLAN_FIELDS = frozenset(
    {
        "authoritative_contract",
        "authoritative_contract_sha256",
        "planned_route_count",
        "scheduled_episodes",
    }
)
_AUTHORITY_BINDING_FIELDS = frozenset(
    {
        "schema",
        "stage",
        "plan_sha256",
        "full_contract",
        "full_contract_sha256",
        "execution_contract_sha256",
        "route_id",
        "output_relative_path",
    }
)
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


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


def canonical_full_stage_contract() -> dict[str, object]:
    """Return an independent copy of the sole decision-authoritative tuple."""
    return {
        "schema": FULL_STAGE_CONTRACT_SCHEMA,
        "pair_ids": list(AUTHORITATIVE_FULL_PAIR_IDS),
        "repetitions": FULL_REPETITIONS,
        "variants_per_pair": FULL_VARIANTS_PER_PAIR,
        "episodes_per_route": FULL_EPISODES_PER_ROUTE,
        "max_api_calls_per_episode": FULL_MAX_API_CALLS_PER_EPISODE,
        "api_call_ceiling_per_route": FULL_API_CALL_CEILING_PER_ROUTE,
    }


def full_stage_contract_sha256(contract: Mapping[str, object]) -> str:
    return sha256_bytes(canonical_bytes(dict(contract)))


def _route_count(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("authoritative_full_contract_invalid")
    return value


def validate_authoritative_full_stage_contract(value: object) -> dict[str, object]:
    """Reject all partial, reordered, custom, or caller-extended full tuples."""
    if not isinstance(value, Mapping) or set(value) != _FULL_CONTRACT_FIELDS:
        raise ValueError("authoritative_full_contract_invalid")
    expected = canonical_full_stage_contract()
    if dict(value) != expected:
        raise ValueError("authoritative_full_contract_invalid")
    return expected


def authoritative_full_contract_for_route_count(route_count: int) -> dict[str, object]:
    """Build the PLAN.full_run object from the fixed contract and route count."""
    count = _route_count(route_count)
    contract = canonical_full_stage_contract()
    return {
        "authoritative_contract": contract,
        "authoritative_contract_sha256": full_stage_contract_sha256(contract),
        "planned_route_count": count,
        "scheduled_episodes": count * FULL_EPISODES_PER_ROUTE,
    }


def validate_authoritative_full_stage_plan(
    value: object, *, route_count: int
) -> dict[str, object]:
    """Validate the exact PLAN.full_run authority binding and arithmetic."""
    count = _route_count(route_count)
    if not isinstance(value, Mapping) or set(value) != _FULL_PLAN_FIELDS:
        raise ValueError("authoritative_full_contract_invalid")
    contract = validate_authoritative_full_stage_contract(value.get("authoritative_contract"))
    if (
        value.get("authoritative_contract_sha256") != full_stage_contract_sha256(contract)
        or value.get("planned_route_count") != count
        or value.get("scheduled_episodes") != count * FULL_EPISODES_PER_ROUTE
    ):
        raise ValueError("authoritative_full_contract_invalid")
    return authoritative_full_contract_for_route_count(count)


def build_authoritative_stage_binding(
    *,
    plan_sha256: str,
    execution_contract_sha256: str,
    route_id: str,
    output_relative_path: str,
    full_plan: Mapping[str, object],
    route_count: int,
) -> dict[str, object]:
    full = validate_authoritative_full_stage_plan(full_plan, route_count=route_count)
    contract = validate_authoritative_full_stage_contract(full["authoritative_contract"])
    if (
        not isinstance(plan_sha256, str)
        or _DIGEST_RE.fullmatch(plan_sha256) is None
        or not isinstance(execution_contract_sha256, str)
        or _DIGEST_RE.fullmatch(execution_contract_sha256) is None
        or not isinstance(route_id, str)
        or not route_id
        or not isinstance(output_relative_path, str)
        or not output_relative_path
    ):
        raise ValueError("authoritative_full_contract_invalid")
    return {
        "schema": AUTHORITATIVE_STAGE_BINDING_SCHEMA,
        "stage": "full",
        "plan_sha256": plan_sha256,
        "full_contract": contract,
        "full_contract_sha256": full_stage_contract_sha256(contract),
        "execution_contract_sha256": execution_contract_sha256,
        "route_id": route_id,
        "output_relative_path": output_relative_path,
    }


def validate_authoritative_stage_binding(
    value: object,
    *,
    plan_sha256: str | None = None,
    execution_contract_sha256: str | None = None,
    route_id: str | None = None,
    output_relative_path: str | None = None,
) -> dict[str, object]:
    """Validate a sealed full-report authority binding without caller defaults."""
    if not isinstance(value, Mapping) or set(value) != _AUTHORITY_BINDING_FIELDS:
        raise ValueError("authoritative_full_contract_invalid")
    contract = validate_authoritative_full_stage_contract(value.get("full_contract"))
    checks: tuple[tuple[object, object | None], ...] = (
        (value.get("schema"), AUTHORITATIVE_STAGE_BINDING_SCHEMA),
        (value.get("stage"), "full"),
        (value.get("full_contract_sha256"), full_stage_contract_sha256(contract)),
        (value.get("plan_sha256"), plan_sha256),
        (value.get("execution_contract_sha256"), execution_contract_sha256),
        (value.get("route_id"), route_id),
        (value.get("output_relative_path"), output_relative_path),
    )
    for actual, expected in checks:
        if expected is not None and actual != expected:
            raise ValueError("authoritative_full_contract_invalid")
    for field in ("plan_sha256", "execution_contract_sha256"):
        candidate = value.get(field)
        if not isinstance(candidate, str) or _DIGEST_RE.fullmatch(candidate) is None:
            raise ValueError("authoritative_full_contract_invalid")
    if not isinstance(value.get("route_id"), str) or not value.get("route_id"):
        raise ValueError("authoritative_full_contract_invalid")
    if not isinstance(value.get("output_relative_path"), str) or not value.get("output_relative_path"):
        raise ValueError("authoritative_full_contract_invalid")
    return dict(value)
