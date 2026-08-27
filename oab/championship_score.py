"""Uncapped championship score for OAB v2.5 (``oab.championship-score/v1``).

One integer is the product headline, and stay/switch is derived from that
integer alone.  Three properties are deliberate:

* **No cap.**  There is no ``min()`` anywhere below.  A dead pair contributes
  zero to its own component and costs exactly those points; it never ceilings
  the rest of the score.  70 + 20 + 10 = 100 is the current bucket total, not a
  clamp — a later suite with more buckets may print above 100.
* **Eligibility is coverage, not quality.**  A route that did not run all
  eighty scheduled episodes has no number at all.  A route that ran all eighty
  and scored badly still prints its number.
* **Authority stamps posture, never the number.**  Unpinned or unauthorized
  paperwork downgrades ``score_posture`` to ``exploratory``; it cannot erase a
  valid score.

Every function here is pure: inputs are already-built suite report mappings.
"""

from __future__ import annotations

import math
from typing import Mapping, Sequence

from .full_stage_contract import (
    AUTHORITATIVE_FULL_PAIR_IDS,
    FULL_EPISODES_PER_ROUTE,
    FULL_REPETITIONS,
)

CHAMPIONSHIP_SCORE_SCHEMA = "oab.championship-score/v1"

# Bucket weights.  These are point budgets, not ceilings on the total.
CORE_POINTS = 70
MATCHED_POINTS = 20
STABILITY_POINTS = 10

SCHEDULED_EPISODES = FULL_EPISODES_PER_ROUTE
MATCHED_PAIR_SLOTS = len(AUTHORITATIVE_FULL_PAIR_IDS) * FULL_REPETITIONS
STABILITY_SLOTS = FULL_REPETITIONS


def _exact_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def official_score_from_raw(raw: float) -> int:
    """Floor the raw total.

    No ``min()``: the score is uncapped by construction.  The epsilon absorbs
    binary float error so an exact 68.0 built from 54.25 + 13.5 + 0.25 cannot
    floor to 67.
    """
    return int(math.floor(raw + 1e-12))


def score_components(
    *,
    completed_contract_episodes: int,
    matched_pair_successes: int,
    weakest_pair_successes: int,
) -> dict[str, float | int]:
    """Compute the three buckets and the headline integer."""
    core = CORE_POINTS * completed_contract_episodes / SCHEDULED_EPISODES
    matched = MATCHED_POINTS * matched_pair_successes / MATCHED_PAIR_SLOTS
    stability = STABILITY_POINTS * weakest_pair_successes / STABILITY_SLOTS
    raw = core + matched + stability
    return {
        "core": core,
        "matched": matched,
        "stability": stability,
        "raw": raw,
        "official_score": official_score_from_raw(raw),
    }


def weakest_pair(report: Mapping[str, object]) -> tuple[str | None, int | None]:
    """Return ``(min_pair_id, S)`` for the suite's weakest matched pair.

    ``S`` is that pair's matched-pair successes in ``{0..5}``, read from the
    existing ``pair_stability.min_pair_id`` selection rather than recomputed.
    """
    stability = report.get("pair_stability")
    if not isinstance(stability, Mapping):
        return None, None
    min_pair_id = stability.get("min_pair_id")
    if not isinstance(min_pair_id, str) or not min_pair_id:
        return None, None
    pairs = report.get("pairs")
    if not isinstance(pairs, list):
        return min_pair_id, None
    for row in pairs:
        if isinstance(row, Mapping) and row.get("pair_id") == min_pair_id:
            return min_pair_id, _exact_int(row.get("matched_pair_successes"))
    return min_pair_id, None


def score_posture(report: Mapping[str, object]) -> str:
    """Authority paperwork only.  Never consulted when computing the number."""
    approval = report.get("release_approval_sha256")
    if (
        report.get("authoritative") is True
        and report.get("release_authorized") is True
        and report.get("identity_source") == "provider_response"
        and isinstance(approval, str)
        and bool(approval)
    ):
        return "authoritative"
    return "exploratory"


def championship_score(report: Mapping[str, object]) -> dict[str, object]:
    """Build the ``oab.championship-score/v1`` payload for one suite report."""
    min_pair_id, weakest = weakest_pair(report)
    completed = _exact_int(report.get("completed_contract_episodes"))
    matched = _exact_int(report.get("matched_pair_successes"))
    infrastructure_valid = _exact_int(report.get("infrastructure_valid_episodes"))
    payload: dict[str, object] = {
        "schema": CHAMPIONSHIP_SCORE_SCHEMA,
        "official_score": None,
        "score_status": "incomplete",
        "score_posture": score_posture(report),
        "core": None,
        "matched": None,
        "stability": None,
        "raw": None,
        "min_pair_id": min_pair_id,
        "S": weakest,
        "C": completed,
        "M": matched,
        "scheduled_episodes": SCHEDULED_EPISODES,
    }
    if infrastructure_valid != SCHEDULED_EPISODES:
        return payload
    if completed is None or matched is None or weakest is None:
        # A coverage-complete route with an unreadable breakdown is a broken
        # report, not a zero-scoring one.  Fail closed rather than invent a number.
        return payload
    payload.update(
        score_components(
            completed_contract_episodes=completed,
            matched_pair_successes=matched,
            weakest_pair_successes=weakest,
        )
    )
    payload["score_status"] = "official"
    return payload


def derive_recommendation(
    *,
    current_route: str,
    current_score: Mapping[str, object],
    candidate_scores: Sequence[tuple[str, Mapping[str, object]]],
) -> dict[str, object]:
    """Derive stay/switch by comparing official-score integers and nothing else.

    Any route in the comparison without an official score makes the whole
    comparison unsupportable: there is no integer to rank it by.
    """
    if not candidate_scores:
        return {
            "recommendation": "stay",
            "recommended_route": current_route,
            "reasons": ["no_higher_official_score"],
        }
    scores = [current_score, *(payload for _, payload in candidate_scores)]
    if any(_exact_int(payload.get("official_score")) is None for payload in scores):
        return {
            "recommendation": "not_supportable",
            "recommended_route": None,
            "reasons": ["official_score_incomplete"],
        }
    baseline = _exact_int(current_score.get("official_score"))
    assert baseline is not None
    best_route, best = max(
        candidate_scores,
        key=lambda item: _exact_int(item[1].get("official_score")) or 0,
    )
    best_score = _exact_int(best.get("official_score"))
    assert best_score is not None
    if best_score > baseline:
        return {
            "recommendation": "switch",
            "recommended_route": best_route,
            "reasons": ["higher_official_score"],
        }
    return {
        "recommendation": "stay",
        "recommended_route": current_route,
        "reasons": ["no_higher_official_score"],
    }


def production_switch_blockers(
    scores: Sequence[tuple[str, Mapping[str, object]]],
) -> list[str]:
    """Authority gates that still stand between an observational switch and production."""
    return sorted(
        f"route:{route}:score_posture_exploratory"
        for route, payload in scores
        if payload.get("score_posture") != "authoritative"
    )
