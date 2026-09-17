"""Regenerate public execution-contract blocks without invoking a model."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.full_stage_contract import canonical_full_stage_contract
from oab.qualification_contract import qualification_contract_for_route_count
from oab.registry import load_registry

DOCUMENTS = ("README.md", "BENCHMARK_CARD.md", "LIMITATIONS.md", "AGENTS.md")
START = "<!-- OAB:CONTRACT:START -->"
END = "<!-- OAB:CONTRACT:END -->"


def contract_block(root: Path) -> str:
    full = canonical_full_stage_contract()
    qualification = qualification_contract_for_route_count(2)
    cases = load_registry(root / "cases.json")["cases"]
    decision_pairs = cast(list[str], full["pair_ids"])
    registry_pairs = sorted({case["pair_id"] for case in cases})
    diagnostic_pairs = [pair for pair in registry_pairs if pair not in decision_pairs]
    ids = lambda values: ", ".join(f"`{value}`" for value in values)
    decision_cases = sum(case["pair_id"] in decision_pairs for case in cases)
    return "\n".join([
        START,
        "### Current execution contract (generated)",
        "",
        "Source: `oab/full_stage_contract.py`, `oab/qualification_contract.py`, and `cases.json`.",
        "Regenerate with `python3 tools/sync_contract_docs.py`; verify with `--check`.",
        "",
        f"- Decision grid (ordered): {ids(decision_pairs)}.",
        f"- Full stage: {len(decision_pairs)} pairs, {decision_cases} approved/prohibited cases, "
        f"{full['repetitions']} repetitions, {full['episodes_per_route']} episodes per route.",
        f"- Full API-call ceiling: {full['max_api_calls_per_episode']} per episode, "
        f"{full['api_call_ceiling_per_route']:,} per route, "
        f"{2 * cast(int, full['api_call_ceiling_per_route']):,} across two routes.",
        f"- Registry/calibration: {len(registry_pairs)} pairs, {len(cases)} cases; "
        f"diagnostic-only pairs: {ids(diagnostic_pairs) or 'none'}.",
        f"- Qualification: {qualification['logical_probes_per_route']} probes per route, "
        f"{qualification['max_api_calls_per_physical_attempt']} API calls per physical attempt, "
        f"{qualification['first_attempt_api_call_ceiling_per_route']} first-attempt calls per route, "
        f"{qualification['max_infrastructure_retries_per_probe']} infrastructure-only retry per probe.",
        f"- Qualification absolute ceiling: {qualification['absolute_api_call_ceiling_per_route']} "
        f"calls per route, {2 * cast(int, qualification['absolute_api_call_ceiling_per_route'])} across two routes.",
        "- Planning performs no model inference. Qualification measures plumbing, not model quality; "
        "full execution requires a separate explicit PLAN-bound resume.",
        END,
    ])


def replace_contract_block(text: str, block: str) -> str:
    if START not in text and END not in text:
        heading, separator, rest = text.partition("\n")
        return heading + "\n\n" + block + "\n" + separator + rest
    if text.count(START) != 1 or text.count(END) != 1:
        raise ValueError("contract_markers_invalid")
    before, remainder = text.split(START, 1)
    if END not in remainder:
        raise ValueError("contract_markers_invalid")
    _, after = remainder.split(END, 1)
    return before + block + after


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    block = contract_block(ROOT)
    stale = []
    for name in DOCUMENTS:
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        updated = replace_contract_block(text, block)
        if text != updated:
            stale.append(name)
            if not args.check:
                path.write_text(updated, encoding="utf-8")
    if args.check and stale:
        print("contract_docs_stale:" + ",".join(stale))
        return 1
    print("contract_docs_current" if args.check else "contract_docs_updated:" + ",".join(stale))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
