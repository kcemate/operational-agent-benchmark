"""Offline release-blocking acceptance gate for the v2.3.0 qualification contract.

This exercises the *real* controller / strict-runner / tool-policy path with
deterministic fake model controllers. It performs **zero** provider calls and is
safe to run in CI and on a developer machine.

Scenarios (plan Task 7, offline portion):

  two_turn_success        approved read tool loop -> final answer completes
  denial_recovery         prohibited mutation is denied and the episode fails closed
  loop_exhaustion         a never-terminating controller stops before call 5
  direct_answer           a model that answers without the tool loop is
                          ``agent_loop_incompatible`` / NOT READY, never a quality %
  route_mismatch          requested/returned route divergence is infrastructure
  telemetry_known_cost    known tokens + known cost qualifies
  telemetry_unknown_cost  unknown cost qualifies but stays ``null``, never $0
  telemetry_missing_calls missing API-call count is infrastructure-invalid

Exit status is 0 only when every scenario reaches its expected outcome.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oab.agent_workflow import classify_qualification  # noqa: E402
from oab.runner import StrictEpisodeSpec  # noqa: E402
from oab.strict_runner import (  # noqa: E402
    ControllerIdentity,
    FinalResponse,
    StrictEpisodeResult,
    ToolPolicy,
    ToolRequest,
    ToolResult,
    run_strict_episode,
)

# v2.3.0 qualification contract constants (plumbing-only).
PROBES_PER_ROUTE = 2
MAX_STEPS_PER_EPISODE = 4
ABSOLUTE_CALLS_PER_ROUTE = 16

_QUALIFICATION_ROUTE = "acceptance/deterministic-fake"


def _identity(
    adapter: str,
    *,
    requested: str = _QUALIFICATION_ROUTE,
    returned: str = _QUALIFICATION_ROUTE,
) -> ControllerIdentity:
    return ControllerIdentity(
        adapter_name=adapter,
        adapter_version="1.0",
        adapter_sha256="sha256:" + "a" * 64,
        requested_route=requested,
        returned_route=returned,
        response_id="acceptance-response",
        identity_source="provider_response",
    )


class _ProbeAController:
    """Approved read flow: request the permitted read, then answer from its result."""

    def __init__(self) -> None:
        self.step = 0
        self.calls = 0

    def begin(self, context: dict[str, object]) -> ControllerIdentity:
        return _identity("acceptance-probe-a")

    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        self.step += 1
        self.calls += 1
        if self.step == 1:
            return ToolRequest("probe-a-1", "read_text", {"path": "input/value.txt"})
        assert previous is not None and previous.ok
        return FinalResponse(json.dumps({"value": previous.result["text"]}))

    def usage_snapshot(self) -> dict[str, int | float | None]:
        return {
            "api_calls": self.calls,
            "input_tokens": 100,
            "output_tokens": 20,
            "latency_ms": 1.0,
            "cost_usd": 0.01,
            "known_cost_usd": 0.01,
            "unknown_cost_api_calls": 0,
        }


class _ProbeBController(_ProbeAController):
    """Denied-effect flow: request a prohibited mutation; the broker must deny it."""

    def begin(self, context: dict[str, object]) -> ControllerIdentity:
        return _identity("acceptance-probe-b")

    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        self.step += 1
        self.calls += 1
        if self.step == 1:
            return ToolRequest(
                "probe-b-1",
                "mock_action",
                {"effect": "mock_release", "payload": {"value": "prohibited"}},
            )
        return FinalResponse("no effect occurred")


class _LoopController(_ProbeAController):
    """Never terminates: must be stopped by the step limit before call 5."""

    def begin(self, context: dict[str, object]) -> ControllerIdentity:
        return _identity("acceptance-loop")

    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse:
        self.step += 1
        self.calls += 1
        return ToolRequest(f"loop-{self.step}", "read_text", {"path": "input/value.txt"})


def _make_fixture(base: Path) -> tuple[Path, StrictEpisodeSpec, ToolPolicy]:
    repository = base / "repository"
    input_tree = repository / "fixture"
    (input_tree / "input").mkdir(parents=True)
    (input_tree / "input/value.txt").write_text("sample-value", encoding="utf-8")
    spec = StrictEpisodeSpec(
        case_id="qualification-probe",
        repetition=1,
        task_bytes=b"Read input/value.txt and return a final answer.\n",
        input_tree=input_tree,
        timeout_seconds=10,
    )
    policy = ToolPolicy(
        allowed_reads=("input/value.txt",),
        allowed_writes=("output/result.json",),
        allowed_effects=(),
        max_steps=MAX_STEPS_PER_EPISODE,
        max_write_bytes=1024,
    )
    return repository, spec, policy


def _run(controller: _ProbeAController) -> StrictEpisodeResult:
    with tempfile.TemporaryDirectory() as td:
        base = Path(td).resolve()
        repository, spec, policy = _make_fixture(base)
        return run_strict_episode(
            spec,
            controller=controller,  # type: ignore[arg-type]
            tool_policy=policy,
            repository_root=repository,
            run_root=base / "episodes",
            evidence_dir=base / "evidence",
        )


def _qualification_report(**overrides: object) -> dict[str, object]:
    report: dict[str, object] = {
        "requested_route": _QUALIFICATION_ROUTE,
        "reasoning_effort": "high",
        "scheduled_episodes": PROBES_PER_ROUTE,
        "infrastructure_valid_episodes": PROBES_PER_ROUTE,
        "infrastructure_invalid_episodes": 0,
        "identity_source": "provider_response",
        "controller_usage": {
            "api_calls": 8,
            "cost_usd": 0.08,
            "known_cost_usd": 0.08,
            "unknown_cost_api_calls": 0,
        },
        "campaign_suite_verified": True,
        "campaign_elapsed_seconds": 1.0,
        "observations": [],
    }
    report.update(overrides)
    return report


def _classify(report: dict[str, object]) -> dict[str, object]:
    return classify_qualification(
        report,
        requested_route=_QUALIFICATION_ROUTE,
        reasoning_effort="high",
    )


def _assert(condition: bool, detail: str) -> None:
    if not condition:
        raise AssertionError(detail)


# --- scenarios -------------------------------------------------------------


def scenario_two_turn_success() -> dict[str, object]:
    controller = _ProbeAController()
    result = _run(controller)
    _assert(result.status == "completed", f"expected completed, got {result.status}")
    _assert(result.valid_for_scoring, "two-turn probe must be infrastructure-valid")
    _assert(controller.calls <= MAX_STEPS_PER_EPISODE, "exceeded per-episode call bound")
    return {"status": result.status, "provider_calls": controller.calls}


def scenario_denial_recovery() -> dict[str, object]:
    controller = _ProbeBController()
    result = _run(controller)
    _assert(result.status == "task_failed", f"expected task_failed, got {result.status}")
    _assert(
        "tool_request_denied" in result.reason_codes,
        f"expected tool_request_denied, got {result.reason_codes}",
    )
    return {"status": result.status, "reason_codes": list(result.reason_codes)}


def scenario_loop_exhaustion() -> dict[str, object]:
    controller = _LoopController()
    result = _run(controller)
    _assert(result.status == "task_failed", f"expected task_failed, got {result.status}")
    _assert(
        "controller_step_limit_exceeded" in result.reason_codes,
        f"expected controller_step_limit_exceeded, got {result.reason_codes}",
    )
    _assert(
        controller.calls < 5,
        f"loop must stop before call 5; observed {controller.calls}",
    )
    return {"status": result.status, "provider_calls": controller.calls}


def scenario_direct_answer_is_agent_loop_incompatible() -> dict[str, object]:
    report = _qualification_report(
        infrastructure_valid_episodes=0,
        infrastructure_invalid_episodes=PROBES_PER_ROUTE,
        controller_usage={
            "api_calls": 8,
            "cost_usd": 0.02,
            "known_cost_usd": 0.02,
            "unknown_cost_api_calls": 0,
        },
        observations=[
            {"runner_status": "task_failed", "reason_codes": ["controller_step_limit_exceeded"]},
            {"runner_status": "task_failed", "reason_codes": ["controller_step_limit_exceeded"]},
        ],
    )
    classification = _classify(report)
    _assert(
        classification["status"] == "agent_loop_incompatible",
        f"expected agent_loop_incompatible, got {classification['status']}",
    )
    _assert("scoreable" not in classification, "qualification must not emit scoreable")
    serialized = json.dumps(classification)
    for banned in ("completion_rate", "pair_stability", "gate_pass_rate", "%"):
        _assert(banned not in serialized, f"quality signal {banned!r} leaked into qualification")
    return {"status": classification["status"], "readiness": "NOT READY"}


def scenario_route_mismatch() -> dict[str, object]:
    classification = _classify(_qualification_report(requested_route="acceptance/other"))
    _assert(
        classification["status"] == "route_mismatch",
        f"expected route_mismatch, got {classification['status']}",
    )
    _assert("scoreable" not in classification, "route mismatch must not be a quality score")
    return {"status": classification["status"]}


def scenario_telemetry_known_cost() -> dict[str, object]:
    classification = _classify(_qualification_report())
    _assert(
        classification["status"] == "qualified",
        f"expected qualified, got {classification['status']}",
    )
    _assert(classification["observed_known_cost_usd"] == 0.08, "known cost must be preserved")
    return {
        "status": classification["status"],
        "observed_known_cost_usd": classification["observed_known_cost_usd"],
    }


def scenario_telemetry_unknown_cost() -> dict[str, object]:
    classification = _classify(
        _qualification_report(
            controller_usage={
                "api_calls": 8,
                "cost_usd": None,
                "known_cost_usd": None,
                "unknown_cost_api_calls": 8,
            }
        )
    )
    _assert(
        classification["status"] == "qualified",
        f"expected qualified, got {classification['status']}",
    )
    _assert(
        classification["observed_known_cost_usd"] is None,
        "unknown cost must stay null, never coerced to $0",
    )
    _assert(
        classification["observed_cost_usd"] is None,
        "unknown cost must stay null, never coerced to $0",
    )
    return {
        "status": classification["status"],
        "observed_known_cost_usd": classification["observed_known_cost_usd"],
        "unknown_cost_api_calls": classification["unknown_cost_api_calls"],
    }


def scenario_telemetry_missing_api_calls() -> dict[str, object]:
    classification = _classify(
        _qualification_report(
            controller_usage={
                "cost_usd": 0.08,
                "known_cost_usd": 0.08,
                "unknown_cost_api_calls": 0,
            }
        )
    )
    _assert(
        classification["status"] == "qualification_contract_invalid",
        f"expected qualification_contract_invalid, got {classification['status']}",
    )
    return {"status": classification["status"]}


SCENARIOS: dict[str, Callable[[], dict[str, object]]] = {
    "two_turn_success": scenario_two_turn_success,
    "denial_recovery": scenario_denial_recovery,
    "loop_exhaustion": scenario_loop_exhaustion,
    "direct_answer_agent_loop_incompatible": scenario_direct_answer_is_agent_loop_incompatible,
    "route_mismatch": scenario_route_mismatch,
    "telemetry_known_cost": scenario_telemetry_known_cost,
    "telemetry_unknown_cost": scenario_telemetry_unknown_cost,
    "telemetry_missing_api_calls": scenario_telemetry_missing_api_calls,
}


def run_acceptance() -> dict[str, object]:
    results: list[dict[str, object]] = []
    passed = True
    for name, scenario in SCENARIOS.items():
        try:
            detail = scenario()
        except AssertionError as exc:
            passed = False
            results.append({"scenario": name, "passed": False, "detail": str(exc)})
        else:
            results.append({"scenario": name, "passed": True, "detail": detail})
    return {
        "schema": "oab.qualification-acceptance/v1",
        "contract": "v2.3.0",
        "provider_calls": 0,
        "probes_per_route": PROBES_PER_ROUTE,
        "max_steps_per_episode": MAX_STEPS_PER_EPISODE,
        "absolute_api_calls_per_route": ABSOLUTE_CALLS_PER_ROUTE,
        "scenario_count": len(SCENARIOS),
        "passed_count": sum(1 for item in results if item["passed"]),
        "passed": passed,
        "scenarios": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline v2.3.0 qualification acceptance gate (no provider calls)."
    )
    parser.add_argument("--json", action="store_true", help="emit the full JSON report")
    parser.add_argument("--output", type=Path, default=None, help="write the JSON report here")
    args = parser.parse_args()
    report = run_acceptance()
    if args.output is not None:
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        scenarios = report["scenarios"]
        assert isinstance(scenarios, list)
        for item in scenarios:
            flag = "PASS" if item["passed"] else "FAIL"
            print(f"{flag}  {item['scenario']}  {item['detail']}")
        print(f"{report['passed_count']}/{report['scenario_count']} scenarios passed")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
