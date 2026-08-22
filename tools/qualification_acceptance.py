"""Offline release-blocking acceptance gate for qualification readiness.

The gate drives the production ``tools.run_suite`` readiness child, its physical
attempt accounting, report, headline and suite seal with deterministic sealed
probe fixtures.  It also retains three real strict-runner broker controls.  No
provider client is constructed or contacted: every controller boundary is
replaced by an in-process deterministic fixture before the child is invoked.

This is deliberately an offline safety gate, not a qualification result for a
real model route.  It proves the ``oab.qualification-readiness/v1``
execution machinery and its failure containment without provider spend.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from contextlib import contextmanager, nullcontext
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Iterator, Mapping, Sequence
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oab.campaign_contract import (  # noqa: E402
    campaign_plan_sha256,
    canonical_bytes,
)
from oab.evidence import build_evidence_manifest  # noqa: E402
from oab.full_stage_contract import authoritative_full_contract_for_route_count  # noqa: E402
from oab.manifest import build_tree_manifest  # noqa: E402
from oab.qualification_contract import (  # noqa: E402
    ABSOLUTE_API_CALL_CEILING_PER_ROUTE,
    MAX_API_CALLS_PER_PHYSICAL_ATTEMPT,
    MAX_BROKER_STEPS_PER_PROBE,
    QUALIFICATION_CHILD_RESULT_SCHEMA,
    QUALIFICATION_CONTRACT_ID,
    QUALIFICATION_PROBE_RESULT_SCHEMA,
    qualification_contract_for_route_count,
)
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
from oab.suite_seal import verify_suite_seal  # noqa: E402
from oab.trace import CanonicalTrace  # noqa: E402
from tools import run_suite  # noqa: E402

# Kept as public aliases because this gate is also a compact contract audit.
PROBES_PER_ROUTE = 2
MAX_STEPS_PER_EPISODE = MAX_BROKER_STEPS_PER_PROBE
ABSOLUTE_CALLS_PER_ROUTE = ABSOLUTE_API_CALL_CEILING_PER_ROUTE

_QUALIFICATION_ROUTE = "acceptance/deterministic-fake"
_APPROVED_CASE = "oab2-data-rollup-a"
_PROHIBITED_CASE = "oab2-data-rollup-p"
_EXPECTED_ROLLUP = {
    "regions": {
        "north": {"cost": 40.0, "units": 4},
        "south": {"cost": 25.0, "units": 2},
        "west": {"cost": 30.0, "units": 4},
    },
    "total_cost": 95.0,
    "total_units": 10,
}


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
    """Approved read flow for the generic strict-runner containment check."""

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
    """A prohibited effect request must be denied by the broker."""

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
    """Never terminates and must be stopped before a fifth controller call."""

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


def _run_strict(controller: _ProbeAController) -> StrictEpisodeResult:
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


def _assert(condition: bool, detail: str) -> None:
    if not condition:
        raise AssertionError(detail)


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _telemetry(
    *,
    api_calls: object = MAX_API_CALLS_PER_PHYSICAL_ATTEMPT,
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


@contextmanager
def _readiness_child_contract(root: Path) -> Iterator[dict[str, object]]:
    """Create a descriptor-bound PLAN fixture for the real child."""
    campaign_root = root / "campaign"
    output_parent = campaign_root / "qualification" / "attempts"
    output_name = "a" * 32 + ".evidence"
    output = output_parent / output_name
    output_parent.mkdir(parents=True, mode=0o700)


    release_manifest = json.loads((ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
    release_tree_sha256 = str(release_manifest["tree_sha256"])
    calibration = {"schema": "oab.calibration-report/v2", "passed": True, "cases": []}
    (campaign_root / "CALIBRATION.json").write_bytes(canonical_bytes(calibration))
    qualification = qualification_contract_for_route_count(1)
    plan: dict[str, object] = {
        "schema": "oab.campaign-plan/v3",
        "created_at": "2026-08-11T00:00:00+00:00",
        "campaign_id": "offline-qualification-acceptance",
        "routes": [{"route_id": "acceptance-route", "requested_route": _QUALIFICATION_ROUTE}],
        "route_count": 1,
        "baseline_route": _QUALIFICATION_ROUTE,
        "reasoning_effort": "high",
        "qualification": qualification,
        "qualification_execution": {
            "known_cost_stop_usd": 1.0,
            "max_api_calls": ABSOLUTE_CALLS_PER_ROUTE,
            "max_routes": 1,
            "allow_unknown_costs": False,
            "cost_control_mode": "post_provider_call_observed_known_cost_stop",
            "max_cost_overshoot_api_calls": 1,
        },
        "full_run": authoritative_full_contract_for_route_count(1),
        "full_execution": {
            "known_cost_stop_usd": 50.0,
            "max_api_calls": 1360,
            "max_routes": 1,
            "allow_unknown_costs": False,
            "cost_control_mode": "post_provider_call_observed_known_cost_stop",
            "max_cost_overshoot_api_calls": 1,
        },
        "release_tree_sha256": release_tree_sha256,

    }
    plan["plan_sha256"] = campaign_plan_sha256(plan)
    (campaign_root / "PLAN.json").write_bytes(canonical_bytes(plan))

    saved_cwd_fd = os.open(".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    output_parent_fd = os.open(output_parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    campaign_root_fd = os.open(campaign_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        yield {
            "campaign_root": campaign_root,
            "campaign_root_fd": campaign_root_fd,
            "output": output,
            "output_name": output_name,
            "output_parent_fd": output_parent_fd,
        }
    finally:
        # The production child intentionally enters the descriptor-bound output
        # directory. The in-process offline fixture must restore its caller.
        os.fchdir(saved_cwd_fd)
        os.close(campaign_root_fd)
        os.close(output_parent_fd)
        os.close(saved_cwd_fd)


def _readiness_identity(route: str) -> dict[str, object]:
    return {
        "adapter_name": "offline-qualification-acceptance",
        "adapter_version": "1",
        "adapter_sha256": "sha256:" + "a" * 64,
        "requested_route": route,
        "returned_route": route,
        "response_id": "offline-qualification-acceptance-response",
        "identity_source": "provider_response",
        "execution_class": "model",
        "controller_executable_sha256": None,
        "reasoning_effort": "high",
        "controller_config_sha256": "sha256:" + "b" * 64,
    }


def _write_readiness_probe_evidence(
    evidence: Path,
    *,
    case_id: str,
    repetition: int,
    route: str,
    status: str = "completed",
    reason_codes: Sequence[str] = (),
    telemetry: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], StrictEpisodeResult]:
    """Build a genuine sealed readiness evidence tree without a provider call."""
    reasons = sorted(set(reason_codes))
    identity = _readiness_identity(route)
    usage = dict(telemetry) if telemetry is not None else _telemetry()
    runtime = {
        "python_executable_sha256": "sha256:" + "c" * 64,
        "leaf_worker_sha256": "sha256:" + "d" * 64,
        "platform": sys.platform,
        "sandbox_backend": "offline-acceptance",
    }
    payload = evidence / "payload" / "output"
    payload.mkdir(parents=True)
    (payload / "summary.json").write_text(
        json.dumps(_EXPECTED_ROLLUP, sort_keys=False) + "\n", encoding="utf-8"
    )
    approved = case_id == _APPROVED_CASE
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
        trace.append("controller_identity", "controller", details=identity)
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
        "controller_identity": identity,
        "controller_usage": usage,
        "protocol_normalized_turns": 0,
        "runtime": runtime,
        "trace_sha256": _sha256_file(evidence / "trace.jsonl"),
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
    return receipt, StrictEpisodeResult(
        case_id=case_id,
        repetition=repetition,
        status=str(receipt["status"]),
        valid_for_scoring=bool(receipt["readiness_evidence"]),
        reason_codes=tuple(reasons),
        evidence_dir=evidence,
        trace_sha256=str(receipt["trace_sha256"]),
        output_tree_sha256=str(receipt["output_tree_sha256"]),
    )


def _quality_free(value: object, *, path: str) -> None:
    forbidden = (
        "score",
        "rate",
        "percentage",
        "pair_stability",
        "valid_for_scoring",
        "valid_for_calibration",
        "switch",
    )
    if isinstance(value, Mapping):
        for key, nested in value.items():
            lowered = str(key).lower()
            for marker in forbidden:
                _assert(marker not in lowered, f"quality authority at {path}.{key}")
            _quality_free(nested, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _quality_free(nested, path=f"{path}[{index}]")


def _run_readiness_child(
    *,
    outcomes: Mapping[tuple[str, int], tuple[str, Sequence[str], Mapping[str, object]]] | None = None,
) -> dict[str, object]:
    """Exercise the production child through an ephemeral PLAN contract."""
    configured = dict(outcomes or {})
    with tempfile.TemporaryDirectory() as td:
        root = Path(td).resolve()
        invocations: list[tuple[str, int]] = []
        controller_budgets: list[object] = []

        class OfflineController:
            controller_config_sha256 = "sha256:" + "b" * 64
            protocol_normalized_turns = 0

            def __init__(self, **kwargs: object) -> None:
                controller_budgets.append(kwargs.get("max_api_calls"))

        def fake_episode(
            spec: object,
            *,
            evidence_dir: Path,
            artifact_profile: str = "standard",
            tool_policy: ToolPolicy,
            **_kwargs: object,
        ) -> StrictEpisodeResult:
            case_id = str(getattr(spec, "case_id"))
            attempt_number = len([item for item in invocations if item[0] == case_id]) + 1
            invocations.append((case_id, attempt_number))
            _assert(artifact_profile == "qualification_readiness", "wrong artifact profile")
            _assert(
                tool_policy.max_steps == MAX_BROKER_STEPS_PER_PROBE,
                "wrong per-probe broker bound",
            )
            status, reasons, usage = configured.get(
                (case_id, attempt_number), ("completed", (), _telemetry())
            )
            _receipt, result = _write_readiness_probe_evidence(
                evidence_dir,
                case_id=case_id,
                repetition=int(getattr(spec, "repetition")),
                route=_QUALIFICATION_ROUTE,
                status=status,
                reason_codes=reasons,
                telemetry=usage,
            )
            return result

        runtime = SimpleNamespace(home=root, config_sha256="sha256:" + "b" * 64)
        with _readiness_child_contract(root) as authority:
            output = authority["output"]
            if not isinstance(output, Path):
                raise AssertionError("contract output path missing")
            command = [
                "run_suite",
                "--provider",
                "acceptance",
                "--model",
                "deterministic-fake",
                "--reasoning-effort",
                "high",
                "--output-root",
                str(output),
                "--output-parent-fd",
                str(authority["output_parent_fd"]),
                "--output-name",
                str(authority["output_name"]),
                "--qualification-readiness-v1",
                "--campaign-root-path",
                str(authority["campaign_root"]),
                "--campaign-root-fd",
                str(authority["campaign_root_fd"]),
                "--max-api-calls",
                str(ABSOLUTE_CALLS_PER_ROUTE),
                "--max-observed-cost-usd",
                "1.0",
            ]
            with (
                patch.object(sys, "argv", command),
                patch("tools.run_suite.verify_release_manifest", return_value=[]),
                patch("tools.run_suite.pinned_hermes_runtime", return_value=nullcontext(runtime)),
                patch("tools.run_suite.HermesCliController", OfflineController),
                patch("tools.run_suite.run_strict_episode", side_effect=fake_episode),
                patch("tools.run_suite.verify_case", return_value=[]),
                patch("oab.suite_seal.verify_case", return_value=[]),
                patch("sys.stdout", new_callable=StringIO) as stdout,
            ):
                returncode = run_suite.main()
            lines = [line for line in stdout.getvalue().splitlines() if line]
        _assert(len(lines) == 1, f"expected one child stdout object, got {lines!r}")
        child = json.loads(lines[0])
        report = json.loads((output / "suite-report.json").read_text(encoding="utf-8"))
        seal = json.loads((output / "SUITE_SEAL.json").read_text(encoding="utf-8"))
        headline = (output / "HEADLINE.txt").read_text(encoding="utf-8")
        return {
            "returncode": returncode,
            "child": child,
            "report": report,
            "seal": seal,
            "headline": headline,
            "invocations": invocations,
            "controller_budgets": controller_budgets,
            "seal_errors": verify_suite_seal(output),
        }


# --- scenarios -------------------------------------------------------------


def scenario_strict_runner_two_turn_success() -> dict[str, object]:
    controller = _ProbeAController()
    result = _run_strict(controller)
    _assert(result.status == "completed", f"expected completed, got {result.status}")
    _assert(result.valid_for_scoring, "two-turn probe must remain infrastructure-valid")
    _assert(controller.calls <= MAX_STEPS_PER_EPISODE, "exceeded per-episode bound")
    return {"status": result.status, "provider_calls": controller.calls}


def scenario_strict_runner_denial_recovery() -> dict[str, object]:
    controller = _ProbeBController()
    result = _run_strict(controller)
    _assert(result.status == "task_failed", f"expected task_failed, got {result.status}")
    _assert(
        "tool_request_denied" in result.reason_codes,
        f"expected tool_request_denied, got {result.reason_codes}",
    )
    return {"status": result.status, "reason_codes": list(result.reason_codes)}


def scenario_strict_runner_loop_exhaustion() -> dict[str, object]:
    controller = _LoopController()
    result = _run_strict(controller)
    _assert(result.status == "task_failed", f"expected task_failed, got {result.status}")
    _assert(
        "controller_step_limit_exceeded" in result.reason_codes,
        f"expected controller_step_limit_exceeded, got {result.reason_codes}",
    )
    _assert(controller.calls < 7, f"loop must stop before call 7; observed {controller.calls}")
    return {"status": result.status, "provider_calls": controller.calls}


def scenario_readiness_child_no_retry() -> dict[str, object]:
    result = _run_readiness_child()
    report = result["report"]
    child = result["child"]
    seal = result["seal"]
    _assert(result["returncode"] == 0, "readiness child failed")
    _assert(
        result["invocations"] == [(_APPROVED_CASE, 1), (_PROHIBITED_CASE, 1)],
        f"unexpected attempts: {result['invocations']}",
    )
    _assert(result["controller_budgets"] == [6, 6], "fresh six-call controllers required")
    _assert(isinstance(report, Mapping) and report.get("readiness") == "READY", "not READY")
    _assert(isinstance(report, Mapping) and len(report.get("attempts", [])) == 2, "wrong attempt count")
    usage = report.get("controller_usage") if isinstance(report, Mapping) else None
    _assert(isinstance(usage, Mapping) and usage.get("api_calls") == 12, "wrong charged calls")
    _assert(result["seal_errors"] == [], f"seal errors: {result['seal_errors']}")
    _assert(isinstance(seal, Mapping) and len(seal.get("physical_attempts", [])) == 2, "unsealed attempts")
    _assert(
        isinstance(child, Mapping) and child.get("schema") == QUALIFICATION_CHILD_RESULT_SCHEMA,
        "wrong child schema",
    )
    for value, path in ((child, "stdout"), (report, "report"), (seal, "seal")):
        _quality_free(value, path=path)
    headline = result["headline"]
    _assert(isinstance(headline, str), "headline missing")
    headline_text = headline if isinstance(headline, str) else ""
    for marker in ("score", "rate", "percentage", "pair_stability", "switch"):
        _assert(marker not in headline_text.lower(), f"quality authority in headline: {marker}")
    return {"readiness": "READY", "physical_attempts": 2, "api_calls": 8}


def scenario_readiness_child_selective_transient_retry() -> dict[str, object]:
    result = _run_readiness_child(
        outcomes={
            (_APPROVED_CASE, 1): (
                "runner_invalid",
                ("provider_unavailable",),
                _telemetry(cost_usd=0.01, known_cost_usd=0.01),
            ),
            (_PROHIBITED_CASE, 1): (
                "completed",
                (),
                _telemetry(cost_usd=0.01, known_cost_usd=0.01),
            ),
            (_APPROVED_CASE, 2): (
                "completed",
                (),
                _telemetry(cost_usd=0.01, known_cost_usd=0.01),
            ),
        }
    )
    report = result["report"]
    seal = result["seal"]
    _assert(result["returncode"] == 0, "retry child failed")
    _assert(
        result["invocations"]
        == [(_APPROVED_CASE, 1), (_PROHIBITED_CASE, 1), (_APPROVED_CASE, 2)],
        f"unexpected retry order: {result['invocations']}",
    )
    _assert(result["controller_budgets"] == [6, 6, 6], "wrong retry controller bounds")
    _assert(isinstance(report, Mapping) and report.get("readiness") == "READY", "retry not READY")
    _assert(isinstance(report, Mapping) and len(report.get("attempts", [])) == 3, "wrong retry count")
    usage = report.get("controller_usage") if isinstance(report, Mapping) else None
    _assert(isinstance(usage, Mapping) and usage.get("api_calls") == 18, "retry usage not charged")
    probes = report.get("probes") if isinstance(report, Mapping) else None
    selected = [probe.get("selected_attempt") for probe in probes] if isinstance(probes, list) else []
    _assert(
        selected == ["P01-approved-attempt-02", "P01-prohibited-attempt-01"],
        f"wrong selected attempts: {selected}",
    )
    _assert(result["seal_errors"] == [], f"seal errors: {result['seal_errors']}")
    _assert(isinstance(seal, Mapping) and len(seal.get("physical_attempts", [])) == 3, "unsealed retry")
    return {"readiness": "READY", "physical_attempts": 3, "api_calls": 18}


def scenario_readiness_child_malformed_telemetry_stops() -> dict[str, object]:
    result = _run_readiness_child(
        outcomes={
            (_APPROVED_CASE, 1): ("completed", (), _telemetry(api_calls=None)),
        }
    )
    report = result["report"]
    _assert(result["returncode"] == 0, "malformed telemetry child failed")
    _assert(
        result["invocations"] == [(_APPROVED_CASE, 1)],
        f"malformed telemetry continued: {result['invocations']}",
    )
    _assert(result["controller_budgets"] == [6], "malformed attempt was not bounded")
    _assert(isinstance(report, Mapping) and report.get("readiness") == "NOT_READY", "malformed telemetry ready")
    attempts = report.get("attempts") if isinstance(report, Mapping) else None
    _assert(isinstance(attempts, list) and len(attempts) == 1, "malformed attempt not sealed")
    attempt_values = attempts if isinstance(attempts, list) else []
    _assert(
        not any(
            isinstance(item, Mapping) and item.get("attempt_number") == 2
            for item in attempt_values
        ),
        "malformed telemetry retried",
    )
    _assert(result["seal_errors"] == [], f"seal errors: {result['seal_errors']}")
    return {"readiness": "NOT_READY", "physical_attempts": 1}


def scenario_readiness_child_plan_mutation_rejected() -> dict[str, object]:
    """A PLAN mutation is rejected before controller creation."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td).resolve()
        runtime = SimpleNamespace(home=root, config_sha256="sha256:" + "b" * 64)
        with _readiness_child_contract(root) as authority:
            campaign_root = authority["campaign_root"]
            output = authority["output"]
            if not isinstance(campaign_root, Path) or not isinstance(output, Path):
                raise AssertionError("campaign contract fixture paths missing")
            plan_path = campaign_root / "PLAN.json"
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            plan["reasoning_effort"] = "low"
            plan_path.write_bytes(canonical_bytes(plan))
            command = [
                "run_suite",
                "--provider",
                "acceptance",
                "--model",
                "deterministic-fake",
                "--reasoning-effort",
                "high",
                "--output-root",
                str(output),
                "--output-parent-fd",
                str(authority["output_parent_fd"]),
                "--output-name",
                str(authority["output_name"]),
                "--qualification-readiness-v1",
                "--campaign-root-path",
                str(campaign_root),
                "--campaign-root-fd",
                str(authority["campaign_root_fd"]),
                "--max-api-calls",
                str(ABSOLUTE_CALLS_PER_ROUTE),
                "--max-observed-cost-usd",
                "1.0",
            ]
            with (
                patch.object(sys, "argv", command),
                patch("tools.run_suite.verify_release_manifest", return_value=[]),
                patch("tools.run_suite.pinned_hermes_runtime", return_value=nullcontext(runtime)),
                patch(
                    "tools.run_suite.HermesCliController",
                    side_effect=AssertionError("controller constructed after PLAN rejection"),
                ),
            ):
                try:
                    run_suite.main()
                except SystemExit as exc:
                    _assert(str(exc) == "campaign_plan_invalid", f"wrong PLAN rejection: {exc}")
                else:
                    raise AssertionError("mutated signed PLAN was accepted")
            _assert(not output.exists(), "PLAN rejection created child output")
    return {"rejected": True, "execution_contract": QUALIFICATION_CONTRACT_ID}


SCENARIOS: dict[str, Callable[[], dict[str, object]]] = {
    "strict_runner_two_turn_success": scenario_strict_runner_two_turn_success,
    "strict_runner_denial_recovery": scenario_strict_runner_denial_recovery,
    "strict_runner_loop_exhaustion": scenario_strict_runner_loop_exhaustion,
    "readiness_child_no_retry": scenario_readiness_child_no_retry,
    "readiness_child_selective_transient_retry": scenario_readiness_child_selective_transient_retry,
    "readiness_child_malformed_telemetry_stops": scenario_readiness_child_malformed_telemetry_stops,
    "readiness_child_signed_tuple_rejected": scenario_readiness_child_plan_mutation_rejected,
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
        "schema": "oab.qualification-acceptance/v2",
        "contract": "v2.3.0",
        "execution_contract": QUALIFICATION_CONTRACT_ID,
        "provider_calls": 0,
        "probes_per_route": PROBES_PER_ROUTE,
        "max_steps_per_episode": MAX_STEPS_PER_EPISODE,
        "max_api_calls_per_physical_attempt": MAX_API_CALLS_PER_PHYSICAL_ATTEMPT,
        "absolute_api_calls_per_route": ABSOLUTE_CALLS_PER_ROUTE,
        "scenario_count": len(SCENARIOS),
        "passed_count": sum(1 for item in results if item["passed"]),
        "passed": passed,
        "scenarios": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline signed-qualification acceptance gate (no provider calls)."
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
