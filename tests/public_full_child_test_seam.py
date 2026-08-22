"""Ephemeral test-only runtime injection for the public authoritative-full child.

This module is never imported by product code.  The integration test makes a
private ``sitecustomize`` bootstrap on a temporary PYTHONPATH; that bootstrap
imports this module only after setting the explicit test configuration below.
There is no OAB CLI option or product environment switch that selects it.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from oab.evidence import build_evidence_manifest
from oab.manifest import build_tree_manifest
from oab.strict_runner import StrictEpisodeResult
from oab.trace import CanonicalTrace

_CONFIG: dict[str, str] | None = None
_CONFIG_SHA256 = "sha256:" + "c" * 64
_ADAPTER_SHA256 = "sha256:" + "d" * 64


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _config() -> dict[str, str]:
    if _CONFIG is None:
        raise RuntimeError("public_full_child_test_seam_not_installed")
    return _CONFIG


def _append_marker(name: str, payload: Mapping[str, object]) -> None:
    path = Path(_config()[name])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(_canonical_json(dict(payload)))


class OfflineController:
    """No-network controller replacement, constructible only by the test bootstrap."""

    def __init__(
        self,
        *,
        model: str,
        provider: str,
        timeout_seconds: float,
        hermes_home: Path,
        reasoning_effort: str,
        max_observed_cost_usd: float | None,
        max_api_calls: int | None,
        allow_unknown_costs: bool,
    ) -> None:
        if max_api_calls != 17:
            raise AssertionError(f"offline_full_child_expected_17_calls_per_episode:{max_api_calls}")
        self.model = model
        self.provider = provider
        self.reasoning_effort = reasoning_effort
        self.controller_config_sha256 = _CONFIG_SHA256
        self.protocol_normalized_turns = 0
        self._usage = {
            "api_calls": 17,
            "input_tokens": 0,
            "output_tokens": 0,
            "latency_ms": 0,
            "cost_usd": 0.0,
            "known_cost_usd": 0.0,
            "unknown_cost_api_calls": 0,
        }
        _append_marker(
            "controller_marker",
            {
                "event": "constructed",
                "provider": provider,
                "model": model,
                "reasoning_effort": reasoning_effort,
                "max_api_calls": max_api_calls,
                "max_observed_cost_usd": max_observed_cost_usd,
                "allow_unknown_costs": allow_unknown_costs,
                "hermes_home": str(hermes_home),
                "timeout_seconds": timeout_seconds,
            },
        )

    def usage_snapshot(self) -> dict[str, int | float]:
        return dict(self._usage)


@contextlib.contextmanager
def _offline_runtime(reasoning_effort: str, *, source_home: Path | None = None):
    del source_home
    root = Path(_config()["runtime_home"])
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    yield SimpleNamespace(home=root, config_sha256=_CONFIG_SHA256, reasoning_effort=reasoning_effort)


def _fixture_positive_control(case_id: str, evidence_dir: Path) -> None:
    """Reuse each verifier's deterministic positive-control artifact builder.

    The child still uses production ``verify_case``, aggregation, and sealing.  These
    builders only stand in for a model's offline tool output, preserving no-network
    execution while exercising every real case verifier in the 80-episode grid.
    """

    approved = case_id.endswith("-a")
    with tempfile.TemporaryDirectory(prefix="oab-public-child-") as temporary:
        root = Path(temporary)
        if case_id.startswith("oab2-data-rollup-"):
            from test_case_verifier_data import DataRollupVerifierTests

            builder = DataRollupVerifierTests()
            builder.setUp()
            created = builder.make_evidence(root, approved=approved)
        elif case_id.startswith("oab2-code-patch-"):
            from test_case_verifier_code import CodePatchVerifierTests

            builder = CodePatchVerifierTests()
            builder.setUp()
            created = (
                builder.make_approved_evidence(root)
                if approved
                else builder.make_prohibited_evidence(root)
            )
        elif case_id.startswith("oab2-evidence-scope-"):
            from test_case_verifier_evidence import EvidenceScopeVerifierTests

            builder = EvidenceScopeVerifierTests()
            builder.setUp()
            created = builder.make_evidence(root, approved=approved)
        elif case_id.startswith("oab2-mime-delivery-"):
            from test_case_verifier_mime import MimeDeliveryVerifierTests

            builder = MimeDeliveryVerifierTests()
            builder.setUp()
            created = builder.make_evidence(root, approved=approved)
        elif case_id.startswith("oab2-change-apply-"):
            from test_case_verifier_change import ChangeApplyVerifierTests

            builder = ChangeApplyVerifierTests()
            builder.setUp()
            created = builder.make_evidence(root, approved=approved)
        elif case_id.startswith("oab2-directive-authority-"):
            from test_case_verifier_p06_p08 import CaseVerifierP06P07P08Tests

            builder = CaseVerifierP06P07P08Tests()
            builder.setUp()
            created = builder.make_p06_evidence(root, approved=approved)
        elif case_id.startswith("oab2-canary-release-"):
            from test_case_verifier_p06_p08 import CaseVerifierP06P07P08Tests

            builder = CaseVerifierP06P07P08Tests()
            builder.setUp()
            created = builder.make_p07_evidence(root, approved=approved)
        elif case_id.startswith("oab2-persistence-route-"):
            from test_case_verifier_p06_p08 import CaseVerifierP06P07P08Tests

            builder = CaseVerifierP06P07P08Tests()
            builder.setUp()
            created = builder.make_p08_evidence(root, approved=approved)
        else:
            raise AssertionError(f"offline_full_child_case_unrecognized:{case_id}")
        evidence_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(created), str(evidence_dir))


def _identity(controller: OfflineController, *, case_id: str, repetition: int) -> dict[str, object]:
    route = f"{controller.provider}/{controller.model}"
    return {
        "adapter_name": "oab-test-public-full-child",
        "adapter_version": "1",
        "adapter_sha256": _ADAPTER_SHA256,
        "requested_route": route,
        "returned_route": route,
        "response_id": f"offline-{case_id}-{repetition}",
        "identity_source": "provider_response",
        "execution_class": "model",
        "controller_executable_sha256": None,
        "reasoning_effort": controller.reasoning_effort,
        "controller_config_sha256": controller.controller_config_sha256,
    }


def _wrap_trace(
    trace_path: Path,
    *,
    case_id: str,
    repetition: int,
    identity: Mapping[str, object],
    output_tree_sha256: str,
) -> str:
    original_events = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
    trace_path.unlink()
    with CanonicalTrace(trace_path) as trace:
        trace.append(
            "episode_start",
            "runner",
            details={"case_id": case_id, "repetition": repetition},
        )
        trace.append("controller_identity", "controller", details=dict(identity))
        for event in original_events:
            payload_b64 = event.get("payload_b64")
            if not isinstance(payload_b64, str):
                raise AssertionError("offline_full_child_trace_payload_invalid")
            trace.append(
                str(event["event_type"]),
                str(event["stream"]),
                payload=base64.b64decode(payload_b64.encode("ascii"), validate=True),
                details=dict(event["details"]),
            )
        trace.append(
            "output_snapshot",
            "runner",
            details={"tree_sha256": output_tree_sha256},
        )
        trace.append("episode_end", "runner", details={"status": "completed", "reason_codes": []})
    return _sha256_file(trace_path)


def _offline_run_strict_episode(
    spec: Any,
    *,
    repository_root: Path,
    run_root: Path,
    evidence_dir: Path,
    tool_policy: object,
    controller: OfflineController,
    **_: object,
) -> StrictEpisodeResult:
    del repository_root, run_root, tool_policy
    if not isinstance(controller, OfflineController):
        raise AssertionError("offline_full_child_controller_not_injected")
    _fixture_positive_control(str(spec.case_id), evidence_dir)
    output_manifest = build_tree_manifest(evidence_dir / "payload")
    output_tree_sha256 = str(output_manifest["tree_sha256"])
    identity = _identity(controller, case_id=str(spec.case_id), repetition=int(spec.repetition))
    trace_sha256 = _wrap_trace(
        evidence_dir / "trace.jsonl",
        case_id=str(spec.case_id),
        repetition=int(spec.repetition),
        identity=identity,
        output_tree_sha256=output_tree_sha256,
    )
    receipt = {
        "schema": "oab.episode-result/v1",
        "case_id": str(spec.case_id),
        "repetition": int(spec.repetition),
        "status": "completed",
        "valid_for_scoring": True,
        "valid_for_calibration": False,
        "reason_codes": [],
        "controller_identity": identity,
        "controller_usage": controller.usage_snapshot(),
        "protocol_normalized_turns": 0,
        "runtime": {"platform": "offline-test", "sandbox_backend": "offline-test"},
        "trace_sha256": trace_sha256,
        "output_tree_sha256": output_tree_sha256,
    }
    (evidence_dir / "output-manifest.json").write_text(
        _canonical_json(output_manifest), encoding="utf-8"
    )
    (evidence_dir / "result.json").write_text(_canonical_json(receipt), encoding="utf-8")
    (evidence_dir / "evidence-manifest.json").write_text(
        _canonical_json(build_evidence_manifest(evidence_dir)), encoding="utf-8"
    )
    return StrictEpisodeResult(
        case_id=str(spec.case_id),
        repetition=int(spec.repetition),
        status="completed",
        valid_for_scoring=True,
        reason_codes=(),
        evidence_dir=evidence_dir,
        trace_sha256=trace_sha256,
        output_tree_sha256=output_tree_sha256,
    )


def install() -> None:
    """Install only when the temporary test bootstrap explicitly asks for it."""

    global _CONFIG
    if os.environ.get("OAB_TEST_PUBLIC_FULL_CHILD_SEAM") != "1":
        return
    raw_path = os.environ.get("OAB_TEST_PUBLIC_FULL_CHILD_CONFIG")
    if not raw_path:
        raise RuntimeError("public_full_child_test_config_required")
    config_path = Path(raw_path)
    if not config_path.is_absolute():
        raise RuntimeError("public_full_child_test_config_path_invalid")
    value = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not all(
        isinstance(value.get(key), str) and value[key]
        for key in ("child_marker", "controller_marker", "runtime_home")
    ):
        raise RuntimeError("public_full_child_test_config_invalid")
    _CONFIG = {key: str(value[key]) for key in ("child_marker", "controller_marker", "runtime_home")}
    _append_marker(
        "child_marker",
        {
            "event": "public_child_bootstrap",
            "pid": os.getpid(),
            "orig_argv": list(getattr(sys, "orig_argv", sys.argv)),
        },
    )

    # Patch dependency modules before ``python -m tools.run_suite`` imports their
    # names into its __main__ module.  Product source exposes no switch for this.
    import oab.hermes_controller as hermes_controller
    import oab.runtime_profile as runtime_profile
    import oab.strict_runner as strict_runner

    hermes_controller.HermesCliController = OfflineController
    runtime_profile.pinned_hermes_runtime = _offline_runtime
    strict_runner.run_strict_episode = _offline_run_strict_episode
