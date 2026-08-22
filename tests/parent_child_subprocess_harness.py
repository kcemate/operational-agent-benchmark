"""Offline child executable used only by parent-to-child authorization integration tests.

The production parent still launches a real subprocess with descriptor-passed
campaign authority.  This harness replaces only provider-facing execution after
the public child has reconstructed that authority; it records controller
construction so rejection cases can prove they stopped before that boundary.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Mapping
from unittest.mock import patch


def _path_from_environment(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing_test_environment:{name}")
    return Path(value)


def _sha256(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


class OfflineController:
    controller_config_sha256 = "sha256:" + "a" * 64
    protocol_normalized_turns = 0

    def __init__(self, **_kwargs: object) -> None:
        _path_from_environment("OAB_TEST_CONTROLLER_MARKER").write_text(
            str(os.getpid()) + "\n", encoding="utf-8"
        )

    def usage_snapshot(self) -> dict[str, object]:
        return {
            "api_calls": 17,
            "input_tokens": 1,
            "output_tokens": 1,
            "latency_ms": 1.0,
            "cost_usd": 0.0,
            "known_cost_usd": 0.0,
            "unknown_cost_api_calls": 0,
        }


@contextlib.contextmanager
def _offline_runtime():
    yield SimpleNamespace(
        home=_path_from_environment("OAB_TEST_STAGE_ROOT"),
        config_sha256=OfflineController.controller_config_sha256,
    )


def _fake_seal(output_root: Path, *, release_manifest: Path | None = None) -> tuple[Path, str]:
    del release_manifest
    path = output_root / "SUITE_SEAL.json"
    payload = {"schema": "oab.test-subprocess-seal/v1"}
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    return path, _sha256("test-subprocess-seal")


def _fake_full_observations(
    *,
    args: object,
    selected_cases: list[dict[str, object]],
    output_root: Path,
    runtime_home: Path,
    authoritative_full: bool = False,
) -> list[dict[str, object]]:
    del output_root, runtime_home
    if not authoritative_full:
        raise ValueError("test_harness_full_mode_required")
    controller = OfflineController()
    repetitions = getattr(args, "repetitions")
    provider = getattr(args, "provider")
    model = getattr(args, "model")
    effort = getattr(args, "reasoning_effort")
    if not isinstance(repetitions, int):
        raise ValueError("test_harness_repetitions_invalid")
    route = f"{provider}/{model}"
    observations: list[dict[str, object]] = []
    for repetition in range(1, repetitions + 1):
        for case in selected_cases:
            case_id = str(case["case_id"])
            pair_id = str(case["pair_id"])
            variant = str(case["variant"])
            label = f"{case_id}:{repetition}"
            observations.append(
                {
                    "pair_id": pair_id,
                    "case_id": case_id,
                    "variant": variant,
                    "repetition": repetition,
                    "runner_status": "completed",
                    "valid_for_authoritative_scoring": True,
                    "reason_codes": [],
                    "all_declared_gates_passed": True,
                    "identity_source": "provider_response",
                    "requested_route": route,
                    "returned_route": route,
                    "response_id": f"offline-{label}",
                    "reasoning_effort": effort,
                    "controller_config_sha256": controller.controller_config_sha256,
                    "gates": [],
                    "controller_usage": controller.usage_snapshot(),
                    "protocol_normalized_turns": 0,
                    "runtime": {
                        "platform": "test-posix",
                        "sandbox_backend": "offline-test",
                    },
                    "trace_sha256": _sha256("trace:" + label),
                    "output_tree_sha256": _sha256("output:" + label),
                    "evidence_dir": f"evidence/rep-{repetition:02d}/{case_id}",
                }
            )
    return observations


def _fake_qualification(
    *,
    args: object,
    output_root: Path,
    runtime_home: Path,
    release_tree_sha256: str | None,
    controller_config_sha256: str | None,
    qualification_contract: Mapping[str, object],
) -> dict[str, object]:
    del runtime_home, controller_config_sha256
    from qualification_fixtures import write_qualification_suite

    controller = OfflineController()
    staging = _path_from_environment("OAB_TEST_STAGE_ROOT") / "qualification-fixture"
    if staging.exists():
        shutil.rmtree(staging)
    route = f"{getattr(args, 'provider')}/{getattr(args, 'model')}"
    report = write_qualification_suite(
        staging,
        route=route,
        contract=qualification_contract,
        effort=str(getattr(args, "reasoning_effort")),
        release_tree_sha256=str(release_tree_sha256),
    )
    shutil.copytree(staging, output_root, dirs_exist_ok=True)
    return {
        "schema": "oab.qualification-child-result/v1",
        "readiness": report["readiness"],
        "reason_codes": report["reason_codes"],
        "controller_usage": report["controller_usage"],
        "suite_report_path": str(output_root / "suite-report.json"),
        "suite_seal_path": str(output_root / "SUITE_SEAL.json"),
        "suite_seal_sha256": _sha256("qualification:" + controller.controller_config_sha256),
    }


def main() -> int:
    repository_root = _path_from_environment("OAB_TEST_REPOSITORY_ROOT")
    sys.path.insert(0, str(repository_root))
    sys.path.insert(0, str(repository_root / "tests"))
    arguments = sys.argv[1:]
    if arguments[:2] != ["-m", "tools.run_suite"]:
        raise RuntimeError("test_harness_unexpected_child_command")

    from tools import run_suite

    _path_from_environment("OAB_TEST_CHILD_MARKER").write_text(
        str(os.getpid()) + "\n", encoding="utf-8"
    )
    with (
        patch.object(run_suite, "verify_release_manifest", return_value=[]),
        patch.object(
            run_suite,
            "pinned_hermes_runtime",
            side_effect=lambda *_args, **_kwargs: _offline_runtime(),
        ),
        patch.object(run_suite, "HermesCliController", OfflineController),
        patch.object(run_suite, "_run_qualification_readiness", side_effect=_fake_qualification),
        patch.object(run_suite, "_run_observations", side_effect=_fake_full_observations),
        patch.object(run_suite, "write_suite_seal", side_effect=_fake_seal),
    ):
        return run_suite.main(arguments[2:])


if __name__ == "__main__":
    raise SystemExit(main())
