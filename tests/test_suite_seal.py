from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from oab.aggregation import aggregate_suite_observations, format_headline
from oab.case_verifier import verify_case
from oab.evidence import build_evidence_manifest
from oab.manifest import build_tree_manifest
from oab.paths import benchmark_root
from oab.registry import load_registry
from oab.suite_seal import verify_suite_seal, write_suite_seal
from oab.trace import CanonicalTrace

ROOT = benchmark_root()
CONFIG_DIGEST = "sha256:" + "3" * 64
RELEASE_DIGEST = "sha256:" + "4" * 64


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class SuiteSealTests(unittest.TestCase):
    def _episode(self, output: Path, *, case: dict[str, object], repetition: int) -> dict[str, object]:
        case_id = str(case["case_id"])
        evidence = output / "evidence" / f"rep-{repetition:02d}" / case_id
        payload = evidence / "payload/output"
        payload.mkdir(parents=True)
        (payload / "result.json").write_text('{"ok":false}\n', encoding="utf-8")
        output_manifest = build_tree_manifest(evidence / "payload")
        reason_codes: list[str] = []
        identity = {
            "identity_source": "provider_response",
            "requested_route": "provider/model",
            "returned_route": "provider/model",
            "response_id": f"response-{case_id}",
            "reasoning_effort": "high",
            "controller_config_sha256": CONFIG_DIGEST,
        }
        usage = {
            "api_calls": 1,
            "input_tokens": 1,
            "output_tokens": 1,
            "latency_ms": 1.0,
            "cost_usd": None,
            "known_cost_usd": 0.0,
            "unknown_cost_api_calls": 1,
        }
        runtime = {"platform": "darwin", "sandbox_backend": "macos-sandbox-exec"}
        with CanonicalTrace(evidence / "trace.jsonl") as trace:
            trace.append(
                "episode_start",
                "controller",
                details={"case_id": case_id, "repetition": repetition},
            )
            trace.append(
                "controller_identity",
                "controller",
                details=identity,
            )
            trace.append(
                "output_snapshot",
                "verifier",
                details={"tree_sha256": output_manifest["tree_sha256"]},
            )
            trace.append(
                "episode_end",
                "controller",
                details={"status": "completed", "reason_codes": reason_codes},
            )
        (evidence / "output-manifest.json").write_bytes(
            _canonical_bytes(output_manifest) + b"\n"
        )
        receipt = {
            "schema": "oab.episode-result/v1",
            "case_id": case_id,
            "repetition": repetition,
            "status": "completed",
            "execution_class": "provider_identity",
            "valid_for_scoring": True,
            "valid_for_calibration": False,
            "reason_codes": reason_codes,
            "trace_sha256": _sha256_file(evidence / "trace.jsonl"),
            "output_tree_sha256": output_manifest["tree_sha256"],
            "controller_identity": identity,
            "controller_usage": usage,
            "runtime": runtime,
        }
        (evidence / "result.json").write_bytes(_canonical_bytes(receipt) + b"\n")
        envelope = build_evidence_manifest(evidence)
        (evidence / "evidence-manifest.json").write_bytes(
            _canonical_bytes(envelope) + b"\n"
        )
        fixture = ROOT / str(case["fixture_path"])
        gates = verify_case(case, fixture, evidence)
        return {
            "pair_id": str(case["pair_id"]),
            "case_id": case_id,
            "variant": str(case["variant"]),
            "repetition": repetition,
            "runner_status": "completed",
            "valid_for_authoritative_scoring": True,
            "reason_codes": reason_codes,
            "all_declared_gates_passed": all(gate.passed for gate in gates),
            "identity_source": "provider_response",
            "requested_route": "provider/model",
            "returned_route": "provider/model",
            "response_id": f"response-{case_id}",
            "reasoning_effort": "high",
            "controller_config_sha256": CONFIG_DIGEST,
            "gates": [
                {"id": gate.dimension, "passed": gate.passed, "code": gate.code}
                for gate in gates
            ],
            "controller_usage": usage,
            "runtime": runtime,
            "trace_sha256": receipt["trace_sha256"],
            "output_tree_sha256": receipt["output_tree_sha256"],
            "evidence_dir": str(evidence.resolve()),
        }

    def _suite(self, root: Path) -> Path:
        output = root / "suite"
        registry = load_registry(ROOT / "cases.json")
        cases = [
            case for case in registry["cases"] if str(case["pair_id"]) == "P01"
        ]
        observations = [self._episode(output, case=case, repetition=1) for case in cases]
        case_map = {
            "P01": {
                str(case["variant"]): str(case["case_id"])
                for case in cases
            }
        }
        report = aggregate_suite_observations(
            observations,
            requested_route="provider/model",
            reasoning_effort="high",
            controller_config_sha256=CONFIG_DIGEST,
            release_tree_sha256=RELEASE_DIGEST,
            release_authorized=False,
            repetitions=1,
            pair_ids=["P01"],
            case_ids_by_pair=case_map,
        )
        (output / "suite-report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (output / "HEADLINE.txt").write_text(str(report["headline"]) + "\n", encoding="utf-8")
        return output

    def test_intact_suite_verifies_with_external_digest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            _path, digest = write_suite_seal(output)
            self.assertEqual([], verify_suite_seal(output, expected_seal_sha256=digest))

    def test_payload_tamper_is_rejected_at_episode_verification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            _path, digest = write_suite_seal(output)
            evidence = output / "evidence/rep-01/oab2-data-rollup-a/result.json"
            evidence.write_text('{"status":"rewritten"}\n', encoding="utf-8")
            errors = verify_suite_seal(output, expected_seal_sha256=digest)
            self.assertTrue(
                any(error.startswith("suite_evidence_unsealed") for error in errors),
                errors,
            )

    def test_coordinated_reseal_fails_against_external_digest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            _path, original_digest = write_suite_seal(output)
            evidence = output / "evidence/rep-01/oab2-data-rollup-a/result.json"
            evidence.write_text('{"status":"rewritten"}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "suite_evidence_unsealed"):
                write_suite_seal(output)
            errors = verify_suite_seal(output, expected_seal_sha256=original_digest)
            self.assertTrue(
                any(error.startswith("suite_evidence_unsealed") for error in errors),
                errors,
            )

    def test_invalid_episode_cannot_be_suite_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            (output / "evidence/rep-01/oab2-data-rollup-a/evidence-manifest.json").unlink()
            with self.assertRaisesRegex(ValueError, "suite_evidence_unsealed"):
                write_suite_seal(output)

    def test_fabricated_metric_and_headline_cannot_be_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            report_path = output / "suite-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["completed_contract_episodes"] = 2
            report["deterministic_contract_completion_rate"] = 1.0
            report["headline"] = "AUTHORITATIVE | fabricated perfect score"
            report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
            (output / "HEADLINE.txt").write_text(str(report["headline"]) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "suite_report_recomputation_mismatch"):
                write_suite_seal(output)

    def test_incomplete_observation_grid_cannot_be_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            report_path = output / "suite-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["observations"] = report["observations"][:-1]
            report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "suite_observation_grid_invalid"):
                write_suite_seal(output)

    def test_headline_file_must_match_recomputed_report(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            (output / "HEADLINE.txt").write_text("fabricated\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "suite_headline_mismatch"):
                write_suite_seal(output)

    def test_release_authorization_requires_bound_approval_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._suite(Path(temp_dir))
            recorded = json.loads(
                (output / "suite-report.json").read_text(encoding="utf-8")
            )
            report = aggregate_suite_observations(
                recorded["observations"],
                requested_route="provider/model",
                reasoning_effort="high",
                controller_config_sha256="sha256:" + "3" * 64,
                release_tree_sha256="sha256:" + "4" * 64,
                release_approval_sha256="sha256:" + "5" * 64,
                release_authorized=True,
                repetitions=1,
                pair_ids=["P01"],
                case_ids_by_pair={
                    "P01": {
                        "approved": "oab2-data-rollup-a",
                        "prohibited": "oab2-data-rollup-p",
                    }
                },
            )
            (output / "suite-report.json").write_text(
                json.dumps(report, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            (output / "HEADLINE.txt").write_text(
                str(report["headline"]) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "release_approval_unreadable"):
                write_suite_seal(output)

    def test_reasoning_effort_cannot_be_rewritten_away_from_episode_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            report = json.loads((output / "suite-report.json").read_text(encoding="utf-8"))
            for observation in report["observations"]:
                observation["reasoning_effort"] = "medium"
            rewritten = aggregate_suite_observations(
                report["observations"],
                requested_route="provider/model",
                reasoning_effort="medium",
                controller_config_sha256=CONFIG_DIGEST,
                release_tree_sha256=RELEASE_DIGEST,
                release_authorized=False,
                repetitions=1,
                pair_ids=["P01"],
                case_ids_by_pair={
                    "P01": {
                        "approved": "oab2-data-rollup-a",
                        "prohibited": "oab2-data-rollup-p",
                    }
                },
            )
            (output / "suite-report.json").write_bytes(_canonical_bytes(rewritten) + b"\n")
            (output / "HEADLINE.txt").write_text(
                format_headline(rewritten) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "suite_report_recomputation_mismatch"):
                write_suite_seal(output)


if __name__ == "__main__":
    unittest.main()
