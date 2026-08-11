from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import patch

from oab.aggregation import aggregate_suite_observations, format_headline
from oab.case_verifier import verify_case
from oab.evidence import build_evidence_manifest, verify_sealed_evidence
from oab.manifest import build_tree_manifest
from oab.paths import benchmark_root
from oab.registry import load_registry
from oab.suite_seal import verify_suite_seal, write_suite_seal
import oab.suite_seal as suite_seal
from oab.trace import CanonicalTrace
from qualification_fixtures import write_qualification_suite

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

    def test_generic_full_quality_aggregation_and_seal_remain_intact(self) -> None:
        """The protected full-suite aggregate remains distinct from readiness mode."""
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            report = json.loads((output / "suite-report.json").read_text(encoding="utf-8"))
            self.assertEqual("oab.suite-report/v1", report["schema"])
            self.assertIn("deterministic_contract_completion_rate", report)
            self.assertIn("matched_pair_completion_rate", report)
            self.assertIn("pair_stability", report)
            self.assertEqual(
                format_headline(report) + "\n",
                (output / "HEADLINE.txt").read_text(encoding="utf-8"),
            )
            _path, digest = write_suite_seal(output)
            self.assertEqual([], verify_suite_seal(output, expected_seal_sha256=digest))

    def test_qualification_seal_rejects_tamper_extra_duplicate_illegal_retry_and_selection(self) -> None:
        """Every readiness seal is reconstructed, not trusted as a caller summary."""
        scenarios = (
            ("tampered-evidence", "qualification_attempt_unsealed"),
            ("extra-attempt", "qualification_evidence_grid_invalid"),
            ("duplicate-attempt", "qualification_retry_illegal"),
            ("illegal-retry", "qualification_retry_illegal"),
            ("selected-attempt-mismatch", "qualification_probe_selection_invalid"),
        )
        for label, expected_error in scenarios:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as td:
                output = Path(td) / "qualification"
                write_qualification_suite(output, route="offline/qualification-seal")
                report_path = output / "suite-report.json"
                report = json.loads(report_path.read_text(encoding="utf-8"))

                if label == "tampered-evidence":
                    receipt_path = (
                        output
                        / "evidence"
                        / "rep-01"
                        / "oab2-data-rollup-a"
                        / "attempt-01"
                        / "result.json"
                    )
                    receipt_path.write_text("{}\n", encoding="utf-8")
                elif label == "extra-attempt":
                    (
                        output
                        / "evidence"
                        / "rep-01"
                        / "oab2-data-rollup-a"
                        / "attempt-99"
                    ).mkdir()
                elif label == "duplicate-attempt":
                    report["attempts"].append(dict(report["attempts"][0]))
                    report_path.write_text(
                        json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
                    )
                elif label == "illegal-retry":
                    retry = dict(report["attempts"][0])
                    retry.update(
                        {
                            "attempt_id": "P01-approved-attempt-02",
                            "attempt_number": 2,
                            "attempt_kind": "infrastructure_retry",
                            "retry_trigger": "P01-approved-attempt-01",
                            "evidence_dir": "evidence/rep-01/oab2-data-rollup-a/attempt-02",
                        }
                    )
                    report["attempts"].append(retry)
                    report_path.write_text(
                        json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
                    )
                else:
                    report["probes"][0]["selected_attempt"] = (
                        "P01-prohibited-attempt-01"
                    )
                    report_path.write_text(
                        json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
                    )

                errors = verify_suite_seal(output)
                self.assertTrue(errors, errors)
                self.assertTrue(
                    any(expected_error in error for error in errors),
                    (label, errors),
                )

    def test_relative_evidence_paths_match_descriptor_bound_suite_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            report_path = output / "suite-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            for observation in report["observations"]:
                observation["evidence_dir"] = str(
                    Path(observation["evidence_dir"]).relative_to(output.resolve())
                )
            report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            _path, digest = write_suite_seal(output)

            self.assertEqual([], verify_suite_seal(output, expected_seal_sha256=digest))

    def _substitute_intermediate_symlink(self, output: Path, level: str) -> None:
        candidate = output / "evidence"
        if level == "repetition":
            candidate = candidate / "rep-01"
        external = output.parent / f"external-{level}"
        candidate.rename(external)
        candidate.symlink_to(external, target_is_directory=True)

    def test_intermediate_evidence_symlinks_cannot_be_sealed(self) -> None:
        for level in ("evidence", "repetition"):
            with self.subTest(level=level), tempfile.TemporaryDirectory() as td:
                output = self._suite(Path(td))
                self._substitute_intermediate_symlink(output, level)

                with self.assertRaisesRegex(ValueError, "suite_evidence_path_unsafe"):
                    write_suite_seal(output)

    def test_intermediate_evidence_symlinks_invalidate_existing_seal(self) -> None:
        for level in ("evidence", "repetition"):
            with self.subTest(level=level), tempfile.TemporaryDirectory() as td:
                output = self._suite(Path(td))
                _path, digest = write_suite_seal(output)
                self._substitute_intermediate_symlink(output, level)

                errors = verify_suite_seal(output, expected_seal_sha256=digest)

                self.assertTrue(
                    any("suite_evidence_path_unsafe" in error for error in errors),
                    errors,
                )

    def test_fixed_suite_metadata_symlinks_are_rejected(self) -> None:
        for name in ("suite-report.json", "HEADLINE.txt"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                output = self._suite(Path(td))
                source = output / name
                external = output.parent / f"external-{name}"
                source.rename(external)
                source.symlink_to(external)
                with self.assertRaisesRegex(ValueError, "suite_metadata_file_unsafe"):
                    write_suite_seal(output)

        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            _path, digest = write_suite_seal(output)
            source = output / "SUITE_SEAL.json"
            external = output.parent / "external-seal.json"
            source.rename(external)
            source.symlink_to(external)
            self.assertIn(
                "suite_seal_unreadable",
                verify_suite_seal(output, expected_seal_sha256=digest),
            )

    def test_report_mutation_after_snapshot_is_rejected(self) -> None:
        for restore in (False, True):
            with self.subTest(restore=restore), tempfile.TemporaryDirectory() as td:
                output = self._suite(Path(td))
                report_path = output / "suite-report.json"
                original = report_path.read_bytes()
                real_context = suite_seal._trusted_episode_directories

                @contextmanager
                def mutate_after_report(*args: object, **kwargs: object):
                    report_path.write_bytes(original + b" ")
                    if restore:
                        report_path.write_bytes(original)
                    with real_context(*args, **kwargs) as value:
                        yield value

                with patch(
                    "oab.suite_seal._trusted_episode_directories",
                    side_effect=mutate_after_report,
                ):
                    with self.assertRaisesRegex(ValueError, "suite_metadata_file_unsafe"):
                        write_suite_seal(output)

    def test_evidence_mutation_after_snapshot_is_rejected(self) -> None:
        for restore in (False, True):
            with self.subTest(restore=restore), tempfile.TemporaryDirectory() as td:
                output = self._suite(Path(td))
                source = output / "evidence/rep-01/oab2-data-rollup-a/result.json"
                original = source.read_bytes()
                real_verify = suite_seal.verify_sealed_evidence
                mutated = False

                def mutate_after_snapshot(path: Path) -> dict[str, object]:
                    nonlocal mutated
                    result = real_verify(path)
                    if not mutated:
                        source.write_bytes(original + b" ")
                        if restore:
                            source.write_bytes(original)
                        mutated = True
                    return result

                with patch(
                    "oab.suite_seal.verify_sealed_evidence",
                    side_effect=mutate_after_snapshot,
                ):
                    with self.assertRaisesRegex(ValueError, "suite_evidence_path_unsafe"):
                        write_suite_seal(output)

    def test_relative_suite_can_be_relocated_after_sealing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = self._suite(root)
            report_path = output / "suite-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            for observation in report["observations"]:
                observation["evidence_dir"] = str(
                    Path(observation["evidence_dir"]).relative_to(output.resolve())
                )
            report_path.write_bytes(_canonical_bytes(report) + b"\n")
            _path, digest = write_suite_seal(output)
            relocated = root / "relocated"
            output.rename(relocated)
            self.assertEqual(
                [], verify_suite_seal(relocated, expected_seal_sha256=digest)
            )

    def test_episode_symlink_hardlink_and_special_file_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            episode = output / "evidence/rep-01/oab2-data-rollup-a"
            held = output.parent / "held-episode"
            episode.rename(held)
            episode.symlink_to(held, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "suite_evidence_path_unsafe"):
                write_suite_seal(output)

        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            episode = output / "evidence/rep-01/oab2-data-rollup-a"
            os.link(episode / "result.json", episode / "alias.json")
            with self.assertRaisesRegex(ValueError, "suite_evidence_path_unsafe"):
                write_suite_seal(output)

        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            episode = output / "evidence/rep-01/oab2-data-rollup-a"
            os.mkfifo(episode / "pipe")
            with self.assertRaisesRegex(ValueError, "suite_evidence_path_unsafe"):
                write_suite_seal(output)

    def test_snapshot_pathname_substitution_leaves_replacement_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            created: list[Path] = []
            real_mkdtemp = suite_seal.tempfile.mkdtemp
            real_copy = suite_seal._copy_snapshot_tree_fd
            substituted: dict[str, Path] = {}

            def recording_mkdtemp(*args: Any, **kwargs: Any) -> str:
                path = real_mkdtemp(*args, **kwargs)
                created.append(Path(path))
                return path

            def substitute_after_copy(*args: Any, **kwargs: Any) -> None:
                real_copy(*args, **kwargs)
                if substituted:
                    return
                snapshot = created[-1].resolve()
                held = snapshot.with_name(snapshot.name + "-held")
                snapshot.rename(held)
                snapshot.mkdir()
                marker = snapshot / "UNOWNED"
                marker.write_text("keep", encoding="utf-8")
                substituted.update(snapshot=snapshot, held=held, marker=marker)

            with patch.object(
                suite_seal.tempfile, "mkdtemp", side_effect=recording_mkdtemp
            ), patch(
                "oab.suite_seal._copy_snapshot_tree_fd",
                side_effect=substitute_after_copy,
            ):
                with self.assertRaisesRegex(ValueError, "suite_evidence_path_unsafe"):
                    write_suite_seal(output)

            self.assertTrue(substituted)
            self.assertTrue(substituted["marker"].exists())
            self.assertEqual(
                "keep", substituted["marker"].read_text(encoding="utf-8")
            )
            shutil.rmtree(substituted["snapshot"])
            shutil.rmtree(substituted["held"])

    def test_snapshot_directory_substituted_before_binding_never_deletes_victim(
        self,
    ) -> None:
        """A leaf substituted between creation and binding must not be followed.

        Regression for the reviewer-reproduced race: the snapshot pathname returned by
        ``tempfile.mkdtemp`` was resolved before descriptor binding, so a same-user
        attacker could replace it with a symlink to a victim directory whose contents
        ownership-bound cleanup then removed.
        """
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            victim = Path(td) / "victim"
            victim.mkdir()
            marker = victim / "VICTIM"
            marker.write_text("keep", encoding="utf-8")
            real_mkdtemp = suite_seal.tempfile.mkdtemp
            hook: dict[str, object] = {}

            def substituting_mkdtemp(*args: Any, **kwargs: Any) -> str:
                created = Path(real_mkdtemp(*args, **kwargs))
                if hook:
                    return str(created)
                held = created.with_name(created.name + "-held")
                created.rename(held)
                created.symlink_to(victim, target_is_directory=True)
                hook.update(created=created, held=held)
                return str(created)

            with patch.object(
                suite_seal.tempfile, "mkdtemp", side_effect=substituting_mkdtemp
            ):
                with self.assertRaises(ValueError) as caught:
                    write_suite_seal(output)

            self.assertTrue(hook)
            self.assertTrue(victim.is_dir())
            self.assertTrue(marker.is_file())
            self.assertEqual("keep", marker.read_text(encoding="utf-8"))
            self.assertIn("suite_evidence_path_unsafe", str(caught.exception))
            created = hook["created"]
            held = hook["held"]
            assert isinstance(created, Path) and isinstance(held, Path)
            self.assertTrue(created.is_symlink())
            created.unlink()
            shutil.rmtree(held)

    def test_retained_report_and_seal_byte_tamper_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            _path, digest = write_suite_seal(output)
            seal = (output / "SUITE_SEAL.json").read_bytes()
            report = (output / "suite-report.json").read_bytes()

            tampered_seal = bytearray(seal)
            tampered_seal[-2] ^= 1
            self.assertEqual(
                ["suite_seal_unreadable"],
                verify_suite_seal(
                    output,
                    expected_seal_sha256=digest,
                    seal_bytes=bytes(tampered_seal),
                    report_bytes=report,
                ),
            )

            self.assertEqual(
                ["suite_metadata_file_unsafe"],
                verify_suite_seal(
                    output,
                    expected_seal_sha256=digest,
                    seal_bytes=seal,
                    report_bytes=report + b" ",
                ),
            )

    def test_full_grid_seal_stays_within_descriptor_budget(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "suite"
            registry = load_registry(ROOT / "cases.json")
            cases = list(registry["cases"])
            observations = [
                self._episode(output, case=case, repetition=repetition)
                for repetition in range(1, 11)
                for case in cases
            ]
            case_map: dict[str, dict[str, str]] = {}
            for case in cases:
                case_map.setdefault(str(case["pair_id"]), {})[
                    str(case["variant"])
                ] = str(case["case_id"])
            report = aggregate_suite_observations(
                observations,
                requested_route="provider/model",
                reasoning_effort="high",
                controller_config_sha256=CONFIG_DIGEST,
                release_tree_sha256=RELEASE_DIGEST,
                release_authorized=False,
                repetitions=10,
                pair_ids=sorted(case_map),
                case_ids_by_pair=case_map,
            )
            (output / "suite-report.json").write_bytes(_canonical_bytes(report) + b"\n")
            (output / "HEADLINE.txt").write_text(
                str(report["headline"]) + "\n", encoding="utf-8"
            )

            before = len(os.listdir("/dev/fd"))
            _path, digest = write_suite_seal(output)
            after = len(os.listdir("/dev/fd"))

            self.assertEqual([], verify_suite_seal(output, expected_seal_sha256=digest))
            self.assertEqual(before, after)

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

    def test_aggregate_known_and_unknown_cost_telemetry_is_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = self._suite(Path(td))
            report_path = output / "suite-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            usage = report["controller_usage"]
            usage["known_cost_usd"] = 999.0
            usage["unknown_cost_api_calls"] = 0
            report_path.write_bytes(_canonical_bytes(report) + b"\n")
            with self.assertRaisesRegex(
                ValueError, "suite_report_recomputation_mismatch:controller_usage"
            ):
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


def _build_suite(base: Path) -> Path:
    """Build the standard one-repetition P01 suite fixture for the audit regressions."""
    return SuiteSealTests()._suite(base)


class SuiteSealPublicationTests(unittest.TestCase):
    """Seal publication must be descriptor-bound, atomic and substitution-proof."""

    def test_returned_digest_matches_written_bytes_without_pathname_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            path, digest = write_suite_seal(output)
            self.assertEqual(_sha256_file(path), digest)
            self.assertEqual([], verify_suite_seal(output, expected_seal_sha256=digest))

    def test_seal_digest_is_not_taken_from_a_substituted_replacement(self) -> None:
        """A file swapped in after the write must not be able to donate the digest.

        Publication no longer stages-then-renames, so there is no ``os.replace`` to
        intercept; the substitution is applied directly to the published seal name
        immediately after the owning descriptor is closed. The returned digest must
        always describe the bytes this call wrote, never the attacker's replacement.
        """
        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            forged = b'{"schema":"forged"}\n'
            real_fsync = suite_seal.os.fsync
            swapped: dict[str, bytes] = {}

            def fsync_then_substitute(fd: int) -> None:
                real_fsync(fd)
                if swapped:
                    return
                seal = output / "SUITE_SEAL.json"
                if not seal.is_file():
                    return
                written = seal.read_bytes()
                seal.unlink()
                seal.write_bytes(forged)
                swapped["written"] = written

            with patch.object(
                suite_seal.os, "fsync", side_effect=fsync_then_substitute
            ):
                try:
                    _path, digest = write_suite_seal(output)
                except ValueError as exc:
                    self.assertIn("suite_seal_publication_unsafe", str(exc))
                    return
            # If publication was allowed to complete, the digest must describe the
            # bytes this call actually wrote, never the attacker's replacement.
            self.assertTrue(swapped)
            self.assertEqual(
                "sha256:" + hashlib.sha256(swapped["written"]).hexdigest(), digest
            )
            self.assertNotEqual(
                "sha256:" + hashlib.sha256(forged).hexdigest(), digest
            )

    def test_substituted_seal_name_is_not_unlinked_on_failure(self) -> None:
        """Failure cleanup must prove inode identity before unlinking by pathname.

        Regression for the reviewer-reproduced race, restated for the descriptor-bound
        publication design: cleanup must never unlink a pathname that no longer maps
        to the inode this call created under ``O_EXCL``. An attacker who displaces the
        owned seal and drops a replacement under that name keeps their file.
        """
        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            real_fsync = suite_seal.os.fsync
            hook: dict[str, Path] = {}

            def substitute_then_fail(fd: int) -> None:
                real_fsync(fd)
                if hook:
                    return
                seal = output / "SUITE_SEAL.json"
                if not seal.is_file():
                    return
                displaced = output / "SUITE_SEAL.json-displaced"
                seal.rename(displaced)
                replacement = output / "SUITE_SEAL.json"
                replacement.write_text("attacker-owned", encoding="utf-8")
                hook.update(replacement=replacement, displaced=displaced)
                raise OSError("injected publication failure")

            with patch.object(
                suite_seal.os, "fsync", side_effect=substitute_then_fail
            ):
                with self.assertRaisesRegex(
                    ValueError, "suite_seal_publication_unsafe"
                ):
                    write_suite_seal(output)

            self.assertTrue(hook)
            self.assertTrue(hook["replacement"].is_file())
            self.assertEqual(
                "attacker-owned", hook["replacement"].read_text(encoding="utf-8")
            )
            hook["replacement"].unlink()
            hook["displaced"].unlink()

    def test_symlinked_seal_target_is_never_followed_or_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            external = output.parent / "external-seal.json"
            external.write_text("untouched", encoding="utf-8")
            (output / "SUITE_SEAL.json").symlink_to(external)

            with self.assertRaisesRegex(ValueError, "suite_seal_publication_unsafe"):
                write_suite_seal(output)

            self.assertEqual("untouched", external.read_text(encoding="utf-8"))
            self.assertTrue((output / "SUITE_SEAL.json").is_symlink())

    def test_hardlinked_and_special_seal_targets_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            seal = output / "SUITE_SEAL.json"
            seal.write_text("original", encoding="utf-8")
            alias = output.parent / "alias-seal.json"
            os.link(seal, alias)
            with self.assertRaisesRegex(ValueError, "suite_seal_publication_unsafe"):
                write_suite_seal(output)
            self.assertEqual("original", alias.read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            os.mkfifo(output / "SUITE_SEAL.json")
            with self.assertRaisesRegex(ValueError, "suite_seal_publication_unsafe"):
                write_suite_seal(output)

    def test_identical_reseal_returns_the_same_digest(self) -> None:
        """Rerun semantics: an identical reseal is accepted and returns one digest."""
        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            _first_path, first = write_suite_seal(output)
            _second_path, second = write_suite_seal(output)
            self.assertEqual(first, second)
            self.assertEqual([], verify_suite_seal(output, expected_seal_sha256=second))

    def test_failed_publication_leaves_no_temporary_files_or_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            os.mkfifo(output / "SUITE_SEAL.json")

            before = len(os.listdir("/dev/fd"))
            with self.assertRaises(ValueError):
                write_suite_seal(output)
            after = len(os.listdir("/dev/fd"))

            self.assertEqual(before, after)
            leftovers = [
                name
                for name in os.listdir(output)
                if name.startswith(".SUITE_SEAL.json.")
            ]
            self.assertEqual([], leftovers)


class SuiteSealSnapshotBindingRaceTests(unittest.TestCase):
    """Reviewer reproduction A: the snapshot pathname must never be followed.

    The independent reviewer bound ``_trusted_evidence_snapshot`` directly, renamed
    the yielded absolute pathname aside, dropped a victim directory in its place, and
    observed that the yielded value resolved to — and was read from — the victim
    before post-yield revalidation raised. These tests reconstruct that reproduction
    against the public sealing entry point and against the context manager itself.
    """

    def test_post_yield_snapshot_pathname_substitution_is_never_followed(self) -> None:
        """The consumer's binding must not resolve to a substituted victim.

        Exact reconstruction of the reviewer's reproducer: after the snapshot is
        bound and yielded, its absolute pathname is renamed aside and replaced by a
        symlink to a victim directory. Nothing OAB does afterwards may read, mutate
        or delete the victim, and the value handed to the consumer must not resolve
        there.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source"
            (source / "nested").mkdir(parents=True)
            (source / "result.json").write_text("{}\n", encoding="utf-8")
            (source / "nested" / "leaf.txt").write_text("owned\n", encoding="utf-8")

            victim = root / "victim"
            victim.mkdir()
            victim_marker = victim / "VICTIM"
            victim_marker.write_text("keep", encoding="utf-8")
            victim_state = sorted(entry.name for entry in victim.iterdir())

            created: list[Path] = []
            real_mkdtemp = suite_seal.tempfile.mkdtemp

            def recording_mkdtemp(*args: Any, **kwargs: Any) -> str:
                path = real_mkdtemp(*args, **kwargs)
                created.append(Path(path))
                return path

            source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            observed: dict[str, object] = {}
            try:
                with patch.object(
                    suite_seal.tempfile, "mkdtemp", side_effect=recording_mkdtemp
                ):
                    with self.assertRaises(ValueError) as caught:
                        with suite_seal._trusted_evidence_snapshot(
                            source_fd, Path("evidence/rep-01/case")
                        ) as bound:
                            snapshot = created[-1]
                            held = snapshot.with_name(snapshot.name + "-held")
                            snapshot.rename(held)
                            snapshot.symlink_to(victim, target_is_directory=True)
                            observed["held"] = held
                            observed["snapshot"] = snapshot
                            # The binding handed to consumers must still read the
                            # owned snapshot, not the substituted victim.
                            observed["entries"] = sorted(
                                entry.name for entry in bound.iterdir()
                            )
                            observed["leaf"] = (
                                bound / "nested" / "leaf.txt"
                            ).read_text(encoding="utf-8")
                            observed["victim_visible"] = (bound / "VICTIM").exists()
                            # A pathname-based consumer (verify_sealed_evidence) must
                            # not be redirected either.
                            observed["verified_dir"] = verify_sealed_evidence(bound)[
                                "evidence_dir"
                            ]
            finally:
                os.close(source_fd)

            self.assertIn("suite_evidence_path_unsafe", str(caught.exception))
            self.assertEqual(
                ["nested", "result.json"], observed["entries"]
            )
            self.assertEqual("owned\n", observed["leaf"])
            self.assertFalse(observed["victim_visible"])
            self.assertNotIn(str(victim), str(observed["verified_dir"]))

            # The victim was never read, mutated or deleted.
            self.assertTrue(victim.is_dir())
            self.assertEqual(
                victim_state, sorted(entry.name for entry in victim.iterdir())
            )
            self.assertEqual("keep", victim_marker.read_text(encoding="utf-8"))

            snapshot_path = observed["snapshot"]
            held_path = observed["held"]
            assert isinstance(snapshot_path, Path) and isinstance(held_path, Path)
            # The substituted pathname itself is left untouched, never deleted.
            self.assertTrue(snapshot_path.is_symlink())
            snapshot_path.unlink()
            shutil.rmtree(held_path)

    def test_snapshot_substituted_after_yield_during_sealing_leaves_victim_intact(
        self,
    ) -> None:
        """Same race through ``write_suite_seal``: sealing fails closed, victim intact."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = _build_suite(root)
            victim = root / "victim"
            victim.mkdir()
            marker = victim / "VICTIM"
            marker.write_text("keep", encoding="utf-8")

            created: list[Path] = []
            real_mkdtemp = suite_seal.tempfile.mkdtemp
            real_verify = suite_seal.verify_sealed_evidence
            hook: dict[str, Path] = {}

            def recording_mkdtemp(*args: Any, **kwargs: Any) -> str:
                path = real_mkdtemp(*args, **kwargs)
                created.append(Path(path))
                return path

            def substitute_then_verify(path: Path) -> dict[str, object]:
                # Substitute the snapshot pathname *after* the snapshot is bound and
                # handed to this consumer — the reviewer's exact window.
                if not hook:
                    snapshot = created[-1]
                    held = snapshot.with_name(snapshot.name + "-held")
                    snapshot.rename(held)
                    snapshot.symlink_to(victim, target_is_directory=True)
                    hook.update(snapshot=snapshot, held=held)
                return real_verify(path)

            with patch.object(
                suite_seal.tempfile, "mkdtemp", side_effect=recording_mkdtemp
            ), patch(
                "oab.suite_seal.verify_sealed_evidence",
                side_effect=substitute_then_verify,
            ):
                with self.assertRaisesRegex(ValueError, "suite_evidence_path_unsafe"):
                    write_suite_seal(output)

            self.assertTrue(hook)
            self.assertTrue(victim.is_dir())
            self.assertTrue(marker.is_file())
            self.assertEqual("keep", marker.read_text(encoding="utf-8"))
            self.assertFalse((output / "SUITE_SEAL.json").exists())
            self.assertTrue(hook["snapshot"].is_symlink())
            hook["snapshot"].unlink()
            shutil.rmtree(hook["held"])

    def test_snapshot_consumers_receive_no_mutable_absolute_pathname(self) -> None:
        """No security-relevant consumer may be handed the snapshot's absolute name."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source"
            source.mkdir()
            (source / "result.json").write_text("{}\n", encoding="utf-8")
            created: list[Path] = []
            real_mkdtemp = suite_seal.tempfile.mkdtemp

            def recording_mkdtemp(*args: Any, **kwargs: Any) -> str:
                path = real_mkdtemp(*args, **kwargs)
                created.append(Path(path))
                return path

            source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(
                    suite_seal.tempfile, "mkdtemp", side_effect=recording_mkdtemp
                ):
                    with suite_seal._trusted_evidence_snapshot(
                        source_fd, Path("evidence/rep-01/case")
                    ) as bound:
                        self.assertFalse(bound.is_absolute())
                        self.assertNotIn(created[-1].name, str(bound))
            finally:
                os.close(source_fd)


class SuiteSealPublicationOwnershipRaceTests(unittest.TestCase):
    """Reviewer reproduction B: never publish an inode this call did not create."""

    def test_no_staging_rename_window_exists_during_publication(self) -> None:
        """There must be no check-then-path-rename ownership gap at all.

        The reviewer displaced the owned staging inode immediately before the real
        ``os.replace`` and had their replacement moved onto ``SUITE_SEAL.json``. This
        asserts the window is gone by construction: publication performs no rename.
        """
        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            calls: list[tuple[Any, ...]] = []
            real_replace = suite_seal.os.replace

            def recording_replace(*args: Any, **kwargs: Any) -> None:
                calls.append(args)
                return real_replace(*args, **kwargs)

            with patch.object(
                suite_seal.os, "replace", side_effect=recording_replace
            ):
                _path, digest = write_suite_seal(output)

            self.assertEqual([], calls)
            self.assertEqual([], verify_suite_seal(output, expected_seal_sha256=digest))
            self.assertEqual(
                [],
                [
                    name
                    for name in os.listdir(output)
                    if name.startswith(".SUITE_SEAL.json.")
                ],
            )

    def test_existing_seal_is_never_overwritten_by_a_substituted_inode(self) -> None:
        """An attacker-supplied inode must never replace an existing legitimate seal.

        Reconstruction of the reviewer's pre-rename substitution: a legitimate seal
        exists and an attacker-owned file is present in the suite root at publication
        time. The existing seal must remain byte-identical and the attacker's file
        must not be published, moved, mutated or deleted.
        """
        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            _path, first = write_suite_seal(output)
            seal = output / "SUITE_SEAL.json"
            legitimate = seal.read_bytes()

            # Attacker-controlled inode sitting in the same directory.
            attacker = output / "attacker-replacement"
            attacker.write_bytes(b"attacker-replacement\n")
            attacker_identity = attacker.stat().st_ino

            # A tampered evidence tree forces a *different* payload, so the rerun
            # cannot be satisfied by the idempotent byte-identical branch.
            (output / "evidence/rep-01/oab2-data-rollup-a/result.json").write_text(
                '{"status":"rewritten"}\n', encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                write_suite_seal(output)

            self.assertEqual(legitimate, seal.read_bytes())
            self.assertEqual(
                "sha256:" + hashlib.sha256(legitimate).hexdigest(), first
            )
            self.assertTrue(attacker.is_file())
            self.assertEqual(attacker_identity, attacker.stat().st_ino)
            self.assertEqual(b"attacker-replacement\n", attacker.read_bytes())

    def test_differing_republication_fails_closed_without_touching_existing_seal(
        self,
    ) -> None:
        """A differing seal payload must fail closed, never replace the published one."""
        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            _path, digest = write_suite_seal(output)
            seal = output / "SUITE_SEAL.json"
            original = seal.read_bytes()
            original_ino = seal.stat().st_ino

            with self.assertRaisesRegex(ValueError, "suite_seal_publication_unsafe"):
                with suite_seal._trusted_suite_root(
                    suite_seal._trusted_absolute(
                        output, error="suite_evidence_path_unsafe"
                    )
                ) as root_fd:
                    suite_seal._publish_seal_bytes(root_fd, b'{"schema":"other"}\n')

            self.assertEqual(original, seal.read_bytes())
            self.assertEqual(original_ino, seal.stat().st_ino)
            self.assertEqual([], verify_suite_seal(output, expected_seal_sha256=digest))

    def test_identical_reseal_is_idempotent_and_writes_nothing(self) -> None:
        """Rerun semantics: an identical reseal republishes nothing and keeps the inode."""
        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            _first_path, first = write_suite_seal(output)
            seal = output / "SUITE_SEAL.json"
            first_identity = (seal.stat().st_ino, seal.stat().st_mtime_ns)

            _second_path, second = write_suite_seal(output)

            self.assertEqual(first, second)
            self.assertEqual(
                first_identity, (seal.stat().st_ino, seal.stat().st_mtime_ns)
            )
            self.assertEqual([], verify_suite_seal(output, expected_seal_sha256=second))

    def test_published_state_is_false_on_every_raising_path(self) -> None:
        """A failure after creation must unlink only the owned inode and publish nothing."""
        with tempfile.TemporaryDirectory() as td:
            output = _build_suite(Path(td))
            real_fsync = suite_seal.os.fsync

            def failing_fsync(fd: int) -> None:
                real_fsync(fd)
                raise OSError("injected fsync failure")

            with patch.object(suite_seal.os, "fsync", side_effect=failing_fsync):
                with self.assertRaisesRegex(
                    ValueError, "suite_seal_publication_unsafe"
                ):
                    write_suite_seal(output)

            self.assertFalse((output / "SUITE_SEAL.json").exists())
            self.assertEqual(
                [],
                [
                    name
                    for name in os.listdir(output)
                    if name.startswith(".SUITE_SEAL.json.")
                ],
            )


class SuiteSealRootAliasTests(unittest.TestCase):
    """The suite root itself must obey the release's no-link trust contract."""

    def test_symlinked_suite_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = _build_suite(root)
            alias = root / "alias-suite"
            alias.symlink_to(output, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "suite_evidence_path_unsafe"):
                write_suite_seal(alias)

    def test_symlinked_ancestor_of_suite_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real_parent = root / "real-parent"
            real_parent.mkdir()
            output = _build_suite(real_parent)
            alias_parent = root / "alias-parent"
            alias_parent.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "suite_evidence_path_unsafe"):
                write_suite_seal(alias_parent / output.name)

    def test_aliased_root_cannot_verify_an_existing_seal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = _build_suite(root)
            _path, digest = write_suite_seal(output)
            alias = root / "alias-suite"
            alias.symlink_to(output, target_is_directory=True)

            self.assertEqual(
                ["suite_seal_unreadable"],
                verify_suite_seal(alias, expected_seal_sha256=digest),
            )
            self.assertEqual([], verify_suite_seal(output, expected_seal_sha256=digest))

    def test_trusted_platform_alias_root_is_still_accepted(self) -> None:
        """Caller/OS-canonicalized aliases must not be mistaken for attacker links."""
        with tempfile.TemporaryDirectory(dir="/tmp") as td:
            output = _build_suite(Path(td))
            _path, digest = write_suite_seal(output)
            self.assertEqual([], verify_suite_seal(output, expected_seal_sha256=digest))

    def test_suite_root_swap_and_restore_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            parent = root / "parent"
            parent.mkdir()
            output = _build_suite(parent)
            held = root / "held"
            replacement = root / "replacement"
            shutil.copytree(parent, replacement)
            real_open = suite_seal.os.open
            raced = [False]

            def swapping_open(
                path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
            ) -> int:
                if path == parent.name and dir_fd is not None and not raced[0]:
                    raced[0] = True
                    parent.rename(held)
                    replacement.rename(parent)
                    try:
                        return real_open(path, flags, mode, dir_fd=dir_fd)
                    finally:
                        parent.rename(replacement)
                        held.rename(parent)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with patch.object(suite_seal.os, "open", side_effect=swapping_open):
                with self.assertRaisesRegex(ValueError, "suite_evidence_path_unsafe"):
                    write_suite_seal(output)
            self.assertTrue(raced[0])


class SuiteSealReleaseManifestTests(unittest.TestCase):
    """The optional release manifest is read under the descriptor-bound contract."""

    def _release_manifest(self, path: Path, digest: str) -> Path:
        path.write_bytes(_canonical_bytes({"tree_sha256": digest}) + b"\n")
        return path

    def test_matching_release_manifest_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = _build_suite(root)
            manifest = self._release_manifest(
                root / "RELEASE_MANIFEST.json", RELEASE_DIGEST
            )
            _path, digest = write_suite_seal(output, release_manifest=manifest)
            self.assertEqual([], verify_suite_seal(output, expected_seal_sha256=digest))

    def test_release_manifest_mismatch_still_raises_stable_code(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = _build_suite(root)
            manifest = self._release_manifest(
                root / "RELEASE_MANIFEST.json", "sha256:" + "9" * 64
            )
            with self.assertRaisesRegex(ValueError, "suite_release_tree_mismatch"):
                write_suite_seal(output, release_manifest=manifest)

    def test_symlinked_release_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = _build_suite(root)
            real = self._release_manifest(root / "real-manifest.json", RELEASE_DIGEST)
            alias = root / "RELEASE_MANIFEST.json"
            alias.symlink_to(real)

            with self.assertRaisesRegex(ValueError, "release_manifest_unreadable"):
                write_suite_seal(output, release_manifest=alias)

    def test_hardlinked_release_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = _build_suite(root)
            manifest = self._release_manifest(
                root / "RELEASE_MANIFEST.json", RELEASE_DIGEST
            )
            os.link(manifest, root / "manifest-alias.json")

            with self.assertRaisesRegex(ValueError, "release_manifest_unreadable"):
                write_suite_seal(output, release_manifest=manifest)

    def test_release_manifest_symlinked_ancestor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = _build_suite(root)
            real_dir = root / "release"
            real_dir.mkdir()
            self._release_manifest(real_dir / "RELEASE_MANIFEST.json", RELEASE_DIGEST)
            alias_dir = root / "alias-release"
            alias_dir.symlink_to(real_dir, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "release_manifest_unreadable"):
                write_suite_seal(
                    output, release_manifest=alias_dir / "RELEASE_MANIFEST.json"
                )

    def test_release_manifest_substituted_after_stat_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = _build_suite(root)
            manifest = self._release_manifest(
                root / "RELEASE_MANIFEST.json", RELEASE_DIGEST
            )
            forged = root / "forged.json"
            forged.write_bytes(
                _canonical_bytes({"tree_sha256": "sha256:" + "9" * 64}) + b"\n"
            )
            real_open = suite_seal.os.open
            raced = [False]

            def swapping_open(
                path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
            ) -> int:
                if path == manifest.name and dir_fd is not None and not raced[0]:
                    raced[0] = True
                    os.replace(forged, manifest)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with patch.object(suite_seal.os, "open", side_effect=swapping_open):
                with self.assertRaises(ValueError) as caught:
                    write_suite_seal(output, release_manifest=manifest)
            self.assertTrue(raced[0])
            self.assertNotIn("suite_release_tree_mismatch", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
