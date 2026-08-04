from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.evidence import build_evidence_manifest, verify_sealed_evidence
from oab.manifest import build_tree_manifest
from oab.trace import CanonicalTrace


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


class SealedEvidenceVerificationTests(unittest.TestCase):
    def _write_completed_tree(self, root: Path, *, mutate_payload: bool = False) -> Path:
        evidence = root / "evidence"
        payload = evidence / "payload" / "output"
        payload.mkdir(parents=True)
        (payload / "summary.json").write_text('{"ok":true}\n', encoding="utf-8")
        if mutate_payload:
            # Leave a trap file that is not in the sealed snapshot path for later.
            pass
        manifest = build_tree_manifest(evidence / "payload")
        with CanonicalTrace(evidence / "trace.jsonl") as trace:
            trace.append(
                "episode_start",
                "controller",
                details={"case_id": "demo", "repetition": 1},
            )
            trace.append(
                "controller_identity",
                "controller",
                details={
                    "identity_source": "adapter_runtime",
                    "requested_route": "provider/model",
                    "returned_route": "provider/model",
                },
            )
            trace.append(
                "output_snapshot",
                "verifier",
                details={"tree_sha256": manifest["tree_sha256"]},
            )
            trace.append(
                "episode_end",
                "controller",
                details={
                    "status": "completed",
                    "reason_codes": ["provider_identity_source_unverified"],
                },
            )
        (evidence / "output-manifest.json").write_bytes(_canonical_bytes(manifest) + b"\n")
        receipt = {
            "schema": "oab.episode-result/v1",
            "case_id": "demo",
            "repetition": 1,
            "status": "completed",
            "reason_codes": ["provider_identity_source_unverified"],
            "trace_sha256": _sha256_file(evidence / "trace.jsonl"),
            "output_tree_sha256": manifest["tree_sha256"],
            "controller_identity": {
                "identity_source": "adapter_runtime",
                "requested_route": "provider/model",
                "returned_route": "provider/model",
            },
        }
        (evidence / "result.json").write_bytes(_canonical_bytes(receipt) + b"\n")
        envelope = build_evidence_manifest(evidence)
        (evidence / "evidence-manifest.json").write_bytes(_canonical_bytes(envelope) + b"\n")
        return evidence

    def test_intact_completed_tree_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = self._write_completed_tree(Path(td))
            result = verify_sealed_evidence(evidence)
            self.assertTrue(result["valid"], result)
            self.assertEqual([], result["errors"])
            self.assertEqual("completed", result["status"])

    def test_payload_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = self._write_completed_tree(Path(td))
            target = evidence / "payload" / "output" / "summary.json"
            target.write_text('{"ok":false}\n', encoding="utf-8")
            result = verify_sealed_evidence(evidence)
            self.assertFalse(result["valid"])
            self.assertTrue(
                any(
                    code.startswith("manifest_") or code.startswith("output_tree")
                    for code in result["errors"]
                ),
                result["errors"],
            )

    def test_trace_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = self._write_completed_tree(Path(td))
            with (evidence / "trace.jsonl").open("ab") as handle:
                handle.write(b'{"schema":"oab.trace-event/v1"}\n')
            result = verify_sealed_evidence(evidence)
            self.assertFalse(result["valid"])
            self.assertTrue(
                any("trace" in code for code in result["errors"]),
                result["errors"],
            )

    def test_missing_receipt_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "empty"
            evidence.mkdir()
            result = verify_sealed_evidence(evidence)
            self.assertFalse(result["valid"])
            self.assertIn("result_missing", result["errors"])

    def test_unsealed_ancillary_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = self._write_completed_tree(Path(td))
            (evidence / "mock-effects.jsonl").write_text('{"effect":"forged"}\n', encoding="utf-8")
            result = verify_sealed_evidence(evidence)
            self.assertFalse(result["valid"])
            self.assertIn("evidence_manifest_entries_mismatch", result["errors"])

    def test_rewritten_receipt_identity_fails_trace_crosscheck_after_remanifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = self._write_completed_tree(Path(td))
            receipt_path = evidence / "result.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["case_id"] = "forged-case"
            receipt_path.write_bytes(_canonical_bytes(receipt) + b"\n")
            envelope = build_evidence_manifest(evidence)
            (evidence / "evidence-manifest.json").write_bytes(_canonical_bytes(envelope) + b"\n")
            result = verify_sealed_evidence(evidence)
            self.assertFalse(result["valid"])
            self.assertIn("result_case_id_trace_mismatch", result["errors"])

    def test_coordinated_payload_receipt_and_manifest_rewrite_fails_trace_crosscheck(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = self._write_completed_tree(Path(td))
            target = evidence / "payload/output/summary.json"
            target.write_text('{"ok":false}\n', encoding="utf-8")
            output_manifest = build_tree_manifest(evidence / "payload")
            (evidence / "output-manifest.json").write_bytes(
                _canonical_bytes(output_manifest) + b"\n"
            )
            receipt_path = evidence / "result.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["output_tree_sha256"] = output_manifest["tree_sha256"]
            receipt_path.write_bytes(_canonical_bytes(receipt) + b"\n")
            envelope = build_evidence_manifest(evidence)
            (evidence / "evidence-manifest.json").write_bytes(
                _canonical_bytes(envelope) + b"\n"
            )
            result = verify_sealed_evidence(evidence)
            self.assertFalse(result["valid"])
            self.assertIn("output_tree_trace_mismatch", result["errors"])


if __name__ == "__main__":
    unittest.main()
