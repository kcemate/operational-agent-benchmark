from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from oab.release_approval import verify_release_approval


class ReleaseApprovalTests(unittest.TestCase):
    release_digest = "sha256:" + "a" * 64

    def _receipt(self) -> dict[str, object]:
        return {
            "schema": "oab.release-approval/v1",
            "release_tree_sha256": self.release_digest,
            "reviews": [
                {
                    "role": "security",
                    "reviewer": "independent-security-reviewer",
                    "decision": "APPROVE",
                    "reviewed_tree_sha256": self.release_digest,
                    "claim_limitations_acknowledged": True,
                },
                {
                    "role": "product",
                    "reviewer": "independent-product-reviewer",
                    "decision": "APPROVE",
                    "reviewed_tree_sha256": self.release_digest,
                    "claim_limitations_acknowledged": True,
                },
            ],
        }

    @staticmethod
    def _write(path: Path, receipt: dict[str, object]) -> str:
        path.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def test_distinct_approved_reviews_with_external_pin_validate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "approval.json"
            digest = self._write(path, self._receipt())
            result = verify_release_approval(
                path,
                expected_release_tree_sha256=self.release_digest,
                expected_file_sha256=digest,
            )
            self.assertTrue(result["valid"], result)
            self.assertEqual(digest, result["file_sha256"])

    def test_duplicate_reviewer_or_unacknowledged_limits_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "approval.json"
            receipt = self._receipt()
            reviews = receipt["reviews"]
            assert isinstance(reviews, list)
            assert isinstance(reviews[1], dict)
            reviews[1]["reviewer"] = "independent-security-reviewer"
            reviews[1]["claim_limitations_acknowledged"] = False
            digest = self._write(path, receipt)
            result = verify_release_approval(
                path,
                expected_release_tree_sha256=self.release_digest,
                expected_file_sha256=digest,
            )
            self.assertFalse(result["valid"])
            self.assertIn("release_approval_reviewers_not_independent", result["errors"])
            self.assertIn("release_approval_claim_limits_unacknowledged", result["errors"])

    def test_external_digest_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "approval.json"
            self._write(path, self._receipt())
            result = verify_release_approval(
                path,
                expected_release_tree_sha256=self.release_digest,
                expected_file_sha256="sha256:" + "b" * 64,
            )
            self.assertFalse(result["valid"])
            self.assertIn("release_approval_external_digest_mismatch", result["errors"])

    def test_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target.json"
            digest = self._write(target, self._receipt())
            link = root / "approval.json"
            link.symlink_to(target)
            result = verify_release_approval(
                link,
                expected_release_tree_sha256=self.release_digest,
                expected_file_sha256=digest,
            )
            self.assertFalse(result["valid"])
            self.assertIn("release_approval_not_regular_file", result["errors"])


if __name__ == "__main__":
    unittest.main()
