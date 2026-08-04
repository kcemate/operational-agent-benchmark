from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any

_SCHEMA = "oab.release-approval/v1"
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_BYTES = 64 * 1024


class _DuplicateKey(ValueError):
    pass


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def verify_release_approval(
    path: Path,
    *,
    expected_release_tree_sha256: str,
    expected_file_sha256: str,
) -> dict[str, object]:
    errors: list[str] = []
    payload = b""
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            errors.append("release_approval_not_regular_file")
        elif metadata.st_size > _MAX_BYTES:
            errors.append("release_approval_too_large")
        else:
            payload = path.read_bytes()
    except OSError:
        errors.append("release_approval_unreadable")

    file_digest = _sha256_bytes(payload) if payload else None
    if not _SHA256.fullmatch(expected_file_sha256):
        errors.append("release_approval_expected_digest_invalid")
    elif file_digest != expected_file_sha256:
        errors.append("release_approval_external_digest_mismatch")
    if not _SHA256.fullmatch(expected_release_tree_sha256):
        errors.append("release_approval_release_digest_invalid")

    approval: dict[str, Any] | None = None
    if payload:
        try:
            value = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_object_without_duplicates,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey):
            errors.append("release_approval_json_invalid")
        else:
            if not isinstance(value, dict):
                errors.append("release_approval_not_json_object")
            else:
                approval = value

    if approval is not None:
        if set(approval) != {"schema", "release_tree_sha256", "reviews"}:
            errors.append("release_approval_schema_fields_invalid")
        if approval.get("schema") != _SCHEMA:
            errors.append("release_approval_schema_invalid")
        if approval.get("release_tree_sha256") != expected_release_tree_sha256:
            errors.append("release_approval_tree_mismatch")
        reviews = approval.get("reviews")
        if not isinstance(reviews, list) or len(reviews) != 2:
            errors.append("release_approval_reviews_invalid")
        else:
            roles: list[str] = []
            reviewers: list[str] = []
            expected_review_fields = {
                "role",
                "reviewer",
                "decision",
                "reviewed_tree_sha256",
                "claim_limitations_acknowledged",
            }
            for review in reviews:
                if not isinstance(review, dict) or set(review) != expected_review_fields:
                    errors.append("release_approval_review_fields_invalid")
                    continue
                role = review.get("role")
                reviewer = review.get("reviewer")
                if isinstance(role, str):
                    roles.append(role)
                if isinstance(reviewer, str) and reviewer.strip():
                    reviewers.append(reviewer.strip())
                else:
                    errors.append("release_approval_reviewer_invalid")
                if review.get("decision") != "APPROVE":
                    errors.append("release_approval_decision_not_approve")
                if review.get("reviewed_tree_sha256") != expected_release_tree_sha256:
                    errors.append("release_approval_review_tree_mismatch")
                if review.get("claim_limitations_acknowledged") is not True:
                    errors.append("release_approval_claim_limits_unacknowledged")
            if set(roles) != {"security", "product"} or len(roles) != 2:
                errors.append("release_approval_roles_invalid")
            if len(reviewers) != 2 or len(set(reviewers)) != 2:
                errors.append("release_approval_reviewers_not_independent")

    errors = sorted(set(errors))
    return {
        "schema": _SCHEMA,
        "valid": not errors,
        "errors": errors,
        "file_sha256": file_digest,
        "release_tree_sha256": expected_release_tree_sha256,
    }
