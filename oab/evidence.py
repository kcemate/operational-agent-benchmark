from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .manifest import ManifestError, build_tree_manifest, verify_tree_manifest
from .trace import validate_trace

_RESULT_SCHEMA = "oab.episode-result/v1"
_SHA256_LENGTH = len("sha256:") + 64
_EVIDENCE_MANIFEST_NAME = "evidence-manifest.json"
_EVIDENCE_MANIFEST_EXCLUDES = frozenset({_EVIDENCE_MANIFEST_NAME})


def build_evidence_manifest(evidence_dir: Path) -> dict[str, Any]:
    """Bind every evidence file except this self-describing manifest."""
    return build_tree_manifest(
        evidence_dir,
        max_files=512,
        max_total_bytes=64 * 1024 * 1024,
        exclude_paths=_EVIDENCE_MANIFEST_EXCLUDES,
    )


def _digest_field_valid(value: object) -> bool:
    if not isinstance(value, str) or len(value) != _SHA256_LENGTH or not value.startswith("sha256:"):
        return False
    try:
        int(value.removeprefix("sha256:"), 16)
    except ValueError:
        return False
    return True


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _load_json_object(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        raw = path.read_bytes()
    except OSError:
        return None, "unreadable"
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None, "invalid_json"
    if not isinstance(value, dict):
        return None, "not_object"
    return value, None


def _load_trace_events(path: Path) -> list[dict[str, Any]] | None:
    try:
        lines = path.read_bytes().splitlines()
        events = [json.loads(line) for line in lines]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    if not all(isinstance(event, dict) for event in events):
        return None
    return events


def verify_sealed_evidence(evidence_dir: Path) -> dict[str, Any]:
    """Verify a completed-tree evidence directory against sealed manifest/trace digests.

    The caller's binding is used exactly as given. ``Path.resolve`` is deliberately
    not called: resolving rewrites symlinked components and re-derives an absolute
    pathname, which would silently convert a descriptor-rooted binding (such as the
    suite sealer's ``Path(".")`` view of a retained snapshot descriptor) back into a
    mutable pathname that a concurrent rename or symlink substitution could redirect
    to a victim directory. Every read below therefore stays relative to the binding
    the caller established. ``reported_dir`` is a lexical, display-only rendering
    that is never opened.
    """
    reported_dir = os.path.abspath(evidence_dir)
    errors: list[str] = []
    status: str | None = None
    trace_output_tree_sha256: str | None = None
    result_path = evidence_dir / "result.json"
    if not result_path.is_file():
        return {
            "valid": False,
            "errors": ["result_missing"],
            "status": None,
            "evidence_dir": reported_dir,
        }

    receipt, receipt_error = _load_json_object(result_path)
    if receipt is None:
        return {
            "valid": False,
            "errors": [f"result_{receipt_error}"],
            "status": None,
            "evidence_dir": reported_dir,
        }
    if receipt.get("schema") != _RESULT_SCHEMA:
        errors.append("result_schema_invalid")
    status_value = receipt.get("status")
    if isinstance(status_value, str):
        status = status_value
    else:
        errors.append("result_status_invalid")

    claimed_trace = receipt.get("trace_sha256")
    claimed_output = receipt.get("output_tree_sha256")
    if not _digest_field_valid(claimed_trace):
        errors.append("result_trace_digest_invalid")
    if not _digest_field_valid(claimed_output):
        errors.append("result_output_tree_digest_invalid")

    evidence_manifest_path = evidence_dir / _EVIDENCE_MANIFEST_NAME
    if not evidence_manifest_path.is_file():
        errors.append("evidence_manifest_missing")
    else:
        evidence_manifest, evidence_manifest_error = _load_json_object(evidence_manifest_path)
        if evidence_manifest is None:
            errors.append(f"evidence_manifest_{evidence_manifest_error}")
        else:
            limits = evidence_manifest.get("limits")
            if not isinstance(limits, dict):
                errors.append("evidence_manifest_limits_invalid")
            else:
                max_files = limits.get("max_files")
                max_total_bytes = limits.get("max_total_bytes")
                if (
                    not isinstance(max_files, int)
                    or isinstance(max_files, bool)
                    or not isinstance(max_total_bytes, int)
                    or isinstance(max_total_bytes, bool)
                ):
                    errors.append("evidence_manifest_limits_invalid")
                else:
                    try:
                        actual_evidence_manifest = build_tree_manifest(
                            evidence_dir,
                            max_files=max_files,
                            max_total_bytes=max_total_bytes,
                            exclude_paths=_EVIDENCE_MANIFEST_EXCLUDES,
                        )
                    except (ManifestError, TypeError, ValueError) as exc:
                        errors.append(f"evidence_manifest_rehash_failed:{exc}")
                    else:
                        if actual_evidence_manifest.get("entries") != evidence_manifest.get(
                            "entries"
                        ):
                            errors.append("evidence_manifest_entries_mismatch")
                        if actual_evidence_manifest.get("tree_sha256") != evidence_manifest.get(
                            "tree_sha256"
                        ):
                            errors.append("evidence_manifest_digest_mismatch")

    trace_path = evidence_dir / "trace.jsonl"
    if not trace_path.is_file():
        errors.append("trace_missing")
    else:
        trace_validation = validate_trace(trace_path)
        if not trace_validation.valid:
            errors.extend(f"trace_{code}" for code in trace_validation.errors)
        try:
            actual_trace = _sha256_file(trace_path)
        except OSError:
            errors.append("trace_digest_unreadable")
            actual_trace = None
        if actual_trace is not None and claimed_trace != actual_trace:
            errors.append("trace_digest_mismatch")
        trace_events = _load_trace_events(trace_path) if trace_validation.valid else None
        if trace_events is not None:
            starts = [event for event in trace_events if event.get("event_type") == "episode_start"]
            identities = [
                event for event in trace_events if event.get("event_type") == "controller_identity"
            ]
            ends = [event for event in trace_events if event.get("event_type") == "episode_end"]
            output_snapshots = [
                event for event in trace_events if event.get("event_type") == "output_snapshot"
            ]
            if len(starts) != 1:
                errors.append("trace_episode_start_count_invalid")
            else:
                details = starts[0].get("details")
                if not isinstance(details, dict) or details.get("case_id") != receipt.get("case_id"):
                    errors.append("result_case_id_trace_mismatch")
                if not isinstance(details, dict) or details.get("repetition") != receipt.get("repetition"):
                    errors.append("result_repetition_trace_mismatch")
            receipt_identity = receipt.get("controller_identity")
            if receipt_identity is None:
                if identities or receipt.get("status") == "completed":
                    errors.append("trace_controller_identity_count_invalid")
            elif len(identities) != 1:
                errors.append("trace_controller_identity_count_invalid")
            elif identities[0].get("details") != receipt_identity:
                errors.append("result_controller_identity_trace_mismatch")
            if len(ends) != 1:
                errors.append("trace_episode_end_count_invalid")
            else:
                details = ends[0].get("details")
                if not isinstance(details, dict) or details.get("status") != receipt.get("status"):
                    errors.append("result_status_trace_mismatch")
                if not isinstance(details, dict) or details.get("reason_codes") != receipt.get(
                    "reason_codes"
                ):
                    errors.append("result_reason_codes_trace_mismatch")
            if len(output_snapshots) != 1:
                errors.append("trace_output_snapshot_count_invalid")
            else:
                details = output_snapshots[0].get("details")
                candidate = details.get("tree_sha256") if isinstance(details, dict) else None
                if not _digest_field_valid(candidate):
                    errors.append("trace_output_snapshot_digest_invalid")
                else:
                    trace_output_tree_sha256 = candidate
                    if claimed_output != trace_output_tree_sha256:
                        errors.append("output_tree_trace_mismatch")

    manifest_path = evidence_dir / "output-manifest.json"
    payload_dir = evidence_dir / "payload"
    if not manifest_path.is_file():
        errors.append("output_manifest_missing")
        manifest = None
    else:
        manifest, manifest_error = _load_json_object(manifest_path)
        if manifest is None:
            errors.append(f"output_manifest_{manifest_error}")
        else:
            if not payload_dir.is_dir():
                errors.append("payload_missing")
            else:
                try:
                    manifest_errors = verify_tree_manifest(payload_dir, manifest)
                except ManifestError as exc:
                    manifest_errors = [f"manifest_invalid:{exc}"]
                errors.extend(manifest_errors)
            tree_digest = manifest.get("tree_sha256")
            if claimed_output != tree_digest:
                errors.append("output_tree_digest_mismatch")
            if (
                trace_output_tree_sha256 is not None
                and tree_digest != trace_output_tree_sha256
            ):
                errors.append("output_manifest_trace_mismatch")
            # Recompute independently to catch a stale self-consistent manifest rewrite.
            if payload_dir.is_dir():
                try:
                    recomputed = build_tree_manifest(
                        payload_dir,
                        max_files=int(manifest.get("limits", {}).get("max_files", 256)),
                        max_total_bytes=int(
                            manifest.get("limits", {}).get("max_total_bytes", 16 * 1024 * 1024)
                        ),
                    )
                except (ManifestError, TypeError, ValueError) as exc:
                    errors.append(f"payload_rehash_failed:{exc}")
                else:
                    if recomputed.get("tree_sha256") != claimed_output:
                        errors.append("output_tree_rehash_mismatch")

    return {
        "valid": not errors,
        "errors": errors,
        "status": status,
        "evidence_dir": reported_dir,
        "trace_sha256": claimed_trace if _digest_field_valid(claimed_trace) else None,
        "output_tree_sha256": claimed_output if _digest_field_valid(claimed_output) else None,
    }
