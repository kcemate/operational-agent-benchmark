"""Descriptor-bound campaign authorization for spend-capable OAB children.

The public suite CLI is intentionally not a capability.  A qualification or
full-stage child may execute only after this module reconstructs authority from
an inherited campaign-root descriptor, a signed stage receipt, and the
campaign's immutable PLAN.  JSON supplied on argv is never an authorization
source.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .full_stage_contract import (
    AUTHORITATIVE_FULL_PAIR_IDS,
    FULL_API_CALL_CEILING_PER_ROUTE,
    authoritative_full_contract_for_route_count,
    canonical_bytes as full_canonical_bytes,
    full_stage_contract_sha256,
    validate_authoritative_full_stage_plan,
)
from .qualification_contract import (
    ABSOLUTE_API_CALL_CEILING_PER_ROUTE,
    QUALIFICATION_CONTRACT_ID,
    canonical_bytes as qualification_canonical_bytes,
    qualification_contract_for_route_count,
    validate_qualification_contract,
)

CAMPAIGN_PLAN_SCHEMA = "oab.campaign-plan/v2"
STAGE_APPROVAL_SCHEMA = "oab.stage-approval/v5"
STAGE_EXECUTION_CONTEXT_SCHEMA = "oab.stage-execution-context/v1"
CHILD_AUTHORIZATION_ENVELOPE_SCHEMA = "oab.campaign-child-authorization/v1"

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_OUTPUT_NAME_RE = re.compile(r"[0-9a-f]{32}\.evidence")
_PLAN_FIELDS = frozenset(
    {
        "schema",
        "created_at",
        "campaign_id",
        "routes",
        "route_count",
        "baseline_route",
        "reasoning_effort",
        "qualification",
        "full_run",
        "release_tree_sha256",
        "approval_authority_public_key_sha256",
        "plan_sha256",
    }
)
_RECEIPT_BASE_FIELDS = frozenset(
    {
        "schema",
        "created_at",
        "stage",
        "plan_sha256",
        "calibration_sha256",
        "route_ids",
        "observed_cost_stop_usd",
        "cost_control_mode",
        "max_cost_overshoot_api_calls",
        "max_api_calls",
        "max_routes",
        "allow_unknown_costs",
        "approval_public_key_sha256",
        "execution_context",
        "receipt_sha256",
    }
)
_CONTEXT_FIELDS = frozenset(
    {"schema", "campaign_root_context_sha256", "stage", "routes"}
)
_CONTEXT_ROUTE_FIELDS = frozenset(
    {"route_id", "requested_route", "output_relative_path"}
)
_ENVELOPE_FIELDS = frozenset(
    {"schema", "approval_receipt", "signature_base64", "public_key_pem_base64"}
)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def campaign_plan_sha256(plan: Mapping[str, object]) -> str:
    """Hash PLAN content without accepting a self-referential digest field."""
    unsigned = {key: value for key, value in plan.items() if key != "plan_sha256"}
    return canonical_sha256(unsigned)


def _positive_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _nonnegative_number(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and float(value) >= 0:
        return float(value)
    return None


def _safe_output_relative_path(stage: str, value: object) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.split("/")
    return (
        len(parts) == 3
        and parts[0] == stage
        and parts[1] == "attempts"
        and _OUTPUT_NAME_RE.fullmatch(parts[2]) is not None
    )


def _routes_from_plan(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise ValueError("campaign_plan_invalid")
    routes: list[dict[str, str]] = []
    route_ids: set[str] = set()
    requested: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {"route_id", "requested_route"}:
            raise ValueError("campaign_plan_invalid")
        route_id = item.get("route_id")
        requested_route = item.get("requested_route")
        if (
            not isinstance(route_id, str)
            or not route_id
            or not isinstance(requested_route, str)
            or not requested_route
            or "/" not in requested_route
            or route_id in route_ids
            or requested_route in requested
        ):
            raise ValueError("campaign_plan_invalid")
        route_ids.add(route_id)
        requested.add(requested_route)
        routes.append({"route_id": route_id, "requested_route": requested_route})
    return routes


def validate_campaign_plan_document(value: object) -> dict[str, object]:
    """Validate the v2 campaign root authority object exactly, without defaults."""
    if not isinstance(value, Mapping) or set(value) != _PLAN_FIELDS:
        raise ValueError("campaign_plan_invalid")
    if value.get("schema") != CAMPAIGN_PLAN_SCHEMA:
        raise ValueError("campaign_plan_invalid")
    if not isinstance(value.get("created_at"), str) or not value.get("created_at"):
        raise ValueError("campaign_plan_invalid")
    if not isinstance(value.get("campaign_id"), str) or not value.get("campaign_id"):
        raise ValueError("campaign_plan_invalid")
    routes = _routes_from_plan(value.get("routes"))
    route_count = _positive_int(value.get("route_count"))
    if route_count != len(routes):
        raise ValueError("campaign_plan_invalid")
    baseline = value.get("baseline_route")
    if not isinstance(baseline, str) or baseline not in {route["requested_route"] for route in routes}:
        raise ValueError("campaign_plan_invalid")
    effort = value.get("reasoning_effort")
    if not isinstance(effort, str) or not effort:
        raise ValueError("campaign_plan_invalid")
    if not _is_digest(value.get("release_tree_sha256")) or not _is_digest(
        value.get("approval_authority_public_key_sha256")
    ):
        raise ValueError("campaign_plan_invalid")
    try:
        qualification = validate_qualification_contract(value.get("qualification"), route_count=route_count)
        full_run = validate_authoritative_full_stage_plan(value.get("full_run"), route_count=route_count)
    except ValueError as exc:
        raise ValueError("campaign_plan_invalid") from exc
    if value.get("plan_sha256") != campaign_plan_sha256(value):
        raise ValueError("campaign_plan_invalid")
    return {
        "schema": CAMPAIGN_PLAN_SCHEMA,
        "created_at": str(value["created_at"]),
        "campaign_id": str(value["campaign_id"]),
        "routes": routes,
        "route_count": route_count,
        "baseline_route": baseline,
        "reasoning_effort": effort,
        "qualification": qualification,
        "full_run": full_run,
        "release_tree_sha256": str(value["release_tree_sha256"]),
        "approval_authority_public_key_sha256": str(value["approval_authority_public_key_sha256"]),
        "plan_sha256": str(value["plan_sha256"]),
    }


def _receipt_contract_fields(stage: str) -> frozenset[str]:
    if stage == "qualification":
        return frozenset({"qualification_contract", "qualification_contract_sha256"})
    if stage == "full":
        return frozenset({"full_contract", "full_contract_sha256"})
    raise ValueError("stage_approval_invalid")


def _validate_context(
    value: object,
    *,
    root: Path,
    stage: str,
    receipt_route_ids: list[str],
    plan_routes: list[dict[str, str]],
) -> list[dict[str, str]]:
    if not isinstance(value, Mapping) or set(value) != _CONTEXT_FIELDS:
        raise ValueError("stage_approval_invalid")
    expected_root = "sha256:" + hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()
    if (
        value.get("schema") != STAGE_EXECUTION_CONTEXT_SCHEMA
        or value.get("campaign_root_context_sha256") != expected_root
        or value.get("stage") != stage
    ):
        raise ValueError("stage_approval_invalid")
    raw_routes = value.get("routes")
    if not isinstance(raw_routes, list) or len(raw_routes) != len(receipt_route_ids):
        raise ValueError("stage_approval_invalid")
    by_id = {route["route_id"]: route for route in plan_routes}
    mapped: list[dict[str, str]] = []
    seen: set[str] = set()
    for item, route_id in zip(raw_routes, receipt_route_ids):
        if not isinstance(item, Mapping) or set(item) != _CONTEXT_ROUTE_FIELDS:
            raise ValueError("stage_approval_invalid")
        if item.get("route_id") != route_id or route_id in seen:
            raise ValueError("stage_approval_invalid")
        plan_route = by_id.get(route_id)
        if plan_route is None or item.get("requested_route") != plan_route["requested_route"]:
            raise ValueError("stage_approval_invalid")
        output_path = item.get("output_relative_path")
        if not _safe_output_relative_path(stage, output_path):
            raise ValueError("stage_approval_invalid")
        seen.add(route_id)
        mapped.append(
            {
                "route_id": route_id,
                "requested_route": plan_route["requested_route"],
                "output_relative_path": str(output_path),
            }
        )
    return mapped


def validate_stage_approval_receipt(
    value: object,
    *,
    plan: Mapping[str, object],
    root: Path,
    calibration_sha256: str,
) -> dict[str, object]:
    """Validate receipt structure and every signed binding before signature use."""
    if not isinstance(value, Mapping):
        raise ValueError("stage_approval_invalid")
    stage = value.get("stage")
    if not isinstance(stage, str):
        raise ValueError("stage_approval_invalid")
    expected_fields = _RECEIPT_BASE_FIELDS | _receipt_contract_fields(stage)
    if set(value) != expected_fields or value.get("schema") != STAGE_APPROVAL_SCHEMA:
        raise ValueError("stage_approval_invalid")
    if not isinstance(value.get("created_at"), str) or not value.get("created_at"):
        raise ValueError("stage_approval_invalid")
    if value.get("plan_sha256") != plan.get("plan_sha256"):
        raise ValueError("stage_approval_invalid")
    if value.get("calibration_sha256") != calibration_sha256:
        raise ValueError("stage_approval_invalid")
    if not _is_digest(value.get("receipt_sha256")):
        raise ValueError("stage_approval_invalid")
    receipt_without_digest = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if value.get("receipt_sha256") != canonical_sha256(receipt_without_digest):
        raise ValueError("stage_approval_invalid")
    raw_ids = value.get("route_ids")
    if (
        not isinstance(raw_ids, list)
        or not raw_ids
        or any(not isinstance(item, str) or not item for item in raw_ids)
        or len(set(raw_ids)) != len(raw_ids)
    ):
        raise ValueError("stage_approval_invalid")
    route_ids = list(raw_ids)
    max_routes = _positive_int(value.get("max_routes"))
    max_api_calls = _positive_int(value.get("max_api_calls"))
    if max_routes != len(route_ids) or max_api_calls is None:
        raise ValueError("stage_approval_invalid")
    if (
        _nonnegative_number(value.get("observed_cost_stop_usd")) is None
        or value.get("cost_control_mode") != "post_provider_call_observed_known_cost_stop"
        or value.get("max_cost_overshoot_api_calls") != 1
        or not isinstance(value.get("allow_unknown_costs"), bool)
        or value.get("approval_public_key_sha256") != plan.get("approval_authority_public_key_sha256")
    ):
        raise ValueError("stage_approval_invalid")
    plan_routes = plan.get("routes")
    if not isinstance(plan_routes, list):
        raise ValueError("stage_approval_invalid")
    context_routes = _validate_context(
        value.get("execution_context"),
        root=root,
        stage=stage,
        receipt_route_ids=route_ids,
        plan_routes=plan_routes,
    )
    if stage == "qualification":
        contract = validate_qualification_contract(
            value.get("qualification_contract"), route_count=int(plan["route_count"])
        )
        if (
            contract != plan.get("qualification")
            or value.get("qualification_contract_sha256") != canonical_sha256(contract)
            or max_api_calls != len(route_ids) * ABSOLUTE_API_CALL_CEILING_PER_ROUTE
        ):
            raise ValueError("stage_approval_invalid")
    else:
        full = validate_authoritative_full_stage_plan(
            value.get("full_contract"), route_count=int(plan["route_count"])
        )
        if (
            full != plan.get("full_run")
            or value.get("full_contract_sha256") != canonical_sha256(full)
            or max_api_calls != len(route_ids) * FULL_API_CALL_CEILING_PER_ROUTE
        ):
            raise ValueError("stage_approval_invalid")
    return {**dict(value), "_context_routes": context_routes}


def encode_child_authorization_envelope(
    *,
    approval_receipt: Mapping[str, object],
    signature: bytes,
    public_key_pem: bytes,
) -> bytes:
    """Encode inherited proof material for an anonymous parent-to-child FD."""
    envelope = {
        "schema": CHILD_AUTHORIZATION_ENVELOPE_SCHEMA,
        "approval_receipt": dict(approval_receipt),
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "public_key_pem_base64": base64.b64encode(public_key_pem).decode("ascii"),
    }
    return canonical_bytes(envelope)


def _read_all_fd(descriptor: int, *, max_bytes: int = 1024 * 1024) -> bytes:
    if not isinstance(descriptor, int) or descriptor < 0:
        raise ValueError("campaign_child_authorization_required")
    try:
        duplicate = os.dup(descriptor)
    except OSError as exc:
        raise ValueError("campaign_child_authorization_required") from exc
    try:
        info = os.fstat(duplicate)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("campaign_child_authorization_invalid")
        os.lseek(duplicate, 0, os.SEEK_SET)
        payload = bytearray()
        while True:
            chunk = os.read(duplicate, min(64 * 1024, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > max_bytes:
                raise ValueError("campaign_child_authorization_invalid")
        if not payload:
            raise ValueError("campaign_child_authorization_required")
        return bytes(payload)
    except OSError as exc:
        raise ValueError("campaign_child_authorization_invalid") from exc
    finally:
        os.close(duplicate)


def _read_regular_bytes_at(
    directory_fd: int, name: str, *, max_bytes: int = 8 * 1024 * 1024
) -> bytes:
    if not isinstance(directory_fd, int) or directory_fd < 0 or name in {"", ".", ".."} or "/" in name:
        raise ValueError("campaign_child_authorization_invalid")
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise ValueError("campaign_child_authorization_invalid") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or opened.st_ino != before.st_ino:
            raise ValueError("campaign_child_authorization_invalid")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > max_bytes:
                raise ValueError("campaign_child_authorization_invalid")
        after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if after.st_ino != opened.st_ino or after.st_dev != opened.st_dev:
            raise ValueError("campaign_child_authorization_invalid")
        return bytes(payload)
    except OSError as exc:
        raise ValueError("campaign_child_authorization_invalid") from exc
    finally:
        os.close(descriptor)


def _json_object(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("campaign_child_authorization_invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("campaign_child_authorization_invalid")
    return value


def _decode_envelope(payload: bytes) -> tuple[dict[str, object], bytes, bytes]:
    value = _json_object(payload)
    if set(value) != _ENVELOPE_FIELDS or value.get("schema") != CHILD_AUTHORIZATION_ENVELOPE_SCHEMA:
        raise ValueError("campaign_child_authorization_invalid")
    receipt = value.get("approval_receipt")
    signature_text = value.get("signature_base64")
    public_text = value.get("public_key_pem_base64")
    if not isinstance(receipt, dict) or not isinstance(signature_text, str) or not isinstance(public_text, str):
        raise ValueError("campaign_child_authorization_invalid")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        public_bytes = base64.b64decode(public_text, validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("campaign_child_authorization_invalid") from exc
    if not signature or not public_bytes:
        raise ValueError("campaign_child_authorization_invalid")
    return receipt, signature, public_bytes


def _verified_public_key(public_bytes: bytes, *, expected_digest: object) -> Ed25519PublicKey:
    if not _is_digest(expected_digest) or expected_digest != "sha256:" + hashlib.sha256(public_bytes).hexdigest():
        raise ValueError("campaign_child_authorization_invalid")
    try:
        public_key = serialization.load_pem_public_key(public_bytes)
    except (ValueError, TypeError) as exc:
        raise ValueError("campaign_child_authorization_invalid") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("campaign_child_authorization_invalid")
    return public_key


def _verified_root(root_path: Path, root_fd: int) -> Path:
    try:
        supplied = root_path.expanduser()
        if supplied.is_symlink():
            raise ValueError("campaign_child_authorization_invalid")
        resolved = supplied.resolve(strict=True)
        path_stat = resolved.stat()
        descriptor_stat = os.fstat(root_fd)
    except (OSError, ValueError) as exc:
        raise ValueError("campaign_child_authorization_invalid") from exc
    if (
        not stat.S_ISDIR(path_stat.st_mode)
        or not stat.S_ISDIR(descriptor_stat.st_mode)
        or path_stat.st_dev != descriptor_stat.st_dev
        or path_stat.st_ino != descriptor_stat.st_ino
    ):
        raise ValueError("campaign_child_authorization_invalid")
    return resolved


def _open_child_directory(parent_fd: int, name: str) -> int:
    """Open one ordinary child directory without following a substituted link."""

    if name in {"", ".", ".."} or "/" in name or "\\" in name:
        raise ValueError("campaign_child_output_parent_invalid")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        child_fd = os.open(name, flags, dir_fd=parent_fd)
        child_info = os.fstat(child_fd)
    except OSError as exc:
        raise ValueError("campaign_child_output_parent_invalid") from exc
    if not stat.S_ISDIR(child_info.st_mode):
        os.close(child_fd)
        raise ValueError("campaign_child_output_parent_invalid")
    return child_fd


def _verify_output_parent_fd(campaign_root_fd: int, output_parent_fd: int, stage: str) -> None:
    """Bind the inherited output descriptor to signed ``<stage>/attempts``."""

    stage_fd = -1
    attempts_fd = -1
    try:
        stage_fd = _open_child_directory(campaign_root_fd, stage)
        attempts_fd = _open_child_directory(stage_fd, "attempts")
        expected = os.fstat(attempts_fd)
        supplied = os.fstat(output_parent_fd)
    except OSError as exc:
        raise ValueError("campaign_child_output_parent_invalid") from exc
    finally:
        if attempts_fd >= 0:
            os.close(attempts_fd)
        if stage_fd >= 0:
            os.close(stage_fd)
    if (
        not stat.S_ISDIR(supplied.st_mode)
        or (expected.st_dev, expected.st_ino) != (supplied.st_dev, supplied.st_ino)
    ):
        raise ValueError("campaign_child_output_parent_invalid")


def verify_campaign_child_authorization(
    *,
    stage: str,
    campaign_root_path: Path,
    campaign_root_fd: int,
    authorization_fd: int,
    output_parent_fd: int,
    requested_route: str,
    reasoning_effort: str,
    output_name: str,
    max_api_calls: object,
    max_observed_cost_usd: object,
    allow_unknown_costs: object,
) -> dict[str, object]:
    """Reconstruct a child capability exclusively from descriptors and signatures.

    The returned tuple is safe to use as runtime configuration.  Any caller
    supplied fields are checked against it rather than used as authority.
    """
    if stage not in {"qualification", "full"} or _OUTPUT_NAME_RE.fullmatch(output_name) is None:
        raise ValueError("campaign_child_authorization_invalid")
    root = _verified_root(campaign_root_path, campaign_root_fd)
    _verify_output_parent_fd(campaign_root_fd, output_parent_fd, stage)
    plan = validate_campaign_plan_document(_json_object(_read_regular_bytes_at(campaign_root_fd, "PLAN.json")))
    calibration = _json_object(_read_regular_bytes_at(campaign_root_fd, "CALIBRATION.json"))
    calibration_digest = canonical_sha256(calibration)
    receipt, signature, public_bytes = _decode_envelope(_read_all_fd(authorization_fd))
    validated_receipt = validate_stage_approval_receipt(
        receipt,
        plan=plan,
        root=root,
        calibration_sha256=calibration_digest,
    )
    if validated_receipt.get("stage") != stage:
        raise ValueError("campaign_child_authorization_invalid")
    public_key = _verified_public_key(
        public_bytes,
        expected_digest=plan.get("approval_authority_public_key_sha256"),
    )
    try:
        public_key.verify(signature, canonical_bytes(receipt))
    except InvalidSignature as exc:
        raise ValueError("campaign_child_authorization_invalid") from exc
    context_routes = validated_receipt.get("_context_routes")
    if not isinstance(context_routes, list):
        raise ValueError("campaign_child_authorization_invalid")
    matching = [
        item
        for item in context_routes
        if isinstance(item, Mapping) and item.get("requested_route") == requested_route
    ]
    if len(matching) != 1:
        raise ValueError("campaign_child_authorization_invalid")
    route_context = matching[0]
    if route_context.get("output_relative_path") != f"{stage}/attempts/{output_name}":
        raise ValueError("campaign_child_authorization_invalid")
    if plan.get("reasoning_effort") != reasoning_effort:
        raise ValueError("campaign_child_authorization_invalid")
    if not isinstance(max_observed_cost_usd, (int, float)) or isinstance(max_observed_cost_usd, bool):
        raise ValueError("campaign_child_authorization_invalid")
    child_cost = float(max_observed_cost_usd)
    signed_cost = _nonnegative_number(validated_receipt.get("observed_cost_stop_usd"))
    if child_cost <= 0.0 or signed_cost is None or child_cost > signed_cost:
        raise ValueError("campaign_child_authorization_invalid")
    if allow_unknown_costs is not validated_receipt.get("allow_unknown_costs"):
        raise ValueError("campaign_child_authorization_invalid")
    if stage == "qualification":
        contract = plan["qualification"]
        expected_calls = ABSOLUTE_API_CALL_CEILING_PER_ROUTE
    else:
        contract = plan["full_run"]
        expected_calls = FULL_API_CALL_CEILING_PER_ROUTE
    if max_api_calls != expected_calls:
        raise ValueError("campaign_child_authorization_invalid")
    return {
        "campaign_id": plan["campaign_id"],
        "plan_sha256": plan["plan_sha256"],
        "release_tree_sha256": plan["release_tree_sha256"],
        "stage_approval_sha256": validated_receipt["receipt_sha256"],
        "approval_public_key_sha256": plan["approval_authority_public_key_sha256"],
        "route_id": route_context["route_id"],
        "requested_route": requested_route,
        "reasoning_effort": reasoning_effort,
        "output_relative_path": route_context["output_relative_path"],
        "contract": contract,
        "allow_unknown_costs": bool(allow_unknown_costs),
        "max_api_calls": expected_calls,
        "max_observed_cost_usd": child_cost,
    }
