"""Immutable campaign-plan validation and descriptor-bound child execution."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Mapping, cast

from .full_stage_contract import (
    FULL_API_CALL_CEILING_PER_ROUTE,
    validate_authoritative_full_stage_plan,
)
from .qualification_contract import (
    ABSOLUTE_API_CALL_CEILING_PER_ROUTE,
    validate_qualification_contract,
)

CAMPAIGN_PLAN_SCHEMA = "oab.campaign-plan/v3"
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
        "qualification_execution",
        "full_run",
        "full_execution",
        "release_tree_sha256",
        "plan_sha256",
    }
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


def campaign_plan_sha256(plan: Mapping[str, object]) -> str:
    return canonical_sha256({key: value for key, value in plan.items() if key != "plan_sha256"})


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
    if not isinstance(value, Mapping) or set(value) != _PLAN_FIELDS:
        raise ValueError("campaign_plan_invalid")
    if value.get("schema") != CAMPAIGN_PLAN_SCHEMA:
        raise ValueError("campaign_plan_invalid")
    if not isinstance(value.get("created_at"), str) or not value.get("created_at"):
        raise ValueError("campaign_plan_invalid")
    if not isinstance(value.get("campaign_id"), str) or not value.get("campaign_id"):
        raise ValueError("campaign_plan_invalid")
    routes = _routes_from_plan(value.get("routes"))
    route_count = value.get("route_count")
    if (
        not isinstance(route_count, int)
        or isinstance(route_count, bool)
        or route_count != len(routes)
    ):
        raise ValueError("campaign_plan_invalid")
    baseline = value.get("baseline_route")
    if not isinstance(baseline, str) or baseline not in {
        route["requested_route"] for route in routes
    }:
        raise ValueError("campaign_plan_invalid")
    effort = value.get("reasoning_effort")
    if not isinstance(effort, str) or not effort:
        raise ValueError("campaign_plan_invalid")
    release_tree = value.get("release_tree_sha256")
    if not isinstance(release_tree, str) or _DIGEST_RE.fullmatch(release_tree) is None:
        raise ValueError("campaign_plan_invalid")
    try:
        qualification = validate_qualification_contract(
            value.get("qualification"), route_count=route_count
        )
        full_run = validate_authoritative_full_stage_plan(
            value.get("full_run"), route_count=route_count
        )
    except ValueError as exc:
        raise ValueError("campaign_plan_invalid") from exc
    validated_execution: dict[str, dict[str, object]] = {}
    for field, calls_per_route in (
        ("qualification_execution", ABSOLUTE_API_CALL_CEILING_PER_ROUTE),
        ("full_execution", FULL_API_CALL_CEILING_PER_ROUTE),
    ):
        execution = value.get(field)
        if not isinstance(execution, Mapping) or set(execution) != {
            "known_cost_stop_usd",
            "max_api_calls",
            "max_routes",
            "allow_unknown_costs",
            "cost_control_mode",
            "max_cost_overshoot_api_calls",
        }:
            raise ValueError("campaign_plan_invalid")
        cost = execution.get("known_cost_stop_usd")
        calls = execution.get("max_api_calls")
        routes_limit = execution.get("max_routes")
        if (
            not isinstance(cost, (int, float))
            or isinstance(cost, bool)
            or float(cost) < 0
            or not isinstance(calls, int)
            or isinstance(calls, bool)
            or not isinstance(routes_limit, int)
            or isinstance(routes_limit, bool)
            or routes_limit < 1
            or routes_limit > route_count
            or calls != routes_limit * calls_per_route
            or not isinstance(execution.get("allow_unknown_costs"), bool)
            or execution.get("cost_control_mode")
            != "post_provider_call_observed_known_cost_stop"
            or execution.get("max_cost_overshoot_api_calls") != 1
        ):
            raise ValueError("campaign_plan_invalid")
        validated_execution[field] = dict(execution)
    if value.get("plan_sha256") != campaign_plan_sha256(value):
        raise ValueError("campaign_plan_invalid")
    return {
        **dict(value),
        "routes": routes,
        "qualification": qualification,
        "qualification_execution": validated_execution["qualification_execution"],
        "full_run": full_run,
        "full_execution": validated_execution["full_execution"],
    }


def _read_regular_json_at(directory_fd: int, name: str) -> dict[str, object]:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("campaign_child_contract_invalid")
        payload = os.read(descriptor, 8 * 1024 * 1024 + 1)
    except OSError as exc:
        raise ValueError("campaign_child_contract_invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > 8 * 1024 * 1024:
        raise ValueError("campaign_child_contract_invalid")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("campaign_child_contract_invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("campaign_child_contract_invalid")
    return value


def _verify_directory_binding(path: Path, descriptor: int) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
        path_info = resolved.stat()
        descriptor_info = os.fstat(descriptor)
    except (OSError, ValueError) as exc:
        raise ValueError("campaign_child_contract_invalid") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(path_info.st_mode)
        or not stat.S_ISDIR(descriptor_info.st_mode)
        or (path_info.st_dev, path_info.st_ino)
        != (descriptor_info.st_dev, descriptor_info.st_ino)
    ):
        raise ValueError("campaign_child_contract_invalid")
    return resolved


def _verify_output_parent(root_fd: int, output_parent_fd: int, stage: str) -> None:
    stage_fd = attempts_fd = -1
    try:
        stage_fd = os.open(
            stage,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        attempts_fd = os.open(
            "attempts",
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=stage_fd,
        )
        expected = os.fstat(attempts_fd)
        supplied = os.fstat(output_parent_fd)
    except OSError as exc:
        raise ValueError("campaign_child_output_parent_invalid") from exc
    finally:
        if attempts_fd >= 0:
            os.close(attempts_fd)
        if stage_fd >= 0:
            os.close(stage_fd)
    if (expected.st_dev, expected.st_ino) != (supplied.st_dev, supplied.st_ino):
        raise ValueError("campaign_child_output_parent_invalid")


def verify_campaign_child_contract(
    *,
    stage: str,
    campaign_root_path: Path,
    campaign_root_fd: int,
    output_parent_fd: int,
    requested_route: str,
    reasoning_effort: str,
    output_name: str,
    max_api_calls: object,
    max_observed_cost_usd: object,
    allow_unknown_costs: object,
) -> dict[str, object]:
    """Reconstruct immutable route and stage identity from descriptor-bound PLAN."""
    if stage not in {"qualification", "full"} or _OUTPUT_NAME_RE.fullmatch(output_name) is None:
        raise ValueError("campaign_child_contract_invalid")
    _verify_directory_binding(campaign_root_path, campaign_root_fd)
    _verify_output_parent(campaign_root_fd, output_parent_fd, stage)
    plan = validate_campaign_plan_document(_read_regular_json_at(campaign_root_fd, "PLAN.json"))
    calibration = _read_regular_json_at(campaign_root_fd, "CALIBRATION.json")
    if calibration.get("passed") is not True:
        raise ValueError("campaign_child_contract_invalid")
    routes = cast(list[dict[str, str]], plan["routes"])
    matching = [
        route
        for route in routes
        if isinstance(route, Mapping) and route.get("requested_route") == requested_route
    ]
    if len(matching) != 1 or plan.get("reasoning_effort") != reasoning_effort:
        raise ValueError("campaign_child_contract_invalid")
    if (
        not isinstance(max_observed_cost_usd, (int, float))
        or isinstance(max_observed_cost_usd, bool)
        or float(max_observed_cost_usd) <= 0
        or not isinstance(allow_unknown_costs, bool)
    ):
        raise ValueError("campaign_child_contract_invalid")
    expected_calls = (
        ABSOLUTE_API_CALL_CEILING_PER_ROUTE
        if stage == "qualification"
        else FULL_API_CALL_CEILING_PER_ROUTE
    )
    if max_api_calls != expected_calls:
        raise ValueError("campaign_child_contract_invalid")
    execution_field = "qualification_execution" if stage == "qualification" else "full_execution"
    execution = plan.get(execution_field)
    if not isinstance(execution, Mapping) or (
        float(max_observed_cost_usd) != float(execution["known_cost_stop_usd"])
        or allow_unknown_costs is not execution["allow_unknown_costs"]
    ):
        raise ValueError("campaign_child_contract_invalid")
    return {
        "stage": stage,
        "campaign_id": plan["campaign_id"],
        "plan_sha256": plan["plan_sha256"],
        "execution_contract_sha256": plan["plan_sha256"],
        "release_tree_sha256": plan["release_tree_sha256"],
        "route_id": matching[0]["route_id"],
        "requested_route": requested_route,
        "reasoning_effort": reasoning_effort,
        "output_relative_path": f"{stage}/attempts/{output_name}",
        "contract": plan["qualification"] if stage == "qualification" else plan["full_run"],
        "allow_unknown_costs": allow_unknown_costs,
        "max_api_calls": expected_calls,
        "max_observed_cost_usd": float(max_observed_cost_usd),
    }
