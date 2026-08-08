from __future__ import annotations

import ctypes.util
import hashlib
import importlib.util
import ipaddress
import json
import os
import platform
import re
import shutil
import stat
import sys
import tempfile
import urllib.parse
import urllib.request
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

_ALLOWED_EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh"}
_COST_CONTROL_MODE = "post_provider_call_observed_known_cost_stop"
_MAX_COST_OVERSHOOT_API_CALLS = 1
_QUALIFICATION_REPETITIONS = 17
_QUALIFICATION_EPISODES_PER_ROUTE = 34
_QUALIFICATION_MAX_API_CALLS_PER_EPISODE = 1
_FULL_MAX_API_CALLS_PER_EPISODE = 17
_PROVIDER_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_MODEL_RE = re.compile(r"^[^\s\x00-\x1f\x7f]{1,256}$")
_AUTH_REASON_CODES = {
    "provider_auth_unavailable",
    "provider_authentication_invalid",
    "authentication_invalid",
    "credential_unavailable",
}
_EFFORT_REASON_CODES = {
    "provider_reasoning_effort_unsupported",
    "reasoning_effort_mismatch",
    "reasoning_effort_unattested",
    "reasoning_effort_unsupported",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _route_id(provider: str, model: str) -> str:
    payload = f"{provider}\0{model}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _canonical_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_sha256(payload: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _plan_sha256(plan: Mapping[str, object]) -> str:
    stable = {
        key: value
        for key, value in plan.items()
        if key not in {"created_at", "status", "spend_authorized", "plan_sha256"}
    }
    return _canonical_sha256(stable)


def _clean_provider(value: object) -> str | None:
    text = str(value or "").strip()
    return text if _PROVIDER_RE.fullmatch(text) else None


def _clean_model(value: object) -> str | None:
    text = str(value or "").strip()
    return text if _MODEL_RE.fullmatch(text) else None


def _atomic_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        + "\n"
    ).encode("utf-8")
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _atomic_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _read_single_link_regular_bytes(
    path: Path, *, error: str, max_bytes: int = 1024 * 1024
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(error) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > max_bytes:
            raise ValueError(error)
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise ValueError(error)
        return data
    finally:
        os.close(descriptor)


def _read_regular_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            _read_single_link_regular_bytes(path, error="campaign_state_file_unsafe").decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("campaign_state_invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("campaign_state_invalid")
    return value


class _RejectInventoryRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _open_inventory_request(
    request: urllib.request.Request, *, timeout: float
) -> Any:
    opener = urllib.request.build_opener(_RejectInventoryRedirects())
    return opener.open(request, timeout=timeout)


def load_hermes_inventory(
    *,
    context_loader: Any | None = None,
    payload_builder: Any | None = None,
    api_base_url: str | None = None,
    api_key: str | None = None,
    urlopen: Any | None = None,
) -> dict[str, object]:
    """Load authenticated Hermes inventory with explicit probes and pricing disabled.

    In-process Hermes context/plugin initialization may still read local configuration,
    refresh authentication, or perform implementation-defined network activity. The
    returned payload may contain provider implementation details and must be passed
    through :func:`sanitize_hermes_inventory` before persistence.
    """

    if api_base_url is not None:
        open_request = urlopen or _open_inventory_request
        parsed = urllib.parse.urlsplit(api_base_url.strip())
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
        ):
            raise RuntimeError("hermes_inventory_api_url_invalid")
        hostname = parsed.hostname
        is_loopback = hostname == "localhost"
        if hostname is not None and not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            raise RuntimeError("inventory_api_credentials_require_loopback")
        key = (api_key or os.environ.get("API_SERVER_KEY") or "").strip()
        if not key:
            raise RuntimeError("hermes_inventory_api_key_missing")
        base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")

        def get_json(path: str) -> dict[str, object]:
            request = urllib.request.Request(
                base + path,
                headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
                method="GET",
            )
            try:
                with open_request(request, timeout=5.0) as response:
                    body = response.read(1_000_001)
            except Exception as exc:
                raise RuntimeError("hermes_inventory_api_unavailable") from exc
            if len(body) > 1_000_000:
                raise RuntimeError("hermes_inventory_api_response_too_large")
            try:
                value = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("hermes_inventory_api_invalid") from exc
            if not isinstance(value, dict):
                raise RuntimeError("hermes_inventory_api_invalid")
            return value

        capabilities = get_json("/v1/capabilities")
        features = capabilities.get("features")
        feature_map = features if isinstance(features, Mapping) else {}
        endpoints = capabilities.get("endpoints")
        endpoint_map = endpoints if isinstance(endpoints, Mapping) else {}
        model_options = endpoint_map.get("model_options")
        model_options_map = model_options if isinstance(model_options, Mapping) else {}
        if feature_map.get("model_options") is not True:
            raise RuntimeError("hermes_inventory_api_capability_missing")
        if model_options_map.get("path") != "/api/model/options":
            raise RuntimeError("hermes_inventory_api_endpoint_invalid")
        payload = get_json("/api/model/options")
        payload["_oab_inventory_source"] = "hermes_api_model_options"
        return payload

    if context_loader is None or payload_builder is None:
        try:
            from hermes_cli.inventory import build_models_payload, load_picker_context
        except ImportError as exc:
            raise RuntimeError("hermes_inventory_unavailable") from exc
        context_loader = context_loader or load_picker_context
        payload_builder = payload_builder or build_models_payload
    assert context_loader is not None
    assert payload_builder is not None
    context = context_loader()
    payload = payload_builder(
        context,
        explicit_only=True,
        include_unconfigured=False,
        picker_hints=False,
        canonical_order=True,
        pricing=False,
        capabilities=True,
        featured=False,
        refresh=False,
        probe_custom_providers=False,
        probe_current_custom_provider=False,
        for_picker=False,
        max_models=2048,
    )
    if not isinstance(payload, dict):
        raise RuntimeError("hermes_inventory_invalid")
    return payload


def doctor_environment(
    *,
    benchmark_root: Path,
    platform_name: str | None = None,
    which: Any = shutil.which,
    inventory_available: bool | None = None,
    release_manifest_errors: Sequence[str] | None = None,
    expected_release_tree_sha256: str | None = None,
) -> dict[str, object]:
    """Return bounded, non-secret readiness checks for campaign execution."""

    root = benchmark_root.expanduser().resolve()
    system = (platform_name or platform.system()).strip().lower()
    checks: list[dict[str, object]] = []

    def add(check_id: str, passed: bool, detail: str) -> None:
        checks.append(
            {
                "id": check_id,
                "status": "pass" if passed else "fail",
                "detail": detail,
            }
        )

    python_ok = (3, 11) <= sys.version_info[:2] < (3, 14)
    add("python_runtime", python_ok, f"python={sys.version_info.major}.{sys.version_info.minor}")

    if release_manifest_errors is None:
        try:
            from tools.release_manifest import verify_release_manifest

            release_manifest_errors = verify_release_manifest(
                root,
                root / "RELEASE_MANIFEST.json",
                expected_tree_sha256=expected_release_tree_sha256,
            )
        except Exception:
            release_manifest_errors = ["release_manifest_check_failed"]
    add(
        "release_manifest",
        not release_manifest_errors,
        "verified" if not release_manifest_errors else ",".join(str(item) for item in release_manifest_errors),
    )

    hermes_path = which("hermes")
    add("hermes_executable", bool(hermes_path), "available" if hermes_path else "not found")

    if release_manifest_errors:
        add("hermes_inventory", False, "skipped because release manifest verification failed")
    else:
        if inventory_available is None:
            try:
                inventory_available = importlib.util.find_spec("hermes_cli.inventory") is not None
            except (ImportError, ModuleNotFoundError, ValueError):
                inventory_available = False
        add(
            "hermes_inventory",
            bool(inventory_available),
            "available" if inventory_available else "module not importable from this Python environment",
        )

    if system in {"darwin", "macos"}:
        sandbox_ok = bool(which("sandbox-exec"))
        sandbox_detail = "macos-sandbox-exec" if sandbox_ok else "sandbox-exec not found"
        backend = "macos-sandbox-exec" if sandbox_ok else None
    elif system == "linux":
        bwrap_ok = bool(which("bwrap"))
        seccomp_ok = bool(ctypes.util.find_library("seccomp")) if bwrap_ok else False
        sandbox_ok = bwrap_ok and seccomp_ok
        if not bwrap_ok:
            sandbox_detail = "bubblewrap not found"
        elif not seccomp_ok:
            sandbox_detail = "libseccomp not found"
        else:
            sandbox_detail = "linux-bubblewrap+libseccomp"
        backend = "linux-bubblewrap" if sandbox_ok else None
    else:
        sandbox_ok = False
        sandbox_detail = f"unsupported platform: {system or 'unknown'}"
        backend = None
    add("sandbox_backend", sandbox_ok, sandbox_detail)

    return {
        "schema": "oab.doctor/v1",
        "created_at": _utc_now(),
        "ready": all(check["status"] == "pass" for check in checks),
        "platform": system,
        "sandbox_backend": backend,
        "benchmark_root": str(root),
        "release_tree_sha256": (
            expected_release_tree_sha256 if not release_manifest_errors else None
        ),
        "checks": checks,
    }


def sanitize_hermes_inventory(payload: Mapping[str, object]) -> dict[str, object]:
    """Reduce Hermes inventory data to a bounded, secret-free route list.

    Inventory establishes configured candidates only. Authentication and route
    usability are established later by the qualification stage.
    """

    raw_rows = payload.get("providers")
    rows = raw_rows if isinstance(raw_rows, list) else []
    routes: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows[:256]:
        if not isinstance(row, Mapping):
            continue
        if row.get("authenticated") is False:
            continue
        provider = _clean_provider(row.get("slug"))
        if provider is None or provider.lower() == "moa":
            continue
        raw_models = row.get("models")
        models = raw_models if isinstance(raw_models, list) else []
        raw_capabilities = row.get("capabilities")
        capabilities = raw_capabilities if isinstance(raw_capabilities, Mapping) else {}
        for raw_model in models[:2048]:
            model = _clean_model(raw_model)
            if model is None or (provider, model) in seen:
                continue
            seen.add((provider, model))
            raw_model_caps = capabilities.get(model)
            model_caps = raw_model_caps if isinstance(raw_model_caps, Mapping) else {}
            routes.append(
                {
                    "route_id": _route_id(provider, model),
                    "provider": provider,
                    "model": model,
                    "requested_route": f"{provider}/{model}",
                    "status": "configured_candidate",
                    "credential_posture": "present_but_unverified",
                    "reasoning_capability_catalogued": (
                        bool(model_caps.get("reasoning"))
                        if isinstance(model_caps.get("reasoning"), bool)
                        else None
                    ),
                }
            )
    routes.sort(key=lambda item: (str(item["provider"]), str(item["model"])))

    current_provider = _clean_provider(payload.get("provider"))
    current_model = _clean_model(payload.get("model"))
    current_route = (
        f"{current_provider}/{current_model}"
        if current_provider is not None and current_model is not None
        else None
    )
    if current_route not in {str(route["requested_route"]) for route in routes}:
        current_route = None
    source = payload.get("_oab_inventory_source")
    safe_source = (
        "hermes_api_model_options"
        if source == "hermes_api_model_options"
        else "hermes_authenticated_provider_inventory"
    )
    return {
        "schema": "oab.route-discovery/v1",
        "created_at": _utc_now(),
        "source": safe_source,
        "discovery_claim": (
            "Configured credential-present candidates; authentication and inference "
            "availability remain unverified until qualification."
        ),
        "current_route": current_route,
        "route_count": len(routes),
        "routes": routes,
    }


def build_campaign_plan(
    discovery: Mapping[str, object],
    *,
    reasoning_effort: str,
    release_tree_sha256: str | None = None,
    pair_ids: Sequence[str] = ("P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08"),
    repetitions: int = 5,
) -> dict[str, object]:
    effort = reasoning_effort.strip().lower()
    if effort not in _ALLOWED_EFFORTS:
        raise ValueError("reasoning_effort_invalid")
    raw_routes = discovery.get("routes")
    routes = raw_routes if isinstance(raw_routes, list) else []
    if repetitions < 1:
        raise ValueError("repetitions_invalid")
    route_count = len(routes)
    qualification_per_route = _QUALIFICATION_EPISODES_PER_ROUTE
    full_per_route = len(pair_ids) * 2 * repetitions
    plan: dict[str, object] = {
        "schema": "oab.campaign-plan/v1",
        "created_at": _utc_now(),
        "status": "awaiting_calibration",
        "reasoning_effort": effort,
        "baseline_route": discovery.get("current_route"),
        "release_tree_sha256": release_tree_sha256,
        "route_count": route_count,
        "routes": [str(route.get("requested_route")) for route in routes if isinstance(route, Mapping)],
        "qualification": {
            "pair_ids": ["P01"],
            "repetitions": _QUALIFICATION_REPETITIONS,
            "episodes_per_route": qualification_per_route,
            "scheduled_episodes": route_count * qualification_per_route,
        },
        "full_run": {
            "pair_ids": list(pair_ids),
            "repetitions": repetitions,
            "episodes_per_route": full_per_route,
            "scheduled_episodes": route_count * full_per_route,
        },
        "cost_estimate": {
            "status": "unknown_until_qualification",
            "estimated_usd": None,
            "basis": "qualification usage telemetry is required before extrapolation",
        },
        "duration_estimate": {
            "status": "unknown_until_qualification",
            "estimated_seconds": None,
            "basis": "qualification wall-clock telemetry is required before extrapolation",
        },
        "spend_authorized": False,
    }
    plan["plan_sha256"] = _plan_sha256(plan)
    return plan


def verify_campaign_plan(plan: Mapping[str, object]) -> list[str]:
    errors: list[str] = []
    if plan.get("schema") != "oab.campaign-plan/v1":
        errors.append("campaign_plan_schema_invalid")
    if plan.get("plan_sha256") != _plan_sha256(plan):
        errors.append("campaign_plan_digest_mismatch")
    return errors


def verify_stage_approval(
    path: Path,
    *,
    expected_plan_sha256: str,
    expected_calibration_sha256: str,
    expected_stage: str,
    expected_route_ids: Sequence[str],
    expected_max_cost_usd: float,
    expected_max_api_calls: int,
    expected_max_routes: int,
    expected_allow_unknown_costs: bool,
    public_key_path: Path,
    signature_path: Path,
) -> list[str]:
    try:
        receipt = _read_regular_json(path)
    except ValueError:
        return ["stage_approval_invalid"]
    errors: list[str] = []
    body_fields = {
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
    }
    if set(receipt) != body_fields | {"receipt_sha256"}:
        errors.append("stage_approval_fields_invalid")
    if receipt.get("schema") != "oab.stage-approval/v4":
        errors.append("stage_approval_schema_invalid")
    if receipt.get("stage") != expected_stage:
        errors.append("stage_approval_stage_mismatch")
    if receipt.get("plan_sha256") != expected_plan_sha256:
        errors.append("stage_approval_plan_mismatch")
    if receipt.get("calibration_sha256") != expected_calibration_sha256:
        errors.append("stage_approval_calibration_mismatch")
    unsigned = {key: receipt.get(key) for key in body_fields}
    try:
        computed_receipt = _canonical_sha256(unsigned)
        signed_bytes = _canonical_bytes(receipt)
    except (TypeError, ValueError):
        computed_receipt = None
        signed_bytes = b""
    if receipt.get("receipt_sha256") != computed_receipt:
        errors.append("stage_approval_digest_mismatch")
    route_ids = receipt.get("route_ids")
    if not isinstance(route_ids, list) or not route_ids or any(
        not isinstance(route_id, str) or not route_id for route_id in route_ids
    ):
        errors.append("stage_approval_routes_invalid")
    elif route_ids != list(expected_route_ids):
        errors.append("stage_approval_routes_mismatch")
    elif len(set(route_ids)) != len(route_ids):
        errors.append("stage_approval_routes_invalid")
    max_cost = receipt.get("observed_cost_stop_usd")
    if (
        not isinstance(max_cost, (int, float))
        or isinstance(max_cost, bool)
        or not (float(max_cost) > 0.0)
        or not (float(max_cost) < float("inf"))
    ):
        errors.append("stage_approval_cost_limit_invalid")
    elif float(max_cost) != float(expected_max_cost_usd):
        errors.append("stage_approval_cost_limit_mismatch")
    if receipt.get("cost_control_mode") != _COST_CONTROL_MODE:
        errors.append("stage_approval_cost_control_mode_invalid")
    if receipt.get("max_cost_overshoot_api_calls") != _MAX_COST_OVERSHOOT_API_CALLS:
        errors.append("stage_approval_cost_overshoot_limit_invalid")
    max_calls = receipt.get("max_api_calls")
    if not isinstance(max_calls, int) or isinstance(max_calls, bool) or max_calls < 1:
        errors.append("stage_approval_api_call_limit_invalid")
    elif max_calls != expected_max_api_calls:
        errors.append("stage_approval_api_call_limit_mismatch")
    max_routes = receipt.get("max_routes")
    if not isinstance(max_routes, int) or isinstance(max_routes, bool) or max_routes < 1:
        errors.append("stage_approval_route_limit_invalid")
    elif max_routes != expected_max_routes:
        errors.append("stage_approval_route_limit_mismatch")
    allow_unknown = receipt.get("allow_unknown_costs")
    if not isinstance(allow_unknown, bool):
        errors.append("stage_approval_unknown_cost_policy_invalid")
    elif allow_unknown != expected_allow_unknown_costs:
        errors.append("stage_approval_unknown_cost_policy_mismatch")
    try:
        public_bytes = _read_single_link_regular_bytes(
            public_key_path, error="stage_approval_public_key_invalid", max_bytes=16 * 1024
        )
        signature = _read_single_link_regular_bytes(
            signature_path, error="stage_approval_signature_invalid", max_bytes=1024
        )
        public_key = serialization.load_pem_public_key(public_bytes)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("stage_approval_public_key_invalid")
    except (ValueError, TypeError):
        errors.append("stage_approval_signature_invalid")
    else:
        key_digest = "sha256:" + hashlib.sha256(public_bytes).hexdigest()
        if receipt.get("approval_public_key_sha256") != key_digest:
            errors.append("stage_approval_public_key_mismatch")
        try:
            public_key.verify(signature, signed_bytes)
        except (InvalidSignature, ValueError):
            errors.append("stage_approval_signature_invalid")
    return errors


def _reason_codes(report: Mapping[str, object]) -> set[str]:
    values: set[str] = set()
    raw = report.get("observations")
    observations = raw if isinstance(raw, list) else []
    for observation in observations:
        if not isinstance(observation, Mapping):
            continue
        reasons = observation.get("reason_codes")
        if isinstance(reasons, list):
            values.update(str(reason) for reason in reasons if isinstance(reason, str))
    return values


def classify_qualification(
    report: Mapping[str, object],
    *,
    requested_route: str,
    reasoning_effort: str,
) -> dict[str, object]:
    reasons = _reason_codes(report)
    usage = report.get("controller_usage")
    usage_map = usage if isinstance(usage, Mapping) else {}
    raw_cost = usage_map.get("cost_usd")
    observed_cost = (
        float(raw_cost)
        if isinstance(raw_cost, (int, float)) and not isinstance(raw_cost, bool)
        else None
    )
    raw_known_cost = usage_map.get("known_cost_usd")
    observed_known_cost = (
        float(raw_known_cost)
        if isinstance(raw_known_cost, (int, float))
        and not isinstance(raw_known_cost, bool)
        and float(raw_known_cost) >= 0
        else (observed_cost if observed_cost is not None else 0.0)
    )
    raw_unknown_calls = usage_map.get("unknown_cost_api_calls")
    unknown_cost_api_calls = (
        raw_unknown_calls
        if isinstance(raw_unknown_calls, int)
        and not isinstance(raw_unknown_calls, bool)
        and raw_unknown_calls >= 0
        else (0 if observed_cost is not None else None)
    )
    raw_duration = report.get("campaign_elapsed_seconds")
    observed_duration = (
        float(raw_duration)
        if isinstance(raw_duration, (int, float)) and not isinstance(raw_duration, bool) and raw_duration >= 0
        else None
    )
    base: dict[str, object] = {
        "requested_route": requested_route,
        "status": "infrastructure_invalid",
        "scoreable": False,
        "reason_codes": sorted(reasons),
        "observed_cost_usd": observed_cost,
        "observed_known_cost_usd": observed_known_cost,
        "unknown_cost_api_calls": unknown_cost_api_calls,
        "observed_duration_seconds": observed_duration,
        "identity_source": report.get("identity_source"),
        "controller_config_sha256": report.get("controller_config_sha256"),
    }
    if report.get("requested_route") != requested_route:
        base["status"] = "route_mismatch"
        return base
    if report.get("reasoning_effort") != reasoning_effort:
        base["status"] = "effort_incompatible"
        return base
    if reasons.intersection(_EFFORT_REASON_CODES):
        base["status"] = "effort_incompatible"
        return base
    if reasons.intersection(_AUTH_REASON_CODES) or any("auth" in reason.lower() for reason in reasons):
        base["status"] = "authentication_invalid"
        return base
    if "provider_route_unavailable" in reasons:
        base["status"] = "route_unavailable"
        return base
    if "provider_rate_limited" in reasons:
        base["status"] = "provider_rate_limited"
        return base
    if "provider_unavailable" in reasons:
        base["status"] = "provider_unavailable"
        return base
    scheduled = report.get("scheduled_episodes")
    valid = report.get("infrastructure_valid_episodes")
    invalid = report.get("infrastructure_invalid_episodes")
    observed_api_calls = usage_map.get("api_calls")
    if (
        scheduled != _QUALIFICATION_EPISODES_PER_ROUTE
        or valid != _QUALIFICATION_EPISODES_PER_ROUTE
        or invalid != 0
        or observed_api_calls != _QUALIFICATION_EPISODES_PER_ROUTE
    ):
        base["status"] = "qualification_contract_invalid"
        return base
    if report.get("identity_source") not in {"provider_response", "adapter_runtime"}:
        base["status"] = "identity_unattested"
        return base
    base["status"] = "qualified"
    base["scoreable"] = True
    base["authority_eligible"] = report.get("identity_source") == "provider_response"
    return base


def initialize_campaign(
    output_root: Path,
    *,
    doctor: Mapping[str, object],
    inventory_payload: Mapping[str, object],
    reasoning_effort: str,
    repository_root: Path | None = None,
) -> dict[str, object]:
    root = output_root.expanduser().resolve()
    if repository_root is None:
        from oab.paths import benchmark_root as installed_benchmark_root

        repository_root = installed_benchmark_root()
    repository = repository_root.expanduser().resolve()
    if (
        root == repository
        or root.is_relative_to(repository)
        or repository.is_relative_to(root)
    ):
        raise ValueError("campaign_and_benchmark_must_be_disjoint")
    root.mkdir(parents=True, exist_ok=False)
    discovery = sanitize_hermes_inventory(inventory_payload)
    release_tree = doctor.get("release_tree_sha256")
    plan = build_campaign_plan(
        discovery,
        reasoning_effort=reasoning_effort,
        release_tree_sha256=(release_tree if isinstance(release_tree, str) else None),
    )
    ready = doctor.get("ready") is True
    status = "awaiting_calibration" if ready else "blocked_environment"
    plan["status"] = status
    state: dict[str, object] = {
        "schema": "oab.campaign/v1",
        "created_at": _utc_now(),
        "updated_at": _utc_now(),
        "status": status,
        "reasoning_effort": plan["reasoning_effort"],
        "current_route": discovery.get("current_route"),
        "route_count": discovery["route_count"],
        "qualified_routes": [],
        "excluded_routes": [],
        "full_run_routes": [],
        **build_evidence_posture([]),
        "spend": {
            "qualification_approved": False,
            "full_run_approved": False,
            "observed_cost_usd": 0.0,
            "unknown_cost_encountered": False,
        },
    }
    _atomic_json(root / "DOCTOR.json", dict(doctor))
    _atomic_json(root / "DISCOVERY.json", discovery)
    _atomic_json(root / "PLAN.json", plan)
    _atomic_json(root / "CAMPAIGN.json", state)
    return state


def load_campaign(output_root: Path, *, expected_reasoning_effort: str | None = None) -> dict[str, Any]:
    root = output_root.expanduser().resolve(strict=True)
    state = _read_regular_json(root / "CAMPAIGN.json")
    if state.get("schema") != "oab.campaign/v1":
        raise ValueError("campaign_schema_invalid")
    if expected_reasoning_effort is not None and state.get("reasoning_effort") != expected_reasoning_effort:
        raise ValueError("campaign_reasoning_effort_mismatch")
    return state


def record_calibration(output_root: Path, report: Mapping[str, object]) -> dict[str, Any]:
    root = output_root.expanduser().resolve(strict=True)
    state = load_campaign(root)
    if report.get("schema") not in {
        "oab.calibration-report/v1",
        "oab.calibration-report/v2",
    }:
        raise ValueError("calibration_schema_invalid")
    passed = report.get("passed") is True
    receipt = dict(report)
    receipt["recorded_at"] = _utc_now()
    calibration_sha256 = _canonical_sha256(receipt)
    _atomic_json(root / "CALIBRATION.json", receipt)
    state["calibration_passed"] = passed
    state["calibration_sha256"] = calibration_sha256
    state["status"] = "awaiting_qualification_approval" if passed else "blocked_calibration"
    state["updated_at"] = _utc_now()
    _atomic_json(root / "CAMPAIGN.json", state)
    return state


def _require_passed_calibration(root: Path, state: Mapping[str, object]) -> None:
    if state.get("calibration_passed") is not True:
        raise ValueError("campaign_calibration_required")
    try:
        receipt = _read_regular_json(root / "CALIBRATION.json")
    except (OSError, ValueError) as exc:
        raise ValueError("campaign_calibration_receipt_invalid") from exc
    if receipt.get("schema") not in {
        "oab.calibration-report/v1",
        "oab.calibration-report/v2",
    } or receipt.get("passed") is not True:
        raise ValueError("campaign_calibration_receipt_invalid")
    if state.get("calibration_sha256") != _canonical_sha256(receipt):
        raise ValueError("campaign_calibration_digest_mismatch")


def _campaign_routes(root: Path) -> list[dict[str, object]]:
    discovery = _read_regular_json(root / "DISCOVERY.json")
    if discovery.get("schema") != "oab.route-discovery/v1":
        raise ValueError("campaign_discovery_schema_invalid")
    raw = discovery.get("routes")
    if not isinstance(raw, list):
        raise ValueError("campaign_discovery_invalid")
    routes = [dict(item) for item in raw if isinstance(item, Mapping)]
    if len(routes) != len(raw):
        raise ValueError("campaign_discovery_invalid")
    return routes


def _plan_bound_routes(root: Path, plan: Mapping[str, object]) -> list[dict[str, object]]:
    planned_value = plan.get("routes")
    if not isinstance(planned_value, list) or not planned_value or any(
        not isinstance(route, str) or not route for route in planned_value
    ):
        raise ValueError("campaign_plan_routes_invalid")
    planned_routes = [str(route) for route in planned_value]
    if len(set(planned_routes)) != len(planned_routes):
        raise ValueError("campaign_plan_routes_invalid")
    routes = _campaign_routes(root)
    observed: list[str] = []
    observed_ids: set[str] = set()
    for route in routes:
        provider = route.get("provider")
        model = route.get("model")
        requested_route = route.get("requested_route")
        route_id = route.get("route_id")
        if (
            not isinstance(provider, str)
            or not isinstance(model, str)
            or not isinstance(requested_route, str)
            or not isinstance(route_id, str)
            or requested_route != f"{provider}/{model}"
            or route_id != _route_id(provider, model)
            or route_id in observed_ids
        ):
            raise ValueError("campaign_discovery_plan_mismatch")
        observed.append(requested_route)
        observed_ids.add(route_id)
    if observed != planned_routes:
        raise ValueError("campaign_discovery_plan_mismatch")
    baseline = plan.get("baseline_route")
    if not isinstance(baseline, str) or baseline not in observed:
        raise ValueError("campaign_plan_baseline_invalid")
    return routes


def _plan_reasoning_effort(
    plan: Mapping[str, object], state: Mapping[str, object]
) -> str:
    effort = plan.get("reasoning_effort")
    if not isinstance(effort, str) or effort not in _ALLOWED_EFFORTS:
        raise ValueError("campaign_plan_reasoning_effort_invalid")
    if state.get("reasoning_effort") != effort:
        raise ValueError("campaign_reasoning_effort_mismatch")
    return effort


def _select_routes(
    routes: Sequence[Mapping[str, object]],
    *,
    current_route: object,
    max_routes: int,
) -> list[dict[str, object]]:
    current = str(current_route) if isinstance(current_route, str) else None
    ordered = sorted(
        (dict(route) for route in routes),
        key=lambda route: 0 if route.get("requested_route") == current else 1,
    )
    return ordered[:max_routes]


def _result_path(root: Path, stage: str, route_id: str) -> Path:
    return root / stage / "results" / f"{route_id}.json"


def _stage_result_receipt(
    body: Mapping[str, object], report: Mapping[str, object]
) -> dict[str, object]:
    receipt = dict(body)
    suite_report = dict(report)
    receipt["suite_report"] = suite_report
    receipt["suite_report_sha256"] = _canonical_sha256(suite_report)
    receipt["receipt_sha256"] = _canonical_sha256(receipt)
    return receipt


def _load_stage_results(
    root: Path,
    stage: str,
    routes: Sequence[Mapping[str, object]],
    *,
    reasoning_effort: str,
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for route in routes:
        route_id = str(route.get("route_id") or "")
        path = _result_path(root, stage, route_id)
        if path.exists() or path.is_symlink():
            result = _read_regular_json(path)
            if result.get("route_id") != route_id or result.get("requested_route") != route.get("requested_route"):
                raise ValueError("campaign_stage_result_route_mismatch")
            receipt_sha256 = result.get("receipt_sha256")
            unsigned = dict(result)
            unsigned.pop("receipt_sha256", None)
            if receipt_sha256 != _canonical_sha256(unsigned):
                raise ValueError("campaign_stage_result_receipt_digest_mismatch")
            suite_report = result.get("suite_report")
            if not isinstance(suite_report, Mapping) or result.get(
                "suite_report_sha256"
            ) != _canonical_sha256(suite_report):
                raise ValueError("campaign_stage_result_report_digest_mismatch")
            expected_suite_output = str(root / stage / "suites" / route_id)
            if result.get("suite_output") != expected_suite_output:
                raise ValueError("campaign_stage_result_output_mismatch")
            if stage == "qualification":
                expected_classification = classify_qualification(
                    suite_report,
                    requested_route=str(route.get("requested_route") or ""),
                    reasoning_effort=reasoning_effort,
                )
                expected_classification["observed_api_calls"] = _api_calls_from_report(
                    suite_report
                )
                if result.get("classification") != expected_classification:
                    raise ValueError("campaign_stage_result_recomputation_mismatch")
            elif stage == "full":
                expected_fields = {
                    "observed_cost_usd": _cost_from_report(suite_report),
                    "observed_known_cost_usd": _known_cost_from_report(suite_report),
                    "unknown_cost_api_calls": _unknown_cost_api_calls_from_report(
                        suite_report
                    ),
                    "observed_api_calls": _api_calls_from_report(suite_report),
                }
                if any(result.get(key) != value for key, value in expected_fields.items()):
                    raise ValueError("campaign_stage_result_recomputation_mismatch")
            else:
                raise ValueError("campaign_stage_invalid")
            results[route_id] = result
    return results


def _cost_from_report(report: Mapping[str, object]) -> float | None:
    usage = report.get("controller_usage")
    if not isinstance(usage, Mapping):
        return None
    value = usage.get("cost_usd")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and float(value) >= 0:
        return float(value)
    return None


def _known_cost_from_report(report: Mapping[str, object]) -> float:
    usage = report.get("controller_usage")
    if not isinstance(usage, Mapping):
        return 0.0
    value = usage.get("known_cost_usd")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and float(value) >= 0:
        return float(value)
    exact = usage.get("cost_usd")
    if isinstance(exact, (int, float)) and not isinstance(exact, bool) and float(exact) >= 0:
        return float(exact)
    return 0.0


def _unknown_cost_api_calls_from_report(report: Mapping[str, object]) -> int | None:
    usage = report.get("controller_usage")
    if not isinstance(usage, Mapping):
        return None
    value = usage.get("unknown_cost_api_calls")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0 if _cost_from_report(report) is not None else None


def _api_calls_from_report(report: Mapping[str, object]) -> int | None:
    usage = report.get("controller_usage")
    if not isinstance(usage, Mapping):
        return None
    value = usage.get("api_calls")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _validate_positive_int(value: int | None, error: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(error)
    return value


def _planned_stage_routes(
    root: Path,
    state: Mapping[str, object],
    *,
    stage: str,
    route_cap: int,
) -> tuple[dict[str, Any], list[dict[str, object]]]:
    plan = _read_regular_json(root / "PLAN.json")
    if verify_campaign_plan(plan):
        raise ValueError("campaign_plan_invalid")
    baseline_route = plan.get("baseline_route")
    if not isinstance(baseline_route, str) or not baseline_route:
        raise ValueError("campaign_plan_baseline_invalid")
    _plan_reasoning_effort(plan, state)
    all_routes = _plan_bound_routes(root, plan)
    if stage == "qualification":
        route_candidates = all_routes
    elif stage == "full":
        qualified_value = state.get("qualified_routes")
        qualified_rows = qualified_value if isinstance(qualified_value, list) else []
        qualified_ids = {
            str(item.get("route_id") or "")
            for item in qualified_rows
            if isinstance(item, Mapping)
        }
        route_candidates = [
            route
            for route in all_routes
            if str(route.get("route_id") or "") in qualified_ids
        ]
    else:
        raise ValueError("stage_approval_stage_invalid")
    routes = _select_routes(
        route_candidates,
        current_route=baseline_route,
        max_routes=route_cap,
    )
    if not routes or (stage == "full" and len(routes) < 2):
        raise ValueError("stage_approval_routes_invalid")
    return plan, routes


def build_approval_preview(
    output_root: Path,
    *,
    stage: str,
    max_cost_usd: float,
    max_api_calls: int,
    max_routes: int,
    allow_unknown_costs: bool,
) -> dict[str, object]:
    """Return a deterministic no-spend preview of the exact stage controls."""
    root = output_root.expanduser().resolve(strict=True)
    state = load_campaign(root)
    _require_passed_calibration(root, state)
    budget = _validate_budget(max_cost_usd)
    call_budget = _validate_positive_int(max_api_calls, "stage_api_call_budget_required")
    route_cap = _validate_positive_int(max_routes, "stage_route_cap_required")
    plan, routes = _planned_stage_routes(root, state, stage=stage, route_cap=route_cap)
    stage_plan = plan.get("qualification" if stage == "qualification" else "full_run")
    if not isinstance(stage_plan, Mapping):
        raise ValueError("campaign_plan_stage_invalid")
    episodes_per_route = stage_plan.get("episodes_per_route")
    if (
        not isinstance(episodes_per_route, int)
        or isinstance(episodes_per_route, bool)
        or episodes_per_route < 1
    ):
        raise ValueError("campaign_plan_stage_invalid")
    scheduled_episodes = episodes_per_route * len(routes)
    calls_per_episode = (
        _QUALIFICATION_MAX_API_CALLS_PER_EPISODE
        if stage == "qualification"
        else _FULL_MAX_API_CALLS_PER_EPISODE
    )
    minimum_calls = scheduled_episodes * calls_per_episode
    return {
        "schema": "oab.approval-preview/v1",
        "stage": stage,
        "plan_sha256": plan.get("plan_sha256"),
        "calibration_sha256": state.get("calibration_sha256"),
        "routes": [
            {
                "route_id": str(route.get("route_id") or ""),
                "requested_route": str(route.get("requested_route") or ""),
            }
            for route in routes
        ],
        "route_count": len(routes),
        "episodes_per_route": episodes_per_route,
        "scheduled_episodes": scheduled_episodes,
        "observed_cost_stop_usd": budget,
        "cost_control_mode": _COST_CONTROL_MODE,
        "max_cost_overshoot_api_calls": _MAX_COST_OVERSHOOT_API_CALLS,
        "max_api_calls": call_budget,
        "minimum_required_api_calls": minimum_calls,
        "max_api_calls_per_episode": calls_per_episode,
        "call_ceiling_sufficient": call_budget >= minimum_calls,
        "max_routes": route_cap,
        "allow_unknown_costs": bool(allow_unknown_costs),
        "intended_evidence_posture": "exploratory_by_default",
        "authority_note": (
            "Spend approval is independent of evidence authority. Authority also requires "
            "an exact-tree release approval and all identity, coverage, grid, and runtime gates."
        ),
        "provider_calls_performed": 0,
    }


def build_stage_approval_request(
    output_root: Path,
    *,
    stage: str,
    max_cost_usd: float,
    max_api_calls: int,
    max_routes: int,
    allow_unknown_costs: bool,
    approval_public_key_path: Path,
) -> dict[str, object]:
    root = output_root.expanduser().resolve(strict=True)
    state = load_campaign(root)
    _require_passed_calibration(root, state)
    budget = _validate_budget(max_cost_usd)
    call_budget = _validate_positive_int(max_api_calls, "stage_api_call_budget_required")
    route_cap = _validate_positive_int(max_routes, "stage_route_cap_required")
    plan, routes = _planned_stage_routes(root, state, stage=stage, route_cap=route_cap)
    plan_digest = _plan_sha256(plan)
    public_bytes = _read_single_link_regular_bytes(
        approval_public_key_path,
        error="stage_approval_public_key_invalid",
        max_bytes=16 * 1024,
    )
    public_key = serialization.load_pem_public_key(public_bytes)
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("stage_approval_public_key_invalid")
    receipt: dict[str, object] = {
        "schema": "oab.stage-approval/v4",
        "created_at": _utc_now(),
        "stage": stage,
        "plan_sha256": plan_digest,
        "calibration_sha256": state["calibration_sha256"],
        "route_ids": [str(route.get("route_id") or "") for route in routes],
        "observed_cost_stop_usd": budget,
        "cost_control_mode": _COST_CONTROL_MODE,
        "max_cost_overshoot_api_calls": _MAX_COST_OVERSHOOT_API_CALLS,
        "max_api_calls": call_budget,
        "max_routes": route_cap,
        "allow_unknown_costs": bool(allow_unknown_costs),
        "approval_public_key_sha256": "sha256:" + hashlib.sha256(public_bytes).hexdigest(),
    }
    receipt["receipt_sha256"] = _canonical_sha256(receipt)
    return receipt


def build_conversational_stage_approval(
    output_root: Path,
    *,
    stage: str,
    max_cost_usd: float,
    max_api_calls: int,
    max_routes: int,
    allow_unknown_costs: bool,
    user_approval_reference: str,
    output_path: Path | None = None,
) -> dict[str, object]:
    """Bind an explicit host-conversation approval without exposing key ceremony."""
    root = output_root.expanduser().resolve(strict=True)
    state = load_campaign(root)
    _require_passed_calibration(root, state)
    budget = _validate_budget(max_cost_usd)
    call_budget = _validate_positive_int(max_api_calls, "stage_api_call_budget_required")
    route_cap = _validate_positive_int(max_routes, "stage_route_cap_required")
    reference = str(user_approval_reference).strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@#$+\-]{0,255}", reference):
        raise ValueError("conversation_approval_reference_invalid")
    plan, routes = _planned_stage_routes(root, state, stage=stage, route_cap=route_cap)
    plan_digest = _plan_sha256(plan)
    receipt: dict[str, object] = {
        "schema": "oab.conversational-stage-approval/v2",
        "created_at": _utc_now(),
        "approval_assurance": "conversation_attested",
        "user_approval_reference": reference,
        "stage": stage,
        "plan_sha256": plan_digest,
        "calibration_sha256": state["calibration_sha256"],
        "route_ids": [str(route.get("route_id") or "") for route in routes],
        "observed_cost_stop_usd": budget,
        "cost_control_mode": _COST_CONTROL_MODE,
        "max_cost_overshoot_api_calls": _MAX_COST_OVERSHOOT_API_CALLS,
        "max_api_calls": call_budget,
        "max_routes": route_cap,
        "allow_unknown_costs": bool(allow_unknown_costs),
    }
    receipt["receipt_sha256"] = _canonical_sha256(receipt)
    if output_path is not None:
        _atomic_json(output_path.expanduser().resolve(), receipt)
    return receipt


def _verify_conversational_stage_approval(
    receipt: Mapping[str, object],
    *,
    expected_plan_sha256: str,
    expected_calibration_sha256: str,
    expected_stage: str,
    expected_route_ids: Sequence[str],
    expected_max_cost_usd: float,
    expected_max_api_calls: int,
    expected_max_routes: int,
    expected_allow_unknown_costs: bool,
) -> list[str]:
    errors: list[str] = []
    body_fields = {
        "schema",
        "created_at",
        "approval_assurance",
        "user_approval_reference",
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
    }
    if set(receipt) != body_fields | {"receipt_sha256"}:
        errors.append("conversation_approval_fields_invalid")
    if receipt.get("schema") != "oab.conversational-stage-approval/v2":
        errors.append("conversation_approval_schema_invalid")
    if receipt.get("approval_assurance") != "conversation_attested":
        errors.append("conversation_approval_assurance_invalid")
    reference = receipt.get("user_approval_reference")
    if not isinstance(reference, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:/@#$+\-]{0,255}", reference
    ):
        errors.append("conversation_approval_reference_invalid")
    if receipt.get("stage") != expected_stage:
        errors.append("conversation_approval_stage_mismatch")
    if receipt.get("plan_sha256") != expected_plan_sha256:
        errors.append("conversation_approval_plan_mismatch")
    if receipt.get("calibration_sha256") != expected_calibration_sha256:
        errors.append("conversation_approval_calibration_mismatch")
    unsigned = {key: receipt.get(key) for key in body_fields}
    try:
        computed_receipt = _canonical_sha256(unsigned)
    except (TypeError, ValueError):
        computed_receipt = None
    if receipt.get("receipt_sha256") != computed_receipt:
        errors.append("conversation_approval_digest_mismatch")
    route_ids = receipt.get("route_ids")
    if not isinstance(route_ids, list) or not route_ids or any(
        not isinstance(route_id, str) or not route_id for route_id in route_ids
    ):
        errors.append("conversation_approval_routes_invalid")
    elif route_ids != list(expected_route_ids):
        errors.append("conversation_approval_routes_mismatch")
    elif len(set(route_ids)) != len(route_ids):
        errors.append("conversation_approval_routes_invalid")
    max_cost = receipt.get("observed_cost_stop_usd")
    if (
        not isinstance(max_cost, (int, float))
        or isinstance(max_cost, bool)
        or not (float(max_cost) > 0.0)
        or not (float(max_cost) < float("inf"))
    ):
        errors.append("conversation_approval_cost_limit_invalid")
    elif float(max_cost) != float(expected_max_cost_usd):
        errors.append("conversation_approval_cost_limit_mismatch")
    if receipt.get("cost_control_mode") != _COST_CONTROL_MODE:
        errors.append("conversation_approval_cost_control_mode_invalid")
    if receipt.get("max_cost_overshoot_api_calls") != _MAX_COST_OVERSHOOT_API_CALLS:
        errors.append("conversation_approval_cost_overshoot_limit_invalid")
    max_calls = receipt.get("max_api_calls")
    if not isinstance(max_calls, int) or isinstance(max_calls, bool) or max_calls < 1:
        errors.append("conversation_approval_api_call_limit_invalid")
    elif max_calls != expected_max_api_calls:
        errors.append("conversation_approval_api_call_limit_mismatch")
    max_routes_value = receipt.get("max_routes")
    if (
        not isinstance(max_routes_value, int)
        or isinstance(max_routes_value, bool)
        or max_routes_value < 1
    ):
        errors.append("conversation_approval_route_limit_invalid")
    elif max_routes_value != expected_max_routes:
        errors.append("conversation_approval_route_limit_mismatch")
    allow_unknown = receipt.get("allow_unknown_costs")
    if not isinstance(allow_unknown, bool):
        errors.append("conversation_approval_unknown_cost_policy_invalid")
    elif allow_unknown != expected_allow_unknown_costs:
        errors.append("conversation_approval_unknown_cost_policy_mismatch")
    return errors


def verify_conversational_stage_approval(
    path: Path,
    *,
    expected_plan_sha256: str,
    expected_calibration_sha256: str,
    expected_stage: str,
    expected_route_ids: Sequence[str],
    expected_max_cost_usd: float,
    expected_max_api_calls: int,
    expected_max_routes: int,
    expected_allow_unknown_costs: bool,
) -> list[str]:
    try:
        receipt = _read_regular_json(path)
    except ValueError:
        return ["conversation_approval_invalid"]
    return _verify_conversational_stage_approval(
        receipt,
        expected_plan_sha256=expected_plan_sha256,
        expected_calibration_sha256=expected_calibration_sha256,
        expected_stage=expected_stage,
        expected_route_ids=expected_route_ids,
        expected_max_cost_usd=expected_max_cost_usd,
        expected_max_api_calls=expected_max_api_calls,
        expected_max_routes=expected_max_routes,
        expected_allow_unknown_costs=expected_allow_unknown_costs,
    )


def stage_approval_signing_payload(receipt: Mapping[str, object]) -> bytes:
    """Return the exact canonical bytes an external Ed25519 approver signs."""
    return _canonical_bytes(receipt)


def _accept_stage_approval(
    root: Path,
    *,
    approval_path: Path,
    signature_path: Path | None,
    public_key_path: Path | None,
    stage: str,
    route_ids: Sequence[str],
    max_cost_usd: float,
    max_api_calls: int,
    max_routes: int,
    allow_unknown_costs: bool,
) -> dict[str, object]:
    plan = _read_regular_json(root / "PLAN.json")
    plan_digest = str(plan.get("plan_sha256") or "")
    state = load_campaign(root)
    _require_passed_calibration(root, state)
    calibration_sha256 = str(state.get("calibration_sha256") or "")
    receipt = _read_regular_json(approval_path)
    if receipt.get("schema") == "oab.conversational-stage-approval/v2":
        errors = _verify_conversational_stage_approval(
            receipt,
            expected_plan_sha256=plan_digest,
            expected_calibration_sha256=calibration_sha256,
            expected_stage=stage,
            expected_route_ids=route_ids,
            expected_max_cost_usd=max_cost_usd,
            expected_max_api_calls=max_api_calls,
            expected_max_routes=max_routes,
            expected_allow_unknown_costs=allow_unknown_costs,
        )
        error_prefix = "conversation_approval_invalid:"
    else:
        if signature_path is None or public_key_path is None:
            raise ValueError("stage_approval_signature_and_public_key_required")
        errors = verify_stage_approval(
            approval_path,
            expected_plan_sha256=plan_digest,
            expected_calibration_sha256=calibration_sha256,
            expected_stage=stage,
            expected_route_ids=route_ids,
            expected_max_cost_usd=max_cost_usd,
            expected_max_api_calls=max_api_calls,
            expected_max_routes=max_routes,
            expected_allow_unknown_costs=allow_unknown_costs,
            public_key_path=public_key_path,
            signature_path=signature_path,
        )
        error_prefix = "stage_approval_invalid:"
    if errors:
        raise ValueError(error_prefix + ",".join(sorted(set(errors))))
    stem = f"{stage}-{str(receipt['receipt_sha256']).removeprefix('sha256:')[:16]}"
    approvals = root / "APPROVALS"
    receipt_destination = approvals / f"{stem}.json"
    _atomic_json(receipt_destination, receipt)
    if receipt.get("schema") == "oab.conversational-stage-approval/v2":
        return {**receipt, "path": str(receipt_destination)}
    assert signature_path is not None
    assert public_key_path is not None
    signature = _read_single_link_regular_bytes(
        signature_path, error="stage_approval_signature_invalid", max_bytes=1024
    )
    public_bytes = _read_single_link_regular_bytes(
        public_key_path, error="stage_approval_public_key_invalid", max_bytes=16 * 1024
    )
    signature_destination = approvals / f"{stem}.sig"
    public_destination = approvals / f"key-{hashlib.sha256(public_bytes).hexdigest()[:16]}.pem"
    _atomic_bytes(signature_destination, signature)
    _atomic_bytes(public_destination, public_bytes)
    return {
        **receipt,
        "path": str(receipt_destination),
        "signature_path": str(signature_destination),
        "public_key_path": str(public_destination),
    }


def _validate_budget(value: float) -> float:
    budget = float(value)
    if not (budget > 0.0) or budget == float("inf") or budget != budget:
        raise ValueError("campaign_budget_invalid")
    return budget


def run_qualification_stage(
    output_root: Path,
    *,
    runner: Any,
    max_cost_usd: float,
    allow_unknown_costs: bool,
    max_api_calls: int | None = None,
    max_routes: int | None = None,
    approval_path: Path,
    approval_signature_path: Path | None,
    approval_public_key_path: Path | None,
) -> dict[str, Any]:
    root = output_root.expanduser().resolve(strict=True)
    state = load_campaign(root)
    if state.get("status") == "blocked_environment":
        raise ValueError("campaign_environment_not_ready")
    budget = _validate_budget(max_cost_usd)
    call_budget = _validate_positive_int(max_api_calls, "qualification_api_call_budget_required")
    route_cap = _validate_positive_int(max_routes, "qualification_route_cap_required")
    plan, routes = _planned_stage_routes(
        root, state, stage="qualification", route_cap=route_cap
    )
    effort = _plan_reasoning_effort(plan, state)
    results = _load_stage_results(
        root, "qualification", routes, reasoning_effort=effort
    )
    approval = _accept_stage_approval(
        root,
        approval_path=approval_path,
        signature_path=approval_signature_path,
        public_key_path=approval_public_key_path,
        stage="qualification",
        route_ids=[str(route.get("route_id") or "") for route in routes],
        max_cost_usd=budget,
        max_api_calls=call_budget,
        max_routes=route_cap,
        allow_unknown_costs=allow_unknown_costs,
    )
    state["status"] = "qualifying"
    spend = state.get("spend")
    spend_state = dict(spend) if isinstance(spend, Mapping) else {}
    spend_state["qualification_approved"] = True
    spend_state["qualification_max_cost_usd"] = budget
    spend_state["allow_unknown_costs"] = bool(allow_unknown_costs)
    spend_state["qualification_max_api_calls"] = call_budget
    spend_state["qualification_max_routes"] = route_cap
    spend_state["qualification_approval_sha256"] = approval["receipt_sha256"]
    spend_state["qualification_approved_route_ids"] = approval["route_ids"]
    spend_state["qualification_approval_path"] = approval["path"]
    spend_state["qualification_approval_assurance"] = approval.get(
        "approval_assurance", "external_signature"
    )
    spend_state["qualification_approval_signature_path"] = approval.get("signature_path")
    spend_state["qualification_approval_public_key_path"] = approval.get("public_key_path")
    state["spend"] = spend_state
    _atomic_json(root / "CAMPAIGN.json", state)

    for route in routes:
        route_id = str(route.get("route_id") or "")
        if route_id in results:
            continue
        observed_calls = sum(
            int(item["classification"]["observed_api_calls"])
            for item in results.values()
            if isinstance(item.get("classification"), Mapping)
            and isinstance(item["classification"].get("observed_api_calls"), int)
        )
        if observed_calls + 34 > call_budget:
            state["status"] = "qualification_call_budget_exhausted"
            break
        observed_known_before = sum(
            float(item["classification"].get("observed_known_cost_usd", 0.0))
            for item in results.values()
            if isinstance(item.get("classification"), Mapping)
            and isinstance(
                item["classification"].get("observed_known_cost_usd"), (int, float)
            )
        )
        if observed_known_before >= budget:
            state["status"] = "qualification_budget_exhausted"
            break
        suite_output = root / "qualification" / "suites" / route_id
        execution_route = dict(route)
        execution_route["max_observed_cost_usd"] = max(
            0.0, budget - observed_known_before
        )
        execution_route["allow_unknown_costs"] = bool(allow_unknown_costs)
        execution_route["max_api_calls"] = min(34, call_budget - observed_calls)
        try:
            report = runner(execution_route, "qualification", suite_output, effort)
        except Exception:
            state["status"] = "qualification_interrupted"
            state["updated_at"] = _utc_now()
            _atomic_json(root / "CAMPAIGN.json", state)
            return state
        if not isinstance(report, Mapping):
            state["status"] = "qualification_interrupted"
            state["updated_at"] = _utc_now()
            _atomic_json(root / "CAMPAIGN.json", state)
            return state
        requested_route = str(route.get("requested_route") or "")
        classification = classify_qualification(
            report,
            requested_route=requested_route,
            reasoning_effort=effort,
        )
        classification["observed_api_calls"] = _api_calls_from_report(report)
        if (
            isinstance(classification["observed_api_calls"], int)
            and classification["observed_api_calls"] > execution_route["max_api_calls"]
        ):
            classification["status"] = "api_call_budget_exceeded"
            state["status"] = "qualification_call_budget_exceeded"
        receipt = _stage_result_receipt(
            {
                "schema": "oab.qualification-result/v2",
                "created_at": _utc_now(),
                "route_id": route_id,
                "requested_route": requested_route,
                "suite_output": str(suite_output),
                "classification": classification,
            },
            report,
        )
        _atomic_json(_result_path(root, "qualification", route_id), receipt)
        results[route_id] = receipt

        if state.get("status") == "qualification_call_budget_exceeded":
            break

        known_costs = [
            item.get("classification", {}).get("observed_known_cost_usd")
            for item in results.values()
            if isinstance(item.get("classification"), Mapping)
        ]
        observed_known = sum(
            float(value) for value in known_costs if isinstance(value, (int, float))
        )
        if observed_known > budget:
            state["status"] = "qualification_budget_exhausted"
            break
        if (
            classification.get("unknown_cost_api_calls") not in {0}
            and not allow_unknown_costs
        ):
            state["status"] = "blocked_unknown_cost"
            break
        if classification.get("observed_api_calls") is None:
            state["status"] = "blocked_unknown_api_calls"
            break
    else:
        state["status"] = "awaiting_full_run_approval"

    qualified: list[dict[str, object]] = []
    excluded: list[dict[str, object]] = []
    costs_known = True
    durations_known = True
    projected = 0.0
    projected_duration = 0.0
    full_plan_for_projection = plan.get("full_run")
    if not isinstance(full_plan_for_projection, Mapping) or not isinstance(
        full_plan_for_projection.get("episodes_per_route"), int
    ):
        raise ValueError("campaign_plan_projection_invalid")
    projection_factor = (
        int(full_plan_for_projection["episodes_per_route"])
        / _QUALIFICATION_EPISODES_PER_ROUTE
    )
    for route in routes:
        receipt_result = results.get(str(route.get("route_id") or ""))
        if receipt_result is None:
            continue
        classification = receipt_result.get("classification")
        if not isinstance(classification, Mapping):
            continue
        summary = {
            "route_id": route.get("route_id"),
            "requested_route": route.get("requested_route"),
            "status": classification.get("status"),
        }
        if classification.get("status") == "qualified":
            qualified.append(summary)
            cost = classification.get("observed_cost_usd")
            if isinstance(cost, (int, float)):
                projected += float(cost) * projection_factor
            else:
                costs_known = False
            duration = classification.get("observed_duration_seconds")
            if isinstance(duration, (int, float)):
                projected_duration += float(duration) * projection_factor
            else:
                durations_known = False
        else:
            excluded.append(summary)
    if len(qualified) < 2 and state.get("status") == "awaiting_full_run_approval":
        state["status"] = "comparison_not_supportable"
    state["qualified_routes"] = qualified
    state["excluded_routes"] = excluded
    state["updated_at"] = _utc_now()
    spend_state["unknown_cost_encountered"] = any(
        isinstance(item.get("classification"), Mapping)
        and item["classification"].get("unknown_cost_api_calls") not in {0}
        for item in results.values()
    )
    observed_qualification_known_cost = sum(
        float(item["classification"].get("observed_known_cost_usd", 0.0))
        for item in results.values()
        if isinstance(item.get("classification"), Mapping)
        and isinstance(
            item["classification"].get("observed_known_cost_usd"), (int, float)
        )
    )
    spend_state["observed_qualification_known_cost_usd"] = (
        observed_qualification_known_cost
    )
    # Backward-compatible field now means the known billed lower bound; exact
    # total remains unavailable whenever unknown_cost_encountered is true.
    spend_state["observed_qualification_cost_usd"] = observed_qualification_known_cost
    state["spend"] = spend_state
    qualification_report: dict[str, object] = {
        "schema": "oab.qualification-summary/v1",
        "created_at": _utc_now(),
        "status": state["status"],
        "route_count": len(routes),
        "discovered_route_count": int(plan["route_count"]),
        "completed_routes": len(results),
        "qualified_routes": qualified,
        "excluded_routes": excluded,
        "projected_full_run_cost_usd": round(projected, 12) if costs_known else None,
        "cost_projection_basis": "qualification observed cost multiplied by 80/34 episodes",
        "projected_full_run_duration_seconds": (
            round(projected_duration, 3) if durations_known else None
        ),
        "duration_projection_basis": "qualification elapsed time multiplied by 80/34 episodes",
    }
    _atomic_json(root / "QUALIFICATION.json", qualification_report)
    _atomic_json(root / "CAMPAIGN.json", state)
    return state


def run_full_stage(
    output_root: Path,
    *,
    runner: Any,
    max_cost_usd: float,
    allow_unknown_costs: bool,
    max_api_calls: int | None = None,
    max_routes: int | None = None,
    approval_path: Path,
    approval_signature_path: Path | None,
    approval_public_key_path: Path | None,
) -> dict[str, Any]:
    root = output_root.expanduser().resolve(strict=True)
    state = load_campaign(root)
    plan = _read_regular_json(root / "PLAN.json")
    if verify_campaign_plan(plan):
        raise ValueError("campaign_plan_invalid")
    full_plan = plan.get("full_run")
    baseline_route = plan.get("baseline_route")
    release_tree_sha256 = plan.get("release_tree_sha256")
    if (
        not isinstance(full_plan, Mapping)
        or not isinstance(full_plan.get("pair_ids"), list)
        or not full_plan.get("pair_ids")
        or not isinstance(full_plan.get("repetitions"), int)
        or isinstance(full_plan.get("repetitions"), bool)
        or int(full_plan["repetitions"]) < 1
        or not isinstance(baseline_route, str)
        or not baseline_route
        or not isinstance(release_tree_sha256, str)
        or not release_tree_sha256
    ):
        raise ValueError("campaign_plan_decision_binding_invalid")
    expected_pair_ids = [str(pair_id) for pair_id in full_plan["pair_ids"]]
    expected_repetitions = int(full_plan["repetitions"])
    if state.get("status") not in {
        "awaiting_full_run_approval",
        "running_full",
        "blocked_unknown_full_cost",
        "blocked_unknown_full_api_calls",
        "full_budget_exhausted",
        "full_call_budget_exhausted",
        "full_run_interrupted",
    }:
        raise ValueError("campaign_not_ready_for_full_run")
    budget = _validate_budget(max_cost_usd)
    call_budget = _validate_positive_int(max_api_calls, "full_api_call_budget_required")
    route_cap = _validate_positive_int(max_routes, "full_route_cap_required")
    plan, routes = _planned_stage_routes(root, state, stage="full", route_cap=route_cap)
    if len(routes) < 2:
        raise ValueError("campaign_comparison_not_supportable")
    effort = _plan_reasoning_effort(plan, state)
    results = _load_stage_results(root, "full", routes, reasoning_effort=effort)
    approval = _accept_stage_approval(
        root,
        approval_path=approval_path,
        signature_path=approval_signature_path,
        public_key_path=approval_public_key_path,
        stage="full",
        route_ids=[str(route.get("route_id") or "") for route in routes],
        max_cost_usd=budget,
        max_api_calls=call_budget,
        max_routes=route_cap,
        allow_unknown_costs=allow_unknown_costs,
    )
    spend = state.get("spend")
    spend_state = dict(spend) if isinstance(spend, Mapping) else {}
    spend_state["full_run_approved"] = True
    spend_state["full_run_max_cost_usd"] = budget
    spend_state["allow_unknown_full_costs"] = bool(allow_unknown_costs)
    spend_state["full_run_max_api_calls"] = call_budget
    spend_state["full_run_max_routes"] = route_cap
    spend_state["full_run_approval_sha256"] = approval["receipt_sha256"]
    spend_state["full_run_approved_route_ids"] = approval["route_ids"]
    spend_state["full_run_approval_path"] = approval["path"]
    spend_state["full_run_approval_assurance"] = approval.get(
        "approval_assurance", "external_signature"
    )
    spend_state["full_run_approval_signature_path"] = approval.get("signature_path")
    spend_state["full_run_approval_public_key_path"] = approval.get("public_key_path")
    state["spend"] = spend_state
    state["status"] = "running_full"
    _atomic_json(root / "CAMPAIGN.json", state)

    for route in routes:
        route_id = str(route.get("route_id") or "")
        if route_id in results:
            continue
        observed_calls = sum(
            int(item["observed_api_calls"])
            for item in results.values()
            if isinstance(item.get("observed_api_calls"), int)
        )
        if observed_calls + 1360 > call_budget:
            state["status"] = "full_call_budget_exhausted"
            break
        observed_known_before = sum(
            float(item.get("observed_known_cost_usd", 0.0))
            for item in results.values()
            if isinstance(item.get("observed_known_cost_usd"), (int, float))
        )
        if observed_known_before >= budget:
            state["status"] = "full_budget_exhausted"
            break
        suite_output = root / "full" / "suites" / route_id
        execution_route = dict(route)
        execution_route["max_observed_cost_usd"] = max(
            0.0, budget - observed_known_before
        )
        execution_route["allow_unknown_costs"] = bool(allow_unknown_costs)
        execution_route["max_api_calls"] = min(1360, call_budget - observed_calls)
        try:
            report = runner(execution_route, "full", suite_output, effort)
        except Exception:
            state["status"] = "full_run_interrupted"
            state["updated_at"] = _utc_now()
            _atomic_json(root / "CAMPAIGN.json", state)
            return state
        if not isinstance(report, Mapping):
            state["status"] = "full_run_interrupted"
            state["updated_at"] = _utc_now()
            _atomic_json(root / "CAMPAIGN.json", state)
            return state
        receipt = _stage_result_receipt(
            {
                "schema": "oab.full-run-result/v2",
                "created_at": _utc_now(),
                "route_id": route_id,
                "requested_route": route.get("requested_route"),
                "suite_output": str(suite_output),
                "observed_cost_usd": _cost_from_report(report),
                "observed_known_cost_usd": _known_cost_from_report(report),
                "unknown_cost_api_calls": _unknown_cost_api_calls_from_report(report),
                "observed_api_calls": _api_calls_from_report(report),
            },
            report,
        )
        _atomic_json(_result_path(root, "full", route_id), receipt)
        results[route_id] = receipt
        observed_route_calls = receipt.get("observed_api_calls")
        if (
            isinstance(observed_route_calls, int)
            and observed_route_calls > execution_route["max_api_calls"]
        ):
            state["status"] = "full_call_budget_exceeded"
            break
        known_costs = [item.get("observed_known_cost_usd") for item in results.values()]
        observed_known = sum(
            float(value) for value in known_costs if isinstance(value, (int, float))
        )
        if observed_known > budget:
            state["status"] = "full_budget_exhausted"
            break
        if receipt["unknown_cost_api_calls"] not in {0} and not allow_unknown_costs:
            state["status"] = "blocked_unknown_full_cost"
            break
        if receipt["observed_api_calls"] is None:
            state["status"] = "blocked_unknown_full_api_calls"
            break
    else:
        state["status"] = "completed"

    reports = [
        item["suite_report"]
        for item in results.values()
        if isinstance(item.get("suite_report"), Mapping)
    ]
    decision = build_decision_report(
        current_route=baseline_route,
        expected_pair_ids=expected_pair_ids,
        expected_repetitions=expected_repetitions,
        expected_release_tree_sha256=release_tree_sha256,
        suite_reports=reports,
    )
    _atomic_json(root / "DECISION_REPORT.json", decision)
    state.update(build_evidence_posture(reports, decision=decision))
    state["full_run_routes"] = [
        {
            "route_id": item.get("route_id"),
            "requested_route": item.get("requested_route"),
        }
        for item in results.values()
    ]
    state["updated_at"] = _utc_now()
    observed_full_known_cost = sum(
        float(item.get("observed_known_cost_usd", 0.0))
        for item in results.values()
        if isinstance(item.get("observed_known_cost_usd"), (int, float))
    )
    spend_state["observed_full_run_known_cost_usd"] = observed_full_known_cost
    spend_state["observed_full_run_cost_usd"] = observed_full_known_cost
    spend_state["unknown_full_cost_encountered"] = any(
        item.get("unknown_cost_api_calls") not in {0} for item in results.values()
    )
    state["spend"] = spend_state
    _atomic_json(root / "CAMPAIGN.json", state)
    return state


def _number(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def build_evidence_posture(
    suite_reports: Sequence[Mapping[str, object]],
    *,
    decision: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Summarize evidence authority without conflating it with spend approval."""
    route_authority: list[dict[str, object]] = []
    for report in suite_reports:
        route = str(report.get("requested_route") or "unknown-route")
        authoritative = report.get("authoritative") is True
        release_authorized = report.get("release_authorized") is True
        reasons: list[str] = []
        if not release_authorized:
            reasons.append("release_not_authorized")
        if not authoritative:
            reason = report.get("non_authoritative_reason")
            if isinstance(reason, str) and reason:
                reasons.append(reason)
            else:
                flags = report.get("integrity_flags")
                if isinstance(flags, list):
                    reasons.extend(str(flag) for flag in flags if isinstance(flag, str))
                if not reasons:
                    reasons.append("suite_authority_attestation_missing")
        route_authority.append(
            {
                "requested_route": route,
                "authoritative": authoritative,
                "release_authorized": release_authorized,
                "blockers": sorted(set(reasons)),
            }
        )

    comparable_value = decision.get("comparable_routes") if isinstance(decision, Mapping) else []
    comparable_routes = (
        [str(route) for route in comparable_value if isinstance(route, str)]
        if isinstance(comparable_value, list)
        else []
    )
    release_authorized = bool(route_authority) and all(
        row["release_authorized"] is True for row in route_authority
    )
    authoritative_routes = {
        str(row["requested_route"])
        for row in route_authority
        if row["authoritative"] is True and row["release_authorized"] is True
    }
    authoritative_comparable = (
        len(comparable_routes) >= 2
        and release_authorized
        and set(comparable_routes).issubset(authoritative_routes)
    )
    blockers: set[str] = set()
    if not route_authority:
        blockers.add("full_stage_not_completed")
    if not release_authorized:
        blockers.add("release_not_authorized")
    for row in route_authority:
        if row["authoritative"] is not True or row["release_authorized"] is not True:
            route = str(row["requested_route"])
            row_blockers = row.get("blockers")
            if isinstance(row_blockers, list):
                for reason in row_blockers:
                    blockers.add(f"route:{route}:{reason}")
    if route_authority and len(comparable_routes) < 2:
        blockers.add("fewer_than_two_authoritative_comparable_routes")
    posture = "authoritative_comparable" if authoritative_comparable else "exploratory"
    return {
        "evidence_posture": posture,
        "release_authorized": bool(authoritative_comparable and release_authorized),
        "authority_blockers": [] if authoritative_comparable else sorted(blockers),
        "route_authority": route_authority,
        "authority_remediation": (
            None
            if authoritative_comparable
            else (
                "Provide and pin an exact-tree release approval, then rerun every full suite "
                "until identity, coverage, grid, runtime, and suite-seal authority gates pass."
            )
        ),
    }


def _comparable_authoritative_reports(
    reports: Sequence[Mapping[str, object]],
    *,
    expected_pair_ids: Sequence[str],
    expected_repetitions: int,
    expected_release_tree_sha256: str,
) -> list[Mapping[str, object]]:
    planned_pairs = list(expected_pair_ids)
    if (
        not planned_pairs
        or any(not isinstance(pair_id, str) or not pair_id for pair_id in planned_pairs)
        or len(set(planned_pairs)) != len(planned_pairs)
        or not isinstance(expected_repetitions, int)
        or isinstance(expected_repetitions, bool)
        or expected_repetitions < 1
        or not isinstance(expected_release_tree_sha256, str)
        or not expected_release_tree_sha256
    ):
        return []
    expected_episodes = len(planned_pairs) * 2 * expected_repetitions
    accepted: list[Mapping[str, object]] = []
    seen_routes: set[str] = set()
    for report in reports:
        scheduled = report.get("scheduled_episodes")
        valid = report.get("infrastructure_valid_episodes")
        environment = report.get("execution_environment")
        requested_route = report.get("requested_route")
        if (
            report.get("authoritative") is True
            and isinstance(requested_route, str)
            and bool(requested_route)
            and requested_route not in seen_routes
            and isinstance(scheduled, int)
            and not isinstance(scheduled, bool)
            and scheduled == expected_episodes
            and valid == scheduled
            and report.get("pair_ids") == planned_pairs
            and report.get("repetitions") == expected_repetitions
            and report.get("release_tree_sha256") == expected_release_tree_sha256
            and isinstance(report.get("reasoning_effort"), str)
            and isinstance(report.get("controller_config_sha256"), str)
            and isinstance(environment, Mapping)
            and isinstance(environment.get("platform"), str)
            and bool(environment.get("platform"))
            and isinstance(environment.get("sandbox_backend"), str)
            and bool(environment.get("sandbox_backend"))
        ):
            accepted.append(report)
            seen_routes.add(requested_route)
    if not accepted:
        return []
    first = accepted[0]
    return [
        report
        for report in accepted
        if report.get("reasoning_effort") == first.get("reasoning_effort")
        and report.get("controller_config_sha256") == first.get("controller_config_sha256")
        and report.get("release_tree_sha256") == first.get("release_tree_sha256")
        and report.get("execution_environment") == first.get("execution_environment")
    ]


def build_decision_report(
    *,
    current_route: str | None,
    expected_pair_ids: Sequence[str],
    expected_repetitions: int,
    expected_release_tree_sha256: str,
    suite_reports: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    comparable = _comparable_authoritative_reports(
        suite_reports,
        expected_pair_ids=expected_pair_ids,
        expected_repetitions=expected_repetitions,
        expected_release_tree_sha256=expected_release_tree_sha256,
    )
    base: dict[str, object] = {
        "schema": "oab.decision-report/v2",
        "created_at": _utc_now(),
        "current_route": current_route,
        "expected_pair_ids": list(expected_pair_ids),
        "expected_repetitions": expected_repetitions,
        "expected_release_tree_sha256": expected_release_tree_sha256,
        "recommendation": "not_supportable",
        "recommended_route": None,
        "reasons": [],
        "claim_scope": "tested route/configuration pairs only; not exact provider serving-model identity",
        "comparable_routes": [str(report.get("requested_route")) for report in comparable],
    }
    if len(comparable) < 2:
        base["reasons"] = ["fewer_than_two_authoritative_routes"]
        return base
    baseline = next(
        (report for report in comparable if report.get("requested_route") == current_route),
        None,
    )
    if baseline is None:
        base["reasons"] = ["current_route_not_in_authoritative_comparison"]
        return base
    baseline_primary = _number(baseline.get("deterministic_contract_completion_rate"))
    baseline_matched = _number(baseline.get("matched_pair_completion_rate"))
    stability = baseline.get("pair_stability")
    baseline_min = _number(stability.get("min")) if isinstance(stability, Mapping) else None
    if None in {baseline_primary, baseline_matched, baseline_min}:
        base["reasons"] = ["baseline_metrics_incomplete"]
        return base
    assert baseline_primary is not None
    assert baseline_matched is not None
    assert baseline_min is not None

    dominant: list[tuple[tuple[float, float, float], Mapping[str, object]]] = []
    for candidate in comparable:
        if candidate is baseline:
            continue
        primary = _number(candidate.get("deterministic_contract_completion_rate"))
        matched = _number(candidate.get("matched_pair_completion_rate"))
        candidate_stability = candidate.get("pair_stability")
        minimum = _number(candidate_stability.get("min")) if isinstance(candidate_stability, Mapping) else None
        if primary is None or matched is None or minimum is None:
            continue
        if primary > baseline_primary and matched >= baseline_matched and minimum >= baseline_min:
            dominant.append(((primary, matched, minimum), candidate))
    if not dominant:
        base["recommendation"] = "stay"
        base["recommended_route"] = current_route
        base["reasons"] = ["no_strictly_dominant_tested_route"]
        return base
    dominant.sort(key=lambda item: item[0], reverse=True)
    winner = dominant[0][1]
    base["recommendation"] = "switch"
    base["recommended_route"] = str(winner.get("requested_route"))
    base["reasons"] = ["strict_primary_gain_without_matched_pair_or_min_stability_regression"]
    return base
