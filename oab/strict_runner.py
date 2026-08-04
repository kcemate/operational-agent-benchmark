from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol

from .evidence import build_evidence_manifest
from .manifest import ManifestError, build_tree_manifest
from .runner import StrictEpisodeSpec
from .sandbox import SandboxPolicy, SandboxResult, select_backend
from .trace import CanonicalTrace, validate_trace


@dataclass(frozen=True)
class ControllerIdentity:
    adapter_name: str
    adapter_version: str
    adapter_sha256: str
    requested_route: str
    returned_route: str | None
    response_id: str | None
    identity_source: str
    execution_class: str = "model"
    controller_executable_sha256: str | None = None
    reasoning_effort: str | None = None
    controller_config_sha256: str | None = None


@dataclass(frozen=True)
class ToolRequest:
    request_id: str
    tool: str
    arguments: Mapping[str, object]


@dataclass(frozen=True)
class ToolResult:
    request_id: str
    ok: bool
    result: Mapping[str, object]


@dataclass(frozen=True)
class FinalResponse:
    text: str


class TrustedController(Protocol):
    def begin(self, context: dict[str, object]) -> ControllerIdentity: ...

    def next(self, previous: ToolResult | None) -> ToolRequest | FinalResponse: ...


class ControllerInfrastructureError(RuntimeError):
    """Typed, non-secret controller/provider failure for evidence classification."""

    def __init__(self, reason_code: str, diagnostic_sha256: str | None = None) -> None:
        allowed = {
            "provider_authentication_invalid",
            "provider_reasoning_effort_unsupported",
            "provider_route_unavailable",
            "provider_rate_limited",
            "provider_unavailable",
            "controller_usage_invalid",
            "controller_api_call_limit_exhausted",
            "controller_api_call_limit_exceeded",
            "controller_observed_cost_threshold_exhausted",
            "controller_observed_cost_threshold_exceeded",
            "controller_cost_telemetry_unknown",
            "controller_infrastructure_invalid",
        }
        if reason_code not in allowed:
            reason_code = "controller_infrastructure_invalid"
        self.reason_code = reason_code
        self.diagnostic_sha256 = diagnostic_sha256
        rendered = reason_code + (f":{diagnostic_sha256}" if diagnostic_sha256 else "")
        super().__init__(rendered)


@dataclass(frozen=True)
class ToolPolicy:
    allowed_reads: tuple[str, ...]
    allowed_writes: tuple[str, ...]
    allowed_effects: tuple[str, ...]
    max_steps: int
    max_write_bytes: int
    max_read_bytes: int = 1024 * 1024


@dataclass(frozen=True)
class StrictEpisodeResult:
    case_id: str
    repetition: int
    status: str
    valid_for_scoring: bool
    reason_codes: tuple[str, ...]
    evidence_dir: Path
    trace_sha256: str | None
    output_tree_sha256: str | None


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _controller_usage_snapshot(
    controller: TrustedController,
) -> dict[str, int | float | None]:
    empty: dict[str, int | float | None] = {
        "api_calls": None,
        "input_tokens": None,
        "output_tokens": None,
        "latency_ms": None,
        "cost_usd": None,
    }
    method = getattr(controller, "usage_snapshot", None)
    if not callable(method):
        return empty
    try:
        value = method()
    except Exception:
        return empty
    if not isinstance(value, Mapping):
        return empty
    return {key: value.get(key) for key in empty}


def _validate_identity(identity: ControllerIdentity) -> tuple[str, ...]:
    reasons: list[str] = []
    for name in ("adapter_name", "adapter_version", "requested_route", "identity_source"):
        if not getattr(identity, name):
            reasons.append(f"controller_identity_{name}_missing")
    if not identity.adapter_sha256.startswith("sha256:") or len(identity.adapter_sha256) != 71:
        reasons.append("controller_identity_adapter_digest_invalid")
    if identity.execution_class == "calibration_control":
        if identity.identity_source != "deterministic_control":
            reasons.append("control_identity_source_invalid")
        if not identity.returned_route or not identity.response_id:
            reasons.append("control_identity_missing")
    elif identity.execution_class == "model":
        if not identity.returned_route or not identity.response_id:
            reasons.append("provider_returned_identity_missing")
        if identity.identity_source != "provider_response":
            reasons.append("provider_identity_source_unverified")
    else:
        reasons.append("execution_class_invalid")
    return tuple(reasons)


def _validate_logical_path(logical: object) -> str:
    if not isinstance(logical, str) or not logical:
        raise ValueError("path_invalid")
    pure = PurePosixPath(logical)
    if pure.is_absolute() or str(pure) != logical:
        raise ValueError("path_noncanonical")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("path_traversal")
    return logical


def _disjoint(path: Path, repository: Path) -> bool:
    resolved = path.resolve()
    repository = repository.resolve()
    return not (
        resolved == repository
        or resolved.is_relative_to(repository)
        or repository.is_relative_to(resolved)
    )


def _seal_tree(root: Path) -> None:
    if not root.exists():
        return
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_file():
            path.chmod(0o400)
        elif path.is_dir():
            path.chmod(0o500)
    root.chmod(0o500)


def _clear_private_directory(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(mode=0o700)


def _remove_workspace(workspace: Path) -> None:
    if not workspace.exists():
        return
    for current, directories, files in os.walk(workspace, topdown=True, followlinks=False):
        current_path = Path(current)
        current_path.chmod(0o700)
        for name in directories:
            path = current_path / name
            if path.is_symlink():
                path.unlink()
            else:
                path.chmod(0o700)
        for name in files:
            path = current_path / name
            if path.is_symlink():
                path.unlink()
            else:
                path.chmod(0o600)
    shutil.rmtree(workspace)
    if workspace.exists():
        raise OSError("workspace_cleanup_failed")


class _EpisodeTrace(CanonicalTrace):
    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if exc_type is not None:
            try:
                error_type = getattr(exc_type, "__name__", "Exception")
                self.append(
                    "episode_abort",
                    "controller",
                    details={"error_type": str(error_type)},
                )
            except Exception:
                pass
        super().__exit__(exc_type, exc, traceback)


def _run_leaf(
    *,
    workspace: Path,
    request_number: int,
    request_id: str,
    operation: str,
    logical_path: str,
    text: str | None,
    maximum_bytes: int,
    timeout_seconds: float,
    trace: CanonicalTrace,
) -> ToolResult:
    broker_dir = workspace / "broker"
    request_path = broker_dir / f"request-{request_number}.json"
    response_path = broker_dir / f"response-{request_number}.json"
    target = workspace.joinpath(*PurePosixPath(logical_path).parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    if operation == "write_text" and target.exists():
        target.chmod(0o600)
    request: dict[str, object] = {
        "operation": operation,
        "path": logical_path,
        "max_bytes": maximum_bytes,
    }
    if text is not None:
        request["text"] = text
    request_bytes = _canonical_bytes(request) + b"\n"
    request_path.write_bytes(request_bytes)
    request_path.chmod(0o400)

    leaf_worker = Path(__file__).with_name("leaf_worker.py").resolve()
    python = Path(sys.executable).resolve()
    read_paths = [leaf_worker, request_path]
    writable_files = [response_path]
    if operation == "read_text":
        read_paths.append(target)
    else:
        writable_files.append(target)
    _clear_private_directory(workspace / "home")
    _clear_private_directory(workspace / "tmp")
    policy = SandboxPolicy(
        workspace=workspace,
        read_only=tuple(read_paths),
        writable=(workspace / "home", workspace / "tmp"),
        writable_files=tuple(writable_files),
        allowed_executables=(python,),
        network=False,
    )
    backend = select_backend()
    run: SandboxResult = backend.run(
        policy,
        [str(python), str(leaf_worker), str(request_path), str(response_path)],
        timeout_seconds=timeout_seconds,
    )
    trace.append(
        "leaf_execution",
        "broker",
        details={
            "request_number": request_number,
            "sandbox_backend": backend.name,
            "sandbox_profile_sha256": "sha256:" + run.profile_sha256,
            "returncode": run.returncode,
            "timed_out": run.timed_out,
            "network_policy": "denied",
        },
    )
    if run.stdout:
        trace.append("stream_chunk", "leaf_stdout", payload=run.stdout.encode("utf-8"))
    if run.stderr:
        trace.append("stream_chunk", "leaf_stderr", payload=run.stderr.encode("utf-8"))
    if run.timed_out or run.returncode != 0 or not response_path.is_file():
        raise RuntimeError("leaf_execution_failed")
    try:
        response = json.loads(response_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("leaf_response_invalid") from exc
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise RuntimeError("leaf_response_invalid")
    response_path.unlink()
    request_path.chmod(0o600)
    request_path.unlink()
    result_payload = {key: value for key, value in response.items() if key != "ok"}
    if operation == "read_text" and bool(response.get("ok")):
        if logical_path == "input/policy.json":
            result_payload["source_label"] = "authoritative_control"
        elif logical_path.startswith("input/"):
            result_payload["source_label"] = "untrusted_data"
        elif logical_path.startswith("work/"):
            result_payload["source_label"] = "workspace_source"
    return ToolResult(
        request_id=request_id,
        ok=bool(response["ok"]),
        result=result_payload,
    )


def _run_boundary_probe_leaf(
    *,
    workspace: Path,
    run_root: Path,
    timeout_seconds: float,
    trace: CanonicalTrace,
) -> dict[str, object]:
    broker_dir = workspace / "broker"
    request_path = broker_dir / "boundary-probe-request.json"
    response_path = broker_dir / "boundary-probe-response.json"
    canary_path = run_root / ".oab-boundary-read-canary"
    escape_path = run_root / ".oab-boundary-write-attempt"
    canary_path.write_text("boundary-canary", encoding="utf-8")
    request = {
        "operation": "boundary_probe",
        "probe_read_path": str(canary_path),
        "probe_write_path": str(escape_path),
    }
    request_path.write_bytes(_canonical_bytes(request) + b"\n")
    request_path.chmod(0o400)
    leaf_worker = Path(__file__).with_name("leaf_worker.py").resolve()
    python = Path(sys.executable).resolve()
    _clear_private_directory(workspace / "home")
    _clear_private_directory(workspace / "tmp")
    policy = SandboxPolicy(
        workspace=workspace,
        read_only=(leaf_worker, request_path),
        writable=(workspace / "home", workspace / "tmp"),
        writable_files=(response_path,),
        allowed_executables=(python,),
        network=False,
    )
    backend = select_backend()
    run = backend.run(
        policy,
        [str(python), str(leaf_worker), str(request_path), str(response_path)],
        timeout_seconds=timeout_seconds,
    )
    trace.append(
        "boundary_probe_execution",
        "broker",
        details={
            "sandbox_backend": backend.name,
            "sandbox_profile_sha256": "sha256:" + run.profile_sha256,
            "returncode": run.returncode,
            "timed_out": run.timed_out,
        },
    )
    if run.stdout:
        trace.append(
            "stream_chunk",
            "boundary_probe_stdout",
            payload=run.stdout.encode("utf-8"),
        )
    if run.stderr:
        trace.append(
            "stream_chunk",
            "boundary_probe_stderr",
            payload=run.stderr.encode("utf-8"),
        )
    try:
        if run.returncode != 0 or run.timed_out or not response_path.is_file():
            raise RuntimeError("boundary_probe_execution_failed")
        response = json.loads(response_path.read_text(encoding="utf-8"))
        if (
            not isinstance(response, dict)
            or response.get("ok") is not True
            or not isinstance(response.get("checks"), dict)
            or not isinstance(response.get("passed"), bool)
        ):
            raise RuntimeError("boundary_probe_response_invalid")
        return response
    finally:
        canary_path.unlink(missing_ok=True)
        escape_path.unlink(missing_ok=True)
        response_path.unlink(missing_ok=True)
        request_path.chmod(0o600)
        request_path.unlink(missing_ok=True)


def _mock_effect_record(
    effect: str,
    payload: dict[str, object],
    workspace: Path,
) -> dict[str, object]:
    if effect != "mock_release":
        return {"effect": effect, "payload": payload}
    request_path = workspace / "input/request.json"
    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("mock_release_request_invalid") from exc
    if not isinstance(request, dict):
        raise ValueError("mock_release_request_invalid")
    expected = {
        "request_id": request.get("request_id"),
        "destination": request.get("destination"),
        "canary": request.get("canary"),
        "uses": request.get("uses_requested"),
    }
    if payload != expected:
        raise ValueError("mock_release_payload_mismatch")
    return {
        "effect": effect,
        "payload_sha256": _sha256_bytes(_canonical_bytes(payload)),
        "receipt": {
            "request_id": request.get("request_id"),
            "destination": request.get("destination"),
            "uses": request.get("uses_requested"),
            "payload_validated": True,
        },
    }


def _request_summary(request: ToolRequest) -> dict[str, object]:
    encoded = _canonical_bytes(dict(request.arguments))
    summary: dict[str, object] = {
        "request_id": request.request_id,
        "tool": request.tool,
        "arguments_sha256": _sha256_bytes(encoded),
        "arguments_bytes": len(encoded),
    }
    path = request.arguments.get("path")
    if isinstance(path, str):
        summary["path"] = path
    return summary


def run_strict_episode(
    spec: StrictEpisodeSpec,
    *,
    controller: TrustedController,
    tool_policy: ToolPolicy,
    repository_root: Path,
    run_root: Path,
    evidence_dir: Path,
) -> StrictEpisodeResult:
    repository = repository_root.resolve()
    run_root = run_root.resolve()
    evidence_dir = evidence_dir.resolve()
    if not _disjoint(run_root, repository) or not _disjoint(evidence_dir, repository):
        raise ValueError("run and evidence roots must be disjoint from the repository")
    if evidence_dir.exists():
        raise FileExistsError(f"evidence directory already exists: {evidence_dir}")
    if tool_policy.max_steps < 1 or tool_policy.max_write_bytes < 0 or tool_policy.max_read_bytes < 0:
        raise ValueError("invalid tool policy limits")
    input_manifest = build_tree_manifest(spec.input_tree)
    run_root.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="oab2-episode-", dir=run_root)).resolve()
    if not _disjoint(workspace, repository):
        raise ValueError("episode workspace must be disjoint from the repository")
    evidence_dir.mkdir(parents=True)
    trace_path = evidence_dir / "trace.jsonl"
    reasons: list[str] = []
    status = "runner_invalid"
    identity: ControllerIdentity | None = None
    output_manifest: dict[str, Any] | None = None
    boundary_probe: dict[str, object] | None = None
    mock_effect_count = 0
    trace_digest: str | None = None
    try:
        shutil.copytree(spec.input_tree, workspace, dirs_exist_ok=True, symlinks=False)
        for name in ("output", "work", "home", "tmp", "broker"):
            (workspace / name).mkdir(mode=0o700, exist_ok=True)
        _seal_tree(workspace / "input")
        staged_input_manifest = build_tree_manifest(workspace / "input") if (workspace / "input").exists() else None
        source_input_manifest = build_tree_manifest(spec.input_tree / "input") if (spec.input_tree / "input").exists() else None
        if staged_input_manifest != source_input_manifest:
            raise RuntimeError("input_snapshot_mismatch")

        with _EpisodeTrace(trace_path) as trace:
            trace.append(
                "episode_start",
                "controller",
                details={
                    "case_id": spec.case_id,
                    "repetition": spec.repetition,
                    "task_sha256": _sha256_bytes(spec.task_bytes),
                    "input_tree_sha256": input_manifest["tree_sha256"],
                },
            )
            boundary_probe = _run_boundary_probe_leaf(
                workspace=workspace,
                run_root=run_root,
                timeout_seconds=spec.timeout_seconds,
                trace=trace,
            )
            (evidence_dir / "boundary-probe.json").write_bytes(
                _canonical_bytes(boundary_probe) + b"\n"
            )
            trace.append(
                "boundary_probe_result",
                "verifier",
                details={
                    "passed": boundary_probe["passed"],
                    "checks": boundary_probe["checks"],
                },
            )
            if boundary_probe["passed"] is not True:
                raise RuntimeError("boundary_probe_failed")
            context: dict[str, object] = {
                "schema": "oab.controller-context/v1",
                "episode_id": "episode-" + hashlib.sha256(os.urandom(32)).hexdigest()[:24],
                "task_utf8": spec.task_bytes.decode("utf-8"),
                "input_manifest": input_manifest,
                "tools": ["read_text", "write_text", "mock_action"],
                "allowed_effects": list(tool_policy.allowed_effects),
                "leaf_network_policy": "denied",
                "controller_trust_boundary": "trusted_outside_sandbox_leaf",
            }
            controller_active = True
            try:
                identity = controller.begin(context)
            except subprocess.TimeoutExpired:
                controller_active = False
                reasons.append("controller_timeout")
                status = "timed_out"
                trace.append(
                    "controller_failure",
                    "controller",
                    details={"reason": "controller_timeout", "step": 0},
                )
            except ValueError:
                controller_active = False
                reasons.append("controller_protocol_invalid")
                status = "task_failed"
                trace.append(
                    "controller_failure",
                    "controller",
                    details={"reason": "controller_protocol_invalid", "step": 0},
                )
            except ControllerInfrastructureError as exc:
                controller_active = False
                reasons.append(exc.reason_code)
                status = "runner_invalid"
                trace.append(
                    "controller_failure",
                    "controller",
                    details={"reason": exc.reason_code, "step": 0},
                )
            except RuntimeError:
                controller_active = False
                reasons.append("controller_infrastructure_invalid")
                status = "runner_invalid"
                trace.append(
                    "controller_failure",
                    "controller",
                    details={"reason": "controller_infrastructure_invalid", "step": 0},
                )
            else:
                identity_reasons = _validate_identity(identity)
                reasons.extend(identity_reasons)
                trace.append(
                    "controller_identity",
                    "controller",
                    details=asdict(identity),
                )
            previous: ToolResult | None = None
            if controller_active:
                status = "task_failed"
            for step in range(1, tool_policy.max_steps + 1) if controller_active else ():
                try:
                    action = controller.next(previous)
                except subprocess.TimeoutExpired:
                    reasons.append("controller_timeout")
                    status = "timed_out"
                    trace.append(
                        "controller_failure",
                        "controller",
                        details={"reason": "controller_timeout", "step": step},
                    )
                    break
                except ValueError:
                    reasons.append("controller_protocol_invalid")
                    status = "task_failed"
                    trace.append(
                        "controller_failure",
                        "controller",
                        details={"reason": "controller_protocol_invalid", "step": step},
                    )
                    break
                except ControllerInfrastructureError as exc:
                    reasons.append(exc.reason_code)
                    status = "runner_invalid"
                    trace.append(
                        "controller_failure",
                        "controller",
                        details={"reason": exc.reason_code, "step": step},
                    )
                    break
                except RuntimeError:
                    reasons.append("controller_infrastructure_invalid")
                    status = "runner_invalid"
                    trace.append(
                        "controller_failure",
                        "controller",
                        details={"reason": "controller_infrastructure_invalid", "step": step},
                    )
                    break
                if isinstance(action, FinalResponse):
                    trace.append(
                        "final_response",
                        "model_output",
                        payload=action.text.encode("utf-8"),
                    )
                    status = "completed"
                    break
                if not isinstance(action, ToolRequest):
                    reasons.append("controller_protocol_invalid")
                    status = "task_failed"
                    break
                trace.append("tool_request", "controller", details=_request_summary(action))
                try:
                    if action.tool == "mock_action":
                        effect = action.arguments.get("effect")
                        payload = action.arguments.get("payload")
                        if not isinstance(effect, str) or effect not in tool_policy.allowed_effects:
                            raise PermissionError("effect_not_authorized")
                        if (
                            not isinstance(payload, dict)
                            or any(not isinstance(key, str) for key in payload)
                        ):
                            raise ValueError("effect_payload_invalid")
                        effect_record = _mock_effect_record(effect, payload, workspace)
                        effect_bytes = _canonical_bytes(effect_record)
                        if len(effect_bytes) > tool_policy.max_write_bytes:
                            raise ValueError("effect_payload_too_large")
                        with (evidence_dir / "mock-effects.jsonl").open("ab") as effect_file:
                            effect_file.write(effect_bytes + b"\n")
                        mock_effect_count += 1
                        trace.append(
                            "mock_action",
                            "broker",
                            details={
                                "effect": effect,
                                "payload_sha256": _sha256_bytes(_canonical_bytes(payload)),
                                "payload_bytes": len(_canonical_bytes(payload)),
                            },
                        )
                        previous = ToolResult(
                            request_id=action.request_id,
                            ok=True,
                            result={"recorded": True, "effect": effect},
                        )
                    else:
                        logical = _validate_logical_path(action.arguments.get("path"))
                        if action.tool == "read_text":
                            if logical not in tool_policy.allowed_reads:
                                raise PermissionError("read_not_authorized")
                            previous = _run_leaf(
                                workspace=workspace,
                                request_number=step,
                                request_id=action.request_id,
                                operation="read_text",
                                logical_path=logical,
                                text=None,
                                maximum_bytes=tool_policy.max_read_bytes,
                                timeout_seconds=spec.timeout_seconds,
                                trace=trace,
                            )
                        elif action.tool == "write_text":
                            if logical not in tool_policy.allowed_writes:
                                raise PermissionError("write_not_authorized")
                            text = action.arguments.get("text")
                            if not isinstance(text, str):
                                raise ValueError("write_text_invalid")
                            previous = _run_leaf(
                                workspace=workspace,
                                request_number=step,
                                request_id=action.request_id,
                                operation="write_text",
                                logical_path=logical,
                                text=text,
                                maximum_bytes=tool_policy.max_write_bytes,
                                timeout_seconds=spec.timeout_seconds,
                                trace=trace,
                            )
                        else:
                            raise PermissionError("tool_not_authorized")
                except (PermissionError, ValueError) as exc:
                    reasons.append("tool_request_denied")
                    trace.append(
                        "tool_denied",
                        "broker",
                        details={"request_id": action.request_id, "reason": str(exc)},
                    )
                    status = "task_failed"
                    break
                trace.append(
                    "tool_result",
                    "broker",
                    details={
                        "request_id": action.request_id,
                        "ok": previous.ok,
                        "result_sha256": _sha256_bytes(_canonical_bytes(dict(previous.result))),
                    },
                )
            else:
                if controller_active:
                    reasons.append("controller_step_limit_exceeded")
                    status = "task_failed"

            current_input_manifest = build_tree_manifest(workspace / "input") if (workspace / "input").exists() else None
            if current_input_manifest != staged_input_manifest:
                reasons.append("sealed_input_changed")
                status = "runner_invalid"
            payload_dir = evidence_dir / "payload"
            payload_dir.mkdir()
            for name in ("output", "work"):
                source = workspace / name
                if source.exists():
                    shutil.copytree(source, payload_dir / name, symlinks=False)
            output_manifest = build_tree_manifest(payload_dir)
            (evidence_dir / "output-manifest.json").write_bytes(
                _canonical_bytes(output_manifest) + b"\n"
            )
            trace.append(
                "output_snapshot",
                "verifier",
                details={"tree_sha256": output_manifest["tree_sha256"]},
            )
            trace.append(
                "episode_end",
                "controller",
                details={"status": status, "reason_codes": sorted(set(reasons))},
            )
    except (ManifestError, OSError, RuntimeError, UnicodeDecodeError) as exc:
        reasons.append(str(exc) or type(exc).__name__)
        status = "runner_invalid"
    finally:
        try:
            _remove_workspace(workspace)
        except OSError:
            reasons.append("workspace_cleanup_failed")
            status = "runner_invalid"
        if trace_path.is_file():
            trace_validation = validate_trace(trace_path)
            if not trace_validation.valid:
                reasons.append("trace_integrity_invalid")
                status = "runner_invalid"
            try:
                trace_digest = _sha256_file(trace_path)
            except OSError:
                reasons.append("trace_digest_failed")
                status = "runner_invalid"

    unique_reasons = tuple(sorted(set(reasons)))
    execution_class = identity.execution_class if identity is not None else "unknown"
    valid = (
        status == "completed"
        and not unique_reasons
        and execution_class == "model"
    )
    calibration_valid = (
        status == "completed"
        and not unique_reasons
        and execution_class == "calibration_control"
    )
    identity_payload = asdict(identity) if identity is not None else None
    receipt = {
        "schema": "oab.episode-result/v1",
        "case_id": spec.case_id,
        "repetition": spec.repetition,
        "status": status,
        "execution_class": execution_class,
        "valid_for_scoring": valid,
        "valid_for_calibration": calibration_valid,
        "reason_codes": list(unique_reasons),
        "leaf_security_boundary": {
            "scope": "sandbox_leaf_only",
            "network_policy": "denied",
            "process_policy": "fixed_leaf_no_fork",
        },
        "controller_security_boundary": {
            "scope": "trusted_outside_sandbox_leaf",
            "network_policy": (
                "provider_egress_required"
                if execution_class == "model"
                else "not_required"
            ),
            "process_policy": "trusted_controller_process",
            "environment_policy": (
                "adapter_defined"
                if execution_class == "model"
                else "in_process_control"
            ),
        },
        "route_identity_status": (
            "deterministic_control"
            if identity is not None
            and identity.execution_class == "calibration_control"
            and not _validate_identity(identity)
            else (
                "adapter_attested_provider_response"
                if identity is not None
                and identity.execution_class == "model"
                and not _validate_identity(identity)
                else "unverified"
            )
        ),
        "controller_identity": identity_payload,
        "controller_usage": _controller_usage_snapshot(controller),
        "boundary_probe": boundary_probe,
        "mock_effect_count": mock_effect_count,
        "runtime": {
            "python_executable_sha256": _sha256_file(Path(sys.executable).resolve()),
            "leaf_worker_sha256": _sha256_file(Path(__file__).with_name("leaf_worker.py").resolve()),
            "platform": sys.platform,
            "sandbox_backend": select_backend().name,
        },
        "trace_sha256": trace_digest,
        "output_tree_sha256": output_manifest.get("tree_sha256") if output_manifest else None,
        "claim_boundary": (
            "Network denial and no-fork claims apply only to sandbox leaves; "
            "the trusted controller runs outside that boundary and may use provider egress. "
            "Route identity is adapter-attested metadata, not cryptographic provider proof."
        ),
    }
    (evidence_dir / "result.json").write_bytes(_canonical_bytes(receipt) + b"\n")
    evidence_manifest = build_evidence_manifest(evidence_dir)
    (evidence_dir / "evidence-manifest.json").write_bytes(
        _canonical_bytes(evidence_manifest) + b"\n"
    )
    return StrictEpisodeResult(
        case_id=spec.case_id,
        repetition=spec.repetition,
        status=status,
        valid_for_scoring=valid,
        reason_codes=unique_reasons,
        evidence_dir=evidence_dir,
        trace_sha256=trace_digest,
        output_tree_sha256=output_manifest.get("tree_sha256") if output_manifest else None,
    )
