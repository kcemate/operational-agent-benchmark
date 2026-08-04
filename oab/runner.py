from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .sandbox import SandboxPolicy, SandboxUnavailable, select_backend

_EVENT_PREFIX = "OAB_EVENT\t"


@dataclass(frozen=True)
class StrictEpisodeSpec:
    case_id: str
    repetition: int
    task_bytes: bytes
    input_tree: Path
    timeout_seconds: float


@dataclass(frozen=True)
class EpisodeSpec:
    case_id: str
    repetition: int
    task_path: Path
    fixture_path: Path
    readable_relative_paths: tuple[str, ...]
    writable_relative_directories: tuple[str, ...]
    writable_relative_files: tuple[str, ...]
    allowed_executables: tuple[Path, ...]
    adapter_read_paths: tuple[Path, ...] = ()
    network: bool = False


@dataclass(frozen=True)
class PreparedEpisode:
    workspace: Path
    policy: SandboxPolicy


@dataclass(frozen=True)
class EpisodeResult:
    case_id: str
    repetition: int
    completed: bool
    timed_out: bool
    exit_code: int
    valid_for_scoring: bool
    invalid_reasons: tuple[str, ...]
    output_dir: Path


def _safe_relative(root: Path, relative: str) -> Path:
    candidate = root / relative
    resolved_parent = candidate.parent.resolve()
    if not resolved_parent.is_relative_to(root.resolve()):
        raise ValueError(f"path escapes workspace: {relative}")
    return candidate


def _reject_symlinks(root: Path) -> None:
    if root.is_symlink():
        raise ValueError(f"symlink not allowed: {root}")
    seen_casefolded: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        folded = relative.casefold()
        if folded in seen_casefolded:
            raise ValueError(f"case-fold collision not allowed: {relative}")
        seen_casefolded.add(folded)
        if path.is_symlink():
            raise ValueError(f"symlink not allowed: {path}")
        info = path.lstat()
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError(f"special file not allowed: {path}")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError(f"hardlink not allowed: {path}")


def _set_read_only(path: Path) -> None:
    if path.is_dir():
        for child in path.rglob("*"):
            if child.is_dir():
                child.chmod(0o500)
            else:
                child.chmod(0o400)
        path.chmod(0o500)
    else:
        path.chmod(0o400)


def _make_tree_writable(path: Path) -> None:
    if not path.exists():
        return
    for child in path.rglob("*"):
        try:
            child.chmod(0o700 if child.is_dir() else 0o600)
        except OSError:
            pass
    try:
        path.chmod(0o700)
    except OSError:
        pass


def prepare_episode(
    spec: EpisodeSpec,
    *,
    repository_root: Path,
    episode_base: Path,
) -> PreparedEpisode:
    repository = repository_root.resolve()
    base = episode_base.resolve()
    if base == repository or base.is_relative_to(repository) or repository.is_relative_to(base):
        raise ValueError("episode base and repository must be disjoint")
    if spec.repetition < 1:
        raise ValueError("repetition must be positive")
    if not spec.task_path.is_file() or not spec.fixture_path.is_dir():
        raise ValueError("task and fixture must exist")
    _reject_symlinks(spec.fixture_path)
    if spec.task_path.is_symlink():
        raise ValueError("task symlink not allowed")

    base.mkdir(parents=True, exist_ok=True)
    workspace = Path(
        tempfile.mkdtemp(
            prefix=f"oab2-{spec.case_id}-r{spec.repetition}-",
            dir=str(base),
        )
    ).resolve()
    if workspace.is_relative_to(repository):
        shutil.rmtree(workspace)
        raise ValueError("allocated workspace is inside the repository")

    try:
        for source in spec.fixture_path.iterdir():
            destination = workspace / source.name
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
        shutil.copy2(spec.task_path, workspace / "task.md")
        for relative in ("submission", "home", "tmp"):
            (workspace / relative).mkdir(parents=True, exist_ok=True)

        if (workspace / "input").exists():
            _set_read_only(workspace / "input")
        _set_read_only(workspace / "task.md")
        if (workspace / "work").exists():
            _set_read_only(workspace / "work")

        writable_directories = tuple(
            _safe_relative(workspace, relative)
            for relative in spec.writable_relative_directories
        )
        writable_files = tuple(
            _safe_relative(workspace, relative)
            for relative in spec.writable_relative_files
        )
        for directory in writable_directories:
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)
        for writable_file in writable_files:
            writable_file.parent.mkdir(parents=True, exist_ok=True)
            writable_file.touch(exist_ok=True)
            writable_file.chmod(0o600)

        read_only = tuple(
            _safe_relative(workspace, relative)
            for relative in spec.readable_relative_paths
        ) + tuple(path.resolve() for path in spec.adapter_read_paths)
        for path in read_only:
            if not path.exists():
                raise ValueError(f"readable path does not exist: {path}")

        policy = SandboxPolicy(
            workspace=workspace,
            read_only=read_only,
            writable=writable_directories,
            writable_files=writable_files,
            allowed_executables=tuple(path.resolve() for path in spec.allowed_executables),
            network=spec.network,
        )
        return PreparedEpisode(workspace=workspace, policy=policy)
    except Exception:
        _make_tree_writable(workspace)
        shutil.rmtree(workspace, ignore_errors=True)
        raise


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extract_events(stdout: str) -> tuple[list[dict[str, object]], list[str]]:
    events: list[dict[str, object]] = []
    errors: list[str] = []
    for line_number, line in enumerate(stdout.splitlines(), start=1):
        if not line.startswith(_EVENT_PREFIX):
            continue
        try:
            event = json.loads(line[len(_EVENT_PREFIX) :])
        except (json.JSONDecodeError, RecursionError):
            errors.append(f"trace_json_invalid:{line_number}")
            continue
        if not isinstance(event, dict):
            errors.append(f"trace_event_not_object:{line_number}")
            continue
        events.append(event)
    if not events:
        errors.append("trace_missing")
    for expected_sequence, event in enumerate(events, start=1):
        if event.get("seq") != expected_sequence:
            errors.append(f"trace_sequence_invalid:{expected_sequence}")
        if not all(isinstance(event.get(key), str) for key in ("kind", "target", "outcome")):
            errors.append(f"trace_shape_invalid:{expected_sequence}")
    return events, errors


def _valid_runtime_identity(event: dict[str, object]) -> bool:
    detail = event.get("detail")
    return (
        event.get("kind") == "runtime_identity"
        and event.get("outcome") == "verified"
        and isinstance(event.get("target"), str)
        and bool(event.get("target"))
        and isinstance(detail, dict)
        and bool(detail.get("response_id"))
        and bool(detail.get("adapter_version"))
    )


def _run_boundary_probe(
    prepared: PreparedEpisode,
    *,
    repository_root: Path,
) -> dict[str, object]:
    workspace = prepared.workspace
    input_directory = workspace / "input"
    probe_code = f"""
import json
import os
import socket
import subprocess
from pathlib import Path

checks = {{}}
try:
    checks["allowed_read"] = Path({str(workspace / 'task.md')!r}).is_file()
except OSError:
    checks["allowed_read"] = False
try:
    temp_path = Path({str(workspace / 'tmp/boundary-write.txt')!r})
    temp_path.write_text("ok", encoding="utf-8")
    checks["allowed_write"] = temp_path.read_text(encoding="utf-8") == "ok"
    temp_path.unlink()
except OSError:
    checks["allowed_write"] = False
try:
    denied_path = Path({str(input_directory / '.oab-boundary-write')!r})
    denied_path.write_text("not-allowed", encoding="utf-8")
except (OSError, PermissionError):
    checks["input_write_denied"] = True
else:
    checks["input_write_denied"] = False
    denied_path.unlink(missing_ok=True)
try:
    os.listdir({str(repository_root.resolve())!r})
except (OSError, PermissionError):
    checks["repository_read_denied"] = True
else:
    checks["repository_read_denied"] = False
try:
    subprocess.run(["/bin/echo", "not-allowed"], check=True, capture_output=True)
except (OSError, PermissionError, subprocess.SubprocessError):
    checks["unlisted_executable_denied"] = True
else:
    checks["unlisted_executable_denied"] = False
try:
    sock = socket.socket()
    sock.settimeout(0.2)
    sock.connect(("127.0.0.1", 9))
except PermissionError:
    checks["network_denied"] = True
except OSError as exc:
    checks["network_denied"] = getattr(exc, "errno", None) in {{1, 13}}
else:
    checks["network_denied"] = False
finally:
    try:
        sock.close()
    except Exception:
        pass
print(json.dumps(checks, sort_keys=True))
""".lstrip()
    executable = Path(sys.executable).resolve()
    probe_policy = SandboxPolicy(
        workspace=workspace,
        read_only=prepared.policy.read_only,
        writable=prepared.policy.writable,
        writable_files=prepared.policy.writable_files,
        allowed_executables=(executable,),
        network=prepared.policy.network,
    )
    backend = select_backend()
    run = backend.run(
        probe_policy,
        [str(executable), "-I", "-c", probe_code],
        timeout_seconds=10,
    )
    try:
        checks = json.loads(run.stdout)
    except (json.JSONDecodeError, RecursionError):
        checks = {}
    if not isinstance(checks, dict) or not all(
        isinstance(key, str) and isinstance(value, bool)
        for key, value in checks.items()
    ):
        checks = {}
    required = {
        "allowed_read",
        "allowed_write",
        "input_write_denied",
        "repository_read_denied",
        "unlisted_executable_denied",
    }
    if not prepared.policy.network:
        required.add("network_denied")
    passed = (
        run.returncode == 0
        and not run.timed_out
        and required.issubset(checks)
        and all(checks.get(name) is True for name in required)
    )
    return {
        "passed": passed,
        "checks": checks,
        "required_checks": sorted(required),
        "returncode": run.returncode,
        "timed_out": run.timed_out,
        "stderr": run.stderr[-2000:],
        "sandbox_profile_sha256": run.profile_sha256,
    }


def run_episode(
    spec: EpisodeSpec,
    *,
    command: Sequence[str],
    repository_root: Path,
    episode_base: Path,
    output_dir: Path,
    timeout_seconds: float,
) -> EpisodeResult:
    if output_dir.exists():
        raise FileExistsError(f"trusted output already exists: {output_dir}")
    prepared = prepare_episode(
        spec,
        repository_root=repository_root,
        episode_base=episode_base,
    )
    boundary_probe = _run_boundary_probe(
        prepared,
        repository_root=repository_root,
    )
    output_dir.mkdir(parents=True)
    (output_dir / "boundary-probe.json").write_text(
        json.dumps(boundary_probe, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if boundary_probe.get("passed") is not True:
        _make_tree_writable(prepared.workspace)
        shutil.rmtree(prepared.workspace, ignore_errors=True)
        raise SandboxUnavailable("per-episode boundary probe failed")
    started = datetime.now(timezone.utc)
    try:
        backend = select_backend()
        run = backend.run(
            prepared.policy,
            command,
            timeout_seconds=timeout_seconds,
        )
        ended = datetime.now(timezone.utc)
        events, trace_errors = _extract_events(run.stdout)
        identities = [event for event in events if _valid_runtime_identity(event)]
        invalid_reasons = list(trace_errors)
        if len(identities) != 1:
            invalid_reasons.append("runtime_identity_missing")
        if run.timed_out:
            invalid_reasons.append("timeout")
        if run.returncode != 0:
            invalid_reasons.append("agent_process_failed")

        stdout_bytes = run.stdout.encode("utf-8")
        stderr_bytes = run.stderr.encode("utf-8")
        (output_dir / "stdout.txt").write_bytes(stdout_bytes)
        (output_dir / "stderr.txt").write_bytes(stderr_bytes)
        with (output_dir / "events.jsonl").open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        shutil.copytree(prepared.workspace, output_dir / "workspace")
        receipt = {
            "schema_version": 1,
            "case_id": spec.case_id,
            "repetition": spec.repetition,
            "started_at": started.isoformat(),
            "ended_at": ended.isoformat(),
            "duration_seconds": (ended - started).total_seconds(),
            "sandbox_backend": "sandbox-exec" if sys_platform() == "darwin" else "bubblewrap",
            "sandbox_profile_sha256": run.profile_sha256,
            "boundary_probe": boundary_probe,
            "network_policy": "allowed" if spec.network else "denied",
            "trace_provenance": "adapter_reported",
            "trace_completeness_claim": "process output plus adapter-reported events",
            "stdout_sha256": _sha256(stdout_bytes),
            "stderr_sha256": _sha256(stderr_bytes),
            "exit_code": run.returncode,
            "timed_out": run.timed_out,
            "valid_for_scoring": not invalid_reasons,
            "invalid_reasons": invalid_reasons,
            "command": list(run.command),
        }
        (output_dir / "process-receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return EpisodeResult(
            case_id=spec.case_id,
            repetition=spec.repetition,
            completed=not run.timed_out and run.returncode == 0,
            timed_out=run.timed_out,
            exit_code=run.returncode,
            valid_for_scoring=not invalid_reasons,
            invalid_reasons=tuple(dict.fromkeys(invalid_reasons)),
            output_dir=output_dir,
        )
    except SandboxUnavailable:
        raise
    finally:
        _make_tree_writable(prepared.workspace)
        shutil.rmtree(prepared.workspace, ignore_errors=True)


def sys_platform() -> str:
    import sys

    return sys.platform
