from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .manifest import (
    ManifestError,
    build_fixture_manifest,
    is_generated_python_cache_path,
)
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


def _directory_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _assert_path_bound_to_fd(path: Path, descriptor: int) -> os.stat_result:
    try:
        current = path.lstat()
    except OSError as exc:
        raise ManifestError("snapshot_source_changed") from exc
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(current.st_mode) or not _same_inode(current, opened):
        raise ManifestError("snapshot_source_changed")
    return opened


def _copy_snapshot_tree_fd(
    source_fd: int,
    destination_fd: int,
    relative_parent: str = "",
) -> None:
    source_before = os.fstat(source_fd)
    try:
        children = list(os.scandir(source_fd))
    except OSError as exc:
        raise ManifestError("snapshot_source_changed") from exc
    children.sort(key=lambda child: child.name)
    for child in children:
        relative = (
            f"{relative_parent}/{child.name}" if relative_parent else child.name
        )
        if is_generated_python_cache_path(relative):
            continue
        try:
            info = os.stat(
                child.name,
                dir_fd=source_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ManifestError("snapshot_source_changed") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ManifestError(f"symlink is not allowed: {relative}")
        if stat.S_ISDIR(info.st_mode):
            try:
                child_source_fd = os.open(
                    child.name,
                    _directory_open_flags(),
                    dir_fd=source_fd,
                )
            except OSError as exc:
                raise ManifestError("snapshot_source_changed") from exc
            try:
                if not _same_inode(info, os.fstat(child_source_fd)):
                    raise ManifestError("snapshot_source_changed")
                os.mkdir(child.name, 0o700, dir_fd=destination_fd)
                child_destination_fd = os.open(
                    child.name,
                    _directory_open_flags(),
                    dir_fd=destination_fd,
                )
                try:
                    _copy_snapshot_tree_fd(
                        child_source_fd,
                        child_destination_fd,
                        relative,
                    )
                finally:
                    os.close(child_destination_fd)
                current = os.stat(
                    child.name,
                    dir_fd=source_fd,
                    follow_symlinks=False,
                )
                if not _same_inode(current, info):
                    raise ManifestError("snapshot_source_changed")
            finally:
                os.close(child_source_fd)
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ManifestError(f"special file is not allowed: {relative}")
        if info.st_nlink != 1:
            raise ManifestError(f"hardlink is not allowed: {relative}")
        source_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            source_flags |= os.O_NOFOLLOW
        try:
            source_file_fd = os.open(
                child.name,
                source_flags,
                dir_fd=source_fd,
            )
        except OSError as exc:
            raise ManifestError("snapshot_source_changed") from exc
        destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            destination_flags |= os.O_NOFOLLOW
        try:
            opened_source = os.fstat(source_file_fd)
            if not _same_inode(opened_source, info) or opened_source.st_nlink != 1:
                raise ManifestError("snapshot_source_changed")
            destination_file_fd = os.open(
                child.name,
                destination_flags,
                0o600,
                dir_fd=destination_fd,
            )
            try:
                while True:
                    chunk = os.read(source_file_fd, 1024 * 1024)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        written = os.write(destination_file_fd, view)
                        view = view[written:]
            finally:
                os.close(destination_file_fd)
            closed_source = os.fstat(source_file_fd)
            if (
                not _same_inode(closed_source, opened_source)
                or closed_source.st_size != opened_source.st_size
                or closed_source.st_mtime_ns != opened_source.st_mtime_ns
                or closed_source.st_ctime_ns != opened_source.st_ctime_ns
                or closed_source.st_nlink != 1
            ):
                raise ManifestError("snapshot_source_changed")
        finally:
            os.close(source_file_fd)
    source_after = os.fstat(source_fd)
    if (
        not _same_inode(source_after, source_before)
        or source_after.st_mtime_ns != source_before.st_mtime_ns
        or source_after.st_ctime_ns != source_before.st_ctime_ns
    ):
        raise ManifestError("snapshot_source_changed")


def _remove_snapshot_tree_fd(directory_fd: int) -> None:
    os.fchmod(directory_fd, 0o700)
    for name in os.listdir(directory_fd):
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child_fd = os.open(
                name,
                _directory_open_flags(),
                dir_fd=directory_fd,
            )
            try:
                if not _same_inode(info, os.fstat(child_fd)):
                    raise ManifestError("snapshot_source_changed")
                _remove_snapshot_tree_fd(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)


def _cleanup_snapshot_name(
    parent_fd: int,
    name: str,
    owned_fd: int,
    owned_identity: os.stat_result,
) -> None:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if _same_inode(current, owned_identity) and stat.S_ISDIR(current.st_mode):
        _remove_snapshot_tree_fd(owned_fd)
        os.rmdir(name, dir_fd=parent_fd)
        return
    # The pathname no longer names the directory represented by owned_fd. It is
    # attacker-controlled for cleanup purposes: fail closed by leaving it untouched.
    return


def _canonical_manifest_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _snapshot_workspace(source: Path, destination: Path) -> None:
    max_files = 4096
    max_total_bytes = 256 * 1024 * 1024
    parent = destination.parent
    parent_info = parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
        raise ManifestError("snapshot_destination_parent_unsafe")
    parent_fd = os.open(parent, _directory_open_flags())
    source_fd = -1
    temporary_fd = -1
    temporary_name = f".{destination.name}.{secrets.token_hex(16)}"
    active_name = temporary_name
    try:
        _assert_path_bound_to_fd(parent, parent_fd)
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(f"workspace snapshot already exists: {destination}")

        source_info = source.lstat()
        if not stat.S_ISDIR(source_info.st_mode) or stat.S_ISLNK(source_info.st_mode):
            raise ManifestError("snapshot_source_changed")
        source_fd = os.open(source, _directory_open_flags())
        if not _same_inode(source_info, os.fstat(source_fd)):
            raise ManifestError("snapshot_source_changed")
        source_manifest = build_fixture_manifest(
            source,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
        )
        _assert_path_bound_to_fd(source, source_fd)

        os.mkdir(temporary_name, 0o700, dir_fd=parent_fd)
        temporary_fd = os.open(
            temporary_name,
            _directory_open_flags(),
            dir_fd=parent_fd,
        )
        temporary_identity = os.fstat(temporary_fd)
        _copy_snapshot_tree_fd(source_fd, temporary_fd)
        _assert_path_bound_to_fd(parent / temporary_name, temporary_fd)
        copied_manifest = build_fixture_manifest(
            parent / temporary_name,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
        )
        _assert_path_bound_to_fd(parent / temporary_name, temporary_fd)
        if _canonical_manifest_bytes(copied_manifest) != _canonical_manifest_bytes(
            source_manifest
        ):
            raise ManifestError("workspace_snapshot_mismatch")
        _assert_path_bound_to_fd(parent, parent_fd)
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(f"workspace snapshot already exists: {destination}")
        os.rename(
            temporary_name,
            destination.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        active_name = destination.name
        installed_info = os.stat(
            destination.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(installed_info.st_mode) or not _same_inode(
            installed_info, temporary_identity
        ):
            raise ManifestError("snapshot_source_changed")
        _assert_path_bound_to_fd(parent, parent_fd)
    except BaseException:
        if temporary_fd >= 0:
            _cleanup_snapshot_name(
                parent_fd,
                active_name,
                temporary_fd,
                os.fstat(temporary_fd),
            )
        raise
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if source_fd >= 0:
            os.close(source_fd)
        os.close(parent_fd)


def _copy_verified_fixture_contents(
    source: Path,
    destination: Path,
    expected_manifest: dict[str, object],
) -> None:
    """Copy a verified fixture through held descriptors into an existing workspace."""
    source_info = source.lstat()
    destination_info = destination.lstat()
    if (
        not stat.S_ISDIR(source_info.st_mode)
        or stat.S_ISLNK(source_info.st_mode)
        or not stat.S_ISDIR(destination_info.st_mode)
        or stat.S_ISLNK(destination_info.st_mode)
    ):
        raise ManifestError("snapshot_source_changed")
    source_fd = os.open(source, _directory_open_flags())
    destination_fd = os.open(destination, _directory_open_flags())
    try:
        if not _same_inode(source_info, os.fstat(source_fd)) or not _same_inode(
            destination_info, os.fstat(destination_fd)
        ):
            raise ManifestError("snapshot_source_changed")
        _copy_snapshot_tree_fd(source_fd, destination_fd)
        _assert_path_bound_to_fd(source, source_fd)
        _assert_path_bound_to_fd(destination, destination_fd)
        copied_manifest = build_fixture_manifest(destination)
        _assert_path_bound_to_fd(destination, destination_fd)
        if _canonical_manifest_bytes(copied_manifest) != _canonical_manifest_bytes(
            expected_manifest
        ):
            raise ManifestError("workspace_snapshot_mismatch")
    finally:
        os.close(destination_fd)
        os.close(source_fd)


def _copy_verified_regular_file(source: Path, destination: Path) -> None:
    """Copy one single-link regular file without following a substituted source."""
    source_parent_fd = os.open(source.parent, _directory_open_flags())
    destination_parent_fd = os.open(destination.parent, _directory_open_flags())
    source_fd = -1
    destination_fd = -1
    try:
        before = os.stat(source.name, dir_fd=source_parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ManifestError("snapshot_source_changed")
        source_fd = os.open(
            source.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=source_parent_fd,
        )
        opened_before = os.fstat(source_fd)
        if not _same_inode(before, opened_before) or opened_before.st_nlink != 1:
            raise ManifestError("snapshot_source_changed")
        destination_fd = os.open(
            destination.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=destination_parent_fd,
        )
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise ManifestError("snapshot_source_changed")
                view = view[written:]
        os.fsync(destination_fd)
        opened_after = os.fstat(source_fd)
        if (
            not _same_inode(opened_before, opened_after)
            or opened_before.st_size != opened_after.st_size
            or opened_before.st_mtime_ns != opened_after.st_mtime_ns
            or opened_before.st_ctime_ns != opened_after.st_ctime_ns
            or opened_after.st_nlink != 1
        ):
            raise ManifestError("snapshot_source_changed")
    except BaseException:
        try:
            os.unlink(destination.name, dir_fd=destination_parent_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if source_fd >= 0:
            os.close(source_fd)
        os.close(destination_parent_fd)
        os.close(source_parent_fd)


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
    fixture_manifest = build_fixture_manifest(spec.fixture_path)
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
        _copy_verified_fixture_contents(
            spec.fixture_path,
            workspace,
            fixture_manifest,
        )
        _copy_verified_regular_file(spec.task_path, workspace / "task.md")
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
        _snapshot_workspace(prepared.workspace, output_dir / "workspace")
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
