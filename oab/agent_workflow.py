from __future__ import annotations

import ctypes.util
import contextvars
import functools
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
import platform
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import urllib.parse
import urllib.request
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

_ACTIVE_CAMPAIGN_DIRECTORIES: contextvars.ContextVar[dict[Path, int] | None] = (
    contextvars.ContextVar("oab_active_campaign_directories", default=None)
)

_ALLOWED_EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh"}
_COST_CONTROL_MODE = "post_provider_call_observed_known_cost_stop"
_MAX_COST_OVERSHOOT_API_CALLS = 1

# v2.2.3 (legacy) qualification: 34 one-call episodes per route
_QUALIFICATION_REPETITIONS = 17
_QUALIFICATION_EPISODES_PER_ROUTE = 34
_QUALIFICATION_MAX_API_CALLS_PER_EPISODE = 1

# v2.3.0 (new) qualification: 2 deterministic probes with up to 4 steps per episode
_QUALIFICATION_V230_PROBES_PER_ROUTE = 2
_QUALIFICATION_V230_MAX_API_CALLS_PER_EPISODE = 4
_QUALIFICATION_V230_MAX_CALLS_PER_ROUTE = 16  # 2 probes × 4 calls + 1 retry per probe = 16

# Full-stage suite (unchanged)
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

LEGACY_V221_RELEASE_TREE_SHA256 = (
    "sha256:967445bec99f6df126ae5bbfd19cce47527f4cc50d78bd918ed8c339f8c99c68"
)


def _qualification_contract_version(
    release_tree_sha256: str | None,
    actual_episodes: int | None = None,
) -> str:
    """Determine qualification contract version based on release tree and actual episodes.

    Returns 'v2.2.3' for legacy contracts, 'v2.3.0' for new contracts.
    If actual_episodes is provided (from a report), use it as the tiebreaker.
    """
    if release_tree_sha256 == LEGACY_V221_RELEASE_TREE_SHA256:
        return "v2.2.3"
    # If we have an actual report with episodes, use that as tiebreaker
    if actual_episodes is not None:
        if actual_episodes == _QUALIFICATION_EPISODES_PER_ROUTE:  # 34
            return "v2.2.3"
        elif actual_episodes == _QUALIFICATION_V230_PROBES_PER_ROUTE:  # 2
            return "v2.3.0"
    # Default to v2.3.0 for new campaigns
    return "v2.3.0"


def _qualification_max_calls_per_route(contract_version: str) -> int:
    """Get max API calls per route for qualification based on contract version."""
    if contract_version == "v2.2.3":
        return _QUALIFICATION_EPISODES_PER_ROUTE  # 34
    return _QUALIFICATION_V230_MAX_CALLS_PER_ROUTE  # 16


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


def _validate_campaign_orchestration_metadata(
    payload: Mapping[str, object], *, required: bool = True
) -> dict[str, object] | None:
    has_verified = "campaign_suite_verified" in payload
    has_elapsed = "campaign_elapsed_seconds" in payload
    if not has_verified and not has_elapsed and not required:
        return None
    verified = payload.get("campaign_suite_verified")
    elapsed = payload.get("campaign_elapsed_seconds")
    if (
        not has_verified
        or not has_elapsed
        or verified is not True
        or not isinstance(elapsed, (int, float))
        or isinstance(elapsed, bool)
    ):
        raise ValueError("campaign_orchestration_metadata_invalid")
    try:
        elapsed_value = float(elapsed)
    except (OverflowError, ValueError):
        raise ValueError("campaign_orchestration_metadata_invalid") from None
    if not math.isfinite(elapsed_value) or elapsed_value < 0:
        raise ValueError("campaign_orchestration_metadata_invalid")
    return {
        "campaign_suite_verified": True,
        "campaign_elapsed_seconds": elapsed_value,
    }


def _normalize_campaign_result_report(
    result: Mapping[str, object],
    sealed_report: Mapping[str, object],
    *,
    campaign_release_tree_sha256: object,
) -> tuple[dict[str, object], dict[str, object]]:
    embedded = result.get("suite_report")
    if not isinstance(embedded, Mapping):
        raise ValueError("campaign_stage_result_report_mismatch")
    comparable = dict(embedded)
    keys = ("campaign_suite_verified", "campaign_elapsed_seconds")
    legacy_metadata = any(key in comparable for key in keys)
    top_level_metadata = any(key in result for key in keys)
    if legacy_metadata:
        if top_level_metadata:
            raise ValueError("campaign_orchestration_metadata_invalid")
        metadata = _validate_campaign_orchestration_metadata(comparable)
        if (
            comparable.get("release_tree_sha256") != LEGACY_V221_RELEASE_TREE_SHA256
            or campaign_release_tree_sha256 != LEGACY_V221_RELEASE_TREE_SHA256
        ):
            raise ValueError("campaign_legacy_receipt_release_invalid")
        for key in keys:
            comparable.pop(key, None)
    else:
        metadata = _validate_campaign_orchestration_metadata(result)
    assert metadata is not None
    if _canonical_bytes(comparable) != _canonical_bytes(dict(sealed_report)):
        raise ValueError("campaign_stage_result_report_mismatch")
    return dict(sealed_report), metadata


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


def _open_directory_fd(path: Path) -> int:
    absolute = path.expanduser().absolute()
    if (
        sys.platform == "darwin"
        and len(absolute.parts) > 1
        and absolute.parts[1] in {"etc", "tmp", "var"}
    ):
        absolute = Path("/private").joinpath(*absolute.parts[1:])
    if not absolute.is_absolute() or any(part == ".." for part in absolute.parts):
        raise ValueError("campaign_internal_path_unsafe")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    active = _ACTIVE_CAMPAIGN_DIRECTORIES.get()
    descriptor = -1
    remaining_parts = absolute.parts[1:]
    if active:
        candidates: list[tuple[int, Path, int]] = []
        for base, base_fd in active.items():
            try:
                relative = absolute.relative_to(base)
            except ValueError:
                continue
            candidates.append((len(base.parts), relative, base_fd))
        if candidates:
            _, relative, base_fd = max(candidates, key=lambda candidate: candidate[0])
            descriptor = os.dup(base_fd)
            remaining_parts = relative.parts
    if descriptor < 0:
        descriptor = os.open(absolute.anchor, flags)
    try:
        for part in remaining_parts:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise ValueError("campaign_internal_path_unsafe")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _atomic_bytes(path: Path, payload: bytes) -> None:
    if _ACTIVE_CAMPAIGN_DIRECTORIES.get() is None:
        path.parent.mkdir(parents=True, exist_ok=True)
    try:
        parent_fd = _open_directory_fd(path.parent)
    except OSError as exc:
        raise ValueError("campaign_internal_path_unsafe") from exc
    temporary_name = f".{path.name}.{secrets.token_hex(16)}"
    temporary_fd = -1
    try:
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        view = memoryview(payload)
        while view:
            written = os.write(temporary_fd, view)
            if written <= 0:
                raise OSError("short atomic write")
            view = view[written:]
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    except OSError as exc:
        raise ValueError("campaign_internal_path_unsafe") from exc
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _atomic_json(path: Path, payload: Mapping[str, object]) -> None:
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        + "\n"
    ).encode("utf-8")
    _atomic_bytes(path, encoded)


def _read_single_link_regular_bytes(
    path: Path, *, error: str, max_bytes: int = 1024 * 1024
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = -1
    if path.name in {"", ".", ".."} or "/" in path.name or "\\" in path.name:
        raise ValueError(error)
    try:
        parent_fd = _open_directory_fd(path.parent)
        descriptor = os.open(path.name, flags, dir_fd=parent_fd)
    except (OSError, ValueError) as exc:
        if parent_fd >= 0:
            os.close(parent_fd)
        raise ValueError(error) from exc
    os.close(parent_fd)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > max_bytes:
            raise ValueError(error)
        identity = (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
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
        final_info = os.fstat(descriptor)
        if identity != (
            final_info.st_dev,
            final_info.st_ino,
            final_info.st_mode,
            final_info.st_nlink,
            final_info.st_size,
            final_info.st_mtime_ns,
            final_info.st_ctime_ns,
        ):
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


def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_regular_json_at(directory_fd: int, name: str) -> dict[str, Any]:
    if not name or name != Path(name).name or name in {".", ".."}:
        raise ValueError("campaign_state_file_unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise ValueError("campaign_state_file_unsafe") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > 1024 * 1024
        ):
            raise ValueError("campaign_state_file_unsafe")
        chunks: list[bytes] = []
        remaining = 1024 * 1024 + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > 1024 * 1024 or _stat_identity(os.fstat(descriptor)) != _stat_identity(before):
            raise ValueError("campaign_state_file_unsafe")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("campaign_state_invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("campaign_state_invalid")
    return value


def _read_json_directory_fd(
    directory_fd: int, *, suffix: str
) -> list[tuple[str, dict[str, Any]]]:
    before = _stat_identity(os.fstat(directory_fd))
    names = sorted(name for name in os.listdir(directory_fd) if name.endswith(suffix))
    values = [(name, _read_regular_json_at(directory_fd, name)) for name in names]
    if _stat_identity(os.fstat(directory_fd)) != before:
        raise ValueError("campaign_internal_path_unsafe")
    return values


_CAMPAIGN_INTERNAL_DIRECTORIES = (
    Path("APPROVALS"),
    Path("qualification"),
    Path("qualification/results"),
    Path("qualification/suites"),
    Path("qualification/attempts"),
    Path("full"),
    Path("full/results"),
    Path("full/suites"),
    Path("full/attempts"),
)


def _open_campaign_directory_fd(root: Path, relative: Path, *, create: bool) -> int:
    """Open and return a campaign directory descriptor without following links."""
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("campaign_internal_path_unsafe")
    if _ACTIVE_CAMPAIGN_DIRECTORIES.get() is not None:
        try:
            return _open_directory_fd(root / relative)
        except (OSError, ValueError) as exc:
            raise ValueError("campaign_internal_path_unsafe") from exc
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = _open_directory_fd(root)
    except (OSError, ValueError) as exc:
        raise ValueError("campaign_internal_path_unsafe") from exc
    try:
        root_info = os.fstat(descriptor)
        if not stat.S_ISDIR(root_info.st_mode):
            raise ValueError("campaign_internal_path_unsafe")
        for part in relative.parts:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise ValueError("campaign_internal_path_unsafe") from exc
            try:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError as exc:
                raise ValueError("campaign_internal_path_unsafe") from exc
            except OSError as exc:
                raise ValueError("campaign_internal_path_unsafe") from exc
            os.close(descriptor)
            descriptor = next_descriptor
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("campaign_internal_path_unsafe")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _trusted_campaign_root(root: Path) -> Path:
    """Bind a caller-supplied lexical campaign root without following a final link."""
    lexical_root = root.expanduser().absolute()
    try:
        root_info = os.lstat(lexical_root)
        checked_root = lexical_root.resolve(strict=True)
    except OSError as exc:
        raise ValueError("campaign_internal_path_unsafe") from exc
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise ValueError("campaign_internal_path_unsafe")
    return checked_root


def _validate_campaign_layout(root: Path, *, create: bool = False) -> None:
    """Reject link-mediated campaign parents and optionally create all trusted parents."""
    checked_root = _trusted_campaign_root(root)
    for relative in _CAMPAIGN_INTERNAL_DIRECTORIES:
        descriptor = _open_campaign_directory_fd(
            checked_root, relative, create=create
        )
        os.close(descriptor)


def _campaign_operation(function: Any) -> Any:
    """Retain trusted campaign-directory descriptors for one complete operation."""

    @functools.wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if args:
            supplied_root = Path(args[0])
        elif "output_root" in kwargs:
            supplied_root = Path(kwargs["output_root"])
        else:
            raise TypeError("campaign operation requires output_root")
        if _ACTIVE_CAMPAIGN_DIRECTORIES.get() is not None:
            return function(*args, **kwargs)
        checked_root = _trusted_campaign_root(supplied_root)
        descriptors: dict[Path, int] = {}
        token: contextvars.Token[dict[Path, int] | None] | None = None
        try:
            descriptors[checked_root] = _open_directory_fd(checked_root)
            token = _ACTIVE_CAMPAIGN_DIRECTORIES.set(descriptors)
            for relative in _CAMPAIGN_INTERNAL_DIRECTORIES:
                descriptors[checked_root / relative] = _open_campaign_directory_fd(
                    checked_root, relative, create=False
                )
            if args:
                return function(checked_root, *args[1:], **kwargs)
            bound_kwargs = dict(kwargs)
            bound_kwargs["output_root"] = checked_root
            return function(**bound_kwargs)
        finally:
            if token is not None:
                _ACTIVE_CAMPAIGN_DIRECTORIES.reset(token)
            for descriptor in descriptors.values():
                os.close(descriptor)

    return wrapped


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


def _bounded_hermes_exec_target(executable_text: str) -> Path | None:
    """Parse one inert shell wrapper whose only action is an absolute exec."""
    target: Path | None = None
    for raw_line in executable_text.splitlines()[1:]:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            words = shlex.split(line)
        except ValueError:
            return None
        if target is None and words[:1] == ["unset"]:
            variables = words[1:]
            if variables and set(variables) <= {"PYTHONPATH", "PYTHONHOME"}:
                continue
            return None
        if target is None and len(words) == 3 and words[0] == "exec" and words[2] == "$@":
            candidate = Path(words[1])
            if not candidate.is_absolute():
                return None
            target = candidate
            continue
        return None
    return target


def _is_single_link_regular_path(path: Path) -> bool:
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd = _open_directory_fd(path.parent)
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        before = _stat_identity(os.fstat(descriptor))
        info = os.fstat(descriptor)
        return (
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and _stat_identity(os.fstat(descriptor)) == before
        )
    except (OSError, ValueError):
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _trusted_hermes_sibling_python(path: Path, executable: Path) -> Path | None:
    """Resolve only the bounded venv-python link chain into Hermes' pinned runtime."""
    if _is_single_link_regular_path(path):
        return path
    expected_root = executable.parents[2] / ".hermes-runtime" / "python"
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(expected_root)
    except (OSError, ValueError):
        return None
    return path if _is_single_link_regular_path(resolved) else None


def _hermes_python_command_from_path(
    executable: Path, *, allow_exec_wrapper: bool
) -> list[str] | None:
    try:
        executable_bytes = _read_single_link_regular_bytes(
            executable,
            error="hermes_executable_unsafe",
            max_bytes=4096,
        )
        executable_text = executable_bytes.decode("utf-8")
        shebang = executable_text.splitlines()[0]
    except (ValueError, UnicodeDecodeError, IndexError):
        return None
    if not shebang.startswith("#!"):
        return None
    try:
        words = shlex.split(shebang[2:].strip())
    except ValueError:
        return None
    if not words:
        return None
    interpreter = Path(words[0])
    if interpreter.name == "env":
        env_program = next((word for word in words[1:] if not word.startswith("-")), "")
        env_program_name = Path(env_program).name
        sibling = executable.parent / "python"
        trusted_sibling = _trusted_hermes_sibling_python(sibling, executable)
        if env_program_name in {"python", "python3"} and trusted_sibling is not None:
            return [str(trusted_sibling)]
        if allow_exec_wrapper and env_program_name in {"sh", "bash", "dash", "zsh"}:
            target = _bounded_hermes_exec_target(executable_text)
            if target is not None:
                return _hermes_python_command_from_path(target, allow_exec_wrapper=False)
        return None
    if interpreter.name in {"sh", "bash", "dash", "zsh"}:
        for name in ("python3", "python"):
            sibling = executable.parent / name
            trusted_sibling = _trusted_hermes_sibling_python(sibling, executable)
            if "hermes_cli" in executable_text and trusted_sibling is not None:
                return [str(trusted_sibling)]
        if allow_exec_wrapper:
            target = _bounded_hermes_exec_target(executable_text)
            if target is not None:
                return _hermes_python_command_from_path(target, allow_exec_wrapper=False)
        return None
    return words if _is_single_link_regular_path(interpreter) else None


def _hermes_python_command(hermes_path: str | None) -> list[str] | None:
    if not hermes_path:
        return None
    return _hermes_python_command_from_path(
        Path(hermes_path).expanduser(), allow_exec_wrapper=True
    )


def _hermes_inventory_bridge_available(hermes_path: str | None) -> bool:
    command = _hermes_python_command(hermes_path)
    if command is None:
        return False
    try:
        completed = subprocess.run(
            [*command, "-c", "import hermes_cli.inventory"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _load_inventory_via_hermes_python(hermes_path: str | None) -> dict[str, object]:
    command = _hermes_python_command(hermes_path)
    if command is None:
        raise RuntimeError("hermes_inventory_unavailable")
    bridge = """
import json
from hermes_cli.inventory import build_models_payload, load_picker_context
payload = build_models_payload(
    load_picker_context(),
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
print(json.dumps(payload, ensure_ascii=False, allow_nan=False))
"""
    try:
        completed = subprocess.run(
            [*command, "-c", bridge],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("hermes_inventory_unavailable") from exc
    if completed.returncode != 0 or len(completed.stdout) > 2_000_000:
        raise RuntimeError("hermes_inventory_unavailable")
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("hermes_inventory_invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("hermes_inventory_invalid")
    return payload


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
            if context_loader is None and payload_builder is None:
                return _load_inventory_via_hermes_python(shutil.which("hermes"))
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
            try:
                manifest_module = importlib.import_module("oab_tools.release_manifest")
            except ModuleNotFoundError:
                manifest_module = importlib.import_module("tools.release_manifest")
            release_manifest_errors = manifest_module.verify_release_manifest(
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
            if not inventory_available:
                inventory_available = _hermes_inventory_bridge_available(hermes_path)
        add(
            "hermes_inventory",
            bool(inventory_available),
            (
                "available"
                if inventory_available
                else "unavailable from this Python environment and Hermes executable"
            ),
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
    qualification_per_route = _QUALIFICATION_V230_PROBES_PER_ROUTE
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
            "repetitions": _QUALIFICATION_V230_PROBES_PER_ROUTE,
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
    """Classify qualification results for route readiness.

    Supports both:
    - v2.2.3 (legacy): 34 one-call episodes per route, emits scoreable
    - v2.3.0: 2 deterministic probes with up to 4 steps, never emits scoreable
    """
    try:
        orchestration_metadata = _validate_campaign_orchestration_metadata(report)
    except ValueError:
        orchestration_metadata = None
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
        else observed_cost  # If known_cost_usd not provided, use total cost_usd if available, else None
    )
    raw_unknown_calls = usage_map.get("unknown_cost_api_calls")
    unknown_cost_api_calls = (
        raw_unknown_calls
        if isinstance(raw_unknown_calls, int)
        and not isinstance(raw_unknown_calls, bool)
        and raw_unknown_calls >= 0
        else (0 if observed_cost is not None else None)
    )
    observed_duration = (
        orchestration_metadata["campaign_elapsed_seconds"]
        if orchestration_metadata is not None
        else None
    )

    # Detect contract version by episode count
    scheduled = report.get("scheduled_episodes")
    is_v230_contract = scheduled == _QUALIFICATION_V230_PROBES_PER_ROUTE

    base: dict[str, object] = {
        "requested_route": requested_route,
        "status": "infrastructure_invalid",
        "reason_codes": sorted(reasons),
        "observed_cost_usd": observed_cost,
        "observed_known_cost_usd": observed_known_cost,
        "unknown_cost_api_calls": unknown_cost_api_calls,
        "observed_duration_seconds": observed_duration,
        "identity_source": report.get("identity_source"),
        "controller_config_sha256": report.get("controller_config_sha256"),
    }

    # Only add scoreable field for legacy v2.2.3 contracts
    if not is_v230_contract:
        base["scoreable"] = False

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
    if orchestration_metadata is None:
        base["status"] = "qualification_contract_invalid"
        return base

    valid = report.get("infrastructure_valid_episodes")
    invalid = report.get("infrastructure_invalid_episodes")
    observed_api_calls = usage_map.get("api_calls")

    # v2.3.0 contract: 2 probes, expect 2 scheduled and valid
    if is_v230_contract:
        # Check for agent_loop_incompatible: both probes failed with controller_step_limit_exceeded
        if (valid == 0 and invalid == _QUALIFICATION_V230_PROBES_PER_ROUTE and
            all("controller_step_limit_exceeded" in obs.get("reason_codes", [])
                for obs in (report.get("observations") or []))):
            base["status"] = "agent_loop_incompatible"
            return base
        # Otherwise treat infrastructure failures normally
        if valid != _QUALIFICATION_V230_PROBES_PER_ROUTE or invalid != 0:
            base["status"] = "qualification_contract_invalid"
            return base
        # v2.3.0: validate api_calls are reasonable (at least 2 per probe minimum)
        if isinstance(observed_api_calls, int) and observed_api_calls < 4:
            base["status"] = "qualification_contract_invalid"
            return base
    # v2.2.3 contract (legacy): 34 episodes, expect 34 scheduled and valid
    else:
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
    # Only set authority_eligible for legacy contracts; v2.3.0 has no authority concept in qualification
    if not is_v230_contract:
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
    _validate_campaign_layout(root, create=True)
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


@_campaign_operation
def load_campaign(output_root: Path, *, expected_reasoning_effort: str | None = None) -> dict[str, Any]:
    root = _trusted_campaign_root(output_root)
    _validate_campaign_layout(root)
    state = _read_regular_json(root / "CAMPAIGN.json")
    if state.get("schema") != "oab.campaign/v1":
        raise ValueError("campaign_schema_invalid")
    if expected_reasoning_effort is not None and state.get("reasoning_effort") != expected_reasoning_effort:
        raise ValueError("campaign_reasoning_effort_mismatch")
    return state


@_campaign_operation
def record_calibration(output_root: Path, report: Mapping[str, object]) -> dict[str, Any]:
    root = _trusted_campaign_root(output_root)
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


def _attempt_event_path(root: Path, stage: str, attempt_id: str, event: str) -> Path:
    return root / stage / "attempts" / f"{attempt_id}.{event}.json"


def _attempt_evidence_path(root: Path, stage: str, attempt_id: str) -> Path:
    return root / stage / "attempts" / f"{attempt_id}.evidence"


def _write_attempt_event(
    root: Path,
    stage: str,
    attempt_id: str,
    event: str,
    body: Mapping[str, object],
) -> dict[str, object]:
    if stage not in {"qualification", "full"} or event not in {
        "reserved",
        "completed",
        "failed",
    }:
        raise ValueError("campaign_attempt_event_invalid")
    receipt: dict[str, object] = {
        "schema": "oab.campaign-attempt/v1",
        "created_at": _utc_now(),
        "stage": stage,
        "attempt_id": attempt_id,
        "event": event,
        **dict(body),
    }
    receipt["receipt_sha256"] = _canonical_sha256(receipt)
    _atomic_json(_attempt_event_path(root, stage, attempt_id, event), receipt)
    return receipt


def _attempt_accounting(
    root: Path,
    stage: str,
    results: Mapping[str, Mapping[str, object]],
    *,
    require_ledger: bool,
) -> dict[str, object]:
    events: dict[str, dict[str, dict[str, Any]]] = {}
    attempts_fd = _open_campaign_directory_fd(
        root, Path(stage) / "attempts", create=False
    )
    try:
        attempt_events = _read_json_directory_fd(attempts_fd, suffix=".json")
    finally:
        os.close(attempts_fd)
    for event_name_on_disk, event in attempt_events:
        receipt_sha256 = event.get("receipt_sha256")
        unsigned = dict(event)
        unsigned.pop("receipt_sha256", None)
        attempt_id = event.get("attempt_id")
        event_name = event.get("event")
        if (
            event.get("schema") != "oab.campaign-attempt/v1"
            or event.get("stage") != stage
            or not isinstance(attempt_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None
            or event_name not in {"reserved", "completed", "failed"}
            or event_name_on_disk != f"{attempt_id}.{event_name}.json"
            or receipt_sha256 != _canonical_sha256(unsigned)
        ):
            raise ValueError("campaign_attempt_ledger_invalid")
        by_event = events.setdefault(attempt_id, {})
        if str(event_name) in by_event:
            raise ValueError("campaign_attempt_ledger_invalid")
        by_event[str(event_name)] = event

    result_by_attempt: dict[str, Mapping[str, object]] = {}
    unbound_results = 0
    for result in results.values():
        attempt_id = result.get("attempt_id")
        if not isinstance(attempt_id, str) or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None:
            unbound_results += 1
            continue
        if attempt_id in result_by_attempt:
            raise ValueError("campaign_attempt_ledger_invalid")
        result_by_attempt[attempt_id] = result
    if unbound_results and (require_ledger or events):
        raise ValueError("campaign_attempt_ledger_invalid")
    if require_ledger and results and not events:
        raise ValueError("campaign_attempt_ledger_invalid")
    approval_digests: set[str] = set()
    approvals_fd = _open_campaign_directory_fd(root, Path("APPROVALS"), create=False)
    try:
        approvals = _read_json_directory_fd(approvals_fd, suffix=".json")
    finally:
        os.close(approvals_fd)
    for _approval_name, approval in approvals:
        approval_digest = approval.get("receipt_sha256")
        unsigned_approval = dict(approval)
        unsigned_approval.pop("receipt_sha256", None)
        if (
            approval.get("schema") != "oab.stage-approval/v4"
            or not isinstance(approval_digest, str)
            or approval_digest != _canonical_sha256(unsigned_approval)
        ):
            raise ValueError("campaign_attempt_approval_invalid")
        approval_digests.add(approval_digest)
    if set(result_by_attempt) - set(events):
        raise ValueError("campaign_attempt_ledger_invalid")
    failed_reserved_calls = 0
    failed_attempts = 0
    open_attempt_ids_by_route: dict[str, list[str]] = {}
    for attempt_id, by_event in events.items():
        reservation = by_event.get("reserved")
        if reservation is None or (
            "completed" in by_event and "failed" in by_event
        ):
            raise ValueError("campaign_attempt_ledger_invalid")
        route_id = reservation.get("route_id")
        reserved_calls = reservation.get("reserved_api_calls")
        approval_sha256 = reservation.get("approval_sha256")
        if (
            not isinstance(route_id, str)
            or not route_id
            or not isinstance(reserved_calls, int)
            or isinstance(reserved_calls, bool)
            or reserved_calls < 1
            or not isinstance(approval_sha256, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", approval_sha256) is None
            or approval_sha256 not in approval_digests
        ):
            raise ValueError("campaign_attempt_ledger_invalid")
        result = result_by_attempt.get(attempt_id)
        completion = by_event.get("completed")
        if completion is not None:
            if (
                result is None
                or completion.get("reservation_sha256") != reservation.get("receipt_sha256")
                or completion.get("result_receipt_sha256") != result.get("receipt_sha256")
            ):
                raise ValueError("campaign_attempt_ledger_invalid")
        if result is not None:
            if completion is None or result.get("route_id") != route_id:
                raise ValueError("campaign_attempt_ledger_invalid")
            continue
        failure = by_event.get("failed")
        if failure is not None and failure.get("reservation_sha256") != reservation.get(
            "receipt_sha256"
        ):
            raise ValueError("campaign_attempt_ledger_invalid")
        failed_reserved_calls += reserved_calls
        failed_attempts += 1
        open_attempt_ids_by_route.setdefault(route_id, []).append(attempt_id)
    return {
        "failed_reserved_api_calls": failed_reserved_calls,
        "failed_attempts": failed_attempts,
        "unknown_cost_encountered": failed_attempts > 0,
        "open_attempt_ids_by_route": open_attempt_ids_by_route,
    }


def _require_monotonic_attempt_accounting(
    state: Mapping[str, object],
    *,
    reserved_key: str,
    attempts_key: str,
    failed_reserved_calls: int,
    failed_attempts: int,
) -> None:
    spend = state.get("spend")
    spend_state = spend if isinstance(spend, Mapping) else {}
    previous_reserved = spend_state.get(reserved_key, 0)
    previous_attempts = spend_state.get(attempts_key, 0)
    if (
        not isinstance(previous_reserved, int)
        or isinstance(previous_reserved, bool)
        or previous_reserved < 0
        or not isinstance(previous_attempts, int)
        or isinstance(previous_attempts, bool)
        or previous_attempts < 0
        or failed_reserved_calls < previous_reserved
        or failed_attempts < previous_attempts
    ):
        raise ValueError("campaign_attempt_ledger_invalid")


def _quarantine_partial_suite(
    root: Path, stage: str, route_id: str, attempt_id: str
) -> str | None:
    """Return attempt-owned evidence in place; never rename a pathname after validation."""
    evidence = _attempt_evidence_path(root, stage, attempt_id)
    try:
        info = os.lstat(evidence)
    except FileNotFoundError:
        legacy_suite = root / stage / "suites" / route_id
        if legacy_suite.exists() or legacy_suite.is_symlink():
            raise ValueError("campaign_partial_suite_unsafe")
        return None
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError("campaign_partial_suite_unsafe")
    return str(evidence)


def _recover_preexisting_partial_suite(
    root: Path,
    stage: str,
    route_id: str,
    attempt_accounting: Mapping[str, object],
) -> None:
    del attempt_accounting
    legacy_suite = root / stage / "suites" / route_id
    if legacy_suite.exists() or legacy_suite.is_symlink():
        # Historical fixed-name partial outputs cannot be moved safely under an
        # adversarial same-user rename race. Preserve them in place and stop.
        raise ValueError("campaign_unledgered_partial_suite")


def _safe_attempt_failure_code(exc: BaseException) -> str:
    rendered = str(exc)
    if re.fullmatch(r"campaign_[a-z0-9_]+", rendered):
        return rendered
    return f"campaign_runner_{type(exc).__name__.lower()}"


def _stage_result_receipt(
    body: Mapping[str, object], report: Mapping[str, object]
) -> dict[str, object]:
    receipt = dict(body)
    suite_report = dict(report)
    orchestration_metadata = _validate_campaign_orchestration_metadata(suite_report)
    assert orchestration_metadata is not None
    suite_report.pop("campaign_suite_verified")
    suite_report.pop("campaign_elapsed_seconds")
    receipt.update(orchestration_metadata)
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
    campaign_release_tree_sha256: object,
) -> dict[str, dict[str, Any]]:
    selected_route_ids = {str(route.get("route_id") or "") for route in routes}
    results_fd = _open_campaign_directory_fd(
        root, Path(stage) / "results", create=False
    )
    try:
        result_entries = _read_json_directory_fd(results_fd, suffix=".json")
    finally:
        os.close(results_fd)
    result_payloads = {name: payload for name, payload in result_entries}
    existing_route_ids = {Path(name).stem for name in result_payloads}
    if not existing_route_ids.issubset(selected_route_ids):
        # A resumed stage may not narrow its route scope around already-billed
        # completed attempts. Doing so would omit those calls from accounting.
        raise ValueError("campaign_stage_result_scope_mismatch")
    results: dict[str, dict[str, Any]] = {}
    for route in routes:
        route_id = str(route.get("route_id") or "")
        result_name = f"{route_id}.json"
        if result_name in result_payloads:
            result = result_payloads[result_name]
            if result.get("route_id") != route_id or result.get("requested_route") != route.get("requested_route"):
                raise ValueError("campaign_stage_result_route_mismatch")
            receipt_sha256 = result.get("receipt_sha256")
            unsigned = dict(result)
            unsigned.pop("receipt_sha256", None)
            if receipt_sha256 != _canonical_sha256(unsigned):
                raise ValueError("campaign_stage_result_receipt_digest_mismatch")
            embedded_report = result.get("suite_report")
            if not isinstance(embedded_report, Mapping) or result.get(
                "suite_report_sha256"
            ) != _canonical_sha256(embedded_report):
                raise ValueError("campaign_stage_result_report_digest_mismatch")
            attempt_id = result.get("attempt_id")
            if (
                isinstance(attempt_id, str)
                and re.fullmatch(r"[0-9a-f]{32}", attempt_id) is not None
            ):
                expected_suite_output = str(
                    _attempt_evidence_path(root, stage, attempt_id)
                )
            elif campaign_release_tree_sha256 == LEGACY_V221_RELEASE_TREE_SHA256:
                expected_suite_output = str(root / stage / "suites" / route_id)
            else:
                raise ValueError("campaign_attempt_ledger_invalid")
            if result.get("suite_output") != expected_suite_output:
                raise ValueError("campaign_stage_result_output_mismatch")
            sealed_report = _read_regular_json(
                Path(expected_suite_output) / "suite-report.json"
            )
            suite_report, orchestration_metadata = _normalize_campaign_result_report(
                result,
                sealed_report,
                campaign_release_tree_sha256=campaign_release_tree_sha256,
            )
            normalized_result = dict(result)
            normalized_result["suite_report"] = suite_report
            normalized_result.update(orchestration_metadata)
            if stage == "qualification":
                classification_report = dict(suite_report)
                classification_report.update(orchestration_metadata)
                expected_classification = classify_qualification(
                    classification_report,
                    requested_route=str(route.get("requested_route") or ""),
                    reasoning_effort=reasoning_effort,
                )
                expected_classification["observed_api_calls"] = _api_calls_from_report(
                    suite_report
                )
                actual_classification = result.get("classification")
                if not isinstance(actual_classification, Mapping) or _canonical_sha256(
                    actual_classification
                ) != _canonical_sha256(expected_classification):
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
                actual_fields = {key: result.get(key) for key in expected_fields}
                if _canonical_sha256(actual_fields) != _canonical_sha256(expected_fields):
                    raise ValueError("campaign_stage_result_recomputation_mismatch")
            else:
                raise ValueError("campaign_stage_invalid")
            results[route_id] = normalized_result
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


@_campaign_operation
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
    root = _trusted_campaign_root(output_root)
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
    if stage == "qualification":
        # v2.3.0 plumbing contract: two probes, up to four steps each.
        # Absolute signed reserve is 16 calls/route (one infrastructure retry/probe).
        calls_per_episode = _QUALIFICATION_V230_MAX_API_CALLS_PER_EPISODE
        first_attempt_calls_per_route = (
            _QUALIFICATION_V230_PROBES_PER_ROUTE
            * _QUALIFICATION_V230_MAX_API_CALLS_PER_EPISODE
        )
        absolute_calls_per_route = _QUALIFICATION_V230_MAX_CALLS_PER_ROUTE
        minimum_calls = first_attempt_calls_per_route * len(routes)
        absolute_calls = absolute_calls_per_route * len(routes)
        purpose = (
            "Plumbing-only route readiness: bounded multi-turn tool loops. "
            "No model-quality score is produced."
        )
    else:
        calls_per_episode = _FULL_MAX_API_CALLS_PER_EPISODE
        first_attempt_calls_per_route = episodes_per_route * calls_per_episode
        absolute_calls_per_route = first_attempt_calls_per_route
        minimum_calls = scheduled_episodes * calls_per_episode
        absolute_calls = minimum_calls
        purpose = "Full 80-episode quality comparison per route."
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
        "stage_purpose": purpose,
        "observed_cost_stop_usd": budget,
        "cost_control_mode": _COST_CONTROL_MODE,
        "max_cost_overshoot_api_calls": _MAX_COST_OVERSHOOT_API_CALLS,
        "max_api_calls": call_budget,
        "minimum_required_api_calls": minimum_calls,
        "absolute_reserved_api_calls": absolute_calls,
        "first_attempt_api_calls_per_route": first_attempt_calls_per_route,
        "absolute_api_calls_per_route": absolute_calls_per_route,
        "max_api_calls_per_episode": calls_per_episode,
        "call_ceiling_sufficient": call_budget >= absolute_calls,
        "max_routes": route_cap,
        "allow_unknown_costs": bool(allow_unknown_costs),
        "intended_evidence_posture": "exploratory_by_default",
        "authority_note": (
            "Spend approval is independent of evidence authority. Authority also requires "
            "an exact-tree release approval and all identity, coverage, grid, and runtime gates."
        ),
        "provider_calls_performed": 0,
    }


@_campaign_operation
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
    root = _trusted_campaign_root(output_root)
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


CONVERSATIONAL_STAGE_APPROVAL_SCHEMA = "oab.conversational-stage-approval/v2"

# No host-backed verifier exists for a conversational approval: nothing in this
# repository or in an installed Hermes can prove that a caller-supplied message
# reference names a real message whose content approves these exact controls. A
# caller can therefore forge any such reference, so conversational receipts are
# refused for every spend-capable path. `approval-preview` stays conversational
# and no-spend; actual execution requires the externally signed stage approval.
CONVERSATION_APPROVAL_NOT_HOST_VERIFIED = "conversation_approval_not_host_verified"


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
    if receipt.get("schema") == CONVERSATIONAL_STAGE_APPROVAL_SCHEMA:
        # A caller-asserted conversation reference is not host-verified evidence of
        # approval, so it can never authorize spend. Fail closed before any route runs.
        raise ValueError(
            f"{CONVERSATION_APPROVAL_NOT_HOST_VERIFIED}:"
            "signed_stage_approval_required"
        )
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


@_campaign_operation
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
    root = _trusted_campaign_root(output_root)
    _validate_campaign_layout(root, create=True)
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
    campaign_release_tree_sha256 = plan.get("release_tree_sha256")
    results = _load_stage_results(
        root,
        "qualification",
        routes,
        reasoning_effort=effort,
        campaign_release_tree_sha256=campaign_release_tree_sha256,
    )
    # Detect contract version by checking existing results for episode count
    actual_episodes = None
    for result in results.values():
        if isinstance(result.get("report"), Mapping):
            report = result["report"]
            actual = report.get("scheduled_episodes")
            if isinstance(actual, int):
                actual_episodes = actual
                break
        # Also check classification for observed_api_calls as a tiebreaker
        if actual_episodes is None and isinstance(result.get("classification"), Mapping):
            observed_calls = result["classification"].get("observed_api_calls")
            if observed_calls == _QUALIFICATION_EPISODES_PER_ROUTE:  # 34
                actual_episodes = _QUALIFICATION_EPISODES_PER_ROUTE
                break
            elif observed_calls == _QUALIFICATION_V230_PROBES_PER_ROUTE * _QUALIFICATION_V230_MAX_API_CALLS_PER_EPISODE:  # 2*4=8
                actual_episodes = _QUALIFICATION_V230_PROBES_PER_ROUTE
                break
    # Also check if call_budget hints at v2.2.3 (multiples of 34)
    if actual_episodes is None and call_budget % _QUALIFICATION_EPISODES_PER_ROUTE == 0:
        # Budget is a multiple of 34 (e.g., 34, 68, 102), suggesting v2.2.3
        actual_episodes = _QUALIFICATION_EPISODES_PER_ROUTE
    qual_contract = _qualification_contract_version(
        campaign_release_tree_sha256 if isinstance(campaign_release_tree_sha256, str) else None,
        actual_episodes=actual_episodes,
    )
    qual_max_calls = _qualification_max_calls_per_route(qual_contract)
    attempt_accounting = _attempt_accounting(
        root,
        "qualification",
        results,
        require_ledger=(
            campaign_release_tree_sha256 != LEGACY_V221_RELEASE_TREE_SHA256
        ),
    )
    failed_reserved_value = attempt_accounting["failed_reserved_api_calls"]
    failed_attempt_value = attempt_accounting["failed_attempts"]
    if not isinstance(failed_reserved_value, int) or not isinstance(failed_attempt_value, int):
        raise ValueError("campaign_attempt_ledger_invalid")
    failed_reserved_calls = failed_reserved_value
    failed_attempt_count = failed_attempt_value
    _require_monotonic_attempt_accounting(
        state,
        reserved_key="qualification_failed_attempt_reserved_api_calls",
        attempts_key="qualification_failed_attempts",
        failed_reserved_calls=failed_reserved_calls,
        failed_attempts=failed_attempt_count,
    )
    interrupted_unknown_cost = bool(attempt_accounting["unknown_cost_encountered"])
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
    spend_state["qualification_failed_attempt_reserved_api_calls"] = failed_reserved_calls
    spend_state["qualification_failed_attempts"] = failed_attempt_count
    if interrupted_unknown_cost:
        spend_state["unknown_cost_encountered"] = True
    state["spend"] = spend_state
    _atomic_json(root / "CAMPAIGN.json", state)

    if interrupted_unknown_cost and not allow_unknown_costs:
        state["status"] = "blocked_unknown_cost"
        state["updated_at"] = _utc_now()
        _atomic_json(root / "CAMPAIGN.json", state)
        return state

    for route in routes:
        route_id = str(route.get("route_id") or "")
        if route_id in results:
            continue
        observed_calls = failed_reserved_calls + sum(
            int(item["classification"]["observed_api_calls"])
            for item in results.values()
            if isinstance(item.get("classification"), Mapping)
            and isinstance(item["classification"].get("observed_api_calls"), int)
        )
        if observed_calls + qual_max_calls > call_budget:
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
        _recover_preexisting_partial_suite(
            root, "qualification", route_id, attempt_accounting
        )
        execution_route = dict(route)
        execution_route["max_observed_cost_usd"] = max(
            0.0, budget - observed_known_before
        )
        execution_route["allow_unknown_costs"] = bool(allow_unknown_costs)
        attempt_reserved_calls = min(qual_max_calls, call_budget - observed_calls)
        execution_route["max_api_calls"] = attempt_reserved_calls
        execution_route["_qualification_contract_version"] = qual_contract
        attempt_id = secrets.token_hex(16)
        suite_output = _attempt_evidence_path(root, "qualification", attempt_id)
        reservation = _write_attempt_event(
            root,
            "qualification",
            attempt_id,
            "reserved",
            {
                "route_id": route_id,
                "requested_route": route.get("requested_route"),
                "reserved_api_calls": attempt_reserved_calls,
                "max_observed_cost_usd": execution_route["max_observed_cost_usd"],
                "approval_sha256": approval["receipt_sha256"],
            },
        )
        try:
            report = runner(execution_route, "qualification", suite_output, effort)
        except Exception as exc:
            quarantine = _quarantine_partial_suite(
                root, "qualification", route_id, attempt_id
            )
            _write_attempt_event(
                root,
                "qualification",
                attempt_id,
                "failed",
                {
                    "route_id": route_id,
                    "reservation_sha256": reservation["receipt_sha256"],
                    "failure_code": _safe_attempt_failure_code(exc),
                    "quarantine_path": (
                        str(Path(quarantine).relative_to(root)) if quarantine else None
                    ),
                },
            )
            state["status"] = "qualification_interrupted"
            state["updated_at"] = _utc_now()
            spend_state["qualification_failed_attempt_reserved_api_calls"] = (
                failed_reserved_calls + attempt_reserved_calls
            )
            spend_state["qualification_failed_attempts"] = failed_attempt_count + 1
            spend_state["unknown_cost_encountered"] = True
            state["spend"] = spend_state
            _atomic_json(root / "CAMPAIGN.json", state)
            return state
        if not isinstance(report, Mapping):
            quarantine = _quarantine_partial_suite(
                root, "qualification", route_id, attempt_id
            )
            _write_attempt_event(
                root,
                "qualification",
                attempt_id,
                "failed",
                {
                    "route_id": route_id,
                    "reservation_sha256": reservation["receipt_sha256"],
                    "failure_code": "campaign_runner_report_invalid",
                    "quarantine_path": (
                        str(Path(quarantine).relative_to(root)) if quarantine else None
                    ),
                },
            )
            state["status"] = "qualification_interrupted"
            state["updated_at"] = _utc_now()
            spend_state["qualification_failed_attempt_reserved_api_calls"] = (
                failed_reserved_calls + attempt_reserved_calls
            )
            spend_state["qualification_failed_attempts"] = failed_attempt_count + 1
            spend_state["unknown_cost_encountered"] = True
            state["spend"] = spend_state
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
            # If this is the first route and it shows v2.2.3 format (34 calls),
            # update our contract understanding rather than failing
            if (
                len(results) == 0
                and classification["observed_api_calls"] == _QUALIFICATION_EPISODES_PER_ROUTE
                and qual_contract == "v2.3.0"
            ):
                # Update to v2.2.3 for this and subsequent routes
                qual_contract = "v2.2.3"
                qual_max_calls = _qualification_max_calls_per_route(qual_contract)
                # Don't fail the budget check - we'll use the correct contract going forward
            else:
                classification["status"] = "api_call_budget_exceeded"
                state["status"] = "qualification_call_budget_exceeded"
        receipt = _stage_result_receipt(
            {
                "schema": "oab.qualification-result/v2",
                "created_at": _utc_now(),
                "route_id": route_id,
                "requested_route": requested_route,
                "attempt_id": attempt_id,
                "suite_output": str(suite_output),
                "classification": classification,
            },
            report,
        )
        _atomic_json(_result_path(root, "qualification", route_id), receipt)
        _write_attempt_event(
            root,
            "qualification",
            attempt_id,
            "completed",
            {
                "route_id": route_id,
                "reservation_sha256": reservation["receipt_sha256"],
                "result_receipt_sha256": receipt["receipt_sha256"],
            },
        )
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
    qual_plan = plan.get("qualification")
    qual_episodes = (
        int(qual_plan["episodes_per_route"])
        if isinstance(qual_plan, Mapping)
        and isinstance(qual_plan.get("episodes_per_route"), int)
        and not isinstance(qual_plan.get("episodes_per_route"), bool)
        and int(qual_plan["episodes_per_route"]) > 0
        else _QUALIFICATION_V230_PROBES_PER_ROUTE
    )
    projection_factor = (
        int(full_plan_for_projection["episodes_per_route"]) / qual_episodes
    )
    for route in routes:
        receipt_result = results.get(str(route.get("route_id") or ""))
        if receipt_result is None:
            continue
        classification = receipt_result.get("classification")
        if not isinstance(classification, Mapping):
            continue
        status = classification.get("status")
        if status == "qualified":
            readiness = "READY"
        elif status == "agent_loop_incompatible":
            readiness = "INCOMPATIBLE"
        else:
            readiness = "NOT READY"
        summary = {
            "route_id": route.get("route_id"),
            "requested_route": route.get("requested_route"),
            "status": status,
            "readiness": readiness,
            "reason_codes": classification.get("reason_codes") or [],
        }
        if status == "qualified":
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
    spend_state["unknown_cost_encountered"] = interrupted_unknown_cost or any(
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
    if any(item.get("readiness") == "INCOMPATIBLE" for item in excluded):
        headline_readiness = "INCOMPATIBLE"
    elif len(qualified) >= 2 and state.get("status") == "awaiting_full_run_approval":
        headline_readiness = "READY"
    else:
        headline_readiness = "NOT READY"
    qualification_report: dict[str, object] = {
        "schema": "oab.qualification-summary/v2",
        "created_at": _utc_now(),
        "status": state["status"],
        "readiness": headline_readiness,
        "headline": (
            f"{headline_readiness}: qualification is a plumbing check only; "
            "no model-quality score is produced."
        ),
        "route_count": len(routes),
        "discovered_route_count": int(plan["route_count"]),
        "completed_routes": len(results),
        "qualified_routes": qualified,
        "excluded_routes": excluded,
        "telemetry_posture": {
            "api_calls": "locally_counted",
            "tokens": "known_or_unknown_never_zero_coerced",
            "billed_cost": "known_or_unknown_never_zero_coerced",
        },
        "projected_full_run_cost_usd": round(projected, 12) if costs_known else None,
        "cost_projection_basis": (
            f"qualification observed cost multiplied by "
            f"{int(full_plan_for_projection['episodes_per_route'])}/{qual_episodes} episodes; "
            "projection is spend planning only, not a quality score"
        ),
        "projected_full_run_duration_seconds": (
            round(projected_duration, 3) if durations_known else None
        ),
        "duration_projection_basis": (
            f"qualification elapsed time multiplied by "
            f"{int(full_plan_for_projection['episodes_per_route'])}/{qual_episodes} episodes; "
            "projection is spend planning only, not a quality score"
        ),
    }
    _atomic_json(root / "QUALIFICATION.json", qualification_report)
    _atomic_json(root / "CAMPAIGN.json", state)
    return state


@_campaign_operation
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
    root = _trusted_campaign_root(output_root)
    _validate_campaign_layout(root, create=True)
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
    campaign_release_tree_sha256 = plan.get("release_tree_sha256")
    results = _load_stage_results(
        root,
        "full",
        routes,
        reasoning_effort=effort,
        campaign_release_tree_sha256=campaign_release_tree_sha256,
    )
    attempt_accounting = _attempt_accounting(
        root,
        "full",
        results,
        require_ledger=(
            campaign_release_tree_sha256 != LEGACY_V221_RELEASE_TREE_SHA256
        ),
    )
    failed_reserved_value = attempt_accounting["failed_reserved_api_calls"]
    failed_attempt_value = attempt_accounting["failed_attempts"]
    if not isinstance(failed_reserved_value, int) or not isinstance(failed_attempt_value, int):
        raise ValueError("campaign_attempt_ledger_invalid")
    failed_reserved_calls = failed_reserved_value
    failed_attempt_count = failed_attempt_value
    _require_monotonic_attempt_accounting(
        state,
        reserved_key="full_failed_attempt_reserved_api_calls",
        attempts_key="full_failed_attempts",
        failed_reserved_calls=failed_reserved_calls,
        failed_attempts=failed_attempt_count,
    )
    interrupted_unknown_cost = bool(attempt_accounting["unknown_cost_encountered"])
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
    spend_state["full_failed_attempt_reserved_api_calls"] = failed_reserved_calls
    spend_state["full_failed_attempts"] = failed_attempt_count
    if interrupted_unknown_cost:
        spend_state["unknown_full_cost_encountered"] = True
    state["spend"] = spend_state
    state["status"] = "running_full"
    _atomic_json(root / "CAMPAIGN.json", state)

    if interrupted_unknown_cost and not allow_unknown_costs:
        state["status"] = "blocked_unknown_full_cost"
        state["updated_at"] = _utc_now()
        _atomic_json(root / "CAMPAIGN.json", state)
        return state

    for route in routes:
        route_id = str(route.get("route_id") or "")
        if route_id in results:
            continue
        observed_calls = failed_reserved_calls + sum(
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
        _recover_preexisting_partial_suite(root, "full", route_id, attempt_accounting)
        execution_route = dict(route)
        execution_route["max_observed_cost_usd"] = max(
            0.0, budget - observed_known_before
        )
        execution_route["allow_unknown_costs"] = bool(allow_unknown_costs)
        attempt_reserved_calls = min(1360, call_budget - observed_calls)
        execution_route["max_api_calls"] = attempt_reserved_calls
        attempt_id = secrets.token_hex(16)
        suite_output = _attempt_evidence_path(root, "full", attempt_id)
        reservation = _write_attempt_event(
            root,
            "full",
            attempt_id,
            "reserved",
            {
                "route_id": route_id,
                "requested_route": route.get("requested_route"),
                "reserved_api_calls": attempt_reserved_calls,
                "max_observed_cost_usd": execution_route["max_observed_cost_usd"],
                "approval_sha256": approval["receipt_sha256"],
            },
        )
        try:
            report = runner(execution_route, "full", suite_output, effort)
        except Exception as exc:
            quarantine = _quarantine_partial_suite(root, "full", route_id, attempt_id)
            _write_attempt_event(
                root,
                "full",
                attempt_id,
                "failed",
                {
                    "route_id": route_id,
                    "reservation_sha256": reservation["receipt_sha256"],
                    "failure_code": _safe_attempt_failure_code(exc),
                    "quarantine_path": (
                        str(Path(quarantine).relative_to(root)) if quarantine else None
                    ),
                },
            )
            state["status"] = "full_run_interrupted"
            state["updated_at"] = _utc_now()
            spend_state["full_failed_attempt_reserved_api_calls"] = (
                failed_reserved_calls + attempt_reserved_calls
            )
            spend_state["full_failed_attempts"] = failed_attempt_count + 1
            spend_state["unknown_full_cost_encountered"] = True
            state["spend"] = spend_state
            _atomic_json(root / "CAMPAIGN.json", state)
            return state
        if not isinstance(report, Mapping):
            quarantine = _quarantine_partial_suite(root, "full", route_id, attempt_id)
            _write_attempt_event(
                root,
                "full",
                attempt_id,
                "failed",
                {
                    "route_id": route_id,
                    "reservation_sha256": reservation["receipt_sha256"],
                    "failure_code": "campaign_runner_report_invalid",
                    "quarantine_path": (
                        str(Path(quarantine).relative_to(root)) if quarantine else None
                    ),
                },
            )
            state["status"] = "full_run_interrupted"
            state["updated_at"] = _utc_now()
            spend_state["full_failed_attempt_reserved_api_calls"] = (
                failed_reserved_calls + attempt_reserved_calls
            )
            spend_state["full_failed_attempts"] = failed_attempt_count + 1
            spend_state["unknown_full_cost_encountered"] = True
            state["spend"] = spend_state
            _atomic_json(root / "CAMPAIGN.json", state)
            return state
        receipt = _stage_result_receipt(
            {
                "schema": "oab.full-run-result/v2",
                "created_at": _utc_now(),
                "route_id": route_id,
                "requested_route": route.get("requested_route"),
                "attempt_id": attempt_id,
                "suite_output": str(suite_output),
                "observed_cost_usd": _cost_from_report(report),
                "observed_known_cost_usd": _known_cost_from_report(report),
                "unknown_cost_api_calls": _unknown_cost_api_calls_from_report(report),
                "observed_api_calls": _api_calls_from_report(report),
            },
            report,
        )
        _atomic_json(_result_path(root, "full", route_id), receipt)
        _write_attempt_event(
            root,
            "full",
            attempt_id,
            "completed",
            {
                "route_id": route_id,
                "reservation_sha256": reservation["receipt_sha256"],
                "result_receipt_sha256": receipt["receipt_sha256"],
            },
        )
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
    spend_state["unknown_full_cost_encountered"] = interrupted_unknown_cost or any(
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
