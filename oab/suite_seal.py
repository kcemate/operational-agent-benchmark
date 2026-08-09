from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

from .aggregation import aggregate_suite_observations
from .case_verifier import verify_case
from .evidence import verify_sealed_evidence
from .manifest import ManifestError, build_tree_manifest
from .paths import benchmark_root
from .release_approval import verify_release_approval
from .registry import load_registry
from .runner import _cleanup_snapshot_name, _copy_snapshot_tree_fd

_SCHEMA = "oab.suite-seal/v1"
_SEAL_NAME = "SUITE_SEAL.json"

# (parent_fd, name, child_fd, (st_dev, st_ino)) for one retained directory link.
_DirectoryLink = tuple[int, str, int, tuple[int, int]]


def _directory_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _same_directory(left: os.stat_result, right: os.stat_result) -> bool:
    return stat.S_ISDIR(left.st_mode) and (left.st_dev, left.st_ino) == (
        right.st_dev,
        right.st_ino,
    )


def _directory_binding(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _trusted_absolute(path: Path, *, error: str) -> Path:
    """Return the absolute suite path only when it contains no attacker-controlled link.

    ``Path.resolve`` silently rewrites symlinked components, so a suite root that is
    itself a symlink (or that is reached through a symlinked ancestor) would otherwise
    be accepted and then descriptor-bound to the *link target*, defeating the release's
    no-link trust contract before ``_open_trusted_root`` ever inspects a component.

    Platform aliases that the OS itself canonicalizes (macOS ``/etc``, ``/tmp`` and
    ``/var`` under ``/private``) are applied first, exactly as the campaign descriptor
    binding in ``agent_workflow._open_directory_fd`` does, so trusted alias prefixes
    stay usable. Any remaining difference between the alias-normalized path and the
    fully resolved path proves a suite-controlled link and fails closed.
    """
    absolute = path.expanduser().absolute()
    if (
        sys.platform == "darwin"
        and len(absolute.parts) > 1
        and absolute.parts[1] in {"etc", "tmp", "var"}
    ):
        absolute = Path("/private").joinpath(*absolute.parts[1:])
    if not absolute.is_absolute() or any(part == ".." for part in absolute.parts):
        raise ValueError(error)
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise ValueError(error) from exc
    if resolved != absolute:
        raise ValueError(error)
    return absolute


def _open_trusted_root(
    output_root: Path,
) -> tuple[list[int], list[_DirectoryLink]]:
    root = _trusted_absolute(output_root, error="suite_evidence_path_unsafe")
    descriptors = [os.open(root.anchor, _directory_flags())]
    links: list[_DirectoryLink] = []
    descriptor = descriptors[0]
    try:
        for part in root.parts[1:]:
            expected = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            child = os.open(part, _directory_flags(), dir_fd=descriptor)
            descriptors.append(child)
            opened = os.fstat(child)
            if not _same_directory(expected, opened):
                raise ValueError("suite_evidence_path_unsafe")
            links.append((descriptor, part, child, _directory_binding(opened)))
            descriptor = child
    except (OSError, ValueError) as exc:
        for item in reversed(descriptors):
            os.close(item)
        if isinstance(exc, ValueError):
            raise
        raise ValueError("suite_evidence_path_unsafe") from exc
    return descriptors, links


def _revalidate_directory_links(
    links: list[_DirectoryLink], *, error: str
) -> None:
    """Prove every retained pathname still names its originally opened directory.

    Only inode binding is compared: directory metadata such as mtime legitimately
    changes when unrelated siblings are created inside a shared ancestor. Episode
    content mutation is detected separately by ``_tree_state_fd``.
    """
    for parent_fd, name, child_fd, identity in links:
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            opened = os.fstat(child_fd)
        except OSError as exc:
            raise ValueError(error) from exc
        if (
            not _same_directory(current, opened)
            or _directory_binding(current) != identity
            or _directory_binding(opened) != identity
        ):
            raise ValueError(error)


@contextmanager
def _trusted_suite_root(output_root: Path) -> Iterator[int]:
    """Open every suite-root path component through retained no-follow descriptors."""
    descriptors, links = _open_trusted_root(output_root)
    try:
        yield descriptors[-1]
        _revalidate_directory_links(links, error="suite_evidence_path_unsafe")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


@contextmanager
def _trusted_metadata_bytes(root_fd: int, name: str) -> Iterator[bytes]:
    """Read one fixed suite file through a retained single-link descriptor."""
    file_fd = -1
    try:
        try:
            expected = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if not stat.S_ISREG(expected.st_mode) or expected.st_nlink != 1:
                raise ValueError("suite_metadata_file_unsafe")
            file_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            opened = os.fstat(file_fd)
            if _stat_identity(expected) != _stat_identity(opened):
                raise ValueError("suite_metadata_file_unsafe")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(file_fd, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 64 * 1024 * 1024:
                    raise ValueError("suite_metadata_file_unsafe")
                chunks.append(chunk)
            identity = _stat_identity(opened)
            if _stat_identity(os.fstat(file_fd)) != identity:
                raise ValueError("suite_metadata_file_unsafe")
            payload = b"".join(chunks)
        except OSError as exc:
            raise ValueError("suite_metadata_file_unsafe") from exc
        yield payload
        try:
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            opened = os.fstat(file_fd)
        except OSError as exc:
            raise ValueError("suite_metadata_file_unsafe") from exc
        if _stat_identity(current) != identity or _stat_identity(opened) != identity:
            raise ValueError("suite_metadata_file_unsafe")
    finally:
        if file_fd >= 0:
            os.close(file_fd)


def _tree_state_fd(root_fd: int) -> tuple[tuple[str, tuple[int, ...]], ...]:
    state: list[tuple[str, tuple[int, ...]]] = [(".", _stat_identity(os.fstat(root_fd)))]

    def walk(directory_fd: int, prefix: str) -> None:
        try:
            entries = sorted(os.scandir(directory_fd), key=lambda entry: entry.name)
        except OSError as exc:
            raise ValueError("suite_evidence_path_unsafe") from exc
        for entry in entries:
            path = f"{prefix}/{entry.name}" if prefix else entry.name
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ValueError("suite_evidence_path_unsafe") from exc
            if stat.S_ISDIR(info.st_mode):
                try:
                    child_fd = os.open(entry.name, _directory_flags(), dir_fd=directory_fd)
                except OSError as exc:
                    raise ValueError("suite_evidence_path_unsafe") from exc
                try:
                    opened = os.fstat(child_fd)
                    if _stat_identity(info) != _stat_identity(opened):
                        raise ValueError("suite_evidence_path_unsafe")
                    state.append((path, _stat_identity(opened)))
                    walk(child_fd, path)
                    if _stat_identity(os.fstat(child_fd)) != _stat_identity(opened):
                        raise ValueError("suite_evidence_path_unsafe")
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                state.append((path, _stat_identity(info)))
            else:
                raise ValueError("suite_evidence_path_unsafe")

    walk(root_fd, "")
    return tuple(state)


@contextmanager
def _trusted_episode_directories(
    root_fd: int,
    grid: list[tuple[int, dict[str, object]]],
) -> Iterator[dict[tuple[int, str], int]]:
    """Retain one no-follow descriptor for every suite evidence hierarchy node."""
    descriptors: list[int] = []
    links: list[_DirectoryLink] = []
    try:
        def open_child(parent_fd: int, name: str) -> int:
            try:
                expected = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                child = os.open(name, _directory_flags(), dir_fd=parent_fd)
            except OSError as exc:
                raise ValueError("suite_evidence_path_unsafe") from exc
            descriptors.append(child)
            opened = os.fstat(child)
            if not _same_directory(expected, opened):
                raise ValueError("suite_evidence_path_unsafe")
            links.append((parent_fd, name, child, _directory_binding(opened)))
            return child

        evidence_fd = open_child(root_fd, "evidence")
        repetition_fds: dict[int, int] = {}
        episode_fds: dict[tuple[int, str], int] = {}
        for repetition, case in grid:
            if repetition not in repetition_fds:
                repetition_fds[repetition] = open_child(
                    evidence_fd, f"rep-{repetition:02d}"
                )
            case_id = str(case["case_id"])
            key = (repetition, case_id)
            episode_fds[key] = open_child(repetition_fds[repetition], case_id)
        yield episode_fds

        _revalidate_directory_links(links, error="suite_evidence_path_unsafe")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


@contextmanager
def _descriptor_rooted_view(directory_fd: int, *, error: str) -> Iterator[Path]:
    """Root every pathname read of ``directory_fd`` in the retained descriptor itself.

    The consumers of a trusted snapshot (``verify_sealed_evidence``, ``verify_case``,
    ``build_tree_manifest`` and the episode receipt read) are ordinary pathname
    readers. Handing them the snapshot's *absolute* pathname would let a post-binding
    rename or symlink substitution redirect their reads to a victim directory before
    any revalidation could observe it, so no absolute pathname is produced at all.

    Instead the process working directory is bound to the retained descriptor and the
    consumers receive ``Path(".")``. Relative resolution starts at the directory
    *inode* the descriptor holds open, which no rename, unlink or symlink
    substitution of the leaf's pathname can redirect: it is an immutable binding for
    exactly as long as the descriptor is retained. The previous working directory is
    itself retained as a descriptor and restored unconditionally.
    """
    try:
        previous_fd = os.open(".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        raise ValueError(error) from exc
    restored = False
    try:
        try:
            os.fchdir(directory_fd)
            # Defense in depth: prove the bound working directory is the retained
            # inode before any consumer reads a relative pathname through it.
            if _directory_binding(os.stat(".")) != _directory_binding(
                os.fstat(directory_fd)
            ):
                raise ValueError(error)
        except OSError as exc:
            raise ValueError(error) from exc
        yield Path(".")
    finally:
        try:
            os.fchdir(previous_fd)
            restored = True
        except OSError:
            restored = False
        os.close(previous_fd)
        if not restored:
            raise ValueError(error)


@contextmanager
def _trusted_evidence_snapshot(source_fd: int, relative: Path) -> Iterator[Path]:
    """Copy an opened episode tree into an ownership-bound verification view.

    The newly created leaf is never resolved or followed by pathname. The trusted
    temporary parent is bound first, and the leaf is opened *relative to that
    descriptor* with ``O_DIRECTORY|O_NOFOLLOW``; a leaf substituted between creation
    and binding therefore fails closed instead of being followed to a victim
    directory that ownership-bound cleanup would then remove.

    The value yielded to consumers is ``Path(".")`` under a working directory bound
    to the retained snapshot descriptor, never the snapshot's mutable absolute
    pathname. Substituting that pathname after the snapshot is bound therefore
    cannot redirect a single verification read; the post-yield identity check below
    remains defense in depth rather than the first line of detection.
    """
    snapshot: Path | None = None
    parent_fd = -1
    destination_fd = -1
    owned_identity: os.stat_result | None = None
    try:
        parent = _trusted_absolute(
            Path(tempfile.gettempdir()),
            error=f"suite_evidence_path_unsafe:{relative.as_posix()}",
        )
        leaf_name = Path(
            tempfile.mkdtemp(prefix="oab-suite-evidence-", dir=parent)
        ).name
        # Bind the trusted parent, then the created leaf relative to it. Neither the
        # leaf's pathname nor its target is ever resolved.
        snapshot = parent / leaf_name
        parent_fd = os.open(parent, _directory_flags())
        expected = os.stat(leaf_name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(expected.st_mode):
            raise ValueError(f"suite_evidence_path_unsafe:{relative.as_posix()}")
        destination_fd = os.open(leaf_name, _directory_flags(), dir_fd=parent_fd)
        owned_identity = os.fstat(destination_fd)
        if not _same_directory(expected, owned_identity):
            raise ValueError(f"suite_evidence_path_unsafe:{relative.as_posix()}")
        try:
            _copy_snapshot_tree_fd(source_fd, destination_fd)
        except ManifestError as exc:
            raise ValueError(
                f"suite_evidence_path_unsafe:{relative.as_posix()}"
            ) from exc
        snapshot_identity = _stat_identity(os.fstat(destination_fd))
        copied = os.stat(snapshot.name, dir_fd=parent_fd, follow_symlinks=False)
        if _stat_identity(copied) != snapshot_identity:
            raise ValueError(f"suite_evidence_path_unsafe:{relative.as_posix()}")
        with _descriptor_rooted_view(
            destination_fd, error=f"suite_evidence_path_unsafe:{relative.as_posix()}"
        ) as rooted:
            yield rooted
        current = os.stat(snapshot.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            _stat_identity(current) != snapshot_identity
            or _stat_identity(os.fstat(destination_fd)) != snapshot_identity
        ):
            raise ValueError(f"suite_evidence_path_unsafe:{relative.as_posix()}")
    except OSError as exc:
        raise ValueError(f"suite_evidence_path_unsafe:{relative.as_posix()}") from exc
    finally:
        if (
            snapshot is not None
            and parent_fd >= 0
            and destination_fd >= 0
            and owned_identity is not None
        ):
            _cleanup_snapshot_name(
                parent_fd, snapshot.name, destination_fd, owned_identity
            )
        if destination_fd >= 0:
            os.close(destination_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


@contextmanager
def _trusted_external_file_bytes(path: Path, *, error: str) -> Iterator[bytes]:
    """Read one caller-supplied file through descriptor-bound, no-follow machinery.

    The release manifest lives outside the suite root, so its ancestors are walked with
    the same retained no-follow descriptors used for the suite itself and its bytes are
    read through ``_trusted_metadata_bytes``. This keeps the release-manifest read under
    the established descriptor-bound contract instead of an ordinary pathname read.
    """
    name = path.name
    if name in {"", ".", ".."} or "/" in name or "\\" in name:
        raise ValueError(error)
    try:
        descriptors, links = _open_trusted_root(path.parent)
    except ValueError as exc:
        raise ValueError(error) from exc
    try:
        inside_body = False
        try:
            with _trusted_metadata_bytes(descriptors[-1], name) as payload:
                inside_body = True
                yield payload
                inside_body = False
        except ValueError as exc:
            # Only descriptor-binding failures are remapped; errors raised by the
            # caller's body keep their own contract-visible codes.
            if inside_body:
                raise
            raise ValueError(error) from exc
        _revalidate_directory_links(links, error=error)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"not_json_object:{path.name}")
    return value


def _load_object_bytes(payload: bytes, *, name: str) -> dict[str, Any]:
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"not_json_object:{name}")
    return value


def _suite_grid(
    report: Mapping[str, object],
) -> tuple[list[tuple[int, dict[str, object]]], dict[str, dict[str, str]]]:
    repetitions = report.get("repetitions")
    pair_ids = report.get("pair_ids")
    if (
        not isinstance(repetitions, int)
        or isinstance(repetitions, bool)
        or repetitions < 1
        or not isinstance(pair_ids, list)
        or not pair_ids
        or any(not isinstance(pair_id, str) or not pair_id for pair_id in pair_ids)
        or len(set(pair_ids)) != len(pair_ids)
    ):
        raise ValueError("suite_grid_metadata_invalid")

    registry_root = benchmark_root()
    registry = load_registry(registry_root / "cases.json")
    selected = [
        dict(case)
        for case in registry["cases"]
        if str(case["pair_id"]) in set(pair_ids)
    ]
    case_map: dict[str, dict[str, str]] = {}
    by_case: dict[str, dict[str, object]] = {}
    for case in selected:
        pair_id = str(case["pair_id"])
        variant = str(case["variant"])
        case_id = str(case["case_id"])
        case_map.setdefault(pair_id, {})[variant] = case_id
        by_case[case_id] = case
    if any(
        set(case_map.get(pair_id, {})) != {"approved", "prohibited"}
        for pair_id in pair_ids
    ):
        raise ValueError("suite_pair_registry_invalid")

    expected = [
        (repetition, by_case[case_map[pair_id][variant]])
        for repetition in range(1, repetitions + 1)
        for pair_id in pair_ids
        for variant in ("approved", "prohibited")
    ]
    observations = report.get("observations")
    if not isinstance(observations, list):
        raise ValueError("suite_observations_invalid")
    observed: set[tuple[int, str, str, str]] = set()
    for item in observations:
        if not isinstance(item, dict):
            raise ValueError("suite_observation_invalid")
        repetition = item.get("repetition")
        case_id = item.get("case_id")
        pair_id = item.get("pair_id")
        variant = item.get("variant")
        if (
            not isinstance(repetition, int)
            or isinstance(repetition, bool)
            or repetition < 1
            or not isinstance(case_id, str)
            or not case_id
            or not isinstance(pair_id, str)
            or variant not in {"approved", "prohibited"}
        ):
            raise ValueError("suite_observation_identity_invalid")
        key = (repetition, case_id, pair_id, variant)
        if key in observed:
            raise ValueError("suite_observation_duplicate")
        observed.add(key)
    expected_keys = {
        (
            repetition,
            str(case["case_id"]),
            str(case["pair_id"]),
            str(case["variant"]),
        )
        for repetition, case in expected
    }
    if observed != expected_keys:
        raise ValueError("suite_observation_grid_invalid")
    return expected, case_map


def _episode_observation(
    output_root: Path,
    report: Mapping[str, object],
    repetition: int,
    case: Mapping[str, object],
    evidence_snapshot: Path,
) -> dict[str, object]:
    case_id = str(case["case_id"])
    recorded_evidence = output_root / "evidence" / f"rep-{repetition:02d}" / case_id
    evidence = evidence_snapshot
    receipt = _load_object(evidence / "result.json")
    identity = receipt.get("controller_identity")
    identity_object = identity if isinstance(identity, dict) else {}
    gates = verify_case(
        dict(case),
        benchmark_root() / str(case["fixture_path"]),
        evidence,
    )
    evidence_text = str(recorded_evidence.relative_to(output_root))
    observations = report.get("observations")
    if isinstance(observations, list):
        for observation in observations:
            if not isinstance(observation, Mapping):
                continue
            if (
                observation.get("case_id") == case_id
                and observation.get("repetition") == repetition
            ):
                recorded = observation.get("evidence_dir")
                if recorded in {evidence_text, str(recorded_evidence)}:
                    evidence_text = str(recorded)
                break
    return {
        "pair_id": str(case["pair_id"]),
        "case_id": case_id,
        "variant": str(case["variant"]),
        "repetition": repetition,
        "runner_status": receipt.get("status"),
        "valid_for_authoritative_scoring": receipt.get("valid_for_scoring") is True,
        "reason_codes": receipt.get("reason_codes"),
        "all_declared_gates_passed": all(gate.passed for gate in gates),
        "identity_source": identity_object.get("identity_source", "adapter_runtime"),
        "requested_route": identity_object.get("requested_route"),
        "returned_route": identity_object.get("returned_route"),
        "response_id": identity_object.get("response_id"),
        "reasoning_effort": (
            identity_object.get("reasoning_effort")
            if identity_object
            else report.get("reasoning_effort")
        ),
        "controller_config_sha256": (
            identity_object.get("controller_config_sha256")
            if identity_object
            else report.get("controller_config_sha256")
        ),
        "gates": [
            {"id": gate.dimension, "passed": gate.passed, "code": gate.code}
            for gate in gates
        ],
        "controller_usage": receipt.get("controller_usage"),
        "protocol_normalized_turns": receipt.get("protocol_normalized_turns"),
        "runtime": (
            dict(receipt["runtime"]) if isinstance(receipt.get("runtime"), Mapping) else {}
        ),
        "trace_sha256": receipt.get("trace_sha256"),
        "output_tree_sha256": receipt.get("output_tree_sha256"),
        "evidence_dir": evidence_text,
    }


def _recomputed_report(
    report: Mapping[str, object],
    observations: list[dict[str, object]],
    case_map: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    requested_route = report.get("requested_route")
    repetitions = report.get("repetitions")
    pair_ids = report.get("pair_ids")
    if (
        not isinstance(requested_route, str)
        or not isinstance(repetitions, int)
        or not isinstance(pair_ids, list)
    ):
        raise ValueError("suite_report_metadata_invalid")
    effort = report.get("reasoning_effort")
    config_digest = report.get("controller_config_sha256")
    release_digest = report.get("release_tree_sha256")
    approval_digest = report.get("release_approval_sha256")
    return aggregate_suite_observations(
        observations,
        requested_route=requested_route,
        reasoning_effort=effort if isinstance(effort, str) else None,
        controller_config_sha256=(
            config_digest if isinstance(config_digest, str) else None
        ),
        release_tree_sha256=(
            release_digest if isinstance(release_digest, str) else None
        ),
        release_approval_sha256=(
            approval_digest if isinstance(approval_digest, str) else None
        ),
        release_authorized=report.get("release_authorized") is True,
        repetitions=repetitions,
        pair_ids=[str(pair_id) for pair_id in pair_ids],
        case_ids_by_pair=case_map,
    )


def _verify_report_claims(
    output_root: Path,
    report: Mapping[str, object],
    observations: list[dict[str, object]],
    case_map: Mapping[str, Mapping[str, str]],
    headline_payload: bytes,
) -> None:
    if report.get("release_authorized") is True:
        release_digest = report.get("release_tree_sha256")
        approval_digest = report.get("release_approval_sha256")
        if not isinstance(release_digest, str) or not isinstance(approval_digest, str):
            raise ValueError("release_approval_binding_invalid")
        approval = verify_release_approval(
            output_root / "RELEASE_APPROVAL.json",
            expected_release_tree_sha256=release_digest,
            expected_file_sha256=approval_digest,
        )
        if approval.get("valid") is not True:
            errors = approval.get("errors")
            rendered = (
                ",".join(str(error) for error in errors)
                if isinstance(errors, list) and errors
                else "invalid"
            )
            raise ValueError("release_approval_invalid:" + rendered)
    recomputed = _recomputed_report(report, observations, case_map)
    for key, expected in recomputed.items():
        if report.get(key) != expected:
            raise ValueError(f"suite_report_recomputation_mismatch:{key}")
    try:
        headline = headline_payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("suite_headline_unreadable") from exc
    if headline != str(recomputed["headline"]) + "\n":
        raise ValueError("suite_headline_mismatch")


def build_suite_seal(
    output_root: Path,
    *,
    release_manifest: Path | None = None,
    report_bytes: bytes | None = None,
) -> dict[str, Any]:
    output_root = _trusted_absolute(output_root, error="suite_evidence_path_unsafe")
    with _trusted_suite_root(output_root) as root_fd:
        with _trusted_metadata_bytes(root_fd, "suite-report.json") as report_payload:
            if report_bytes is not None and report_bytes != report_payload:
                raise ValueError("suite_metadata_file_unsafe")
            report = _load_object_bytes(report_payload, name="suite-report.json")
            grid, case_map = _suite_grid(report)
            with _trusted_metadata_bytes(root_fd, "HEADLINE.txt") as headline_payload:
                episodes: list[dict[str, object]] = []
                observations: list[dict[str, object]] = []
                with _trusted_episode_directories(root_fd, grid) as episode_fds:
                    source_states = {
                        key: _tree_state_fd(descriptor)
                        for key, descriptor in episode_fds.items()
                    }
                    for repetition, case in grid:
                        case_id = str(case["case_id"])
                        key = (repetition, case_id)
                        relative = Path("evidence") / f"rep-{repetition:02d}" / case_id
                        with _trusted_evidence_snapshot(
                            episode_fds[key], relative
                        ) as evidence:
                            verification = verify_sealed_evidence(evidence)
                            if verification.get("valid") is not True:
                                codes = verification.get("errors")
                                rendered = (
                                    ",".join(str(code) for code in codes)
                                    if isinstance(codes, list)
                                    else "unknown"
                                )
                                raise ValueError(
                                    f"suite_evidence_unsealed:{relative.as_posix()}:{rendered}"
                                )
                            try:
                                manifest = build_tree_manifest(
                                    evidence,
                                    max_files=1024,
                                    max_total_bytes=128 * 1024 * 1024,
                                )
                            except ManifestError as exc:
                                raise ValueError(
                                    f"suite_evidence_invalid:{relative.as_posix()}:{exc}"
                                ) from None
                            observations.append(
                                _episode_observation(
                                    output_root, report, repetition, case, evidence
                                )
                            )
                        episodes.append(
                            {
                                "repetition": repetition,
                                "case_id": case_id,
                                "path": relative.as_posix(),
                                "tree_sha256": manifest["tree_sha256"],
                                "file_count": manifest["file_count"],
                                "total_bytes": manifest["total_bytes"],
                            }
                        )
                    _verify_report_claims(
                        output_root,
                        report,
                        observations,
                        case_map,
                        headline_payload,
                    )
                    for key, descriptor in episode_fds.items():
                        if _tree_state_fd(descriptor) != source_states[key]:
                            raise ValueError("suite_evidence_path_unsafe")

                release_tree_sha256 = report.get("release_tree_sha256")
                if release_manifest is not None:
                    with _trusted_external_file_bytes(
                        release_manifest, error="release_manifest_unreadable"
                    ) as release_payload:
                        release_value = _load_object_bytes(
                            release_payload, name=release_manifest.name
                        )
                        release_tree_sha256 = release_value.get("tree_sha256")
                        if not isinstance(release_tree_sha256, str):
                            raise ValueError("release_manifest_tree_digest_invalid")
                        if report.get("release_tree_sha256") != release_tree_sha256:
                            raise ValueError("suite_release_tree_mismatch")
                body: dict[str, Any] = {
                    "schema": _SCHEMA,
                    "suite_report_sha256": _sha256_bytes(report_payload),
                    "headline_sha256": _sha256_bytes(headline_payload),
                    "release_tree_sha256": release_tree_sha256,
                    "release_approval_sha256": report.get("release_approval_sha256"),
                    "requested_route": report.get("requested_route"),
                    "reasoning_effort": report.get("reasoning_effort"),
                    "repetitions": report.get("repetitions"),
                    "pair_ids": report.get("pair_ids"),
                    "episodes": episodes,
                }
                body["content_sha256"] = _sha256_bytes(_canonical_bytes(body))
    return body


def _publish_seal_bytes(root_fd: int, payload: bytes) -> str:
    """Publish SUITE_SEAL.json as an inode this call creates, owns and never renames.

    Design. There is no portable way to rename a *descriptor* into place: Linux's
    ``linkat(AT_EMPTY_PATH)`` is privileged and unavailable here, and macOS refuses
    ``link("/dev/fd/N", ...)`` with ``EPERM``. Any staging-name design therefore ends
    in a pathname ``os.replace`` whose source can be substituted between the
    ownership check and the rename — the reviewer-reproduced race in which an
    attacker's inode was moved on top of an existing legitimate seal. Adding another
    precheck cannot close that window, so the staging name is removed entirely.

    Instead the seal is created directly at its final name with
    ``O_CREAT|O_EXCL|O_NOFOLLOW``. The kernel grants the name and the inode in one
    atomic operation, so the published inode is by construction the one this call
    created, and no pre-existing ``SUITE_SEAL.json`` can ever be overwritten or
    displaced: ``O_EXCL`` fails instead.

    Rerun semantics are explicit. A suite is sealed once. If ``SUITE_SEAL.json``
    already exists, this call publishes nothing and instead reads the existing seal
    through the retained no-follow descriptor contract:

    * byte-identical to the payload just computed — the seal is already published;
      the digest of those exact bytes is returned and nothing is written, moved or
      deleted (idempotent reseal);
    * anything else, including a symlink, hardlinked file, directory, special file
      or a differing regular file — ``suite_seal_publication_unsafe``. Republishing
      over it is refused rather than attempted.

    ``published`` becomes true only after the bytes are written, fsynced, proven to
    still be the owned inode under the owned name, and the root directory is fsynced.
    Every raising path therefore leaves ``published`` false, and the failure branch
    unlinks the seal name only while it still maps to the inode this call created —
    which, because of ``O_EXCL``, is never a file that existed beforehand.
    """
    try:
        existing = os.stat(_SEAL_NAME, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise ValueError("suite_seal_publication_unsafe") from exc
    if existing is not None:
        if not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
            raise ValueError("suite_seal_publication_unsafe")
        with _trusted_metadata_bytes(root_fd, _SEAL_NAME) as current:
            if current != payload:
                raise ValueError("suite_seal_publication_unsafe")
            return _sha256_bytes(payload)

    seal_fd = -1
    owned: os.stat_result | None = None
    published = False

    def _names_owned_file() -> bool:
        """True only when ``_SEAL_NAME`` still lstats to the inode this call created."""
        if owned is None:
            return False
        try:
            current = os.stat(_SEAL_NAME, dir_fd=root_fd, follow_symlinks=False)
        except OSError:
            return False
        return (
            stat.S_ISREG(current.st_mode)
            and current.st_nlink == 1
            and (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino)
        )

    try:
        try:
            seal_fd = os.open(
                _SEAL_NAME,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=root_fd,
            )
            opened = os.fstat(seal_fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise ValueError("suite_seal_publication_unsafe")
            # Retained identity of the inode this call created, owns and publishes.
            owned = opened
            view = memoryview(payload)
            while view:
                written = os.write(seal_fd, view)
                if written <= 0:
                    raise OSError("short seal write")
                view = view[written:]
            os.fsync(seal_fd)
            after = os.fstat(seal_fd)
            if (
                after.st_ino != opened.st_ino
                or after.st_dev != opened.st_dev
                or after.st_nlink != 1
                or after.st_size != len(payload)
            ):
                raise ValueError("suite_seal_publication_unsafe")
            if not _names_owned_file():
                raise ValueError("suite_seal_publication_unsafe")
            os.close(seal_fd)
            seal_fd = -1
            os.fsync(root_fd)
            if not _names_owned_file():
                raise ValueError("suite_seal_publication_unsafe")
            published = True
        except OSError as exc:
            raise ValueError("suite_seal_publication_unsafe") from exc
    finally:
        if seal_fd >= 0:
            os.close(seal_fd)
        if not published:
            # Remove the seal name only while it still identifies the exact inode
            # this call created under O_EXCL. A substituted replacement is left
            # untouched: a matching name is not proof of ownership, and no
            # pre-existing seal can be reached here.
            if _names_owned_file():
                try:
                    os.unlink(_SEAL_NAME, dir_fd=root_fd)
                except OSError:
                    pass
    return _sha256_bytes(payload)


def write_suite_seal(
    output_root: Path,
    *,
    release_manifest: Path | None = None,
) -> tuple[Path, str]:
    output_root = _trusted_absolute(output_root, error="suite_evidence_path_unsafe")
    seal = build_suite_seal(output_root, release_manifest=release_manifest)
    payload = _canonical_bytes(seal) + b"\n"
    with _trusted_suite_root(output_root) as root_fd:
        digest = _publish_seal_bytes(root_fd, payload)
    return output_root / _SEAL_NAME, digest


def verify_suite_seal(
    output_root: Path,
    *,
    expected_seal_sha256: str | None = None,
    seal_bytes: bytes | None = None,
    report_bytes: bytes | None = None,
) -> list[str]:
    try:
        output_root = _trusted_absolute(
            output_root, error="suite_evidence_path_unsafe"
        )
        with _trusted_suite_root(output_root) as root_fd:
            with _trusted_metadata_bytes(root_fd, _SEAL_NAME) as seal_payload:
                if seal_bytes is not None and seal_bytes != seal_payload:
                    return ["suite_seal_unreadable"]
                recorded = _load_object_bytes(seal_payload, name=_SEAL_NAME)
                errors: list[str] = []
                if (
                    expected_seal_sha256 is not None
                    and _sha256_bytes(seal_payload) != expected_seal_sha256
                ):
                    errors.append("suite_external_seal_digest_mismatch")
                if recorded.get("schema") != _SCHEMA:
                    errors.append("suite_seal_schema_invalid")
                recorded_content_digest = recorded.get("content_sha256")
                unsigned = dict(recorded)
                unsigned.pop("content_sha256", None)
                if recorded_content_digest != _sha256_bytes(_canonical_bytes(unsigned)):
                    errors.append("suite_seal_content_digest_mismatch")
                try:
                    actual = build_suite_seal(output_root, report_bytes=report_bytes)
                except (
                    OSError,
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    ValueError,
                ) as exc:
                    errors.append(str(exc))
                    return sorted(set(errors))
                if recorded != actual:
                    errors.append("suite_seal_tree_mismatch")
        return sorted(set(errors))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return ["suite_seal_unreadable"]
