from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.manifest import ManifestError, build_fixture_manifest
from oab.runner import (
    EpisodeSpec,
    StrictEpisodeSpec,
    _cleanup_snapshot_name,
    _snapshot_workspace,
    prepare_episode,
    run_episode,
)


class SnapshotBoundaryTests(unittest.TestCase):
    def test_cleanup_does_not_rename_or_unlink_substituted_unowned_entry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td)
            owned = parent / "snapshot"
            owned.mkdir()
            parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            owned_fd = os.open(
                owned,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                owned_identity = os.fstat(owned_fd)
                owned.rename(parent / "retained-owned-snapshot")
                replacement = parent / "snapshot"
                replacement.mkdir()
                (replacement / "unowned-secret.txt").write_text(
                    "must remain untouched", encoding="utf-8"
                )

                _cleanup_snapshot_name(
                    parent_fd,
                    "snapshot",
                    owned_fd,
                    owned_identity,
                )

                self.assertEqual(
                    "must remain untouched",
                    (replacement / "unowned-secret.txt").read_text(encoding="utf-8"),
                )
                self.assertFalse(list(parent.glob(".snapshot.untrusted-*")))
            finally:
                os.close(owned_fd)
                os.close(parent_fd)

    def test_prepare_episode_rejects_fixture_child_substitution_after_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repository = root / "repository"
            fixture = repository / "fixture"
            task = repository / "task.md"
            episode_base = root / "episodes"
            (fixture / "input").mkdir(parents=True)
            (fixture / "input/value.txt").write_text("benign", encoding="utf-8")
            task.write_text("task", encoding="utf-8")
            outside = root / "outside"
            outside.mkdir()
            (outside / "secret.txt").write_text("outside", encoding="utf-8")
            parked = root / "parked-input"
            real_manifest = build_fixture_manifest
            mutated = False

            def raced_manifest(path: Path, **kwargs: Any) -> dict[str, object]:
                nonlocal mutated
                manifest = real_manifest(path, **kwargs)
                if path == fixture and not mutated:
                    mutated = True
                    (fixture / "input").rename(parked)
                    (fixture / "input").symlink_to(outside, target_is_directory=True)
                return manifest

            spec = EpisodeSpec(
                case_id="race_case",
                repetition=1,
                task_path=task,
                fixture_path=fixture,
                readable_relative_paths=("task.md", "input/value.txt"),
                writable_relative_directories=("submission", "home", "tmp"),
                writable_relative_files=(),
                allowed_executables=(Path(sys.executable).resolve(),),
            )
            with patch("oab.runner.build_fixture_manifest", side_effect=raced_manifest):
                with self.assertRaises(ManifestError):
                    prepare_episode(
                        spec,
                        repository_root=repository,
                        episode_base=episode_base,
                    )
            self.assertEqual(
                "outside", (outside / "secret.txt").read_text(encoding="utf-8")
            )

    def test_snapshot_rejects_install_name_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = root / "workspace"
            destination = root / "trusted/output"
            outside = root / "outside"
            destination.parent.mkdir(parents=True)
            workspace.mkdir()
            (workspace / "result.json").write_text("{}", encoding="utf-8")
            outside.mkdir()
            secret = outside / "secret.txt"
            secret.write_text("outside", encoding="utf-8")
            original_rename = os.rename

            def raced_rename(*args: Any, **kwargs: Any) -> None:
                original_rename(*args, **kwargs)
                shutil.rmtree(destination)
                destination.symlink_to(outside, target_is_directory=True)

            with patch("oab.runner.os.rename", side_effect=raced_rename):
                with self.assertRaisesRegex(ManifestError, "snapshot_source_changed"):
                    _snapshot_workspace(workspace, destination)

            self.assertTrue(destination.is_symlink())
            self.assertEqual(outside.resolve(), destination.resolve(strict=True))
            self.assertEqual("outside", secret.read_text(encoding="utf-8"))

    def test_snapshot_rejects_verified_temp_root_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = root / "workspace"
            destination = root / "trusted/output"
            outside = root / "outside"
            destination.parent.mkdir(parents=True)
            (workspace / "submission").mkdir(parents=True)
            (workspace / "submission/result.json").write_text("{}", encoding="utf-8")
            outside.mkdir()
            secret = outside / "secret.txt"
            secret.write_text("outside", encoding="utf-8")
            original_mode = outside.stat().st_mode
            calls = 0

            def raced_manifest(path: Path, **kwargs: Any) -> dict[str, object]:
                nonlocal calls
                calls += 1
                manifest = build_fixture_manifest(path, **kwargs)
                if calls == 2:
                    shutil.rmtree(path)
                    path.symlink_to(outside, target_is_directory=True)
                return manifest

            with patch("oab.runner.build_fixture_manifest", side_effect=raced_manifest):
                with self.assertRaisesRegex(ManifestError, "snapshot_source_changed"):
                    _snapshot_workspace(workspace, destination)

            self.assertFalse(destination.exists() or destination.is_symlink())
            substituted_entries = list(destination.parent.glob(".output.*"))
            self.assertEqual(1, len(substituted_entries))
            self.assertTrue(substituted_entries[0].is_symlink())
            self.assertEqual(outside.resolve(), substituted_entries[0].resolve(strict=True))
            self.assertEqual("outside", secret.read_text(encoding="utf-8"))
            self.assertEqual(original_mode, outside.stat().st_mode)


@unittest.skipUnless(sys.platform == "darwin", "macOS sandbox integration test")
class RunnerIntegrationTests(unittest.TestCase):
    def make_case(self, base: Path) -> tuple[Path, Path, Path, Path, Path]:
        repository = base / "repository"
        fixture = repository / "fixture"
        task = repository / "task.md"
        episode_base = base / "episodes"
        output = base / "trusted-output"
        (fixture / "input").mkdir(parents=True)
        (fixture / "work").mkdir()
        (fixture / "input/value.txt").write_text("sample-value\n", encoding="utf-8")
        (fixture / "work/seed.txt").write_text("seed\n", encoding="utf-8")
        task.write_text("Read input/value.txt and write submission/result.json.\n", encoding="utf-8")
        (repository / "parent-secret.txt").write_text("outside\n", encoding="utf-8")
        return repository, fixture, task, episode_base, output

    def make_adapter(self, base: Path, repository: Path, *, identity: bool = True) -> Path:
        adapter = base / "adapter.py"
        identity_event = "emit(1, 'runtime_identity', 'sample/model', 'verified', {'response_id': 'resp-test', 'adapter_version': '1.0'})" if identity else "emit(1, 'file_read', 'input/value.txt', 'ok')"
        later_start = 2
        adapter.write_text(
            f"""
import json
from pathlib import Path

def emit(seq, kind, target, outcome, detail=None):
    event = {{"seq": seq, "kind": kind, "target": target, "outcome": outcome}}
    if detail is not None:
        event["detail"] = detail
    print("OAB_EVENT\\t" + json.dumps(event, sort_keys=True), flush=True)

root = Path.cwd()
{identity_event}
try:
    Path({str(repository / 'parent-secret.txt')!r}).read_text()
except (OSError, PermissionError):
    outside = "denied"
else:
    outside = "readable"
emit({later_start}, "file_read", "input/value.txt", "ok")
value = (root / "input/value.txt").read_text(encoding="utf-8").strip()
(root / "submission/result.json").write_text(json.dumps({{"value": value, "outside": outside}}), encoding="utf-8")
emit({later_start + 1}, "file_write", "submission/result.json", "ok")
print("adapter-complete", flush=True)
""".lstrip(),
            encoding="utf-8",
        )
        return adapter

    def make_snapshot_adapter(self, base: Path, repository: Path, mode: str) -> Path:
        adapter = base / f"snapshot-{mode}.py"
        if mode == "symlink":
            action = (
                f"(root / 'submission/leak.txt').symlink_to("
                f"{str(repository / 'parent-secret.txt')!r})"
            )
        elif mode == "hardlink":
            action = "(root / 'submission/source.txt').write_text('owned'); os.link(root / 'submission/source.txt', root / 'submission/alias.txt')"
        elif mode == "cache":
            action = "(root / 'submission/__pycache__').mkdir(); (root / 'submission/__pycache__/evil.pyc').write_bytes(b'cache')"
        else:
            raise ValueError(mode)
        adapter.write_text(
            f"""
import json
import os
from pathlib import Path

root = Path.cwd()
print("OAB_EVENT\\t" + json.dumps({{"seq": 1, "kind": "runtime_identity", "target": "sample/model", "outcome": "verified", "detail": {{"response_id": "resp-test", "adapter_version": "1.0"}}}}, sort_keys=True), flush=True)
{action}
""".lstrip(),
            encoding="utf-8",
        )
        return adapter

    def spec(self, fixture: Path, task: Path, adapter: Path) -> EpisodeSpec:
        return EpisodeSpec(
            case_id="sample_case",
            repetition=1,
            task_path=task,
            fixture_path=fixture,
            readable_relative_paths=("task.md", "input/value.txt", "work/seed.txt"),
            writable_relative_directories=("submission", "home", "tmp"),
            writable_relative_files=("work/seed.txt",),
            allowed_executables=(Path(sys.executable).resolve(),),
            adapter_read_paths=(adapter,),
            network=False,
        )

    def test_preparation_uses_external_root_and_seals_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, fixture, task, episode_base, _ = self.make_case(base)
            adapter = self.make_adapter(base, repository)
            prepared = prepare_episode(
                self.spec(fixture, task, adapter),
                repository_root=repository,
                episode_base=episode_base,
            )
            self.assertFalse(prepared.workspace.is_relative_to(repository))
            self.assertTrue(prepared.workspace.is_relative_to(episode_base.resolve()))
            self.assertEqual("sample-value\n", (prepared.workspace / "input/value.txt").read_text())
            self.assertFalse(bool((prepared.workspace / "input/value.txt").stat().st_mode & 0o222))
            self.assertFalse(bool((prepared.workspace / "task.md").stat().st_mode & 0o222))
            self.assertTrue((prepared.workspace / "home").is_dir())
            self.assertTrue((prepared.workspace / "tmp").is_dir())

    def test_preparation_does_not_stage_generated_python_caches(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, fixture, task, episode_base, _ = self.make_case(base)
            adapter = self.make_adapter(base, repository)
            cache = fixture / "work/__pycache__"
            cache.mkdir()
            (cache / "seed.cpython-311.pyc").write_bytes(b"generated")
            (fixture / "generated.pyo").write_bytes(b"generated")

            prepared = prepare_episode(
                self.spec(fixture, task, adapter),
                repository_root=repository,
                episode_base=episode_base,
            )

            generated = [
                path.relative_to(prepared.workspace).as_posix()
                for path in prepared.workspace.rglob("*")
                if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}
            ]
            self.assertEqual([], generated)

    def test_preparation_ignores_generated_cache_links_and_suffix_directories(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, fixture, task, episode_base, _ = self.make_case(base)
            adapter = self.make_adapter(base, repository)
            outside = base / "outside-cache"
            outside.write_bytes(b"outside")
            cache = fixture / "work/__pycache__"
            cache.mkdir()
            (cache / "linked.pyc").symlink_to(outside)
            os.link(outside, fixture / "work/hardlinked.pyc")
            suffix_directory = fixture / "work/generated.pyo"
            suffix_directory.mkdir()
            (suffix_directory / "visible.txt").write_text("ignored\n", encoding="utf-8")

            prepared = prepare_episode(
                self.spec(fixture, task, adapter),
                repository_root=repository,
                episode_base=episode_base,
            )

            self.assertFalse((prepared.workspace / "work/__pycache__").exists())
            self.assertFalse((prepared.workspace / "work/hardlinked.pyc").exists())
            self.assertFalse((prepared.workspace / "work/generated.pyo").exists())

    def test_run_denies_parent_access_and_captures_trace_and_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, fixture, task, episode_base, output = self.make_case(base)
            adapter = self.make_adapter(base, repository)
            result = run_episode(
                self.spec(fixture, task, adapter),
                command=[str(Path(sys.executable).resolve()), str(adapter)],
                repository_root=repository,
                episode_base=episode_base,
                output_dir=output,
                timeout_seconds=10,
            )
            self.assertTrue(result.completed, result)
            self.assertTrue(result.valid_for_scoring, result)
            artifact = json.loads((output / "workspace/submission/result.json").read_text())
            self.assertEqual({"value": "sample-value", "outside": "denied"}, artifact)
            events = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
            self.assertEqual([1, 2, 3], [event["seq"] for event in events])
            self.assertEqual("runtime_identity", events[0]["kind"])
            receipt = json.loads((output / "process-receipt.json").read_text())
            self.assertEqual("sandbox-exec", receipt["sandbox_backend"])
            self.assertEqual("denied", receipt["network_policy"])
            self.assertEqual("adapter_reported", receipt["trace_provenance"])
            self.assertTrue(receipt["stdout_sha256"])
            self.assertTrue(receipt["sandbox_profile_sha256"])
            self.assertTrue(receipt["boundary_probe"]["passed"])
            probe = json.loads((output / "boundary-probe.json").read_text())
            self.assertTrue(all(probe["checks"].values()), probe)

    def test_trusted_snapshot_rejects_submission_symlinks_and_hardlinks(self) -> None:
        for mode, expected in (("symlink", "symlink"), ("hardlink", "hardlink")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                base = Path(td).resolve()
                repository, fixture, task, episode_base, output = self.make_case(base)
                adapter = self.make_snapshot_adapter(base, repository, mode)
                with self.assertRaisesRegex(ValueError, expected):
                    run_episode(
                        self.spec(fixture, task, adapter),
                        command=[str(Path(sys.executable).resolve()), str(adapter)],
                        repository_root=repository,
                        episode_base=episode_base,
                        output_dir=output,
                        timeout_seconds=10,
                    )
                self.assertFalse((output / "workspace").exists())

    def test_trusted_snapshot_omits_generated_submission_caches(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, fixture, task, episode_base, output = self.make_case(base)
            adapter = self.make_snapshot_adapter(base, repository, "cache")
            result = run_episode(
                self.spec(fixture, task, adapter),
                command=[str(Path(sys.executable).resolve()), str(adapter)],
                repository_root=repository,
                episode_base=episode_base,
                output_dir=output,
                timeout_seconds=10,
            )
            self.assertTrue(result.valid_for_scoring)
            self.assertFalse((output / "workspace/submission/__pycache__").exists())

    def test_strict_public_spec_has_no_policy_escape_hatches(self) -> None:
        names = {field.name for field in fields(StrictEpisodeSpec)}
        self.assertFalse(
            names
            & {
                "network",
                "environment",
                "mounts",
                "sandbox_profile",
                "allowed_executables",
                "command",
            }
        )

    def test_preparation_rejects_run_root_that_is_repository_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve().resolve()
            repository, fixture, task, _, _ = self.make_case(base)
            adapter = self.make_adapter(base, repository)
            spec = EpisodeSpec(
                case_id="sample",
                repetition=1,
                task_path=task,
                fixture_path=fixture,
                readable_relative_paths=("task.md", "input"),
                writable_relative_directories=("submission", "home", "tmp"),
                writable_relative_files=("work/seed.txt",),
                allowed_executables=(Path(sys.executable).resolve(),),
                adapter_read_paths=(adapter,),
            )
            with self.assertRaisesRegex(ValueError, "disjoint"):
                prepare_episode(spec, repository_root=repository, episode_base=base)

    def test_preparation_rejects_hardlinked_fixture_alias(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve().resolve()
            repository, fixture, task, _, _ = self.make_case(base)
            adapter = self.make_adapter(base, repository)
            os.link(fixture / "input/value.txt", fixture / "input/alias.txt")
            spec = EpisodeSpec(
                case_id="sample",
                repetition=1,
                task_path=task,
                fixture_path=fixture,
                readable_relative_paths=("task.md", "input"),
                writable_relative_directories=("submission", "home", "tmp"),
                writable_relative_files=("work/seed.txt",),
                allowed_executables=(Path(sys.executable).resolve(),),
                adapter_read_paths=(adapter,),
            )
            with self.assertRaisesRegex(ValueError, "hardlink"):
                prepare_episode(
                    spec,
                    repository_root=repository,
                    episode_base=base / "episodes",
                )

    def test_missing_runtime_identity_invalidates_scoring(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            repository, fixture, task, episode_base, output = self.make_case(base)
            adapter = self.make_adapter(base, repository, identity=False)
            result = run_episode(
                self.spec(fixture, task, adapter),
                command=[str(Path(sys.executable).resolve()), str(adapter)],
                repository_root=repository,
                episode_base=episode_base,
                output_dir=output,
                timeout_seconds=10,
            )
            self.assertTrue(result.completed)
            self.assertFalse(result.valid_for_scoring)
            self.assertIn("runtime_identity_missing", result.invalid_reasons)


if __name__ == "__main__":
    unittest.main()
