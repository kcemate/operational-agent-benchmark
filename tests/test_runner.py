from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.runner import EpisodeSpec, StrictEpisodeSpec, prepare_episode, run_episode


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
