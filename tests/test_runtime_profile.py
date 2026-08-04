from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import yaml

from oab.runtime_profile import pinned_hermes_runtime


class PinnedHermesRuntimeTests(unittest.TestCase):
    def test_overrides_effort_links_credentials_and_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source"
            source.mkdir()
            (source / "config.yaml").write_text(
                "agent:\n  model: sample\n  reasoning_effort: xhigh\n",
                encoding="utf-8",
            )
            auth = source / "auth.json"
            auth.write_text("opaque-credential-store", encoding="utf-8")
            with pinned_hermes_runtime("medium", source_home=source) as runtime:
                runtime_home = runtime.home
                self.assertEqual(runtime.reasoning_effort, "medium")
                self.assertRegex(runtime.config_sha256, r"^sha256:[0-9a-f]{64}$")
                config = yaml.safe_load((runtime.home / "config.yaml").read_text())
                self.assertEqual(config["agent"]["reasoning_effort"], "medium")
                self.assertEqual(config["agent"]["max_iterations"], 1)
                self.assertTrue((runtime.home / "auth.json").is_symlink())
                self.assertEqual((runtime.home / "auth.json").resolve(), auth.resolve())
                self.assertEqual(os.stat(runtime.home).st_mode & 0o777, 0o700)
                self.assertEqual(os.stat(runtime.home / "config.yaml").st_mode & 0o777, 0o600)
            self.assertFalse(runtime_home.exists())

    def test_rejects_unknown_effort(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            source = Path(td)
            (source / "config.yaml").write_text("agent: {}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "reasoning_effort_invalid"):
                with pinned_hermes_runtime("ultra", source_home=source):
                    pass

    def test_rejects_symlinked_source_config(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "actual.yaml"
            target.write_text("agent: {}\n", encoding="utf-8")
            source = root / "source"
            source.mkdir()
            (source / "config.yaml").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "source_hermes_config_invalid"):
                with pinned_hermes_runtime("high", source_home=source):
                    pass


if __name__ == "__main__":
    unittest.main()
