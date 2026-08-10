from __future__ import annotations

import tomllib
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


class PackagingContractTests(unittest.TestCase):
    def test_frozen_release_tree_excludes_local_agent_runtime(self) -> None:
        """`.hermes/` must never be copied into the wheel's frozen release tree.

        It is git-ignored local agent runtime and plans; embedding it would both
        diverge from RELEASE_MANIFEST.json and publish untracked local state.
        """
        sys.path.insert(0, str(ROOT))
        try:
            spec = importlib.util.spec_from_file_location(
                "_oab_setup_under_test", ROOT / "setup.py"
            )
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            with patch("setuptools.setup"):
                spec.loader.exec_module(module)
            self.assertIn(".hermes", module.EXCLUDED_PARTS)
            offenders = [
                str(path)
                for path in module.release_files()
                if path.parts and path.parts[0] == ".hermes"
            ]
            self.assertEqual([], offenders)
        finally:
            sys.path.remove(str(ROOT))

    def test_frozen_release_tree_matches_release_manifest_exclusions(self) -> None:
        """setup.py and tools/release_manifest.py must agree on what is release content."""
        sys.path.insert(0, str(ROOT))
        try:
            spec = importlib.util.spec_from_file_location(
                "_oab_setup_exclusions", ROOT / "setup.py"
            )
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            with patch("setuptools.setup"):
                spec.loader.exec_module(module)
            from tools.release_manifest import _EXCLUDED_PARTS

            self.assertEqual(set(_EXCLUDED_PARTS), set(module.EXCLUDED_PARTS))
        finally:
            sys.path.remove(str(ROOT))

    def test_runtime_package_does_not_import_collision_prone_tools_namespace(self) -> None:
        offenders = []
        for path in sorted((ROOT / "oab").glob("*.py")):
            if "from tools." in path.read_text(encoding="utf-8"):
                offenders.append(path.name)

        self.assertEqual([], offenders)

    def test_source_suite_script_remains_directly_executable(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/run_suite.py"), "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stdout)

    def test_console_scripts_do_not_use_collision_prone_tools_namespace(self) -> None:
        config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        scripts = config["project"]["scripts"]

        self.assertTrue(scripts)
        self.assertFalse(
            any(target.startswith("tools.") for target in scripts.values()),
            "installed console scripts must not resolve through the generic top-level tools package",
        )

    def test_install_docs_do_not_assume_python_sibling_of_hermes(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

        for document in (readme, agents):
            self.assertNotIn('$(dirname "$(command -v hermes)")/python3', document)
            self.assertIn('python3 -m venv "$HOME/.local/share/oab-<version>"', document)
            self.assertIn('export PATH="$HOME/.local/share/oab-<version>/bin:$PATH"', document)

    def test_calibration_help_describes_all_deterministic_pairs(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/run_calibration.py"), "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stdout)
        self.assertNotIn("P01 approved/prohibited", completed.stdout)
        self.assertIn("eight", completed.stdout)
        self.assertIn("16 controls", completed.stdout)


if __name__ == "__main__":
    unittest.main()
