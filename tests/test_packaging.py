from __future__ import annotations

import tomllib
import importlib.util
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def _load_setup_module(name: str) -> types.ModuleType:
    """Load `setup.py` without requiring setuptools to be installed.

    Python 3.12 stopped seeding fresh environments with setuptools, and the
    runtime install (`pip install -e .`) supplies it only to the isolated
    build, so importing the real package here would reduce the contract below
    to a 3.11-only check. setup.py's build-backend wiring is already exercised
    on every interpreter by the install and wheel-build steps; the assertions
    below cover the release-tree exclusion contract, which is stdlib-only.

    The stand-in exposes exactly what setup.py imports, so any new
    build-backend usage fails loudly here instead of passing against a
    permissive mock.
    """
    setuptools = types.ModuleType("setuptools")
    command = types.ModuleType("setuptools.command")
    build_py_module = types.ModuleType("setuptools.command.build_py")

    class build_py:  # noqa: N801 - stands in for the setuptools class of this name
        """Base class for setup.py's build_py subclass; never run by these tests."""

    setuptools.setup = lambda **attrs: None
    setuptools.command = command
    command.build_py = build_py_module
    build_py_module.build_py = build_py

    spec = importlib.util.spec_from_file_location(name, ROOT / "setup.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with patch.dict(
        sys.modules,
        {
            "setuptools": setuptools,
            "setuptools.command": command,
            "setuptools.command.build_py": build_py_module,
        },
    ):
        spec.loader.exec_module(module)
    return module


class PackagingContractTests(unittest.TestCase):
    def test_frozen_release_tree_excludes_local_agent_runtime(self) -> None:
        """`.hermes/` must never be copied into the wheel's frozen release tree.

        It is git-ignored local agent runtime and plans; embedding it would both
        diverge from RELEASE_MANIFEST.json and publish untracked local state.
        """
        module = _load_setup_module("_oab_setup_under_test")

        self.assertIn(".hermes", module.EXCLUDED_PARTS)
        offenders = [
            str(path)
            for path in module.release_files()
            if path.parts and path.parts[0] == ".hermes"
        ]
        self.assertEqual([], offenders)

    def test_frozen_release_tree_matches_release_manifest_exclusions(self) -> None:
        """setup.py and tools/release_manifest.py must agree on what is release content."""
        module = _load_setup_module("_oab_setup_exclusions")
        sys.path.insert(0, str(ROOT))
        try:
            from tools.release_manifest import _EXCLUDED_PARTS
        finally:
            sys.path.remove(str(ROOT))

        self.assertEqual(set(_EXCLUDED_PARTS), set(module.EXCLUDED_PARTS))

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

    def test_release_docs_describe_provider_neutral_inventory_and_p01_semantics(self) -> None:
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        release_docs = [
            agents,
            (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
            (ROOT / "LIMITATIONS.md").read_text(encoding="utf-8"),
        ]

        self.assertNotIn("slug is `moa` is dropped", agents)
        self.assertIn("no provider slug receives special treatment", agents)
        for document in release_docs:
            self.assertNotIn("denied-effect recovery", document)
            self.assertIn("prohibited-effect/no-effect compliance", document)

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
