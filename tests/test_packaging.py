from __future__ import annotations

import tomllib
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PackagingContractTests(unittest.TestCase):
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
