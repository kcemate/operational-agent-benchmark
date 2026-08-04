from __future__ import annotations

import py_compile
import tempfile
import unittest
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path

from oab.paths import verify_installed_code_binding


class InstalledCodeBindingTests(unittest.TestCase):
    def test_installed_code_must_match_frozen_release_copies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            packages = base / "site-packages"
            frozen = base / "share" / "operational-agent-benchmark"
            for relative in ("oab/core.py", "tools/entry.py"):
                (packages / relative).parent.mkdir(parents=True, exist_ok=True)
                (frozen / relative).parent.mkdir(parents=True, exist_ok=True)
                (packages / relative).write_text("VALUE = 1\n", encoding="utf-8")
                (frozen / relative).write_text("VALUE = 1\n", encoding="utf-8")

            self.assertEqual([], verify_installed_code_binding(packages, frozen))
            (packages / "tools" / "entry.py").write_text("VALUE = 2\n", encoding="utf-8")
            self.assertIn(
                "installed_code_digest_mismatch:tools/entry.py",
                verify_installed_code_binding(packages, frozen),
            )

    def test_extra_or_missing_installed_module_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            packages = base / "site-packages"
            frozen = base / "share" / "operational-agent-benchmark"
            (packages / "oab").mkdir(parents=True)
            (frozen / "oab").mkdir(parents=True)
            (packages / "oab" / "extra.py").write_text("pass\n", encoding="utf-8")
            self.assertIn(
                "installed_code_path_set_mismatch:oab",
                verify_installed_code_binding(packages, frozen),
            )

    def test_bytecode_shadow_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            packages = base / "site-packages"
            frozen = base / "share" / "operational-agent-benchmark"
            for root in (packages, frozen):
                (root / "oab").mkdir(parents=True)
                (root / "oab" / "core.py").write_text("VALUE = 1\n", encoding="utf-8")
            cache = packages / "oab" / "__pycache__"
            cache.mkdir()
            shadow = cache / "core.cpython-311.pyc"
            shadow.write_bytes(b"malicious-bytecode")

            self.assertIn(
                "installed_code_shadow_artifact:oab/__pycache__/core.cpython-311.pyc",
                verify_installed_code_binding(packages, frozen),
            )

    def test_native_extension_shadow_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            packages = base / "site-packages"
            frozen = base / "share" / "operational-agent-benchmark"
            for root in (packages, frozen):
                (root / "oab").mkdir(parents=True)
                (root / "oab" / "core.py").write_text("VALUE = 1\n", encoding="utf-8")
            extension = packages / "oab" / f"core{EXTENSION_SUFFIXES[0]}"
            extension.write_bytes(b"malicious-native-module")

            self.assertIn(
                f"installed_code_shadow_artifact:oab/{extension.name}",
                verify_installed_code_binding(packages, frozen),
            )

    def test_bytecode_compiled_from_verified_source_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            packages = base / "site-packages"
            frozen = base / "share" / "operational-agent-benchmark"
            for relative in ("oab/core.py", "tools/entry.py"):
                for root in (packages, frozen):
                    (root / relative).parent.mkdir(parents=True, exist_ok=True)
                    (root / relative).write_text("VALUE = 1\n", encoding="utf-8")
                py_compile.compile(str(packages / relative), doraise=True)

            self.assertEqual([], verify_installed_code_binding(packages, frozen))


if __name__ == "__main__":
    unittest.main()
