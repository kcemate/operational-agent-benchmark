from __future__ import annotations

import ctypes
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.sandbox import (
    BubblewrapBackend,
    SandboxPolicy,
    SandboxUnavailable,
    macos_backend,
    select_backend,
)


@unittest.skipUnless(sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file(), "macOS sandbox required")
class MacOSSandboxTests(unittest.TestCase):
    def test_profile_has_no_broad_process_mach_sysctl_or_metadata_grants(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "episode"
            for relative in ("input", "submission", "home", "tmp"):
                (workspace / relative).mkdir(parents=True)
            policy = SandboxPolicy(
                workspace=workspace,
                read_only=(workspace / "input",),
                writable=(workspace / "submission", workspace / "home", workspace / "tmp"),
                allowed_executables=(Path(sys.executable).resolve(),),
            )
            profile = macos_backend().build_profile(policy)
            self.assertNotIn("(allow process*)", profile)
            self.assertNotIn("(allow mach*)", profile)
            self.assertNotIn("\n(allow sysctl-read)\n", profile)
            self.assertNotIn("\n(allow file-read-metadata)\n", profile)
            self.assertIn("(deny process-fork)", profile)

    def test_policy_allows_case_paths_and_denies_outside_paths_and_executables(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            workspace = base / "episode"
            outside = base / "outside.txt"
            outside.write_text("outside-secret", encoding="utf-8")
            for relative in ("input", "work", "submission", "home", "tmp"):
                (workspace / relative).mkdir(parents=True)
            (workspace / "input/allowed.txt").write_text("allowed", encoding="utf-8")
            script = workspace / "work/probe.py"
            script.write_text(
                """
import json, os, pathlib, socket, subprocess
root = pathlib.Path(os.environ['OAB_WORKSPACE'])
result = {
  'allowed_read': (root / 'input/allowed.txt').read_text(),
  'home': os.environ['HOME'],
  'tmpdir': os.environ['TMPDIR'],
  'home_empty': list(pathlib.Path(os.environ['HOME']).iterdir()) == [],
  'tmp_empty': list(pathlib.Path(os.environ['TMPDIR']).iterdir()) == [],
}
(root / 'submission/result.txt').write_text('written')
for name, action in {
  'outside_read_denied': lambda: pathlib.Path(os.environ['OAB_OUTSIDE']).read_text(),
  'outside_write_denied': lambda: pathlib.Path(os.environ['OAB_OUTSIDE']).write_text('changed'),
  'unlisted_exec_denied': lambda: subprocess.run(['/bin/cat', str(root / 'input/allowed.txt')], check=True),
}.items():
    try:
        action()
    except Exception:
        result[name] = True
    else:
        result[name] = False
try:
    pathlib.Path('/etc/passwd').read_text()
except Exception:
    result['system_secret_denied'] = True
else:
    result['system_secret_denied'] = False
try:
    child = os.fork()
except Exception:
    result['fork_denied'] = True
else:
    if child == 0:
        os._exit(0)
    os.waitpid(child, 0)
    result['fork_denied'] = False
try:
    connection = socket.create_connection(('127.0.0.1', 9), timeout=0.2)
except PermissionError:
    result['network_denied'] = True
except OSError as exc:
    result['network_denied'] = getattr(exc, 'errno', None) in {1, 13}
else:
    connection.close()
    result['network_denied'] = False
print(json.dumps(result, sort_keys=True))
""".strip()
                + "\n",
                encoding="utf-8",
            )
            policy = SandboxPolicy(
                workspace=workspace,
                read_only=(workspace / "input", script),
                writable=(workspace / "work", workspace / "submission", workspace / "home", workspace / "tmp"),
                allowed_executables=(Path(sys.executable).resolve(),),
                network=False,
            )
            result = macos_backend().run(
                policy,
                [sys.executable, str(script)],
                timeout_seconds=10,
                extra_env={"OAB_OUTSIDE": str(outside)},
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(result.stdout, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual("allowed", payload["allowed_read"])
            self.assertEqual(str(workspace / "home"), payload["home"])
            self.assertEqual(str(workspace / "tmp"), payload["tmpdir"])
            self.assertTrue(payload["home_empty"])
            self.assertTrue(payload["tmp_empty"])
            self.assertTrue(payload["outside_read_denied"])
            self.assertTrue(payload["outside_write_denied"])
            self.assertTrue(payload["unlisted_exec_denied"])
            self.assertTrue(payload["system_secret_denied"])
            self.assertTrue(payload["fork_denied"])
            self.assertTrue(payload["network_denied"])
            self.assertEqual("outside-secret", outside.read_text(encoding="utf-8"))
            self.assertEqual("written", (workspace / "submission/result.txt").read_text())
            self.assertTrue(result.profile_sha256)


class SandboxSelectionTests(unittest.TestCase):
    def test_seccomp_ctypes_signature_preserves_64_bit_filter_context(self) -> None:
        class CFunction:
            def __init__(self) -> None:
                self.argtypes: list[object] = []
                self.restype: object | None = None

        class Library:
            seccomp_init = CFunction()
            seccomp_release = CFunction()
            seccomp_syscall_resolve_name = CFunction()
            seccomp_rule_add = CFunction()
            seccomp_export_bpf = CFunction()

        library = Library()
        BubblewrapBackend._configure_seccomp_library(library)
        self.assertEqual(
            [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint],
            library.seccomp_rule_add.argtypes,
        )
        self.assertIs(ctypes.c_int, library.seccomp_rule_add.restype)

    def test_bubblewrap_command_installs_seccomp_filter_fd(self) -> None:
        policy = SandboxPolicy(
            workspace=Path("/tmp/episode"),
            read_only=(),
            writable=(Path("/tmp/episode/home"), Path("/tmp/episode/tmp")),
            allowed_executables=(Path("/usr/bin/python3"),),
            network=False,
        )
        command = BubblewrapBackend(Path("/usr/bin/bwrap")).build_command(
            policy,
            ["/usr/bin/python3", "leaf.py"],
            seccomp_fd=17,
        )
        index = command.index("--seccomp")
        self.assertEqual("17", command[index + 1])
        self.assertIn("--unshare-net", command)

    def test_backend_selection_fails_closed_when_platform_backend_is_missing(self) -> None:
        with self.assertRaises(SandboxUnavailable):
            select_backend(platform_name="linux", which=lambda _: None)

    def test_environment_is_minimal_and_does_not_inherit_parent_values(self) -> None:
        policy = SandboxPolicy(
            workspace=Path("/tmp/episode"),
            read_only=(),
            writable=(Path("/tmp/episode/home"), Path("/tmp/episode/tmp")),
            allowed_executables=(Path("/usr/bin/python3"),),
            network=False,
        )
        env = policy.environment({"SAFE_INPUT": "yes", "PATH": "/attacker/bin", "HOME": "/private"})
        self.assertEqual("yes", env["SAFE_INPUT"])
        self.assertEqual("/usr/bin:/bin", env["PATH"])
        self.assertEqual("/tmp/episode/home", env["HOME"])
        self.assertEqual("/tmp/episode/tmp", env["TMPDIR"])
        self.assertNotIn("USER", env)


if __name__ == "__main__":
    unittest.main()
