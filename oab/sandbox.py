from __future__ import annotations

import ctypes
import ctypes.util
import errno
import hashlib
import os
import platform
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Mapping, Sequence


class SandboxUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxPolicy:
    workspace: Path
    read_only: tuple[Path, ...]
    writable: tuple[Path, ...]
    allowed_executables: tuple[Path, ...]
    writable_files: tuple[Path, ...] = ()
    network: bool = False

    def environment(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        env = dict(extra or {})
        home = self.workspace / "home"
        temp = self.workspace / "tmp"
        env.update(
            {
                "HOME": str(home),
                "TMPDIR": str(temp),
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "OAB_WORKSPACE": str(self.workspace),
            }
        )
        return env


@dataclass(frozen=True)
class SandboxResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    profile_sha256: str


def _quote_profile(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _kill_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class MacOSSandboxBackend:
    executable = Path("/usr/bin/sandbox-exec")
    name = "macos-sandbox-exec"

    def build_profile(self, policy: SandboxPolicy) -> str:
        if not policy.allowed_executables:
            raise SandboxUnavailable("sandbox policy has no allowed executables")
        system_read_paths = (
            Path("/System"),
            Path("/usr/lib"),
            Path("/usr/share"),
            Path("/private/etc/localtime"),
            Path("/private/var/db/timezone"),
            Path("/dev/null"),
            Path("/dev/random"),
            Path("/dev/urandom"),
        )
        runtime_paths = {
            executable.resolve().parent.parent
            for executable in policy.allowed_executables
        }
        lines = [
            "(version 1)",
            "(deny default)",
            "(allow process-info*)",
            "(deny process-fork)",
            "(allow sysctl-read (sysctl-name \"security.mac.lockdown_mode_state\"))",
            "(allow sysctl-read (sysctl-name \"kern.bootargs\"))",
        ]
        allowed_read_paths = {*system_read_paths, *runtime_paths, *policy.read_only}
        ancestors: set[Path] = set()
        for allowed_path in allowed_read_paths | set(policy.writable) | set(policy.writable_files):
            resolved = allowed_path.resolve()
            ancestors.update(resolved.parents)
        for ancestor in sorted(ancestors, key=str):
            lines.append(
                f"(allow file-read-metadata file-read-data (literal {_quote_profile(str(ancestor))}))"
            )
        for path in sorted(allowed_read_paths, key=str):
            resolved = path.resolve()
            clause = "subpath" if resolved.is_dir() else "literal"
            lines.append(f"(allow file-read* ({clause} {_quote_profile(str(resolved))}))")
        for path in sorted(policy.writable, key=str):
            resolved = path.resolve()
            lines.append(f"(allow file-read* (subpath {_quote_profile(str(resolved))}))")
            lines.append(f"(allow file-write* (subpath {_quote_profile(str(resolved))}))")
        for path in sorted(policy.writable_files, key=str):
            resolved = path.resolve()
            lines.append(f"(allow file-read* (literal {_quote_profile(str(resolved))}))")
            lines.append(f"(allow file-write* (literal {_quote_profile(str(resolved))}))")
        executable_filters = " ".join(
            f"(literal {_quote_profile(str(executable.resolve()))})"
            for executable in sorted(policy.allowed_executables, key=str)
        )
        for executable in sorted(policy.allowed_executables, key=str):
            lines.append(
                f"(allow process-exec (literal {_quote_profile(str(executable.resolve()))}))"
            )
        lines.append(
            f"(deny process-exec (require-not (require-any {executable_filters})))"
        )
        if policy.network:
            lines.append("(allow network*)")
        return "\n".join(lines) + "\n"

    def run(
        self,
        policy: SandboxPolicy,
        command: Sequence[str],
        *,
        timeout_seconds: float,
        extra_env: Mapping[str, str] | None = None,
    ) -> SandboxResult:
        if not self.executable.is_file():
            raise SandboxUnavailable(f"missing sandbox backend: {self.executable}")
        if not command:
            raise ValueError("command must not be empty")
        normalized_executable = Path(command[0]).resolve()
        allowed = {path.resolve() for path in policy.allowed_executables}
        if normalized_executable not in allowed:
            raise SandboxUnavailable("command executable is not allowlisted")
        for directory in policy.writable:
            directory.mkdir(parents=True, exist_ok=True)
        for writable_file in policy.writable_files:
            writable_file.parent.mkdir(parents=True, exist_ok=True)
            writable_file.touch(exist_ok=True)
        profile = self.build_profile(policy)
        profile_hash = hashlib.sha256(profile.encode("utf-8")).hexdigest()
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".sb", delete=False
        ) as handle:
            handle.write(profile)
            profile_path = Path(handle.name)
        full_command = [
            str(self.executable),
            "-f",
            str(profile_path),
            str(normalized_executable),
            *command[1:],
        ]
        process = subprocess.Popen(
            full_command,
            cwd=policy.workspace,
            env=policy.environment(extra_env),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(process.pid)
            stdout, stderr = process.communicate()
        finally:
            _kill_process_group(process.pid)
            profile_path.unlink(missing_ok=True)
        return SandboxResult(
            command=tuple(full_command),
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            profile_sha256=profile_hash,
        )


class BubblewrapBackend:
    name = "linux-bubblewrap"

    def __init__(self, executable: Path) -> None:
        self.executable = executable

    @staticmethod
    def _configure_seccomp_library(library: Any) -> None:
        library.seccomp_init.argtypes = [ctypes.c_uint32]
        library.seccomp_init.restype = ctypes.c_void_p
        library.seccomp_release.argtypes = [ctypes.c_void_p]
        library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        library.seccomp_syscall_resolve_name.restype = ctypes.c_int
        library.seccomp_rule_add.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint,
        ]
        library.seccomp_rule_add.restype = ctypes.c_int
        library.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
        library.seccomp_export_bpf.restype = ctypes.c_int

    @staticmethod
    def _denied_syscalls(*, network: bool) -> tuple[bytes, ...]:
        process_syscalls = (b"clone", b"clone3", b"fork", b"vfork")
        if network:
            return process_syscalls
        return process_syscalls + (b"socket", b"connect", b"sendto", b"sendmsg")

    @staticmethod
    def _containment_seccomp_program(*, network: bool) -> tuple[BinaryIO, bytes]:
        library_path = ctypes.util.find_library("seccomp")
        if not library_path:
            raise SandboxUnavailable("libseccomp is required for Linux no-fork containment")
        try:
            library = ctypes.CDLL(library_path)
        except OSError as exc:
            raise SandboxUnavailable("libseccomp could not be loaded") from exc
        BubblewrapBackend._configure_seccomp_library(library)

        allow = 0x7FFF0000
        deny = 0x00050000 | errno.EPERM
        context = library.seccomp_init(allow)
        if not context:
            raise SandboxUnavailable("seccomp filter initialization failed")
        handle: BinaryIO | None = None
        try:
            for name in BubblewrapBackend._denied_syscalls(network=network):
                syscall = library.seccomp_syscall_resolve_name(name)
                if syscall < 0:
                    raise SandboxUnavailable(
                        f"seccomp syscall mapping unavailable: {name.decode('ascii')}"
                    )
                result = library.seccomp_rule_add(
                    context,
                    ctypes.c_uint32(deny),
                    ctypes.c_int(syscall),
                    ctypes.c_uint(0),
                )
                if result != 0:
                    raise SandboxUnavailable(
                        f"seccomp rule installation failed: {name.decode('ascii')}"
                    )
            handle = tempfile.TemporaryFile(mode="w+b")
            if library.seccomp_export_bpf(context, handle.fileno()) != 0:
                raise SandboxUnavailable("seccomp BPF export failed")
            handle.flush()
            handle.seek(0)
            payload = handle.read()
            if not payload:
                raise SandboxUnavailable("seccomp BPF export was empty")
            handle.seek(0)
            return handle, payload
        except Exception:
            if handle is not None:
                handle.close()
            raise
        finally:
            library.seccomp_release(context)

    @staticmethod
    def _runtime_bind_roots(policy: SandboxPolicy) -> tuple[Path, ...]:
        system_roots = (Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64"))
        roots: set[Path] = set()
        for executable in policy.allowed_executables:
            resolved = executable.resolve()
            if any(resolved == root or resolved.is_relative_to(root) for root in system_roots):
                continue
            candidate = resolved.parent.parent if resolved.parent.name in {"bin", "sbin"} else resolved.parent
            if candidate == Path("/"):
                raise SandboxUnavailable("non-system executable runtime root is too broad")
            roots.add(candidate)
        return tuple(sorted(roots, key=lambda item: str(item)))

    def build_command(
        self,
        policy: SandboxPolicy,
        command: Sequence[str],
        *,
        seccomp_fd: int,
    ) -> list[str]:
        if seccomp_fd < 0:
            raise SandboxUnavailable("seccomp filter fd is invalid")
        args = [
            str(self.executable),
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
        ]
        for system_root in (Path("/lib"), Path("/lib64")):
            if system_root.exists():
                args.extend(["--ro-bind", str(system_root), str(system_root)])
        created_directories: set[Path] = set()
        for runtime_root in self._runtime_bind_roots(policy):
            for parent in reversed(runtime_root.parents):
                if parent == Path("/") or parent in created_directories:
                    continue
                args.extend(["--dir", str(parent)])
                created_directories.add(parent)
            args.extend(["--ro-bind", str(runtime_root), str(runtime_root)])
        args.extend(["--seccomp", str(seccomp_fd)])
        for path in policy.read_only:
            resolved = str(path.resolve())
            args.extend(["--ro-bind", resolved, resolved])
        for path in policy.writable:
            resolved = str(path.resolve())
            args.extend(["--bind", resolved, resolved])
        for path in policy.writable_files:
            resolved = str(path.resolve())
            args.extend(["--bind", resolved, resolved])
        args.append("--share-net" if policy.network else "--unshare-net")
        env = policy.environment()
        for key, value in sorted(env.items()):
            args.extend(["--setenv", key, value])
        args.extend(["--chdir", str(policy.workspace.resolve()), "--", *command])
        return args

    def run(
        self,
        policy: SandboxPolicy,
        command: Sequence[str],
        *,
        timeout_seconds: float,
        extra_env: Mapping[str, str] | None = None,
    ) -> SandboxResult:
        if not command:
            raise ValueError("command must not be empty")
        normalized = Path(command[0]).resolve()
        if normalized not in {path.resolve() for path in policy.allowed_executables}:
            raise SandboxUnavailable("command executable is not allowlisted")
        for directory in policy.writable:
            directory.mkdir(parents=True, exist_ok=True)
        for writable_file in policy.writable_files:
            writable_file.parent.mkdir(parents=True, exist_ok=True)
            writable_file.touch(exist_ok=True)
        seccomp_file, seccomp_payload = self._containment_seccomp_program(
            network=policy.network
        )
        try:
            seccomp_fd = seccomp_file.fileno()
            full_command = self.build_command(
                policy,
                [str(normalized), *command[1:]],
                seccomp_fd=seccomp_fd,
            )
            env = policy.environment(extra_env)
            digest_command = list(full_command)
            digest_command[digest_command.index("--seccomp") + 1] = "<seccomp-fd>"
            command_hash = hashlib.sha256(
                "\0".join(digest_command).encode("utf-8")
                + b"\0"
                + seccomp_payload
            ).hexdigest()
            process = subprocess.Popen(
                full_command,
                cwd=policy.workspace,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
                pass_fds=(seccomp_fd,),
            )
            timed_out = False
            try:
                stdout, stderr = process.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_process_group(process.pid)
                stdout, stderr = process.communicate()
            finally:
                _kill_process_group(process.pid)
        finally:
            seccomp_file.close()
        return SandboxResult(
            command=tuple(full_command),
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            profile_sha256=command_hash,
        )


def macos_backend() -> MacOSSandboxBackend:
    return MacOSSandboxBackend()


def select_backend(
    *,
    platform_name: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
):
    name = (platform_name or platform.system()).lower()
    if name in {"darwin", "macos"} and which("sandbox-exec"):
        return MacOSSandboxBackend()
    if name == "linux" and (path := which("bwrap")):
        return BubblewrapBackend(Path(path))
    raise SandboxUnavailable(f"no supported fail-closed sandbox backend for {name}")
