from __future__ import annotations

import errno
import json
import os
import socket
import sys
from pathlib import Path


def _safe_target(workspace: Path, logical: str) -> Path:
    if logical.startswith("/"):
        raise ValueError("absolute path denied")
    parts = Path(logical).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("non-normalized path denied")
    target = workspace.joinpath(*parts)
    if not target.parent.resolve().is_relative_to(workspace.resolve()):
        raise ValueError("path escape denied")
    return target


def _read_text(path: Path, max_bytes: int) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        data = os.read(descriptor, max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("read limit exceeded")
        return data.decode("utf-8")
    finally:
        os.close(descriptor)


def _write_text(path: Path, text: str, max_bytes: int) -> int:
    data = text.encode("utf-8")
    if len(data) > max_bytes:
        raise ValueError("write limit exceeded")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        written = os.write(descriptor, data)
        os.fsync(descriptor)
        if written != len(data):
            raise OSError("short write")
        return written
    finally:
        os.close(descriptor)


def _permission_denied(exc: BaseException) -> bool:
    return isinstance(exc, OSError) and exc.errno in {errno.EACCES, errno.EPERM}


def _boundary_probe(request: dict[str, object]) -> dict[str, object]:
    read_path = request.get("probe_read_path")
    write_path = request.get("probe_write_path")
    if not isinstance(read_path, str) or not isinstance(write_path, str):
        raise ValueError("probe paths must be strings")
    checks: dict[str, bool] = {}
    try:
        Path(read_path).read_bytes()
    except Exception as exc:
        checks["outside_read_denied"] = _permission_denied(exc)
    else:
        checks["outside_read_denied"] = False
    try:
        Path(write_path).write_text("escape", encoding="utf-8")
    except Exception as exc:
        checks["outside_write_denied"] = _permission_denied(exc)
    else:
        checks["outside_write_denied"] = False
        Path(write_path).unlink(missing_ok=True)
    try:
        process_id = os.fork()
    except Exception as exc:
        checks["process_fork_denied"] = _permission_denied(exc)
    else:
        if process_id == 0:
            os._exit(0)
        os.waitpid(process_id, 0)
        checks["process_fork_denied"] = False
    try:
        process_id = os.posix_spawn("/usr/bin/true", ["true"], {})
    except Exception as exc:
        checks["unlisted_exec_denied"] = _permission_denied(exc)
    else:
        os.waitpid(process_id, 0)
        checks["unlisted_exec_denied"] = False
    try:
        probe_socket = socket.socket()
    except Exception as exc:
        checks["network_denied"] = _permission_denied(exc)
    else:
        probe_socket.settimeout(0.2)
        try:
            probe_socket.connect(("127.0.0.1", 9))
        except Exception as exc:
            checks["network_denied"] = _permission_denied(exc)
        else:
            checks["network_denied"] = False
        finally:
            probe_socket.close()
    return {"ok": True, "checks": checks, "passed": all(checks.values())}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return 64
    request_path = Path(argv[1])
    response_path = Path(argv[2])
    workspace = Path(os.environ["OAB_WORKSPACE"]).resolve()
    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        operation = request.get("operation")
        if operation == "boundary_probe":
            response = _boundary_probe(request)
        else:
            logical = request.get("path")
            if not isinstance(logical, str):
                raise ValueError("path must be a string")
            target = _safe_target(workspace, logical)
            max_bytes = request.get("max_bytes")
            if not isinstance(max_bytes, int) or max_bytes < 0:
                raise ValueError("max_bytes must be nonnegative")
            if operation == "read_text":
                response = {"ok": True, "text": _read_text(target, max_bytes)}
            elif operation == "write_text":
                text = request.get("text")
                if not isinstance(text, str):
                    raise ValueError("text must be a string")
                response = {"ok": True, "bytes_written": _write_text(target, text, max_bytes)}
            else:
                raise ValueError("unsupported operation")
    except Exception as exc:
        response = {"ok": False, "error": type(exc).__name__, "message": str(exc)}
    response_path.write_text(
        json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
