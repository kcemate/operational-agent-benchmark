from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Sequence


def verify_artifact(path: Path, expected_sha256: str) -> dict[str, object]:
    expected = expected_sha256.removeprefix("sha256:").lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise ValueError("expected_sha256_invalid")
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError("artifact_unreadable") from exc
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise ValueError("artifact_file_unsafe")
    if before.st_nlink != 1:
        raise ValueError("artifact_hardlink_rejected")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError("artifact_unreadable") from exc
    digest = hashlib.sha256()
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("artifact_file_unsafe")
        if opened.st_nlink != 1:
            raise ValueError("artifact_hardlink_rejected")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("artifact_changed_during_open")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(fd)
    observed = digest.hexdigest()
    return {
        "schema": "oab.bootstrap-artifact-verification/v1",
        "valid": observed == expected,
        "expected_sha256": "sha256:" + expected,
        "observed_sha256": "sha256:" + observed,
        "size_bytes": opened.st_size,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an OAB artifact before installation")
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        report = verify_artifact(args.artifact, args.expected_sha256)
    except (OSError, ValueError) as exc:
        print(json.dumps({"schema": "oab.bootstrap-artifact-verification/v1", "valid": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["valid"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
