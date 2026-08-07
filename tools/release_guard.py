"""Guard a tagged release: manifest freshness and version/tag agreement.

Run by .github/workflows/release.yml before anything is built or published.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def check_manifest(exported: Path, committed: Path) -> list[str]:
    exported_manifest = json.loads(exported.read_text(encoding="utf-8"))
    committed_manifest = json.loads(committed.read_text(encoding="utf-8"))
    if exported_manifest["tree_sha256"] != committed_manifest["tree_sha256"]:
        return [
            "release_manifest_stale: committed RELEASE_MANIFEST.json does not match "
            "the tagged tree",
            f"  committed = {committed_manifest['tree_sha256']}",
            f"  exported  = {exported_manifest['tree_sha256']}",
            "  Regenerate with tools/release_manifest.py, commit, and retag.",
        ]
    return []


def check_version(tag: str, version: str) -> list[str]:
    expected = tag.lstrip("v")
    if expected != version:
        return [f"version_mismatch: tag={expected} package={version}"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--exported-manifest", type=Path, required=True)
    parser.add_argument("--committed-manifest", type=Path, required=True)
    args = parser.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from oab import __version__

    errors = check_manifest(args.exported_manifest, args.committed_manifest)
    errors.extend(check_version(args.tag, __version__))
    if errors:
        for line in errors:
            print(line, file=sys.stderr)
        return 1
    print(f"release guard passed: {args.tag} (version {__version__})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
