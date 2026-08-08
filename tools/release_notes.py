"""Compose verified release notes for a tagged OAB release.

Run by .github/workflows/release.yml after CI has rebuilt the release from a
clean `git archive` export and confirmed the committed RELEASE_MANIFEST.json
matches that export. Emits a notes file whose digest block is computed from the
built artifacts rather than copied by hand -- the drift that forced the 2.0.2
release cannot recur.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import re
from pathlib import Path

_NOTES_TEMPLATE = """## Release digests

```
release tree : {tree_sha256}
wheel        : sha256:{wheel_sha256}
git commit   : {commit}
files        : {file_count}
```

Verify the wheel before installing:

```bash
gh release download {tag} --repo kcemate/operational-agent-benchmark --pattern '*.whl'
test "$(shasum -a 256 {wheel_name} | cut -d' ' -f1)" = "{wheel_sha256}" || exit 1
```

CI computed these digests from a clean `git archive` export of `{tag}` and
verified that the committed `RELEASE_MANIFEST.json` matches that export.

**What this check does and does not prove.** These digests are published on the
same page as the artifact they describe, so they detect a corrupted, truncated,
or substituted download — not a compromise of this repository, where the wheel
and this digest block could be rewritten together. `AGENTS.md` therefore asks
for digests obtained from a channel independent of the repository and wheel:
for high-assurance use, record these values somewhere you control as soon as
you read them, and verify future downloads against that copy rather than
against this page.

{changelog_section}
"""


def changelog_section(changelog: str, version: str) -> str:
    match = re.search(
        rf"^## {re.escape(version)}\b.*?(?=^## |\Z)",
        changelog,
        re.MULTILINE | re.DOTALL,
    )
    return match.group(0).strip() if match else "(no CHANGELOG entry found)"


def build_notes(
    *,
    tag: str,
    wheel_path: Path,
    manifest: dict,
    changelog: str,
    commit: str,
) -> str:
    version = tag.lstrip("v")
    wheel_sha256 = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    return _NOTES_TEMPLATE.format(
        tree_sha256=manifest["tree_sha256"],
        wheel_sha256=wheel_sha256,
        commit=commit,
        file_count=manifest["file_count"],
        tag=tag,
        wheel_name=wheel_path.name,
        changelog_section=changelog_section(changelog, version),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    parser.add_argument("--commit", default="")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    wheels = sorted(glob.glob(str(args.dist_dir / "*.whl")))
    if not wheels:
        raise SystemExit("no_wheel_built")
    notes = build_notes(
        tag=args.tag,
        wheel_path=Path(wheels[0]),
        manifest=json.loads(args.manifest.read_text(encoding="utf-8")),
        changelog=args.changelog.read_text(encoding="utf-8"),
        commit=args.commit,
    )
    args.output.write_text(notes, encoding="utf-8")
    print(notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
