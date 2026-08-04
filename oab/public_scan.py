from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

_SKIPPED_DIRECTORIES = {".git", ".mypy_cache", ".pytest_cache", "__pycache__"}


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    term: str
    location: str


def load_denylist(path: Path) -> list[str]:
    terms = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not terms:
        raise ValueError("denylist is empty")
    return terms


def scan_tree(
    root: Path,
    terms: Iterable[str],
    *,
    exclude: set[str] | None = None,
) -> list[Finding]:
    excluded = exclude or set()
    normalized = [(term, term.casefold()) for term in terms if term]
    findings: list[Finding] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in _SKIPPED_DIRECTORIES for part in relative.parts):
            continue
        relative_text = relative.as_posix()
        if relative_text in excluded:
            continue
        folded_path = relative_text.casefold()
        for term, folded_term in normalized:
            if folded_term in folded_path:
                findings.append(Finding(relative_text, term, "path"))
        if not path.is_file():
            continue
        payload = path.read_bytes()
        if b"\x00" in payload:
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            continue
        folded_text = text.casefold()
        for term, folded_term in normalized:
            if folded_term in folded_text:
                findings.append(Finding(relative_text, term, "content"))
    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a public package for denied terms")
    parser.add_argument("root", type=Path)
    parser.add_argument("--denylist", required=True, type=Path)
    parser.add_argument("--exclude", action="append", default=[])
    args = parser.parse_args()
    findings = scan_tree(args.root, load_denylist(args.denylist), exclude=set(args.exclude))
    for finding in findings:
        print(f"{finding.path}:{finding.location}:{finding.term}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
