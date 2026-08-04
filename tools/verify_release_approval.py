from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.release_approval import verify_release_approval


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify an OAB v2 release-approval receipt against an exact release tree "
            "and externally published receipt digest"
        )
    )
    parser.add_argument("approval", type=Path)
    parser.add_argument("--release-tree-sha256", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = verify_release_approval(
        args.approval,
        expected_release_tree_sha256=args.release_tree_sha256,
        expected_file_sha256=args.expected_sha256,
    )
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("VALID" if result["valid"] else "INVALID")
        print(f"release_tree_sha256={result['release_tree_sha256']}")
        print(f"approval_file_sha256={result['file_sha256']}")
        errors = result.get("errors")
        if isinstance(errors, list):
            for error in errors:
                print(error)
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
