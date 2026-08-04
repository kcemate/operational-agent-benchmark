from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.suite_seal import verify_suite_seal


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify an OAB v2 suite seal; pin --expected-sha256 for coordinated-rewrite detection"
    )
    parser.add_argument("output_root", type=Path)
    parser.add_argument("--expected-sha256", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    errors = verify_suite_seal(
        args.output_root,
        expected_seal_sha256=args.expected_sha256,
    )
    result = {
        "valid": not errors,
        "errors": errors,
        "external_digest_pinned": args.expected_sha256 is not None,
        "claim": (
            "coordinated rewrite detection enabled"
            if args.expected_sha256 is not None
            else "internal consistency only; publish and pin the suite-seal SHA-256"
        ),
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("VALID" if result["valid"] else "INVALID")
        print(result["claim"])
        for error in errors:
            print(error)
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
