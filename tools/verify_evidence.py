from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.evidence import verify_sealed_evidence


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify one sealed OAB v2 completed-tree evidence directory using "
            "result.json digests, canonical trace integrity, and output-tree manifest rehash."
        )
    )
    parser.add_argument(
        "evidence_dir",
        type=Path,
        help="Path to an episode evidence directory containing result.json",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full verification object as JSON",
    )
    args = parser.parse_args()
    result = verify_sealed_evidence(args.evidence_dir)
    if args.json:
        print(
            json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        )
    else:
        status = "VALID" if result["valid"] else "INVALID"
        print(f"{status} {result['evidence_dir']}")
        if result["errors"]:
            for error in result["errors"]:
                print(f"  - {error}")
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
