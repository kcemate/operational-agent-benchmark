from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class HoldoutAuthorshipTests(unittest.TestCase):
    def test_holdout_pairs_are_not_sol_authored(self) -> None:
        payload = json.loads((ROOT / "AUTHORSHIP.json").read_text(encoding="utf-8"))
        rows = payload["cases"]
        holdout = [row for row in rows if row["pair_id"] in {"P09", "P10"}]
        self.assertEqual(len(holdout), 4)
        for row in holdout:
            self.assertNotIn("gpt-5.6-sol", str(row.get("author_id", "")))
            self.assertNotIn("openai-codex/gpt-5.6-sol", json.dumps(row))
            self.assertEqual(row["author_class"], "moa")
            self.assertFalse(row.get("sol_touched"))


if __name__ == "__main__":
    unittest.main()
