from __future__ import annotations

import unittest
from pathlib import Path
import contextlib
import io
import shutil
import tempfile
from unittest.mock import patch
from typing import cast

from tools import sync_contract_docs

from oab.full_stage_contract import canonical_full_stage_contract

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = ("README.md", "BENCHMARK_CARD.md", "LIMITATIONS.md", "AGENTS.md")


class PublicContractDocumentationTests(unittest.TestCase):
    def test_all_live_documents_publish_current_ordered_execution_grid(self):
        contract = canonical_full_stage_contract()
        pairs = ", ".join(f"`{pair}`" for pair in cast(list[str], contract["pair_ids"]))
        expected = f"- Decision grid (ordered): {pairs}."
        for name in DOCUMENTS:
            with self.subTest(document=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn(expected, text)
                self.assertIn("<!-- OAB:CONTRACT:START -->", text)
                self.assertIn("<!-- OAB:CONTRACT:END -->", text)


    def test_live_prose_does_not_describe_retired_grid_or_decision_rule(self):
        retired = ("P01–P08", "`P01`–`P08`", "`P01`-`P08`",
                   "all eight pairs (16 cases)", "all 8 pairs (16 cases)",
                   "without* regressing matched pairs or the weakest pair")
        for name in DOCUMENTS:
            text = (ROOT / name).read_text(encoding="utf-8")
            for phrase in retired:
                with self.subTest(document=name, phrase=phrase):
                    self.assertNotIn(phrase, text)

    def test_contract_blocks_are_current_and_regeneration_is_idempotent(self):
        block = sync_contract_docs.contract_block(ROOT)
        for name in DOCUMENTS:
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertEqual(text, sync_contract_docs.replace_contract_block(text, block))

    def test_check_detects_drift_without_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (*DOCUMENTS, "cases.json"):
                shutil.copyfile(ROOT / name, root / name)
            path = root / "README.md"
            path.write_text(path.read_text().replace("`P09`", "`P03`"))
            before = {name: (root / name).read_bytes() for name in DOCUMENTS}
            with patch.object(sync_contract_docs, "ROOT", root), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(1, sync_contract_docs.main(["--check"]))
            self.assertEqual(before, {name: (root / name).read_bytes() for name in DOCUMENTS})

    def test_benchmark_card_names_actual_selection_metric(self):
        text = (ROOT / "BENCHMARK_CARD.md").read_text(encoding="utf-8")
        self.assertIn("**Primary metric:** `official_score` (`oab.championship-score/v1`)", text)
        self.assertNotIn("**Primary metric:** `deterministic_contract_completion_rate`", text)
        self.assertNotIn("contract completion — active (primary)", text)

    def test_calibration_help_describes_registry_not_retired_grid(self):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/run_calibration.py"), "--help"],
            capture_output=True, text=True, cwd=ROOT, check=True,
        )
        self.assertIn("all registered", " ".join(result.stdout.split()))
        self.assertNotIn("16 controls", result.stdout)

    def test_malformed_markers_fail_closed(self):
        block = sync_contract_docs.contract_block(ROOT)
        for text in (sync_contract_docs.START, sync_contract_docs.END,
                     sync_contract_docs.END + sync_contract_docs.START,
                     sync_contract_docs.START + block):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, "contract_markers_invalid"):
                    sync_contract_docs.replace_contract_block(text, block)


if __name__ == "__main__":
    unittest.main()
