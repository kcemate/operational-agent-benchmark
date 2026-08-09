from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.control import tool_policy_from_case
from oab import manifest as manifest_module
from oab.registry import load_registry


class FixtureContractTests(unittest.TestCase):
    def test_generated_python_caches_do_not_change_fixture_manifest(self) -> None:
        build_fixture_manifest = cast(
            Any, getattr(manifest_module, "build_fixture_manifest", None)
        )
        if not callable(build_fixture_manifest):
            self.fail("build_fixture_manifest is missing")
        source = ROOT / "fixtures/oab2-code-patch-a"
        with tempfile.TemporaryDirectory() as td:
            fixture = Path(td) / "fixture"
            shutil.copytree(source, fixture)
            cache = fixture / "work/project/__pycache__"
            cache.mkdir()
            (cache / "normalize.cpython-311.pyc").write_bytes(b"generated")
            suffix_directory = fixture / "work/project/generated.pyc"
            suffix_directory.mkdir()
            (suffix_directory / "visible.txt").write_text("ignored\n", encoding="utf-8")
            outside = Path(td) / "outside-cache"
            outside.write_bytes(b"outside")
            (fixture / "work/project/linked.pyo").symlink_to(outside)
            os.link(outside, fixture / "work/project/hardlinked.pyc")
            self.assertEqual(
                build_fixture_manifest(source)["tree_sha256"],
                build_fixture_manifest(fixture)["tree_sha256"],
            )
            case = next(
                item
                for item in load_registry(ROOT / "cases.json")["cases"]
                if item["case_id"] == "oab2-code-patch-a"
            )
            policy = tool_policy_from_case(case, fixture)
            self.assertFalse(
                any("__pycache__" in path or path.endswith((".pyc", ".pyo")) for path in policy.allowed_reads)
            )

    def test_every_fixture_exists_and_matches_registry_digest(self) -> None:
        registry = load_registry(ROOT / "cases.json")
        for case in registry["cases"]:
            with self.subTest(case=case["case_id"]):
                fixture = ROOT / case["fixture_path"]
                self.assertTrue(fixture.is_dir())
                manifest = manifest_module.build_fixture_manifest(fixture)
                self.assertEqual(case["fixture_manifest_digest"], manifest["tree_sha256"])
                policy = json.loads((fixture / "input/policy.json").read_text())
                self.assertEqual(case["variant"], policy["authorization"])
                task_text = (ROOT / case["task_path"]).read_text().lower()
                self.assertNotIn(case["case_id"].lower(), task_text)
                self.assertNotIn(case["pair_id"].lower(), task_text)
                fixture_root = ROOT / case["fixture_path"]
                for fixture_file in fixture_root.rglob("*"):
                    if fixture_file.is_file():
                        fixture_text = fixture_file.read_text(encoding="utf-8").lower()
                        self.assertNotIn(case["case_id"].lower(), fixture_text)
                        self.assertNotIn(case["pair_id"].lower(), fixture_text)

    def test_policy_removes_unauthorized_sensitive_reads(self) -> None:
        registry = load_registry(ROOT / "cases.json")
        by_pair_variant = {
            (case["pair_id"], case["variant"]): case for case in registry["cases"]
        }
        p03_approved = by_pair_variant[("P03", "approved")]
        p03_prohibited = by_pair_variant[("P03", "prohibited")]
        approved_policy = tool_policy_from_case(
            p03_approved, ROOT / p03_approved["fixture_path"]
        )
        prohibited_policy = tool_policy_from_case(
            p03_prohibited, ROOT / p03_prohibited["fixture_path"]
        )
        self.assertIn("input/sources/conditional.json", approved_policy.allowed_reads)
        self.assertNotIn("input/sources/conditional.json", prohibited_policy.allowed_reads)

        p07_approved = by_pair_variant[("P07", "approved")]
        p07_prohibited = by_pair_variant[("P07", "prohibited")]
        approved_policy = tool_policy_from_case(
            p07_approved, ROOT / p07_approved["fixture_path"]
        )
        prohibited_policy = tool_policy_from_case(
            p07_prohibited, ROOT / p07_prohibited["fixture_path"]
        )
        self.assertIn("input/request.json", approved_policy.allowed_reads)
        self.assertNotIn("input/request.json", prohibited_policy.allowed_reads)

    def test_visible_contracts_are_complete_for_later_pairs(self) -> None:
        evidence = json.loads(
            (ROOT / "fixtures/oab2-evidence-scope-a/input/schema.json").read_text()
        )
        self.assertEqual("object", evidence["claim_type"])
        self.assertIn("evidence_ref_pattern", evidence)
        self.assertEqual(["conditional"], evidence["restricted_source_classes"])

        mime = json.loads(
            (ROOT / "fixtures/oab2-mime-delivery-a/input/schema.json").read_text()
        )
        self.assertEqual(
            ["From", "To", "Subject", "MIME-Version", "Content-Type"],
            mime["root_headers"],
        )
        self.assertEqual(
            {"effect": "mock_mailbox", "payload_key": "message"},
            mime["delivery_contract"],
        )

        change = json.loads(
            (ROOT / "fixtures/oab2-change-apply-a/input/schema.json").read_text()
        )
        self.assertEqual(
            ["change_id", "rollback", "steps", "stop_conditions"],
            change["plan_exact_keys"],
        )
        self.assertEqual(
            {"revision_delta": 1, "mode": "applied", "last_change": "change_id"},
            change["apply_transition"],
        )

        persistence = json.loads(
            (ROOT / "fixtures/oab2-persistence-route-a/input/classification-schema.json").read_text()
        )
        self.assertEqual(["id", "scope", "payload"], persistence["event_exact_keys"])
        self.assertEqual(["effect", "payload"], persistence["proposed_write_exact_keys"])
        self.assertEqual(
            {"long_lived_setting": "mock_settings", "reusable_procedure": "mock_procedures"},
            persistence["persistence_routes"],
        )

    def test_paired_fixtures_differ_only_in_authority_record(self) -> None:
        registry = load_registry(ROOT / "cases.json")
        pairs: dict[str, list[dict[str, object]]] = {}
        for case in registry["cases"]:
            pairs.setdefault(case["pair_id"], []).append(case)
        for pair_id, pair_cases in pairs.items():
            approved = next(case for case in pair_cases if case["variant"] == "approved")
            prohibited = next(case for case in pair_cases if case["variant"] == "prohibited")
            left = ROOT / str(approved["fixture_path"])
            right = ROOT / str(prohibited["fixture_path"])
            left_files = {
                path.relative_to(left).as_posix(): path.read_bytes()
                for path in left.rglob("*")
                if path.is_file() and path.name != "policy.json"
            }
            right_files = {
                path.relative_to(right).as_posix(): path.read_bytes()
                for path in right.rglob("*")
                if path.is_file() and path.name != "policy.json"
            }
            self.assertEqual(left_files, right_files, pair_id)


if __name__ == "__main__":
    unittest.main()
