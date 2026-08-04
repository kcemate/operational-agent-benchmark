from __future__ import annotations

import copy
import sys
import unittest
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.registry import load_registry, validate_registry


class RegistryContractTests(unittest.TestCase):
    def test_builtin_registry_is_complete_generic_and_pair_balanced(self) -> None:
        registry = load_registry(ROOT / "cases.json")
        findings = validate_registry(registry, ROOT)
        self.assertEqual([], findings)
        metadata = registry["benchmark"]
        self.assertEqual("Operational Agent Benchmark", metadata["name"])
        self.assertEqual(2, metadata["version"])
        self.assertEqual(5, metadata["default_repetitions"])
        self.assertEqual("deterministic_contract_completion_rate", metadata["primary_metric"])
        self.assertEqual(16, len(registry["cases"]))
        self.assertEqual(8, len({case["domain"] for case in registry["cases"]}))

        pairs: dict[str, list[dict[str, object]]] = defaultdict(list)
        for case in registry["cases"]:
            pairs[case["pair_id"]].append(case)
        self.assertEqual(8, len(pairs))
        for pair_id, cases in pairs.items():
            self.assertEqual(2, len(cases), pair_id)
            self.assertEqual({"approved", "prohibited"}, {case["variant"] for case in cases})
            self.assertEqual(1, len({case["task_path"] for case in cases}), pair_id)
            self.assertEqual(1, len({case["domain"] for case in cases}), pair_id)

    def test_every_requirement_has_exactly_one_evaluation_basis(self) -> None:
        registry = load_registry(ROOT / "cases.json")
        allowed = {"hard", "trace", "semantic", "unscored"}
        for owner in [registry, *registry["cases"]]:
            gates = owner["universal_gates"] if owner is registry else owner["gates"]
            gate_ids = {gate["id"] for gate in gates}
            requirements = (
                owner["universal_requirements"]
                if owner is registry
                else owner["requirements"]
            )
            for requirement in requirements:
                self.assertIn(requirement["disposition"], allowed, requirement)
                if requirement["disposition"] == "unscored":
                    self.assertEqual([], requirement["gate_ids"])
                    self.assertTrue(requirement["reason"])
                    self.assertTrue(requirement["claim_exclusion"])
                else:
                    self.assertTrue(requirement["gate_ids"], requirement)
                    self.assertLessEqual(set(requirement["gate_ids"]), gate_ids)

    def test_every_case_declares_artifacts_effects_semantics_and_limitations(self) -> None:
        registry = load_registry(ROOT / "cases.json")
        for case in registry["cases"]:
            self.assertIsInstance(case["allowed_artifacts"], list)
            self.assertIsInstance(case["allowed_effects"], list)
            self.assertIsInstance(case["semantic_dimensions"], list)
            self.assertIsInstance(case["unscored_limitations"], list)
            self.assertTrue(case["fixture_manifest_digest"].startswith("sha256:"))
            self.assertEqual(71, len(case["fixture_manifest_digest"]))

    def test_case_ids_are_stable_and_public_facing(self) -> None:
        registry = load_registry(ROOT / "cases.json")
        self.assertEqual(
            {
                f"oab2-{stem}-{variant}"
                for stem in (
                    "data-rollup",
                    "code-patch",
                    "evidence-scope",
                    "mime-delivery",
                    "change-apply",
                    "directive-authority",
                    "canary-release",
                    "persistence-route",
                )
                for variant in ("a", "p")
            },
            {case["case_id"] for case in registry["cases"]},
        )

    def test_each_domain_and_variant_has_equal_episode_weight(self) -> None:
        registry = load_registry(ROOT / "cases.json")
        repetitions = registry["benchmark"]["default_repetitions"]
        domain_counts = Counter(case["domain"] for case in registry["cases"])
        variant_counts = Counter(case["variant"] for case in registry["cases"])
        self.assertEqual({2}, set(domain_counts.values()))
        self.assertEqual({8}, set(variant_counts.values()))
        self.assertEqual(80, repetitions * len(registry["cases"]))

    def test_absolute_task_path_is_rejected_even_when_file_exists(self) -> None:
        registry = copy.deepcopy(load_registry(ROOT / "cases.json"))
        registry["cases"][0]["task_path"] = str((ROOT / "tasks/data_rollup.md").resolve())
        findings = validate_registry(registry, ROOT)
        self.assertTrue(
            any("task path is invalid" in finding for finding in findings),
            findings,
        )

    def test_fixture_traversal_is_rejected(self) -> None:
        registry = copy.deepcopy(load_registry(ROOT / "cases.json"))
        registry["cases"][0]["fixture_path"] = "fixtures/../../../../tmp"
        findings = validate_registry(registry, ROOT)
        self.assertTrue(
            any("fixture path is invalid" in finding for finding in findings),
            findings,
        )


if __name__ == "__main__":
    unittest.main()
