from __future__ import annotations

import unittest
from typing import Mapping, cast

from oab.agent_workflow import (
    sanitize_hermes_inventory,
    select_model_comparison_inventory,
)


class ProviderGenericityTests(unittest.TestCase):
    def test_named_provider_is_never_special_cased_by_route_discovery(self) -> None:
        inventory = {
            "provider": "moa",
            "model": "virtual-model",
            "providers": [
                {"slug": "moa", "models": ["virtual-model"]},
                {"slug": "ordinary-provider", "models": ["ordinary-model"]},
            ],
        }

        discovery = sanitize_hermes_inventory(inventory)
        routes = {item["requested_route"] for item in discovery["routes"]}

        self.assertEqual({"moa/virtual-model", "ordinary-provider/ordinary-model"}, routes)
        self.assertEqual("moa/virtual-model", discovery["current_route"])

    def test_model_comparison_selection_is_provider_neutral(self) -> None:
        inventory = {
            "provider": "ordinary-provider",
            "model": "baseline",
            "providers": [
                {"slug": "ordinary-provider", "models": ["baseline"]},
                {"slug": "moa", "models": ["candidate"]},
            ],
        }

        selected = select_model_comparison_inventory(
            inventory, candidate_route="moa/candidate"
        )
        discovery = sanitize_hermes_inventory(selected)
        routes = cast(list[Mapping[str, object]], discovery["routes"])

        self.assertEqual("ordinary-provider/baseline", discovery["current_route"])
        self.assertEqual(
            {"ordinary-provider/baseline", "moa/candidate"},
            {route["requested_route"] for route in routes},
        )


if __name__ == "__main__":
    unittest.main()
