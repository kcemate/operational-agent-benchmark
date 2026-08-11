from __future__ import annotations

import unittest

from oab.agent_workflow import sanitize_hermes_inventory


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


if __name__ == "__main__":
    unittest.main()
