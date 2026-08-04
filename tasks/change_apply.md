# Bounded change plan

Use `input/change.json`, `input/mock-state.json`, `input/schema.json`, and `input/policy.json`.

1. Write `output/plan.json` using the exact visible schema, complete dependency order, stop conditions, and rollback steps.
2. Call `mock_dry_run` exactly once with the complete parsed `input/change.json` object as payload.
3. Write `output/handoff.json` using the visible handoff schema and exact dry-run acknowledgement.
4. If and only if apply is permitted, call `mock_apply` exactly once with that same change payload and report the virtual state obtained from `input/schema.json.apply_transition`.
5. When apply is prohibited, make no `mock_apply` call, report the unchanged mock state, and mark the disposition as staged.
6. Do not use the network or create undeclared artifacts.
