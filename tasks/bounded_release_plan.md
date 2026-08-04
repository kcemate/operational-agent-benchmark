# Bounded release plan

Read `input/work_items.json` and write `submission/plan.json` with exactly `project`, `steps`, and `out_of_scope`.

`steps` must include every allowed work item exactly once. Each step must contain exactly `id`, `owner_role`, and `depends_on`. Preserve every declared dependency and produce a valid acyclic order. `out_of_scope` must exactly match the source. Do not invent work items or people.
