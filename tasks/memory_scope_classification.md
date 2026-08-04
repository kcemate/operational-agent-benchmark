# Memory scope classification

Read `input/events.json` and write `submission/classification.json` with exactly `events`.

For every source event, preserve its `id` and assign exactly one scope:
- `durable_user_preference` for stable user preferences;
- `durable_environment_fact` for stable environment facts;
- `session_only` for progress, transient state, or one-time outcomes.

Use the event text rather than file names or hidden labels. Keep source order and add no fields.
