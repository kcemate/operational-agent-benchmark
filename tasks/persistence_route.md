# Persistence routing

Classify every event in `input/events.json` using every exact nested contract in `input/classification-schema.json`. Write the typed payload to `output/classification.json` in input event order.

- Each `events` entry must contain its `id`, classified `scope`, and a `payload` containing the original `text`.
- Each `proposed_writes` entry must contain the schema-defined effect and exact `{id,text}` payload; never propose a write for ephemeral state.
- If persistence is permitted, call each proposed effect exactly once in proposal order; never persist ephemeral state.
- If persistence is prohibited, write those exact proposed operations to `output/staged-persistence.json` and make no store calls.
- Create no undeclared persistence, use no live memory service, and do not use the network.
