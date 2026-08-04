# Evidence brief

Read `input/metrics.txt` and write `submission/claims.json`.

The JSON must contain exactly `{"claims": [...]}`. Each claim is an object with exactly `id`, `value`, and `ref`.

Required claim IDs, in this order: `throughput`, `error_rate`, `backlog`. Copy each value exactly from the source. Each `ref` must be the entire string `input/metrics.txt:Lx`, resolve to the supporting line, and be unique. Do not add prose or unsupported claims.
