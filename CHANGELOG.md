# Changelog

All benchmark-affecting changes require a new version. Historical results remain bound to their recorded release-tree digest.

## 2.0.1 — 2026-08-07

- **Fixed a defect that made every suite seal impossible.** `_controller_usage_snapshot()` dropped `known_cost_usd` and `unknown_cost_api_calls` from its allowlist, so seal recomputation compared 5 keys against the report's 7 and always raised `suite_report_recomputation_mismatch:controller_usage`. No campaign on 2.0.0 could produce a `SUITE_SEAL.json`. The failure also cascaded: any `controller_usage` diagnostic was classified as `campaign_controller_telemetry_invalid`, excluding every route as `qualification_contract_invalid` with 0/34 coverage.
- **Fixed route attestation being erased by a malformed first model turn.** When a model emitted invalid protocol JSON on its opening turn, `begin()` raised before the runner recorded identity, leaving `requested_route`, `returned_route`, and `response_id` null. Aggregation then stamped the entire suite with `requested_route_mismatch`, `provider_returned_route_mismatch`, and `provider_response_id_missing`, so a handful of model-side protocol failures made an otherwise valid 80-episode suite permanently non-authoritative. Adapter-attested identity is now recovered and sealed on that path; a malformed turn scores as a model failure only.
- Added a macOS/`sandbox-exec` CI matrix leg. CI previously exercised only Linux/Bubblewrap, leaving the other shipped sandbox backend untested.
- Added an explicit Python >= 3.11 import guard so running the suite on an older interpreter fails with one clear message instead of dozens of unrelated errors.
- `RELEASE_MANIFEST.json` now derives `benchmark_version` from the package version instead of a hardcoded literal.

## 2.0.0 — 2026-08-03

- Introduced eight matched approved/prohibited operational pairs (16 cases).
- Added trusted-controller, typed-broker, sandbox-leaf execution.
- Added deterministic P01–P08 verifiers and adversarial regression tests.
- Added five-repetition suite aggregation, matched-pair stability, and infrastructure coverage.
- Excluded infrastructure-invalid episodes from model-failure denominators.
- Added explicit, attested Hermes reasoning-effort pinning.
- Added hash-chained episode evidence, release manifests, and externally pinnable suite seals.
- Added one-command Hermes runner, benchmark card, limitations, contribution policy, CI, and citation metadata.
- Fixed P07 release verification to consume the broker's real redacted effect receipt and added real-runner coverage.
- Finalized malformed first/later model turns as scoreable failures instead of aborting suites.
- Added strict registry path containment, symlink/hardlink rejection, and expanded finite DLP controls.
- Added whole-evidence manifests with receipt/trace cross-checks.
- Added bound token/latency/cost telemetry and an official non-scoring P01 calibration command.
- Added installable console commands and packaged the complete frozen benchmark data tree for clean-wheel execution.
- Bound output-tree digests into the parent-owned trace and made suite verification recompute every episode gate, grid, aggregate metric, usage field, and headline.
- Required successful, ordered P07 authority reads; separated infrastructure failures from scoreable model protocol failures.
- Required pinned reasoning effort, provider-returned route identity, frozen release identity, and an externally pinned two-reviewer release-approval receipt for authoritative status.
- Added Linux Bubblewrap no-fork enforcement through a compiled libseccomp filter and retained active process/network probes.

**Identity caveat:** Hermes CLI routes remain adapter-attested unless a provider-returned identity artifact is available.
