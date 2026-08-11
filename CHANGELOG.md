# Changelog

All benchmark-affecting changes require a new version. Historical results remain bound to their recorded release-tree digest. References below to publishing, wheels, releases, or CI are historical and exact-tree scoped: they do not attest an untagged, dirty, or later checkout.

## 2.3.0 — unreleased release candidate (2026-08-10)

**Qualification redesign to bounded multi-turn plumbing probes. Scoring-affecting for qualification semantics only; full-suite quality metrics unchanged.** Replaces the misleading 34 one-call qualification mini-benchmark with two deterministic probes per route (approved tool loop + denied-effect recovery), each capped at four provider calls. Absolute reserve is 16 calls/route (one infrastructure-only retry per probe). Qualification emits READY / NOT READY / INCOMPATIBLE readiness only — never completion-rate or “0% model” quality headlines. Missing billed cost remains unknown/null (never coerced to $0); missing API-call counts remain infrastructure-invalid. New campaigns default to the v2.3.0 contract; do not resume v2.2.3 qualification receipts under this release identity. Full comparison remains 80 episodes/route with a 17-call episode ceiling.

**Signed campaign-child authority hardening.** Public readiness and full children now reconstruct authority only from the signed parent campaign: `PLAN.json`, calibration digest, v5 detached stage approval, route, reasoning effort, cost policy, and descriptor-bound output location. Mutable `--qualification-contract-json` is refused. Unsigned proofs and route, effort, PLAN, approval-key, cost-policy, or output-path substitutions reject before controller construction. Full-stage authority is exact P01–P08 × approved/prohibited × five repetitions (80 episodes/route, ≤17 calls/episode, 1,360 calls/route); custom or partial plans remain non-authoritative. Campaign verification also binds stage approvals to the parent campaign root and exact plan rather than detached CLI arguments.

This is a source release candidate, not a publication claim: no tag, wheel, release-note digest, hosted CI result, or release approval may be inferred from this entry. Those artifacts must be created and verified against the final clean tree separately.

## 2.2.3 — 2026-08-09

**Suite-sealing path-normalization and containment repair. Not scoring-affecting.** Descriptor-bound suite creation records episode evidence paths relative to the suite root, but v2.2.2 recomputed those paths as absolute paths before comparing the report. The same evidence directory therefore failed with `suite_report_recomputation_mismatch:observations`, preventing every production suite from receiving a seal. Recomputed observations now preserve either exact supported representation. Suite sealing also traverses the suite hierarchy through retained no-follow descriptors, snapshots each episode from its bound directory into a private verification view, and revalidates every directory entry before accepting the seal; intermediate symlinks, substitutions, hardlinks, and source mutation fail closed. Production-shaped and adversarial regressions cover relative paths plus `evidence` and `rep-NN` symlink substitution during both sealing and verification. The fixed suite files — `suite-report.json`, `HEADLINE.txt`, and `SUITE_SEAL.json` — are now opened only through retained `O_NOFOLLOW` descriptors that require single-link regular files, and are consumed from their retained bytes; symlink aliases and any post-read mutation, including mutate-then-restore, fail closed. Episode evidence carries the same guarantee: full directory metadata and content state is recorded before the private snapshot and revalidated afterwards, so post-snapshot source mutation and swap/restore are rejected. Private snapshot cleanup is descriptor- and inode-bound: the snapshot leaf is created inside a trusted temporary parent, bound through a retained `O_DIRECTORY|O_NOFOLLOW` descriptor without ever resolving its pathname, and removed only while that name still lstats to the exact inode this call created — a substituted temporary pathname is left untouched rather than deleted. Snapshot verification is additionally rooted in the retained snapshot descriptor itself rather than in the leaf's mutable absolute pathname, so no security-relevant consumer resolves or follows that pathname and a post-binding rename or symlink substitution cannot redirect a single read to a victim directory; the post-yield identity check remains defense in depth rather than the first point of detection. Seal publication no longer stages and renames at all: `SUITE_SEAL.json` is created directly at its final name with `O_CREAT|O_EXCL|O_NOFOLLOW`, so the published inode is by construction the one this call created, there is no check-then-rename ownership gap, and no pre-existing seal can be overwritten or displaced by a substituted inode. Rerun semantics are explicit: a byte-identical reseal is idempotent and writes nothing, while any other existing content at the seal name fails closed with `suite_seal_publication_unsafe`; every raising path leaves the publication unpublished, and cleanup unlinks the seal name only while it still maps to the owned inode. Spend authorization was also tightened: `approval-request --conversation-approval-reference` is refused with `conversation_approval_not_host_verified` and an unverified conversational receipt cannot authorize `resume`, because no host-backed verifier exists to prove that a quoted message reference exists or approves these exact controls. Conversational no-spend preview and explicit user approval remain required; spend-capable execution requires the externally signed Ed25519 stage approval path, which is unchanged and still accepted. A relocated relative-path suite still verifies against its externally pinned seal digest, and a legacy absolute-path suite remains bound to its recorded location; `LIMITATIONS.md` limitation 24 and the `oab-calibrate` help text (all eight deterministic pairs, 16 controls) were corrected to match.

Evidence for this release is reported in two distinct sets and they are not interchangeable: the original 21-case containment audit (`oab_security_audit_v223.py`, 21/21) covers symlink, substitution, hardlink and mutation containment for suite sealing and verification, and was authored before these repairs; the new race regressions are separate deterministic tests added in `tests/test_suite_seal.py` and `tests/test_agent_workflow*.py` covering the post-yield snapshot pathname-substitution race, the seal publication ownership race and its rerun semantics, and rejection of unverified conversational approval receipts. Passing the 21-case audit does not by itself demonstrate the race repairs, and vice versa.

## 2.2.2 — 2026-08-08

**Workflow-integrity and installation repair. Not scoring-affecting.** New campaign receipts keep the embedded `suite_report` identical to the sealed report; elapsed time and suite-verification state remain orchestration metadata. Verification and resume accept historical 2.2.1 receipts only when those two legacy annotations are complete, valid, and the remaining report exactly matches the sealed source; ambiguous dual encoding fails closed. Fixture integrity, policy construction, verification, and staging now consistently exclude pip-generated `__pycache__`, `.pyc`, and `.pyo` artifacts, while all authored fixture files remain digest-bound.

## 2.2.1 — 2026-08-08

**Workflow bug fix. Not scoring-affecting.** The 2.2.0 all-pairs calibrator correctly emitted `oab.calibration-report/v2`, but campaign initialization still accepted only the retired v1 schema and stopped with `calibration_schema_invalid` before any model call. Campaign recording and verification now accept both v1 historical receipts and current v2 receipts. CLI integration tests execute the v2 path.

## 2.2.0 — 2026-08-08

**Validity milestone. Not scoring-affecting** — no gate, oracle, or metric changed, so 2.1.1 rates remain comparable.

### Every pair is now proven satisfiable

Calibration covered `P01` only. That proved the harness could carry one pair end to end, but seven domain oracles had never been shown to accept a correct solution — so a 0% campaign score could not be attributed to the model rather than to an unreachable gate. The benchmark's only published result is 0.0% on every route, which made this the most load-bearing gap in the project.

- New `oab/controls_all_pairs.py` provides deterministic, non-model controls for `P02`–`P08`. Each reads the same inputs a model would, derives its answer from those inputs, and drives the real broker; none is hardcoded to a fixture value it has not read.
- `tools/run_calibration.py` now runs **all 16 cases** (8 pairs × approved/prohibited) instead of 2. Report schema is `oab.calibration-report/v2`, adding `pairs_calibrated`, `cases_expected`, and `cases_passed`.
- **Result: 16/16 pass** through the real sandbox, broker, verifier, and sealing paths, with every declared gate green and sealed evidence valid.
- `tests/test_all_pairs_calibration.py` pins this with one test per case, so a regression names the pair that broke. A coverage test additionally fails if a newly registered case ships without a control, and asserts no control can ever earn model credit.

This closes the F3 finding from the internal review: **a 0% score is now attributable to the model.**

Controls remain non-scoring: `execution_class=calibration_control`, `identity_source=deterministic_control`, excluded from completion-rate denominators.

`LIMITATIONS.md` #20 is rewritten accordingly, and states plainly what all-pairs calibration still does *not* prove — that difficulty is well calibrated, that results generalize beyond this harness, or that a control's solution is the only acceptable one.

## 2.1.1 — 2026-08-08

**Benchmark-affecting. Scoring-integrity fix.** A candidate could forge a passing test gate, so completion rates from 2.1.0 and earlier are not comparable for pair P02.

### Test gates no longer trust an exit code

`COD-TESTS` and `preserved_tests` decided success from the child process return code. `unittest discover` imports a candidate module before it collects tests, so two lines at module scope —

```python
import os
os._exit(0)
```

— exited with status 0 before a single test ran and were scored as a clean pass. A deliberately wrong implementation could pass every declared gate on P02. The hash gate on the test files did not help: the tests were untouched, they simply never executed.

- The sandboxed runner now writes a nonce-bound JSON attestation reporting `testsRun`, failures, errors, and loader errors. The gate requires that document to exist, to carry the expected nonce, and to report **exactly** the number of tests declared by the hash-pinned test files, with zero failures and zero errors.
- Expected test count is derived by static AST parse of the pinned test files — no import, so candidate code cannot influence it. An unparseable file fails closed as `tests_not_countable`.
- The exit status is no longer consulted at all. Any early exit produces no attestation, which is `tests_did_not_run` — a hard failure.
- New failure codes: `tests_did_not_run`, `tests_not_countable`.
- Failure detail now carries assertion text from the attestation rather than scraped stdout, so `oab explain` output is unchanged in substance.
- Adversarial regression tests cover `os._exit(0)` at import, `atexit`-registered `os._exit`, import-time raise, silent test skipping, nonce mismatch, and a fabricated/malformed document. `tests/test_verifier_test_attestation.py` plus a case-level exploit test against the real P02 registry entry.

**Disclosed residual risk** (`LIMITATIONS.md` #25): the runner shares an interpreter with candidate code and the nonce is therefore readable in-process. A model that deliberately fabricates an attestation can still defeat the gate. That is overt fabrication rather than an innocuous early exit, but it is not closed; closing it requires observing execution from outside the sandboxed interpreter.

## 2.1.0 — 2026-08-07

**Benchmark-affecting.** Protocol normalization changes which episodes are scoreable, so rates are not comparable with 2.0.x. The suite-report schema gained diagnostic fields.

### Diagnosability

The first real full campaign produced 0.0% completion on both routes with 100% infrastructure coverage, and the report could not say why. Reconstructing the cause required manually decoding evidence payloads. That is now first-class output.

- Suite reports and per-pair rows carry `gate_failures` (per-gate evaluated/failed counts with a failure-code histogram) and `first_failing_gate` (which gate ends episodes first). `HEADLINE.txt` appends `top_gate_failure` when completion is below 100%.
- New `oab explain <evidence-dir>` prints a per-episode post-mortem: task text, live-recomputed gate results, the model's final response, produced artifacts, and — for schema gates — the declared keys beside the keys actually produced. This surfaces the "right values, wrong shape" failure directly.
- Added `diagnostic_gate_pass_rate` (passed gate evaluations ÷ total evaluations). It is **diagnostic only**: excluded from `HEADLINE.txt` and never consulted by decision logic, enforced by test. It distinguishes routes that tie at 0% completion.

### Protocol normalization

- A single markdown code fence wrapping an otherwise-valid protocol turn is now unwrapped and counted rather than failing the episode. In the first campaign, 90 of 160 episodes failed protocol parsing, largely because small models emit fenced JSON; production harnesses strip fences, so failing them measured chat-template habit rather than operational competence.
- Only one fence enclosing the entire response is accepted. Prose around a fence, trailing commentary, multiple fences, and invalid inner JSON all remain `controller_protocol_invalid`. Normalization never repairs a payload.
- Disclosed as `protocol_normalized_turns` per episode receipt and `protocol_normalized_turn_total` / `protocol_normalized_episodes` per suite.

### Release integrity

- New tag-driven release workflow rebuilds from a clean `git archive` export, verifies the committed `RELEASE_MANIFEST.json` matches that export and that the package version equals the tag, runs the suite, builds the wheel, and opens a **draft** release whose digest block is computed by CI. It never publishes automatically.
- New test asserts the committed manifest matches the working tree on every push, so manifest staleness is caught before a tag exists. This is the defect class that forced the 2.0.2 release.

## 2.0.2 — 2026-08-07

Documentation and packaging only. No harness, verifier, or scoring behavior changed from 2.0.1.

- Rewrote `README.md` around the decision a Hermes user is actually making, led with the agent-native workflow, and documented the free local-route on-ramp.
- Because `README.md` is part of the hashed release tree, this changes the release-tree digest. 2.0.2 exists so the published digest matches `main` exactly; a clone of `main` verified against the 2.0.1 digest would otherwise mismatch.

## 2.0.1 — 2026-08-07

- **Fixed macOS framework-interpreter execution, which broke every episode on stock python.org installs.** The sandbox allowlists `process-exec` by literal path, but a framework CPython ships `<prefix>/bin/python3.x` as a stub that `posix_spawn`s `<prefix>/Resources/Python.app/Contents/MacOS/Python`. That target was never allowlisted, so every leaf failed with `boundary_probe_execution_failed` and no episode could complete. The re-exec target is now allowlisted in both the grant and the deny filter, only when the framework layout is present on disk. Development machines using a standalone CPython (whose `python3` is the real binary) never hit this, which is why it survived to release.
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
