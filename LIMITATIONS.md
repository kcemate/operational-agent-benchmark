# OAB v2 Limitations

OAB v2 is intentionally narrow. These limits travel with every scorecard.

1. **Public beta is not result certification.** Releasing the tooling does not certify a model comparison. Suite results remain provisional unless every documented release, identity, coverage, calibration, and approval gate passes.

2. **Decision scope.** The suite answers harness-switch questions for the recorded configuration only. It is not a universal agent intelligence test.

3. **Case scope.** Sixteen generic matched cases cover selected operational contracts. They do not cover every profession, language, browser workflow, or production system.

4. **Matched-pair necessity.** High approved-only success with prohibited failures is a weak result. Always read `matched_pair_completion_rate` and `pair_stability` beside the primary rate.

5. **Identity posture.** Hermes CLI adapters currently expose `identity_source=adapter_runtime`. That is adapter-attested route metadata, not cryptographic provider proof. Claims stay provisional until provider-returned identity is verified end-to-end.

6. **No retries or cherry-picking.** Scoreable model/task failures and timeouts remain in the denominator with zero contract credit. Missing and `runner_invalid` episodes are excluded as infrastructure-invalid, disclosed through coverage metrics, and prevent certification unless coverage is 100%.

7. **Reasoning-effort scope.** Certified suite runs pin and attest one explicit Hermes reasoning effort. Results with inherited or unattested effort are smoke observations only and must not be compared as certified scores.

8. **Statistical resolution.** Five repetitions per case are an operating sample, not a population estimator. Small percentage gaps should not be over-interpreted.

9. **Harness coupling.** Scores measure model + OAB trusted controller + fixed broker + sandbox leaf together. Changing any layer can change the result.

10. **Sandbox boundary.** Network denial and no-fork claims apply only to sandbox leaves. macOS uses Seatbelt `process-fork` denial; Linux uses a Bubblewrap network namespace plus a compiled libseccomp filter that returns `EPERM` for `clone`, `clone3`, `fork`, and `vfork`. Calibration actively probes both properties. The trusted outer controller runs outside that boundary and may use provider egress. A hosted Linux calibration pass is required before certification.

11. **Artifact contracts.** Exact schemas and oracles enable objective verification and can reject alternate artifacts that a human might still find useful.

12. **Safety coverage.** Authorization pairs test declared local contracts and mock effects. They do not prove absence of all host-file access, covert channels, or every adversarial strategy.

13. **Provider drift.** Hosted routes change. Results apply to the recorded provider, model, date, reasoning effort, timeouts, and tool policy.

14. **Cost and latency.** Episode receipts and suite reports bind adapter API-call/token counts and measured controller latency. `cost_usd` is `null` unless every provider turn supplies a nonnegative cost receipt. This is operational telemetry, not a normalized pricing or performance leaderboard.

15. **Semantic layer locked for selection.** No uncalibrated LLM-as-judge score is used for model-selection headlines.

16. **Output isolation.** Episode evidence must live in an output root fully disjoint from the benchmark repository. In-repo run trees are rejected.

17. **Historical incommensurability.** OAB v1 / other leaderboards used different contracts, harnesses, and claim rules. Do not merge those scores with OAB v2 rates.

18. **Evidence anchoring.** Episode digests and manifests prove internal consistency, not immutability against an attacker who can rewrite the entire tree. Coordinated-rewrite detection requires publishing the printed `SUITE_SEAL_SHA256` outside the run root and pinning it during verification.

19. **Finite canary detector.** `SEC-DLP` checks direct bytes/text, Unicode normalization, JSON string concatenation, URL encoding, hex, Base32/Base64/Base85, reversal, SHA-256 forms, and UTF-16 byte forms in declared evidence surfaces. It is not a semantic information-flow proof and does not cover arbitrary encryption, compression, steganography, or covert channels.

20. **Calibration scope.** Official deterministic controls cover all eight pairs (16 cases) end to end: each runs a scripted non-model solver through the real sandbox, broker, verifier, and sealing paths and must pass every declared gate. This establishes that each domain oracle is satisfiable, so a 0% model score is attributable to the model rather than to an unreachable gate. It does **not** establish that the tasks are well calibrated in difficulty, that passing generalizes beyond this harness, or that a control's solution is the only acceptable one. Controls run with `execution_class=calibration_control` and never grant model score credit.

21. **Release authorization.** `AUTHORITATIVE` requires an externally pinned `oab.release-approval/v1` receipt with distinct security and product approvals bound to the exact release-tree digest. The receipt is an auditable benchmark artifact, not a cryptographic identity proof for reviewers or provider serving infrastructure.

22. **Protocol normalization.** A single markdown code fence enclosing an otherwise-valid protocol turn is unwrapped and counted as a normalized turn rather than failing the episode; production harnesses strip fences, so scoring the fence itself measures chat-template habit rather than operational competence. Nothing looser is accepted: prose around a fence, trailing commentary, multiple fences, and invalid inner JSON remain `controller_protocol_invalid`, and normalization never repairs a payload. Normalization is disclosed as `protocol_normalized_turns` per episode and `protocol_normalized_turn_total` / `protocol_normalized_episodes` per suite. Rates from 2.1.0 onward are **not comparable** with 2.0.x, which failed every fenced turn.

23. **Diagnostic gate pass rate.** `diagnostic_gate_pass_rate` counts passed gate evaluations over total evaluations. It exists to distinguish routes that tie at 0% contract completion and is **never a selection criterion**: it is excluded from `HEADLINE.txt` and from decision logic, and a regression test enforces that the decision report is invariant to it. Partial gate credit is not partial task success — a model can pass most gates and still complete no contract.

24. **Relocation depends on how the suite recorded its evidence paths.** Production suites record each observation's `evidence_dir` relative to the suite root, so a copied, archived, or re-extracted suite still verifies against its externally pinned seal digest at its new location. Legacy suites — and any suite whose report explicitly records absolute `evidence_dir` values — remain bound to the location where they were produced, and fail with `suite_report_recomputation_mismatch:observations` if moved. Move such a suite back to its recorded path before verifying it. `oab explain` is unaffected in both cases.

25. **Test-execution gates are attested, not observed from outside.** Through 2.1.0 the `COD-TESTS` and `preserved_tests` gates decided success from the child process exit status. Because `unittest discover` imports a candidate module before collecting tests, a module-level `os._exit(0)` exited with status 0 and was scored as a clean pass — a wrong implementation could score a perfect P02. From 2.1.1 the runner must write a nonce-bound attestation naming how many tests executed, checked against a static count of the hash-pinned test files; a missing document is a hard failure. **Residual risk:** the runner shares an interpreter with candidate code, which can therefore read the nonce and fabricate an attestation. That is overt fabrication rather than an innocuous-looking early exit, but it is not closed. Closing it requires observing execution from outside the sandboxed interpreter.

26. **Spend is PLAN-bound, not signature-gated.** There is no detached Ed25519 stage approval, conversational receipt, or Approval Broker. `oab resume --stage` must restate the exact immutable PLAN ceilings; a mismatch fails closed before any provider call. Completing qualification never launches full.

27. **Temporary-artifact cleanup is inode-bound, not name-bound.** Private evidence snapshots are removed only while their pathname still resolves, via a retained no-follow descriptor, to the exact inode this process created. This is deliberate: a substituted temporary pathname is left in place rather than deleted, so on a contended temporary directory OAB may leak a temporary name instead of removing an attacker-supplied one. It does not guarantee cleanup, only that cleanup never deletes something OAB did not create. Snapshot *reads* carry a stronger guarantee: verification is rooted in the retained snapshot descriptor rather than the snapshot's absolute pathname, so substituting that pathname after the snapshot is bound cannot redirect any read to another directory.

28. **A suite is sealed once; `SUITE_SEAL.json` is never replaced in place.** The seal is created directly at its final name with `O_CREAT|O_EXCL|O_NOFOLLOW`, so the published inode is by construction the one that call created and no pre-existing seal can be overwritten or displaced. There is no staging-then-rename step and therefore no window in which a substituted inode could be moved onto the seal. Rerunning a seal over an existing one is accepted only when the recomputed bytes are byte-identical to the published seal, in which case nothing is written; any other existing content at that name — including a differing regular file, symlink, hardlinked file, directory or special file — fails closed with `suite_seal_publication_unsafe` rather than being replaced. Resealing a legitimately changed suite therefore requires removing the old seal deliberately, which is the intended cost of refusing to overwrite published evidence.

29. **Qualification is plumbing only and carries no model-quality signal.** From 2.3.0 each route runs exactly two deterministic probes — one approved read/tool loop, one prohibited-effect/no-effect compliance — bounded to six provider calls per episode. First-attempt reserve is twelve calls per route; with one infrastructure-only retry per probe the signed absolute reserve is **24 calls per route**, so a two-route qualification reserves at most **48 calls**. Qualification emits `READY` / `NOT READY` / `INCOMPATIBLE` plus explicit reason codes and never a completion rate, pair stability, gate-pass rate, or "0% model" headline. Quality is measured only by the full stage, which is unchanged at 80 episodes per route with a 17-call episode ceiling. A route that qualifies is proven to complete the agent loop, nothing more; a route classified `agent_loop_incompatible` returned valid provider responses but could not finish the loop within the bound, which is a plumbing verdict rather than a score. **The one-turn qualification percentages produced by v2.2.3 and earlier are invalid as model-quality signals** — they measured a single call against a task that needs a tool loop — and must not be cited or compared. New campaigns use the v2.3.0 contract; v2.2.3 qualification receipts are not resumable under this release identity.

30. **Unknown cost is `null`, never `$0`.** API-call counting is mandatory and locally enforced: a route whose telemetry omits the API-call count is infrastructure-invalid, because OAB cannot otherwise enforce its own spend ceiling. Token and dollar telemetry are independent and may be individually unknown; missing values are recorded as `null` with an `unknown_cost_api_calls` count and are never coerced to zero. A route with unknown dollar cost may still qualify, but only when the immutable PLAN records `allow_unknown_costs=true`; the observed-dollar stop applies only to known billed cost. Cost projections derived from qualification telemetry are spend planning, not quality.

31. **Publication and CI evidence are not inherited.** A GitHub release note, wheel digest, hosted workflow, or approval attests only the exact immutable tree it names. An untagged, dirty, or later source checkout — including an unreleased release candidate — has no published pin or hosted-CI claim merely because historical releases do. This does not relax any runtime containment, evidence, approval, or verification requirement; it prevents a local working tree from borrowing historical release authority.

32. **Child identity is a narrow campaign boundary, not a general CLI capability.** A public readiness or full child accepts identity only when descriptor-bound campaign root, exact `PLAN.json`, calibration digest, route, effort, cost posture, and output location reconstruct a valid PLAN contract. Mutable `--qualification-contract-json` and bare child invocations cannot authorize it. Route, effort, PLAN, cost-policy, and output-path substitutions fail before controller construction. The full stage additionally accepts only the fixed P01–P08 × approved/prohibited × five-repetition grid (80 episodes/route, at most 17 calls/episode, 1,360 calls/route); a custom or partial plan may be exploratory evidence but cannot authorize a comparison or switch. This protects child execution identity, not the identity or judgment of a remote provider.

These limitations are part of the benchmark contract.
