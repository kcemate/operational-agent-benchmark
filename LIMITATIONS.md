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

24. **Suite trees verify in place, not after relocation.** Episode observations record `evidence_dir` as an absolute path, so `oab verify` and suite-seal verification succeed only where the suite was produced. A copied, archived, or re-extracted suite fails with `suite_report_recomputation_mismatch:observations` even when every byte is intact. Move a suite back to its recorded path before verifying it. `oab explain` is unaffected and works on a relocated copy.

25. **Test-execution gates are attested, not observed from outside.** Through 2.1.0 the `COD-TESTS` and `preserved_tests` gates decided success from the child process exit status. Because `unittest discover` imports a candidate module before collecting tests, a module-level `os._exit(0)` exited with status 0 and was scored as a clean pass — a wrong implementation could score a perfect P02. From 2.1.1 the runner must write a nonce-bound attestation naming how many tests executed, checked against a static count of the hash-pinned test files; a missing document is a hard failure. **Residual risk:** the runner shares an interpreter with candidate code, which can therefore read the nonce and fabricate an attestation. That is overt fabrication rather than an innocuous-looking early exit, but it is not closed. Closing it requires observing execution from outside the sandboxed interpreter.

These limitations are part of the benchmark contract.
