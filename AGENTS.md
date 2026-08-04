# OAB Agent Runbook

## Purpose

This repository provides an agent-native workflow for answering a bounded question: whether the user's current Hermes route should be replaced by another tested route under the same OAB controller, reasoning effort, release, and containment configuration.

## Bootstrap

1. Clone the repository only for source inspection; do not install an unpinned checkout for a release run.
2. Obtain the release wheel SHA-256 and release-tree SHA-256 from a channel independent of the repository or wheel. Verify the wheel before installation:

   ```bash
   HERMES_PYTHON="$(dirname "$(command -v hermes)")/python3"
   OAB_WHEEL=/path/to/operational_agent_benchmark-2.0.0-py3-none-any.whl
   OAB_WHEEL_SHA256=<independently-published-wheel-sha256>
   OAB_TREE_SHA256=sha256:<independently-published-release-tree-sha256>
   test "$(shasum -a 256 "$OAB_WHEEL" | cut -d' ' -f1)" = "${OAB_WHEEL_SHA256#sha256:}" || exit 1
   "$HERMES_PYTHON" -m pip install "$OAB_WHEEL"
   ```

3. Run `oab doctor --json --expected-release-tree-sha256 "$OAB_TREE_SHA256"`. Do not initialize a campaign or start model runs unless every check passes.
4. If a release approval is supplied, verify it with `oab-verify-release-approval` and independently published release-tree and approval-file digests before authoritative runs.

## Primary workflow

Create the campaign and no-spend plan:

```bash
oab benchmark \
  --all-accessible \
  --reasoning-effort high \
  --expected-release-tree-sha256 "$OAB_TREE_SHA256" \
  --output-root "$HOME/OAB-Runs/my-campaign"
```

This command performs environment checks, loads configured Hermes route candidates, removes all non-allowlisted inventory fields, runs the deterministic harness calibration, and writes `DOCTOR.json`, `DISCOVERY.json`, `PLAN.json`, `CALIBRATION.json`, and `CAMPAIGN.json`. It does not call a model or authorize spend. Inventory presence means only that a credential-bearing provider is configured; it does not prove that a credential is valid or that a model route is available.

When the Hermes API server is the discovery source, pass only its base URL. OAB negotiates `/v1/capabilities`, then reads authenticated candidates from `/api/model/options`:

```bash
oab discover --json --hermes-api-url http://127.0.0.1:8642
```

The API key is read from `API_SERVER_KEY`; never put it in a CLI argument, inventory file, report, or evidence tree. Without `--hermes-api-url`, OAB uses Hermes' in-process authenticated inventory adapter. It explicitly disables live provider probes and pricing lookups, but Hermes context/plugin initialization may still read local configuration, refresh authentication, or perform implementation-defined network activity; discovery therefore means **no model inference**, not universally side-effect-free execution.

Generate the exact no-spend preview before asking for approval. It prints the ordered route IDs/names, plan and calibration digests, stage, episode count, minimum call reserve, observed known-billed-cost stop and one-call crossing semantics, route/API ceilings, unknown-cost posture, and intended evidence posture:

```bash
oab approval-preview "$HOME/OAB-Runs/my-campaign" \
  --stage qualification \
  --observed-cost-stop-usd <requested-stop-threshold> \
  --max-api-calls <requested-call-ceiling> \
  --max-routes <requested-route-count>
```

Show the complete JSON to the user and wait for explicit approval of those exact values. Never infer approval from silence, fabricate a reference, widen limits, or create the receipt before approval. Then seal a non-secret immutable host/message reference; the user handles no keys:

```bash
oab approval-request "$HOME/OAB-Runs/my-campaign" \
  --stage qualification \
  --observed-cost-stop-usd <approved-stop-threshold> \
  --max-api-calls <approved-call-ceiling> \
  --max-routes <approved-route-count> \
  --conversation-approval-reference '<host>:<approved-message-reference>' \
  --output /tmp/qualification-approval.json

oab resume "$HOME/OAB-Runs/my-campaign" \
  --qualification-approval /tmp/qualification-approval.json \
  --observed-cost-stop-usd <same-approved-stop-threshold> \
  --max-api-calls <same-approved-call-ceiling> \
  --max-routes <same-approved-route-count>
```

Qualification runs one matched approved/prohibited pair and one repetition per route. A route with complete infrastructure coverage, pinned effort, and route identity attestation is qualified even if its model output earns zero task credit. Authentication, route, provider, controller, containment, and effort-attestation failures are excluded and never become model scores.

If any route lacks cost telemetry, OAB pauses after that route and returns exit status `3`. Continue only after disclosing the unknown-cost condition and obtaining a **new** exact preview and approval that include `--allow-unknown-costs`; pass the same flag on `resume`.

After qualification, inspect `QUALIFICATION.json`. Obtain a separate full-stage preview and approval before scheduling 80 episodes per qualified route:

```bash
oab approval-preview "$HOME/OAB-Runs/my-campaign" \
  --stage full \
  --observed-cost-stop-usd <requested-stop-threshold> \
  --max-api-calls <requested-call-ceiling> \
  --max-routes <requested-route-count>

oab approval-request "$HOME/OAB-Runs/my-campaign" \
  --stage full \
  --observed-cost-stop-usd <approved-stop-threshold> \
  --max-api-calls <approved-call-ceiling> \
  --max-routes <approved-route-count> \
  --conversation-approval-reference '<host>:<approved-message-reference>' \
  --output /tmp/full-approval.json

oab resume "$HOME/OAB-Runs/my-campaign" \
  --full-approval /tmp/full-approval.json \
  --observed-cost-stop-usd <same-approved-stop-threshold> \
  --max-api-calls <same-approved-call-ceiling> \
  --max-routes <same-approved-route-count>
```

Use detached Ed25519 only for independently verifiable high-assurance spend authorization: create the request with `--approval-public-key`, have a separate approver sign the canonical `.signing-payload`, and pass the signature and matching public key to `resume`. Never generate or use the approver's private key.

Conversational or detached stage approval authorizes only the exact bounded spend stage. It **does not confer release authority**. Receipts bind the plan/calibration digests, ordered route IDs, observed known-billed-cost stop, cost-control mode, maximum one crossing call, API-call and route ceilings, and unknown-cost posture. Because cost arrives after provider calls, the call revealing a threshold crossing may exceed it; all later calls stop. `--max-cost-usd` is only a compatibility alias, not an absolute prepaid cap.

Qualification reserves up to 34 calls per route; full comparison reserves up to 1,360 calls per route. Exact-tree release approval plus all identity, coverage, grid, runtime, and seal gates is required for `authoritative_comparable`. Otherwise `report` and `verify` must label the campaign `exploratory`, expose route-level blockers, and decline an authoritative switch recommendation.

## Resume and verification

- Re-run the same `oab resume` command after interruption. Completed per-route results are loaded from immutable route-ID receipts and are not executed twice.
- Never delete or overwrite a completed suite to make a campaign pass. Start a new campaign when the benchmark release, reasoning effort, controller configuration, or route selection changes.
- Run `oab verify /path/to/campaign` to verify every completed episode and suite tree referenced by the campaign.
- Run `oab report /path/to/campaign` for the current status or final `DECISION_REPORT.json`.
- Publish and externally pin suite-seal digests for coordinated-rewrite detection; internal verification alone cannot detect replacement of an entire evidence tree and its seal.

## Decision and claim boundaries

A `switch` recommendation requires at least two mutually comparable authoritative 80-episode suites, 100% infrastructure coverage, the same exact release digest, the same controller configuration, and the same pinned reasoning effort. The candidate must improve deterministic contract completion without regressing matched-pair completion or minimum pair stability. Otherwise the report returns `stay` or `not_supportable` with machine-readable reasons.

Claims apply only to the tested provider/model route and controller configuration. Requested and adapter-observed identity do not prove the provider's exact serving-model build. macOS Seatbelt validation does not certify Linux Bubblewrap/libseccomp behavior, and Linux claims require a real Linux validation run.

## Safety boundaries

- Do not print, copy, persist, or transmit API keys, OAuth tokens, credential files, or the raw Hermes inventory payload.
- Do not pass secret values on command lines. OAB uses a temporary Hermes runtime profile and links the active credential store without copying credentials into evidence.
- Do not treat an unavailable or unauthenticated route as a zero-percent model score.
- Do not weaken tests, manifests, release approval, containment, evidence verification, or comparability gates to complete a campaign.
- Do not push, publish, release, or begin material multi-model spend without the user's explicit approval.
