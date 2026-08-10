# OAB Agent Runbook

## Purpose

This repository provides an agent-native workflow for answering a bounded question: whether the user's current Hermes route should be replaced by another tested route under the same OAB controller, reasoning effort, release, and containment configuration.

## Bootstrap

1. Clone the repository only for source inspection; do not install an unpinned checkout for a release run.
2. Obtain the release wheel SHA-256 and release-tree SHA-256 from a channel independent of the repository or wheel. Each release publishes both in its [GitHub release notes](https://github.com/kcemate/operational-agent-benchmark/releases); that is the only place a cold agent should read them from, because the README and this runbook are inside the hashed tree. **If the version you intend to install has no published release notes carrying both digests, no trusted pin exists — stop and report `release_pin_unavailable` rather than installing an unpinned artifact or computing a digest from the working tree.** Verify the wheel before installation:

   ```bash
   OAB_WHEEL=/path/to/operational_agent_benchmark-<version>-py3-none-any.whl
   OAB_WHEEL_SHA256=<independently-published-wheel-sha256>
   OAB_TREE_SHA256=sha256:<independently-published-release-tree-sha256>
   test "$(shasum -a 256 "$OAB_WHEEL" | cut -d' ' -f1)" = "${OAB_WHEEL_SHA256#sha256:}" || exit 1
   python3 -c 'import sys; assert (3, 11) <= sys.version_info[:2] < (3, 14)'
   python3 -m venv "$HOME/.local/share/oab-<version>"
   "$HOME/.local/share/oab-<version>/bin/python" -m pip install --no-compile "$OAB_WHEEL"
   export PATH="$HOME/.local/share/oab-<version>/bin:$PATH"
   command -v hermes >/dev/null || exit 1
   ```

3. Run `oab doctor --json --expected-release-tree-sha256 "$OAB_TREE_SHA256"`. Do not initialize a campaign or start model runs unless every check passes.
4. If a release approval is supplied, verify it with `oab-verify-release-approval` and independently published release-tree and approval-file digests before authoritative runs.

## Conversational "candidate vs current" workflow

The common request is conversational: *"Run OAB on this new model and tell me if it beats our current model."* Treat that as a **two-route comparison**, not a spend authorization.

1. **Infer and confirm the pair.** The baseline is `current_route` from `DISCOVERY.json`; the candidate is the model the user named. If `current_route` is null, or the wording is ambiguous about which route is current, ask **one** concise question before creating a campaign. A campaign with a null `baseline_route` fails later at `campaign_plan_baseline_invalid`.
2. **Say up front that a winner is not guaranteed.** `stay` and `not_supportable` are ordinary outcomes. An `exploratory` campaign cannot authorize a switch no matter what the numbers show.
3. **Pin the comparison to exactly two routes** with `--inventory-json` (below), and verify `PLAN.json` holds two routes before requesting any approval.
4. **Preview, then stop.** Qualification and full are separate approvals; neither is implied by the original request or by silence.
5. **Report** the pair, the verdict in plain English, the authority posture, and the actual spend and cost posture. Keep route IDs, seals, and receipt digests out of the user-facing answer unless a failure requires naming one.

### Selecting exactly two routes

`oab discover` and `oab benchmark` both accept `--inventory-json <path>`, which supplies the route inventory directly instead of reading the full Hermes inventory. This is the supported mechanism for restricting a campaign to a baseline and one candidate.

The file must be a JSON object. OAB sanitizes it and discards every field not listed here, so extras are pointless and risk leaking secrets:

- `providers[]` — candidate rows (max 256). Each row uses `slug` (provider name; a row whose slug is `moa` is dropped), `models` (array of model names, max 2048), optional `authenticated` (a row is dropped only when this is exactly `false`), and optional `capabilities` mapping model name to `{"reasoning": bool}`.
- `provider` and `model` — the **current** route. These become `current_route` only if that pair also appears in `providers`; otherwise `current_route` is silently `null`. Always list the baseline in `providers` too.

```json
{
  "provider": "example-provider",
  "model": "current-model",
  "providers": [
    {"slug": "example-provider", "authenticated": true,
     "models": ["current-model", "candidate-model"]}
  ]
}
```

```bash
oab benchmark --all-accessible --reasoning-effort high \
  --inventory-json /tmp/two-route-inventory.json \
  --expected-release-tree-sha256 "$OAB_TREE_SHA256" \
  --output-root "$HOME/OAB-Runs/my-campaign"
```

Never place an API key, token, or credential in the inventory file. Name routes the way the harness attests them: a requested/returned route mismatch is scored as an infrastructure failure, never as a model failure.

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

Show the complete JSON to the user and wait for explicit approval of those exact values. Never infer approval from silence, fabricate a reference, widen limits, or create the receipt before approval. Explicit conversational approval is required, but it is **not** sufficient to execute: OAB has no host-backed verifier for a quoted message reference, so `--conversation-approval-reference` is refused with `conversation_approval_not_host_verified`, and a hand-written conversational receipt is refused at `resume`. Spend-capable execution requires an externally signed Ed25519 stage approval:

```bash
oab approval-request "$HOME/OAB-Runs/my-campaign" \
  --stage qualification \
  --observed-cost-stop-usd <approved-stop-threshold> \
  --max-api-calls <approved-call-ceiling> \
  --max-routes <approved-route-count> \
  --approval-public-key /path/to/approval-public.pem \
  --output /tmp/qualification-approval.json

# A separate approver signs the canonical
# /tmp/qualification-approval.json.signing-payload with the matching Ed25519
# private key. Never generate or handle that private key yourself.

oab resume "$HOME/OAB-Runs/my-campaign" \
  --qualification-approval /tmp/qualification-approval.json \
  --approval-signature /tmp/qualification-approval.sig \
  --approval-public-key /path/to/approval-public.pem \
  --observed-cost-stop-usd <same-approved-stop-threshold> \
  --max-api-calls <same-approved-call-ceiling> \
  --max-routes <same-approved-route-count>
```

Qualification runs two deterministic multi-turn plumbing probes per route (approved read/tool loop and denied-effect recovery), each bounded to four provider calls. First-attempt reserve is eight calls per route; with one infrastructure-only retry per probe the absolute signed ceiling is sixteen calls per route. Qualification reports only READY / NOT READY / INCOMPATIBLE plus failure reasons — never a completion rate, pair stability, or “0% model” quality headline. It is not a substitute for the 80-episode full comparison. Authentication, route, provider, controller, containment, effort-attestation, and missing API-call-count failures remain infrastructure exclusions, never model scores.

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
  --approval-public-key /path/to/approval-public.pem \
  --output /tmp/full-approval.json

# Sign /tmp/full-approval.json.signing-payload externally (Ed25519).

oab resume "$HOME/OAB-Runs/my-campaign" \
  --full-approval /tmp/full-approval.json \
  --approval-signature /tmp/full-approval.sig \
  --approval-public-key /path/to/approval-public.pem \
  --observed-cost-stop-usd <same-approved-stop-threshold> \
  --max-api-calls <same-approved-call-ceiling> \
  --max-routes <same-approved-route-count>
```

The detached Ed25519 path is the only spend-capable authorization path: create the request with `--approval-public-key`, have a separate approver sign the canonical `.signing-payload`, and pass the signature and matching public key to `resume`. Never generate or use the approver's private key.

A stage approval authorizes only the exact bounded spend stage. It **does not confer release authority**. Receipts bind the plan/calibration digests, ordered route IDs, observed known-billed-cost stop, cost-control mode, maximum one crossing call, API-call and route ceilings, and unknown-cost posture. Because cost arrives after provider calls, the call revealing a threshold crossing may exceed it; all later calls stop. `--max-cost-usd` is only a compatibility alias, not an absolute prepaid cap.

Qualification schedules exactly two probes and reserves up to 16 calls per route (32 for a two-route campaign); full comparison reserves up to 1,360 calls per route. Exact-tree release approval plus all identity, coverage, grid, runtime, and seal gates is required for `authoritative_comparable`. Otherwise `report` and `verify` must label the campaign `exploratory`, expose route-level blockers, and decline an authoritative switch recommendation.

## Resume and verification

- Re-run the same `oab resume` command after interruption. Completed per-route results are loaded from immutable route-ID receipts and are not executed twice.
- Never delete or overwrite a completed suite to make a campaign pass. Start a new campaign when the benchmark release, reasoning effort, controller configuration, or route selection changes.
- Run `oab verify /path/to/campaign` to verify every completed episode and suite tree referenced by the campaign.
- Run `oab report /path/to/campaign` for the current status or final `DECISION_REPORT.json`.
- Run `oab explain /path/to/evidence/rep-NN/<case-id>` to diagnose one episode: task text, live-recomputed gate results, the model's final response, produced artifacts, and declared-versus-actual schema keys. Add `--json` for machine-readable output. It is read-only, exits 0 even when the episode failed, and is the fastest way to distinguish "the model cannot do this" from "the model missed one key." Start from the suite report's `first_failing_gate` and `gate_failures` to pick which episode to open.
- Publish and externally pin suite-seal digests for coordinated-rewrite detection; internal verification alone cannot detect replacement of an entire evidence tree and its seal.

## Decision and claim boundaries

A `switch` recommendation requires at least two mutually comparable authoritative 80-episode suites, 100% infrastructure coverage, the same exact release digest, the same controller configuration, and the same pinned reasoning effort. The candidate must improve deterministic contract completion without regressing matched-pair completion or minimum pair stability. Otherwise the report returns `stay` or `not_supportable` with machine-readable reasons.

**A winner is not guaranteed, and most runs will not produce one.** `stay`, `not_supportable`, and `exploratory` are ordinary, correct outcomes — not harness failures. Exploratory evidence may be reported as observations only; it can never authorize a route switch, however favourable the numbers look. Use authoritative switch/stay language only when `evidence_posture` is `authoritative_comparable`, `release_authorized` is true, `oab verify` reports valid, and the decision report itself supports the claim. Note that release authorization requires an exact-tree release approval with two distinct reviewers, so a cold user with no published release approval will land in `exploratory` by default; disclose that before they approve any spend, not after.

Claims apply only to the tested provider/model route and controller configuration. Requested and adapter-observed identity do not prove the provider's exact serving-model build. macOS Seatbelt validation does not certify Linux Bubblewrap/libseccomp behavior, and Linux claims require a real Linux validation run.

## Safety boundaries

- Do not print, copy, persist, or transmit API keys, OAuth tokens, credential files, or the raw Hermes inventory payload.
- Do not pass secret values on command lines. OAB uses a temporary Hermes runtime profile and links the active credential store without copying credentials into evidence.
- Do not treat an unavailable or unauthenticated route as a zero-percent model score.
- Do not weaken tests, manifests, release approval, containment, evidence verification, or comparability gates to complete a campaign.
- Do not push, publish, release, or begin material multi-model spend without the user's explicit approval.
