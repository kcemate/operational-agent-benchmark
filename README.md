# Operational Agent Benchmark v2 (OAB v2)

OAB v2 is a **decision tool** for one question:

> Should I switch my Hermes-style agent harness to model X?

It measures whether a model, under a fixed trusted-controller / fixed-broker / sandbox-leaf harness, can complete declared **deterministic contracts** on matched **approved / prohibited** authorization pairs. OAB v2 ships as public-beta tooling; it is not a general intelligence ranking, and benchmark results remain provisional unless every release, identity, coverage, calibration, and approval gate passes.

## What you get

| Output | Meaning |
|---|---|
| `deterministic_contract_completion_rate` | Share of **infrastructure-valid** episodes that completed every declared contract gate and left sealed digests |
| `infrastructure_coverage_rate` | Share of scheduled episodes that reached a scoreable runner outcome; must be 100% for certification |
| `matched_pair_completion_rate` | Share of scoreable pair×rep slots where **both** approved and prohibited variants completed |
| `pair_stability` | Per-pair matched success rate across reps (`mean` / `min`) |
| `controller_usage` | Bound totals for API calls, tokens, measured controller latency, and nullable provider-reported cost |
| `HEADLINE.txt` | One actionable line a Hermes user can compare across routes |

When the Hermes adapter records `identity_source=adapter_runtime`, every score is **PROVISIONAL**. Do not treat provisional rates as authoritative model-selection proof.

## Quick start (Hermes users)

### 60-second install from a published release

Each release publishes its wheel digest and release-tree digest **in the GitHub release notes**. Those digests are deliberately not restated here: the README is itself part of the hashed release tree, so an inline copy could never match the digest it claims to pin. Read both values from the release notes (ideally confirmed through a channel independent of the repository) and export them:

```bash
VERSION=v2.0.1
gh release download "$VERSION" --repo kcemate/operational-agent-benchmark --pattern '*.whl'

HERMES_PYTHON="$(dirname "$(command -v hermes)")/python3"
OAB_WHEEL=operational_agent_benchmark-2.0.1-py3-none-any.whl
OAB_WHEEL_SHA256=sha256:<wheel-digest-from-the-release-notes>
OAB_TREE_SHA256=sha256:<release-tree-digest-from-the-release-notes>

test "$(shasum -a 256 "$OAB_WHEEL" | cut -d' ' -f1)" = "${OAB_WHEEL_SHA256#sha256:}" || exit 1
"$HERMES_PYTHON" -m pip install "$OAB_WHEEL"
oab doctor --json --expected-release-tree-sha256 "$OAB_TREE_SHA256"
```

Stop on any mismatch. `oab doctor` must pass every check before you initialize a campaign.

### Route naming: use the route your harness attests, not the one you assume

OAB binds every episode to the route the controller **reports back**, and rejects the episode when the returned route differs from the requested route. Some harness configurations rewrite the provider slug — for example a locally served OpenAI-compatible endpoint may be requested as `ollama-launch/<model>` but attested as `custom/<model>`.

Check what your harness actually reports before building an inventory:

```bash
hermes -z 'Reply with exactly: PING' -m <model> --provider <provider> --usage-file /tmp/probe.json
python3 -c "import json;d=json.load(open('/tmp/probe.json'));print(d['provider'], d['model'])"
```

Declare routes in the inventory using the attested `provider/model` pair. A mismatch surfaces as `runner_invalid` with `controller_infrastructure_invalid`, which OAB deliberately scores as an infrastructure failure rather than a model failure.

### Context window requirement

Hermes requires a controller model with at least a 64K context window. Local models served with a smaller default window are rejected before any episode runs. With Ollama, publish a larger window explicitly:

```bash
printf 'FROM %s\nPARAMETER num_ctx 65536\n' "qwen3:8b" > /tmp/Modelfile.64k
ollama create qwen3-64k:8b -f /tmp/Modelfile.64k
```

### Agent-native all-accessible workflow

Install only an externally pinned wheel into the Python environment next to the active Hermes executable. Obtain both digests from a channel independent of the repository or wheel, and stop on any mismatch.

On Linux, install Bubblewrap and libseccomp and ensure the host permits unprivileged user namespaces. Ubuntu/AppArmor hosts may otherwise fail with `setting up uid map: Permission denied`. The hosted CI relaxes `kernel.apparmor_restrict_unprivileged_userns` only on its disposable runner and verifies `unshare --user --map-root-user true`; do not weaken that control on a shared host without administrator review.

```bash
HERMES_PYTHON="$(dirname "$(command -v hermes)")/python3"
OAB_WHEEL=/path/to/operational_agent_benchmark-2.0.1-py3-none-any.whl
OAB_WHEEL_SHA256=<independently-published-wheel-sha256>
OAB_TREE_SHA256=sha256:<independently-published-release-tree-sha256>

test "$(shasum -a 256 "$OAB_WHEEL" | cut -d' ' -f1)" = "${OAB_WHEEL_SHA256#sha256:}" || exit 1
# Equivalent stdlib-only verifier: python3 /trusted/path/bootstrap_verify.py \
#   --artifact "$OAB_WHEEL" --expected-sha256 "$OAB_WHEEL_SHA256"
"$HERMES_PYTHON" -m pip install "$OAB_WHEEL"
oab doctor --json --expected-release-tree-sha256 "$OAB_TREE_SHA256"

oab benchmark \
  --all-accessible \
  --reasoning-effort high \
  --expected-release-tree-sha256 "$OAB_TREE_SHA256" \
  --output-root "$HOME/OAB-Runs/my-campaign"
```

`oab benchmark` verifies the environment and release manifest before inventory initialization, discovers configured Hermes route candidates without persisting inventory credentials, runs the deterministic harness calibration, and writes a resumable machine-readable plan. It performs **no model inference calls**. Explicit live probes and pricing lookups are disabled, but in-process Hermes/plugin initialization may still read local configuration, refresh authentication, or perform implementation-defined network activity. Candidate discovery does not prove authentication or availability.

To use the Hermes API server as the discovery source, provide only its base URL. OAB negotiates `/v1/capabilities` and reads `/api/model/options`; it reads the key from `API_SERVER_KEY` and never accepts a key argument:

```bash
oab discover --json --hermes-api-url http://127.0.0.1:8642
```

Normal stage approval is conversational and requires a no-spend preview first. The preview is generated from the same hashed plan and ordered route selector as the receipt; it performs zero provider calls:

```bash
oab approval-preview "$HOME/OAB-Runs/my-campaign" \
  --stage qualification \
  --observed-cost-stop-usd <requested-stop-threshold> \
  --max-api-calls <requested-call-ceiling> \
  --max-routes <requested-route-count>
```

Show the complete JSON preview to the user: ordered route names and IDs, plan/calibration digests, stage, episodes, minimum call reserve, observed known-billed-cost stop, one-call crossing semantics, route ceiling, unknown-cost posture, and `intended_evidence_posture`. Wait for explicit approval of those exact values. Then create the receipt using a non-secret immutable host/message reference to that approval:

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

OAB qualification runs the P01 approved/prohibited pair for 17 repetitions: exactly 34 one-call episodes per route and at most 34 provider API calls per route. These are bounded infrastructure, identity, effort, telemetry, and first-response probes; they are not substitutes for the separately approved 80-episode full comparison. Authentication/provider/controller/effort failures are excluded without becoming model scores, and full-run cost is projected from the 34-episode sample when telemetry exists. Unknown cost pauses the campaign unless `--allow-unknown-costs` is shown in the preview and separately approved.

A full comparison requires a new preview and approval and schedules all eight pairs × five repetitions = 80 episodes per qualified route:

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

oab verify "$HOME/OAB-Runs/my-campaign"
oab report "$HOME/OAB-Runs/my-campaign"
```

Conversational approval is a bounded, digest-bound spend audit record; it is only as strong as the referenced host conversation. It **does not confer release authority**. For independently verifiable high-assurance spend authorization, use `--approval-public-key`, sign the canonical `.signing-payload` externally, and pass the detached Ed25519 signature and matching public key to `resume`.

Every stage receipt binds the plan and calibration digests, exact ordered route IDs, observed known-billed-cost stop, API-call and route ceilings, cost-control mode, maximum one crossing call, and unknown-cost posture. Because providers reveal billed cost only after a call, the call that first reveals a threshold crossing may exceed it; all later calls stop. `--max-cost-usd` remains a compatibility alias, not an absolute prepaid cap.

`oab report` and `oab verify` expose `evidence_posture`, `release_authorized`, `authority_blockers`, and route-level authority. A valid exact-tree release approval plus all identity, coverage, grid, runtime, and seal gates is required for `authoritative_comparable`; otherwise the campaign is explicitly `exploratory` and cannot support an authoritative switch recommendation. OAB reserves up to 34 calls per qualification route and 1,360 calls per full route and refuses to start a route unless its full allowance remains.

See `AGENTS.md` for the cold-agent runbook, resume semantics, credential boundaries, and permitted claims. Lower-level commands remain available for diagnostics and expert operation.

### Lower-level workflow

Install from a source checkout or release wheel:

```bash
python3 -m pip install .
oab-calibrate --output-root "$HOME/OAB-Runs/calibration-$(date -u +%Y%m%dT%H%M%SZ)"
```

The wheel includes the frozen registry, tasks, fixtures, release manifest, verifier sources, and console commands under an installation-local benchmark tree. From a source checkout, the equivalent direct command is:

```bash
chmod +x tools/oab-run.sh
./tools/oab-run.sh --provider openai-codex --model gpt-5.6-sol --reasoning-effort high --pairs P01 --repetitions 1
```

Installed command equivalent:

```bash
oab-run --provider openai-codex --model gpt-5.6-sol --reasoning-effort high --pairs P01 --repetitions 1
```

Full default suite (all pairs × registry default repetitions, usually 5):

```bash
./tools/oab-run.sh --provider xai-oauth --model grok-4.5 --reasoning-effort high
```

Equivalent Python entrypoint:

```bash
python3 tools/run_suite.py \
  --provider <provider> \
  --model <model> \
  --reasoning-effort <none|minimal|low|medium|high|xhigh> \
  --pairs all \
  --output-root "$HOME/OAB-Runs/suite-$(date -u +%Y%m%dT%H%M%SZ)"
```

**Hard rules:** `--output-root` must be fully disjoint from this repository (neither path may contain the other). The suite creates a private temporary Hermes runtime profile, pins the requested reasoning effort, links the active credential store without copying it into evidence, records the config digest, and deletes the runtime profile after the run. Default shell entrypoint writes evidence under `~/OAB-Runs/`.

Runs are provisional unless an independently produced approval receipt for the exact release tree is supplied with its externally published digest:

```bash
oab-run ... \
  --release-approval /path/to/RELEASE_APPROVAL.json \
  --expected-release-approval-sha256 sha256:<published-approval-digest>
```

The `oab.release-approval/v1` receipt must contain distinct security and product reviewers, both approving the exact `RELEASE_MANIFEST.json` tree digest and acknowledging the benchmark claim limits. The path and digest options are required together. A report cannot become `AUTHORITATIVE` from a Boolean flag alone.

Verify that receipt independently before use:

```bash
oab-verify-release-approval /path/to/RELEASE_APPROVAL.json \
  --release-tree-sha256 sha256:<release-tree-digest> \
  --expected-sha256 sha256:<published-approval-digest>
```

### Smoke one pair first

The legacy smoke command is useful for harness diagnostics, but it inherits the active profile's reasoning effort and is **not a certified comparison**. Use `run_suite.py --pairs P01 --repetitions 1 --reasoning-effort …` for a pinned one-pair observation.

```bash
python3 tools/run_model_smoke.py \
  --provider <provider> \
  --model <model> \
  --pair P01 \
  --output-root "$HOME/OAB-Runs/model-smoke-$(date -u +%Y%m%dT%H%M%SZ)"
```

### Calibrate the harness without scoring a model

Run the deterministic P01 approved/prohibited controls before a model comparison:

```bash
python3 tools/run_calibration.py \
  --output-root "$HOME/OAB-Runs/calibration-$(date -u +%Y%m%dT%H%M%SZ)"
```

Both variants must pass their real sandbox, broker, verifier, and sealed-evidence paths. Calibration uses `execution_class=calibration_control`, sets `model_score_credit=false`, and never enters a model leaderboard.

## Headline format

```text
PROVISIONAL | route=provider/model | reasoning_effort=medium | identity_source=adapter_runtime | infrastructure_coverage: 100.0% (16/16) | deterministic_contract_completion_rate: 75.0% (12/16) | matched_pair_completion_rate: 50.0% | pair_stability_min: 0.0% (P02) | Do not treat as release-ready.
```

`NO SCORE` means no episode reached a scoreable runner outcome. `INCOMPLETE` means some infrastructure-invalid or missing episodes were excluded; do not compare it as a certified score.

How to act on it:

1. Compare only runs with **100% infrastructure coverage**, the same suite/version, repetitions, harness, and pinned reasoning effort.
2. Prefer higher `deterministic_contract_completion_rate` only after that comparability check.
3. Require healthy `matched_pair_completion_rate` — approved-only success is not enough.
4. Inspect `pair_stability.min` — a single fragile pair can hide behind a decent average.
5. If `identity_source` is `adapter_runtime`, label the result provisional in any write-up.

## Verify evidence

Each finalized scoreable episode writes an internally consistent evidence tree under `evidence/…` with `result.json`, `trace.jsonl`, `output-manifest.json`, `evidence-manifest.json`, and `payload/`. The evidence manifest binds every evidence file except its own self-describing JSON; receipt identity, status, reasons, case, and repetition are cross-checked against the trace.

```bash
python3 tools/verify_evidence.py /path/to/evidence/rep-01/oab2-data-rollup-a
python3 tools/verify_evidence.py --json /path/to/evidence/rep-01/oab2-data-rollup-a
```

Verification rechecks:

- episode receipt schema and claimed digests
- canonical hash-chained trace integrity
- output-tree manifest entries and independent payload rehash
- whole-evidence manifest entries, including effects and boundary receipts
- critical receipt metadata against trace start/identity/end events
- the registry-defined pair×variant×repetition grid
- every episode's sealed evidence and deterministic case gates
- aggregate coverage, completion, matched-pair, stability, usage, and authority fields recomputed from episode receipts
- exact `HEADLINE.txt` agreement with the recomputed report
- the bound release-approval receipt when release authorization is claimed

For coordinated-rewrite detection, pin the `SUITE_SEAL_SHA256=…` line printed at run completion in an external publication or ledger, then verify:

```bash
python3 tools/verify_suite.py /path/to/suite \
  --expected-sha256 sha256:<published-suite-seal-digest>
```

Without `--expected-sha256`, suite verification proves internal consistency only; an attacker able to replace the full tree can also replace an unpinned seal.

## Suite layout

- **8 matched pairs** (`P01`–`P08`), each with approved (`-a`) and prohibited (`-p`) variants → **16 cases**
- **Default repetitions:** 5 (80 scheduled episodes for a full route)
- **Primary metric:** `deterministic_contract_completion_rate`
- **Architecture:** trusted outer controller → fixed tool broker → network-denied, OS no-fork sandbox leaf (macOS Seatbelt or Linux Bubblewrap + libseccomp)
- **Calibration:** official non-scoring P01 approved/prohibited deterministic controls

See `BENCHMARK_CARD.md` for the construct card and `LIMITATIONS.md` for claim boundaries.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Focused product-surface tests:

```bash
python3 -m unittest tests.test_aggregation tests.test_evidence -v
```

## Status

OAB v2 is under active hardening. Public docs and tooling here support provisional multi-rep suite runs and sealed-evidence checks. **No release-ready claim is made.**
