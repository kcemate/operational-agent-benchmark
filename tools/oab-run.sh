#!/usr/bin/env bash
# One-command Hermes-user entrypoint for OAB v2 suite runs.
# Writes all evidence outside the repository.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${OAB_PYTHON:-}" ]]; then
  PYTHON="${OAB_PYTHON}"
elif [[ -x "${HOME}/.hermes/hermes-agent/venv/bin/python3" ]]; then
  PYTHON="${HOME}/.hermes/hermes-agent/venv/bin/python3"
else
  PYTHON="$(command -v python3)"
fi
PYTHON_MINOR="$("${PYTHON}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
case "${PYTHON_MINOR}" in
  3.11|3.12|3.13) ;;
  *)
    echo "error: OAB v2 requires Python 3.11-3.13; found ${PYTHON_MINOR} at ${PYTHON}" >&2
    echo "set OAB_PYTHON to a supported interpreter (the Hermes venv is preferred)" >&2
    exit 2 ;;
esac

PROVIDER=""
MODEL=""
REASONING_EFFORT=""
PAIRS="all"
REPETITIONS=""
OUTPUT_ROOT=""
TIMEOUT_SECONDS="240"
EPISODE_TIMEOUT_SECONDS="30"

usage() {
  cat <<'EOF'
Usage:
  ./tools/oab-run.sh --provider <provider> --model <model> --reasoning-effort <level> [options]

Required:
  --provider           Hermes provider id (example: openai-codex, xai-oauth)
  --model              Model id for that provider
  --reasoning-effort   none|minimal|low|medium|high|xhigh (pinned and attested)

Options:
  --pairs                 Comma-separated pair ids or 'all' (default: all)
  --repetitions           Override registry default (usually 5)
  --output-root           External directory for evidence/report (default: ~/OAB-Runs/suite-<utc>)
  --timeout-seconds       Controller call timeout (default: 240)
  --episode-timeout-seconds  Leaf/episode timeout (default: 30)
  -h, --help              Show this help

Examples:
  ./tools/oab-run.sh --provider openai-codex --model gpt-5.6-sol --reasoning-effort high --pairs P01 --repetitions 1
  ./tools/oab-run.sh --provider xai-oauth --model grok-4.5 --reasoning-effort high

Output:
  <output-root>/suite-report.json
  <output-root>/HEADLINE.txt
  <output-root>/evidence/rep-NN/<case-id>/

Notes:
  - Output root must be fully disjoint from this repository.
  - Hermes adapter identity_source is adapter_runtime; scores are PROVISIONAL.
  - This benchmark is not declared release-ready.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider)
      PROVIDER="${2:-}"; shift 2 ;;
    --model)
      MODEL="${2:-}"; shift 2 ;;
    --reasoning-effort)
      REASONING_EFFORT="${2:-}"; shift 2 ;;
    --pairs)
      PAIRS="${2:-}"; shift 2 ;;
    --repetitions)
      REPETITIONS="${2:-}"; shift 2 ;;
    --output-root)
      OUTPUT_ROOT="${2:-}"; shift 2 ;;
    --timeout-seconds)
      TIMEOUT_SECONDS="${2:-}"; shift 2 ;;
    --episode-timeout-seconds)
      EPISODE_TIMEOUT_SECONDS="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2 ;;
  esac
done

if [[ -z "${PROVIDER}" || -z "${MODEL}" || -z "${REASONING_EFFORT}" ]]; then
  echo "error: --provider, --model, and --reasoning-effort are required" >&2
  usage >&2
  exit 2
fi

if [[ -z "${OUTPUT_ROOT}" ]]; then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  safe_model="$(printf '%s' "${MODEL}" | tr '/ ' '__')"
  OUTPUT_ROOT="${HOME}/OAB-Runs/suite-${PROVIDER}-${safe_model}-${stamp}"
fi

cmd=(
  "${PYTHON}" "${ROOT}/tools/run_suite.py"
  --provider "${PROVIDER}"
  --model "${MODEL}"
  --reasoning-effort "${REASONING_EFFORT}"
  --pairs "${PAIRS}"
  --output-root "${OUTPUT_ROOT}"
  --timeout-seconds "${TIMEOUT_SECONDS}"
  --episode-timeout-seconds "${EPISODE_TIMEOUT_SECONDS}"
)
if [[ -n "${REPETITIONS}" ]]; then
  cmd+=(--repetitions "${REPETITIONS}")
fi

echo "OAB v2 suite entrypoint"
echo "  repo: ${ROOT}"
echo "  python: ${PYTHON}"
echo "  route: ${PROVIDER}/${MODEL}"
echo "  reasoning-effort: ${REASONING_EFFORT} (pinned)"
echo "  pairs: ${PAIRS}"
echo "  output-root: ${OUTPUT_ROOT}"
echo "  claim posture: provisional when identity_source=adapter_runtime; not release-ready"
exec "${cmd[@]}"
