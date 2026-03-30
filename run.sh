#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
export PYTHONPATH="${SCRIPT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"
export PYTHONDONTWRITEBYTECODE=1

if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
  PY="${VIRTUAL_ENV}/bin/python"
elif [[ -x "${SCRIPT_DIR}/.venv/bin/python" ]]; then
  PY="${SCRIPT_DIR}/.venv/bin/python"
elif [[ -x "${SCRIPT_DIR}/../.venv/bin/python" ]]; then
  PY="${SCRIPT_DIR}/../.venv/bin/python"
else
  PY="${PYTHON:-python3}"
fi

run_public_artifact_validation() {
  if [[ ! -f "${SCRIPT_DIR}/artifact_manifest.json" ]]; then
    echo "Error: validate-public-artifact requires an artifact package root." >&2
    exit 1
  fi

  echo "Running artifact integrity check..."
  "${PY}" -m soc_llm_policy.artifact_verify --package-root .
  echo "Artifact integrity OK: release_candidate_checklist.json"

  echo "Running dataset audit recheck..."
  "${PY}" -m soc_llm_policy.dataset_audit \
    --repo-root . \
    --all \
    --output-json artifact_outputs/analysis/dataset_audit_recheck.json \
    --readiness-json artifact_outputs/analysis/corpus_readiness_recheck.json
  echo "Dataset audit recheck OK: artifact_outputs/analysis/dataset_audit_recheck.json"

  echo "Running global artifact assessment recheck..."
  "${PY}" -m soc_llm_policy.global_artifact_assessment \
    --repo-root . \
    --all \
    --official-summary-json artifact_outputs/analysis/official_evaluation_summary.json \
    --official-summary-output-json artifact_outputs/analysis/official_evaluation_summary_recheck.json \
    --output-json artifact_outputs/analysis/global_artifact_assessment_recheck.json \
    --output-md artifact_outputs/analysis/global_artifact_assessment_recheck.md
  echo "Global artifact assessment recheck OK: artifact_outputs/analysis/global_artifact_assessment_recheck.json"

  echo "Running release hygiene recheck..."
  "${PY}" -m soc_llm_policy.release_audit \
    --repo-root . \
    --allow-local-env \
    --output-json artifact_outputs/analysis/release_readiness_recheck.json
  echo "Release hygiene recheck OK: artifact_outputs/analysis/release_readiness_recheck.json"
}

COMMAND="${1:-}"

case "${COMMAND}" in
  validate-public-artifact)
    shift
    run_public_artifact_validation "$@"
    ;;
  artifact-verify)
    shift
    exec "${PY}" -m soc_llm_policy.artifact_verify --package-root . "$@"
    ;;
  dataset-audit)
    shift
    exec "${PY}" -m soc_llm_policy.dataset_audit --repo-root . "$@"
    ;;
  release-audit)
    shift
    exec "${PY}" -m soc_llm_policy.release_audit --repo-root . "$@"
    ;;
  *)
    exec "${PY}" -m soc_llm_policy.pipeline "$@"
    ;;
esac
