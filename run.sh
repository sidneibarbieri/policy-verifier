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

ensure_runtime_deps() {
  if "${PY}" - <<'PY' >/dev/null 2>&1
import dotenv
import pydantic
import yaml
PY
  then
    return 0
  fi

  cat >&2 <<'EOF'
Error: required Python dependencies are unavailable for the runner.

Recommended setup:
  python3 -m venv .venv
  source .venv/bin/activate
  .venv/bin/pip install -r requirements.txt -r requirements-dev.txt

Then rerun:
  bash run.sh validate-public-artifact
EOF
  exit 1
}

cleanup_reproduction_transients() {
  find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".ruff_cache" \) -prune -exec rm -rf {} +
}

run_packaged_script_or_note() {
  local script_path="$1"
  shift
  if [[ -f "${script_path}" ]]; then
    "${PY}" "${script_path}" "$@"
    return
  fi

  cat >&2 <<EOF
Command unavailable in this public artifact package: ${script_path}

This package intentionally exposes the zero-cost reviewer path:
  bash run.sh reproduce-results

Maintainer-only commands that require private workspaces or non-packaged
scripts are excluded from the public artifact boundary.
EOF
}

run_public_artifact_validation() {
  if [[ -f "${SCRIPT_DIR}/artifact_manifest.json" ]]; then
    echo "Running artifact integrity check..."
    "${PY}" -m soc_llm_policy.artifact_verify --package-root .
    echo "Artifact integrity OK: release_candidate_checklist.json"
  elif [[ -x "${SCRIPT_DIR}/artifact/run.sh" ]]; then
    exec bash "${SCRIPT_DIR}/artifact/run.sh" validate-public-artifact "$@"
  else
    echo "Error: validate-public-artifact requires an artifact package." >&2
    exit 1
  fi

  cleanup_reproduction_transients
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

  if [[ -f artifact_outputs/analysis/official_llm_analysis_bundle.json ]]; then
    echo "Running official public bundle recheck..."
    "${PY}" -m soc_llm_policy.official_public_recheck \
      --repo-root . \
      --output-json artifact_outputs/analysis/official_public_consistency.json
    echo "Official public bundle recheck OK: artifact_outputs/analysis/official_public_consistency.json"
  fi

  echo "Running release hygiene recheck..."
  cleanup_reproduction_transients
  "${PY}" -m soc_llm_policy.release_audit \
    --repo-root . \
    --allow-local-env \
    --output-json artifact_outputs/analysis/release_readiness_recheck.json
  echo "Release hygiene recheck OK: artifact_outputs/analysis/release_readiness_recheck.json"
}

run_zero_cost_reproduction() {
  if [[ ! -f "${SCRIPT_DIR}/artifact_manifest.json" && -x "${SCRIPT_DIR}/artifact/run.sh" ]]; then
    exec bash "${SCRIPT_DIR}/artifact/run.sh" reproduce-results "$@"
  fi

  run_public_artifact_validation

  echo "Rendering paper tables and figures from shipped public analysis bundles..."
  "${PY}" scripts/render_evaluation_assets.py \
    --analysis-bundle-json artifact_outputs/analysis/analysis_bundle.json \
    --llm-fallback-bundle-json artifact_outputs/analysis/official_llm_analysis_bundle.json \
    --table-output-dir artifact_outputs/reproduced_paper_assets/results \
    --figure-output-dir artifact_outputs/reproduced_paper_assets/figures \
    --support-output-dir artifact_outputs/reproduced_paper_assets/docs
  echo "Reproduced paper assets OK: artifact_outputs/reproduced_paper_assets/"

  echo "Writing SOCpilot reproduction report..."
  "${PY}" -m soc_llm_policy.reproduction_report \
    --repo-root . \
    --output-json artifact_outputs/reproduction_report.json \
    --output-md artifact_outputs/reproduction_report.md

  echo "Rendering reviewer audit dashboard..."
  "${PY}" scripts/render_audit_dashboard.py \
    --analysis-dir artifact_outputs/analysis \
    --output-html artifact_outputs/dashboard/index.html \
    --landing-html REVIEWER_DASHBOARD.html
  echo "Audit dashboard OK: REVIEWER_DASHBOARD.html"
}

run_protocol_extension_analysis() {
  echo "Analyzing protocol-extension activation without provider calls..."
  "${PY}" scripts/analyze_protocol_extension_candidates.py "$@"
}

run_reviewer_surface_audit() {
  echo "Auditing reviewer-facing paper and artifact surfaces..."
  run_packaged_script_or_note scripts/audit_reviewer_surface.py "$@"
}

run_literature_alignment_audit() {
  echo "Auditing paper structure and local literature alignment..."
  run_packaged_script_or_note scripts/audit_paper_literature_alignment.py "$@"
}

run_raw_soar_trace_audit() {
  echo "Auditing raw IBM SOAR workflow trace structure..."
  run_packaged_script_or_note scripts/audit_raw_soar_human_traces.py "$@"
}

run_paid_execution_candidate_analysis() {
  echo "Analyzing zero-cost evidence for a future paid provider run..."
  run_packaged_script_or_note scripts/analyze_paid_execution_candidates.py "$@"
}

build_provider_execution_plan() {
  echo "Building draft provider execution plan from zero-cost evidence..."
  run_packaged_script_or_note scripts/build_provider_execution_plan.py "$@"
}

validate_provider_execution_plan() {
  echo "Validating provider execution plan..."
  run_packaged_script_or_note scripts/validate_provider_execution_plan.py "$@"
}

analyze_approval_mode_sensitivity() {
  echo "Analyzing approval-mode sensitivity from public metrics..."
  "${PY}" scripts/analyze_approval_mode_sensitivity.py "$@"
}

audit_mapping_samples() {
  echo "Building stratified task-to-action mapping audit packet..."
  run_packaged_script_or_note scripts/audit_mapping_samples.py "$@"
}

render_policy_coverage_table() {
  echo "Rendering policy coverage summary and paper table..."
  run_packaged_script_or_note scripts/render_policy_coverage_table.py "$@"
}

replay_approval_modes_from_outputs() {
  echo "Replaying remove-vs-defer approval modes from preserved verifier outputs..."
  run_packaged_script_or_note scripts/replay_approval_modes_from_verifier_outputs.py "$@"
}

render_reviewer_diagnostics_tables() {
  echo "Rendering reviewer diagnostic paper tables..."
  run_packaged_script_or_note scripts/render_reviewer_diagnostics_tables.py "$@"
}

validate_fresh_clone_reproduction() {
  echo "Validating fresh-clone reviewer reproduction path..."
  "${PY}" scripts/validate_fresh_clone_reproduction.py "$@"
}

render_execution_dashboard() {
  echo "Rendering maintainer provider-execution dashboard..."
  "${PY}" scripts/render_execution_dashboard.py "$@"
}

COMMAND="${1:-}"
ensure_runtime_deps

case "${COMMAND}" in
  reproduce-results)
    shift
    run_zero_cost_reproduction "$@"
    ;;
  validate-public-artifact)
    shift
    run_public_artifact_validation "$@"
    ;;
  analyze-protocol-extension)
    shift
    run_protocol_extension_analysis "$@"
    ;;
  audit-reviewer-surface)
    shift
    run_reviewer_surface_audit "$@"
    ;;
  audit-literature-alignment)
    shift
    run_literature_alignment_audit "$@"
    ;;
  audit-raw-soar-traces)
    shift
    run_raw_soar_trace_audit "$@"
    ;;
  analyze-paid-execution-candidates)
    shift
    run_paid_execution_candidate_analysis "$@"
    ;;
  build-provider-execution-plan)
    shift
    build_provider_execution_plan "$@"
    ;;
  validate-provider-execution-plan)
    shift
    validate_provider_execution_plan "$@"
    ;;
  analyze-approval-mode-sensitivity)
    shift
    analyze_approval_mode_sensitivity "$@"
    ;;
  audit-mapping-samples)
    shift
    audit_mapping_samples "$@"
    ;;
  render-policy-coverage-table)
    shift
    render_policy_coverage_table "$@"
    ;;
  replay-approval-modes-from-outputs)
    shift
    replay_approval_modes_from_outputs "$@"
    ;;
  render-reviewer-diagnostics-tables)
    shift
    render_reviewer_diagnostics_tables "$@"
    ;;
  validate-fresh-clone)
    shift
    validate_fresh_clone_reproduction "$@"
    ;;
  render-execution-dashboard)
    shift
    render_execution_dashboard "$@"
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
    if [[ " $* " == *" --llm-mode "* && "${SOCPILOT_ALLOW_DIRECT_PROVIDER_CALLS:-}" != "1" ]]; then
      cat >&2 <<'EOF'
Error: direct provider execution is disabled by default.

Use the audited execution path instead:
  bash run.sh analyze-paid-execution-candidates
  bash run.sh build-provider-execution-plan --dataset-release-id <ID>
  bash run.sh validate-provider-execution-plan
  ./run_experiments.sh official --execution-plan results/analysis/provider_execution_plan.json ...

Set SOCPILOT_ALLOW_DIRECT_PROVIDER_CALLS=1 only for an explicitly approved local
debug session.
EOF
      exit 2
    fi
    exec "${PY}" -m soc_llm_policy.pipeline "$@"
    ;;
esac
