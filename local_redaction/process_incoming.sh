#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IN_DIR="${ROOT_DIR}/incoming/raw"
OUT_DIR="${ROOT_DIR}/dataset/incidents"
STAGING_DIR="${ROOT_DIR}/incoming/redacted"
MAPPING_FILE="${ROOT_DIR}/local_redaction/action_mapping_bank.yaml"
OVERWRITE_EXISTING=0
PLAN_ONLY=0

usage() {
  cat <<'EOF'
Usage: ./local_redaction/process_incoming.sh [--plan-only] [--overwrite-existing]

Default behavior is incremental and safe:
- complete canonical incidents already present under dataset/incidents/ are skipped
- only missing or incomplete incidents are processed

Options:
  --plan-only           Show what would be processed or skipped without writing.
  --overwrite-existing  Reprocess even complete canonical incidents.
  --help                Show this message.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only)
      PLAN_ONLY=1
      shift
      ;;
    --overwrite-existing)
      OVERWRITE_EXISTING=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  PYTHON="${ROOT_DIR}/.venv/bin/python"
elif [[ -x "${ROOT_DIR}/../.venv/bin/python" ]]; then
  PYTHON="${ROOT_DIR}/../.venv/bin/python"
else
  PYTHON="${PYTHON:-python3}"
fi

mkdir -p "${IN_DIR}" "${OUT_DIR}" "${STAGING_DIR}"

count=0
skipped=0

incident_dir_for_file() {
  local file="$1"
  local base digits
  base="$(basename "${file}")"
  digits="$(printf '%s' "${base}" | tr -cd '0-9')"
  if [[ -z "${digits}" ]]; then
    digits="000000"
  fi
  printf 'INC_BANK_%s' "${digits}"
}

incident_dir_complete() {
  local dir="$1"
  [[ -f "${dir}/incident_meta.json" ]] &&
  [[ -f "${dir}/incident_telemetry.jsonl" ]] &&
  [[ -f "${dir}/incident_human_actions.jsonl" ]] &&
  [[ -f "${dir}/evidence/source_manifest.json" ]] &&
  [[ -f "${dir}/evidence/conversion_quality.json" ]]
}

for file in "${IN_DIR}"/*.json; do
  [[ -e "${file}" ]] || continue
  incident_id="$(incident_dir_for_file "${file}")"
  incident_dir="${OUT_DIR}/${incident_id}"
  if [[ "${OVERWRITE_EXISTING}" -eq 0 ]] && incident_dir_complete "${incident_dir}"; then
    echo "[anonymizer] skipping complete canonical incident ${incident_id}"
    skipped=$((skipped+1))
    continue
  fi
  if [[ "${PLAN_ONLY}" -eq 1 ]]; then
    if [[ -d "${incident_dir}" ]]; then
      echo "[anonymizer] would refresh incomplete incident ${incident_id}"
    else
      echo "[anonymizer] would process new incident ${incident_id}"
    fi
    count=$((count+1))
    continue
  fi
  echo "[anonymizer] processing $(basename "${file}")"
  "${PYTHON}" "${ROOT_DIR}/local_redaction/anonymize_export.py" \
    --input-json "${file}" \
    --out-incidents-dir "${OUT_DIR}" \
    --staging-dir "${STAGING_DIR}" \
    --mapping-rules "${MAPPING_FILE}" \
    --skip-existing-complete
  count=$((count+1))
done

if [[ "${PLAN_ONLY}" -eq 1 ]]; then
  echo "[anonymizer] plan complete. files to process: ${count}; files skipped: ${skipped}"
else
  echo "[anonymizer] done. files processed: ${count}; files skipped: ${skipped}"
fi

SUGGEST_SCRIPT="${ROOT_DIR}/scripts/suggest_global_policy_updates.py"
if [[ "${PLAN_ONLY}" -eq 0 ]] && [[ -f "${SUGGEST_SCRIPT}" ]]; then
  echo "[anonymizer] refreshing safe global suggestions..."
  "${PYTHON}" "${SUGGEST_SCRIPT}" \
    --raw-incoming-dir "${IN_DIR}" \
    --mapping-rules "${MAPPING_FILE}" \
    --action-catalog "${ROOT_DIR}/policy/action_catalog.yaml" \
    --constraints "${ROOT_DIR}/policy/constraints.yaml" \
    --output-dir "${ROOT_DIR}/results/analysis/global_policy_suggestions" \
    --min-unmapped-frequency 2 || echo "[anonymizer] warning: suggestion refresh failed."
fi
