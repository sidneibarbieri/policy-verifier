#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IN_DIR="${ROOT_DIR}/incoming/raw"
OUT_DIR="${ROOT_DIR}/dataset/incidents"
STAGING_DIR="${ROOT_DIR}/incoming/redacted"
MAPPING_FILE="${ROOT_DIR}/local_redaction/action_mapping_bank.yaml"

if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  PYTHON="${ROOT_DIR}/.venv/bin/python"
elif [[ -x "${ROOT_DIR}/../.venv/bin/python" ]]; then
  PYTHON="${ROOT_DIR}/../.venv/bin/python"
else
  PYTHON="${PYTHON:-python3}"
fi

mkdir -p "${IN_DIR}" "${OUT_DIR}" "${STAGING_DIR}"

count=0
for file in "${IN_DIR}"/*.json; do
  [[ -e "${file}" ]] || continue
  echo "[anonymizer] processing $(basename "${file}")"
  "${PYTHON}" "${ROOT_DIR}/local_redaction/anonymize_export.py" \
    --input-json "${file}" \
    --out-incidents-dir "${OUT_DIR}" \
    --staging-dir "${STAGING_DIR}" \
    --mapping-rules "${MAPPING_FILE}"
  count=$((count+1))
done

echo "[anonymizer] done. files processed: ${count}"

SUGGEST_SCRIPT="${ROOT_DIR}/scripts/suggest_global_policy_updates.py"
if [[ -f "${SUGGEST_SCRIPT}" ]]; then
  echo "[anonymizer] refreshing safe global suggestions..."
  "${PYTHON}" "${SUGGEST_SCRIPT}" \
    --raw-incoming-dir "${IN_DIR}" \
    --mapping-rules "${MAPPING_FILE}" \
    --action-catalog "${ROOT_DIR}/policy/action_catalog.yaml" \
    --constraints "${ROOT_DIR}/policy/constraints.yaml" \
    --output-dir "${ROOT_DIR}/results/analysis/global_policy_suggestions" \
    --min-unmapped-frequency 2 || echo "[anonymizer] warning: suggestion refresh failed."
fi
