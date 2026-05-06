#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

resolve_paper_dir() {
  if [[ -n "${SOC_LLM_POLICY_PAPER_DIR:-}" ]]; then
    if [[ -d "${SOC_LLM_POLICY_PAPER_DIR}" ]]; then
      printf '%s\n' "${SOC_LLM_POLICY_PAPER_DIR}"
      return
    fi
    echo "Configured paper workspace not found: ${SOC_LLM_POLICY_PAPER_DIR}" >&2
    exit 1
  fi

  local candidate
  for candidate in "${ROOT_DIR}/../paper"; do
    if [[ -d "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return
    fi
  done

  echo "Paper workspace not found. Set SOCPILOT_PAPER_DIR or create ../paper." >&2
  exit 1
}

PAPER_DIR="$(resolve_paper_dir)"
LOCK_FILE="${PAPER_DIR}/template_lock.sha256"
NORMALIZED_LOCK_FILE="$(mktemp)"
trap 'rm -f "${NORMALIZED_LOCK_FILE}"' EXIT

if [[ ! -f "${LOCK_FILE}" ]]; then
  echo "Missing lock file: ${LOCK_FILE}"
  exit 1
fi

echo "Verifying template locked files..."
PAPER_DIR_ENV="${PAPER_DIR}" LOCK_FILE_ENV="${LOCK_FILE}" NORMALIZED_LOCK_FILE_ENV="${NORMALIZED_LOCK_FILE}" python3 <<'PY'
from __future__ import annotations

import os
from pathlib import Path

paper_dir = Path(os.environ["PAPER_DIR_ENV"])
lock_file = Path(os.environ["LOCK_FILE_ENV"])
normalized_lock = Path(os.environ["NORMALIZED_LOCK_FILE_ENV"])

normalized_lines: list[str] = []
for line in lock_file.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    digest, rel_path = line.split("  ", 1)
    candidate = paper_dir / rel_path
    if not candidate.exists():
        fallback = paper_dir / Path(rel_path).name
        if fallback.exists():
            rel_path = fallback.name
    normalized_lines.append(f"{digest}  {rel_path}")

normalized_lock.write_text(
    "\n".join(normalized_lines) + ("\n" if normalized_lines else ""),
    encoding="utf-8",
)
PY
(
  cd "${PAPER_DIR}"
  shasum -a 256 -c "${NORMALIZED_LOCK_FILE}"
)

echo "Template lock integrity OK."
