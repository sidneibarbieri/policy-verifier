#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SOURCE_DIR="${SOURCE_DIR:-${POLICY_ROOT}/artifact}"
OUTPUT_DIR="${OUTPUT_DIR:-${POLICY_ROOT}/.local/blind_artifact_export}"
MAKE_TARBALL=0
SKIP_VALIDATE=0

usage() {
  cat <<'EOF'
Usage:
  scripts/export_blind_artifact.sh [--output-dir PATH] [--make-tarball] [--skip-validate]

Behavior:
  - Validates the tracked artifact package by default.
  - Copies only the blind-safe public artifact/ surface into a clean export
    directory with no git metadata.
  - Optionally creates a tarball beside the export directory.

Notes:
  - Use this export for anonymous artifact hosting during blind review.
  - Do not publish the maintainer repository when the venue still requires
    anonymous artifact access.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --make-tarball)
      MAKE_TARBALL=1
      shift
      ;;
    --skip-validate)
      SKIP_VALIDATE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "${SOURCE_DIR}" ]]; then
  echo "Artifact source not found: ${SOURCE_DIR}" >&2
  exit 1
fi

if [[ "${SKIP_VALIDATE}" -ne 1 ]]; then
  (
    cd "${SOURCE_DIR}"
    ./run.sh validate-public-artifact
  )
fi

rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"
rsync -a --delete "${SOURCE_DIR}/" "${OUTPUT_DIR}/"

if [[ "${MAKE_TARBALL}" -eq 1 ]]; then
  tarball_path="${OUTPUT_DIR%/}.tar.gz"
  rm -f "${tarball_path}"
  tar -czf "${tarball_path}" -C "${OUTPUT_DIR}" .
  echo "Tarball written to: ${tarball_path}"
fi

echo "Blind artifact export ready at: ${OUTPUT_DIR}"
