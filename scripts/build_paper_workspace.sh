#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

resolve_paper_dir() {
  local configured_dir="${SOCPILOT_PAPER_DIR:-${SOC_LLM_POLICY_PAPER_DIR:-}}"
  if [[ -n "${configured_dir}" ]]; then
    if [[ -d "${configured_dir}" ]]; then
      printf '%s\n' "${configured_dir}"
      return
    fi
    echo "Configured paper workspace not found: ${configured_dir}" >&2
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

resolve_latexmk() {
  if [[ -x "/Library/TeX/texbin/latexmk" ]]; then
    printf '%s\n' "/Library/TeX/texbin/latexmk"
    return
  fi
  if command -v latexmk >/dev/null 2>&1; then
    command -v latexmk
    return
  fi
  local fallback="/usr/local/texlive/2026/bin/universal-darwin/latexmk"
  if [[ -x "${fallback}" ]]; then
    printf '%s\n' "${fallback}"
    return
  fi
  echo "latexmk not found. Install TeX Live/TinyTeX or add latexmk to PATH." >&2
  exit 1
}

clean_root_aux_files() {
  local paper_dir="$1"
  find "${paper_dir}" -maxdepth 1 -type f \
    \( \
      -name '*.aux' -o \
      -name '*.bbl' -o \
      -name '*.blg' -o \
      -name '*.fdb_latexmk' -o \
      -name '*.fls' -o \
      -name '*.log' -o \
      -name '*.out' -o \
      -name '*.synctex.gz' -o \
      -name '*.toc' -o \
      -name '*.lof' -o \
      -name '*.lot' -o \
      -name '*.bcf' -o \
      -name '*.run.xml' -o \
      -name '*.nav' -o \
      -name '*.snm' -o \
      -name '*.vrb' -o \
      -name '*.xdv' -o \
      -name '*.dvi' \
    \) \
    -delete
}

PAPER_DIR=""
BUILD_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --paper-dir)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --paper-dir" >&2
        exit 2
      fi
      PAPER_DIR="$2"
      BUILD_DIR="${PAPER_DIR}/.paper-build"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${PAPER_DIR}" ]]; then
  PAPER_DIR="$(resolve_paper_dir)"
  BUILD_DIR="${PAPER_DIR}/.paper-build"
fi

LATEXMK_BIN="$(resolve_latexmk)"

if [[ ! -f "${PAPER_DIR}/main.tex" ]]; then
  echo "Missing paper source: ${PAPER_DIR}/main.tex" >&2
  exit 1
fi

clean_root_aux_files "${PAPER_DIR}"
mkdir -p "${BUILD_DIR}"

(
  cd "${PAPER_DIR}"
  "${LATEXMK_BIN}" \
    -synctex=1 \
    -interaction=nonstopmode \
    -file-line-error \
    -pdf \
    -auxdir=".paper-build" \
    -outdir=".paper-build" \
    main.tex
  cp ".paper-build/main.pdf" "main.pdf"
  clean_root_aux_files "."
)
