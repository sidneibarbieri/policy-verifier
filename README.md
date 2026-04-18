# Artifact Package

This package contains the anonymized dataset, frozen policy artifacts, and the code needed to reproduce the public analyses for the paper.

## Environment setup
Create and activate a virtual environment inside this package before running the
checks below. The bundled `run.sh` already exposes the packaged `src/` tree and
auto-detects `.venv/` when present, so you only need the dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
```

## Recommended verification order
```bash
bash run.sh validate-public-artifact
```

This zero-cost command runs artifact integrity checks, dataset audit,
global-artifact assessment, and release-hygiene rechecks and writes fresh
verification reports under
`artifact_outputs/analysis/`.
Local transient files such as `.venv/` and `__pycache__/` are ignored by
the integrity check.
It also verifies that `artifact_outputs/analysis/protocol_freeze.json` points
to packaged files whose SHA-256 digests match the published bundle.
The public package does not include the paid official LLM execution bundle; its
shipped analysis outputs are the non-private zero-cost outputs included at
packaging time, including the human-baseline analysis bundle, the copied
official summary, the public run-accounting manifest, and the public paired-test
summary used to audit the paper's main aggregate results.
When present, the packaged `artifact_outputs/analysis/repeat_stability/`
directory also exposes the non-private stability summaries used by the paper's
robustness discussion.

Readers should interpret the frozen rule surface and the observed rule slice
together: the official summary reports observed violations only for the
approval-gated rules (`R3`, `R4`). `R1` remains globally active but is keyed to
a narrow reverse-shell signature absent from the frozen incident slice, and `R2`
requires restoration without earlier forensics, which does not occur in the
reported freeze.

## Package layout
- `artifact_data/`: anonymized incident dataset and frozen global policy inputs
- `artifact_outputs/analysis/`: non-private analysis outputs, public run accounting, public paired contrasts, and the official protocol manifest
- `src/`, `scripts/`, `config/`, `local_redaction/`: reproducibility code and frozen mapping contract

Use `ARTIFACT_README.md` for the high-level package summary and `EVAL_PROTOCOL.md` for the frozen evaluation setup. The frozen model registry is recorded in `config/models.freeze.yaml`; local execution overrides are intentionally excluded.
