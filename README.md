# Artifact Package

This package starts from the already anonymized canonical dataset and includes the frozen policy artifacts plus the code needed to reproduce the public analyses for the paper.

## Environment setup
Create and activate a virtual environment inside this package before running the
checks below. The bundled `run.sh` already exposes the packaged `src/` tree, so
you only need the dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
```

## Recommended verification order
```bash
./run.sh validate-public-artifact
```

This zero-cost command runs artifact integrity checks, dataset audit, and
release-hygiene rechecks and writes fresh verification reports under
`artifact_outputs/analysis/`.
Local reviewer transients such as `.venv/` and `__pycache__/` are ignored by
the integrity check.
It also verifies that `artifact_outputs/analysis/protocol_freeze.json` points
to packaged files whose SHA-256 digests match the published bundle.
The public package does not include the paid official LLM execution bundle; its
shipped analysis outputs are the non-private zero-cost outputs included at
packaging time, including the human-baseline analysis bundle.
The paper sources and the private anonymization workflow are intentionally
excluded from this repository.

## Package layout
- `artifact_data/`: anonymized incident dataset and frozen global policy inputs
- `artifact_outputs/analysis/`: non-private analysis outputs and the official protocol manifest
- `src/`, `scripts/`, `config/`: reproducibility code and frozen audit inputs
- `local_redaction/action_mapping_bank.yaml`: frozen task-to-action mapping contract for the paired human baseline

Use `ARTIFACT_README.md` for the high-level package summary and `EVAL_PROTOCOL.md` for the frozen evaluation setup. The frozen model registry is recorded in `config/models.freeze.yaml`; local execution overrides are intentionally excluded.
