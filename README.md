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

## Optional paid reruns with your own keys
Reviewers do not need any provider key for the public zero-cost path above.
If you want to attempt your own paid rerun, copy `.env.example` to `.env`,
fill only the provider block you intend to use, and optionally copy
`config/models.example.yaml` to `config/models.local.yaml` for local registry
overrides.

Example single-provider rerun command:

```bash
cp .env.example .env
cp config/models.example.yaml config/models.local.yaml
# edit .env and config/models.local.yaml first
PYTHONPATH=src python -m soc_llm_policy.experiment_runner \
  --repo-root . \
  --models openai_gpt52,anthropic_sonnet46 \
  --arms llm_zero,llm_policy_prompt \
  --repeats 1 \
  --all \
  --dataset-release-id submission_freeze \
  --eval-protocol-version official
```

Any rerun with your own keys is a fresh execution, not part of the canonical
paper lineage.

## Official aggregate paper results
The public package preserves the aggregate official results used by the paper
under `artifact_outputs/official_evaluation/`. These files let reviewers compare
their own reruns against the canonical reported metrics without redistributing
the raw paid execution snapshots.

## Package layout
- `artifact_data/`: anonymized incident dataset and frozen global policy inputs
- `artifact_outputs/analysis/`: non-private analysis outputs and the official protocol manifest
- `artifact_outputs/official_evaluation/`: aggregate official paid evaluation outputs used by the paper
- `src/`, `scripts/`, `config/`: reproducibility code and frozen audit inputs
- `local_redaction/action_mapping_bank.yaml`: frozen task-to-action mapping contract for the paired human baseline

Use `ARTIFACT_README.md` for the high-level package summary and `EVAL_PROTOCOL.md` for the frozen evaluation setup. The frozen model registry is recorded in `config/models.freeze.yaml`; local execution overrides are intentionally excluded.
