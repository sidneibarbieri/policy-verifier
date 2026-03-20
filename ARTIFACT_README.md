# Artifact README

This package is the canonical public artifact for the official frozen evaluation.

## What is inside
- `artifact_data/`: anonymized dataset and active global artifacts used by the study.
- `artifact_outputs/analysis/protocol_freeze.json`: single source of truth for the official protocol freeze.
- `artifact_outputs/analysis/`: canonical non-private analysis outputs included at packaging time.
- `src/`, `scripts/`, `config/`: code and frozen audit inputs needed to audit and reproduce the artifact.
- `local_redaction/action_mapping_bank.yaml`: frozen mapping contract retained for paired-baseline auditability.
- `config/models.freeze.yaml`: the frozen model registry used for the reported study, retained for auditability and cost reconstruction.
- `config/models.example.yaml`: template for optional local reruns; local overrides are not part of the frozen artifact.

## Freeze summary
- Artifact label: `submission_freeze`
- Protocol label: `official`
- Incident count: `100`
- Official models: `openai_gpt52, anthropic_sonnet46`

## Release boundary
This public package begins after the private anonymization step. It contains the canonical anonymized dataset and the frozen mapping/policy inputs used by the paper, but it does not include the raw-export preprocessing workflow.
It also excludes the paper sources; reviewers verify the study from the public artifact itself.

## Inspectable frozen surfaces
- `src/soc_llm_policy/pipeline.py`: arm-to-prompt mapping (`llm_zero` versus `llm_policy_prompt`).
- `src/soc_llm_policy/llm_adapter.py`: shared prompt template, JSON output contract, and inline rendering of frozen policy rules.
- `config/models.freeze.yaml`: frozen model registry for the reported study.
- `local_redaction/action_mapping_bank.yaml`: frozen task-to-action mapping contract used by the canonical incident package.

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
analysis outputs are the non-private zero-cost outputs shipped at packaging
time, including the human-baseline analysis bundle.
Per-run prompt messages and run snapshots belong to the paid execution lineage;
the public bundle exposes the frozen arm definition and global inputs, but not
the paid execution payloads.

Reviewers should treat `artifact_outputs/analysis/protocol_freeze.json` as the canonical protocol manifest for this package.
