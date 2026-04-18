# Artifact README

This package is the canonical public artifact for the official frozen evaluation.

## What is inside
- `artifact_data/`: anonymized dataset and active global artifacts used by the study.
- `artifact_outputs/analysis/protocol_freeze.json`: single source of truth for the official protocol freeze.
- `artifact_outputs/analysis/`: canonical non-private analysis outputs included at packaging time.
- `artifact_outputs/analysis/official_evaluation_summary.json`: aggregate totals from the completed paid evaluation, retained for auditability without shipping paid execution traces.
- `artifact_outputs/analysis/official_runs_manifest.json`: public execution accounting for the reported official evaluation, including per-cell run counts, tokens, and costs.
- `artifact_outputs/analysis/official_pairwise_tests.json`: public paired-test summary for the reported official evaluation, including the exact contrasts shown in the paper's paired-tests table.
- `artifact_outputs/analysis/repeat_stability/`: optional non-private robustness summaries for repeated frozen-corpus reruns.
- `src/`, `scripts/`, `config/`, `local_redaction/`: code and frozen global mapping contract needed to audit and reproduce the artifact.
- `config/models.freeze.yaml`: the frozen model registry used for the reported study, retained for auditability and cost reconstruction.
- `config/models.example.yaml`: template for optional local reruns; local overrides are not part of the frozen artifact.

## Freeze summary
- Artifact label: `submission_freeze`
- Protocol label: `official`
- Incident count: `200`
- Official models: `openai_gpt52, anthropic_sonnet46`

## Inspectable frozen surfaces
- `src/soc_llm_policy/pipeline.py`: arm-to-prompt mapping (`llm_zero` versus `llm_policy_prompt`).
- `src/soc_llm_policy/llm_adapter.py`: shared prompt template, JSON output contract, and inline rendering of frozen policy rules.
- `config/models.freeze.yaml`: frozen model registry for the reported study.
- `local_redaction/action_mapping_bank.yaml`: frozen task-to-action mapping contract used by the canonical incident package.

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
verification reports under `artifact_outputs/analysis/`.
Local transient files such as `.venv/` and `__pycache__/` are ignored by
the integrity check.
It also verifies that `artifact_outputs/analysis/protocol_freeze.json` points
to packaged files whose SHA-256 digests match the published bundle.
The public package does not include the paid official LLM execution bundle; its
analysis outputs are the non-private zero-cost outputs shipped at packaging
time, including the human-baseline analysis bundle, the copied official
summary, the public run-accounting manifest, and the public paired-test
summary used for auditability. When present, `artifact_outputs/analysis/repeat_stability/` adds the non-private
stability summaries used for robustness reporting in the paper. Per-run prompt
messages and run snapshots belong to the paid execution lineage; the public
bundle exposes the frozen arm definition, aggregate official accounting, and
global inputs, but not the paid execution payloads.

The frozen global policy surface is broader than the empirically exercised rule
slice in this package. The official summary reports observed violations only for
`R3` and `R4`; `R1` is a narrow reverse-shell signature absent from the frozen
incident slice, and `R2` requires restoration without earlier forensics, which
did not occur in the paired baselines or official LLM trajectories.

Readers should treat `artifact_outputs/analysis/protocol_freeze.json` as the canonical protocol manifest for this package.
