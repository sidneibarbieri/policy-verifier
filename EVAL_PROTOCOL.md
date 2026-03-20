# Evaluation Protocol

## Objective
Evaluate whether LLM-generated incident-response plans violate formal SOC constraints, where those violations concentrate, and how deterministic enforcement changes the resulting plans.

## Official frozen configuration
- Incident count: `100`
- Official models: `openai_gpt52, anthropic_sonnet46`
- Arms: `llm_zero, llm_policy_prompt`
- Approval policy mode: `remove`

## Canonical outputs
- `artifact_outputs/analysis/protocol_freeze.json`
- `artifact_outputs/analysis/summary.json`
- `artifact_outputs/analysis/analysis_bundle.json`
- `artifact_outputs/analysis/global_artifact_provenance.json`

## Public-bundle scope
- The packaged zero-cost bundle includes the frozen protocol manifest, canonical non-private analysis outputs, and the code needed to rerun integrity checks and dataset audits.
- `artifact_outputs/analysis/analysis_bundle.json` in this public package covers the human-baseline analysis included at packaging time.
- The completed official LLM evaluation bundle, including the paid full-corpus execution lineage, is not included in this package because reproducing it requires paid API access.
- The private raw-export anonymization workflow is intentionally excluded; this package starts from the canonical anonymized dataset already included under `artifact_data/dataset/`.

## Inspectable frozen arm surfaces
- `src/soc_llm_policy/pipeline.py`: binds `llm_zero` to `policy_prompt_mode=none` and `llm_policy_prompt` to `policy_prompt_mode=inline_constraints`.
- `src/soc_llm_policy/llm_adapter.py`: defines the shared prompt template, JSON response contract, and inline policy-constraint block.
- `config/models.freeze.yaml`: records the frozen model registry used in the study.
- `local_redaction/action_mapping_bank.yaml`: records the frozen mapping contract used to derive the paired baseline traces.

## Reproducibility requirements
- Preserve the packaged anonymized dataset under `artifact_data/`
- Treat `artifact_outputs/analysis/protocol_freeze.json` as the official protocol manifest
- Re-run verification and dataset audit from the package root to confirm integrity before any additional analysis
