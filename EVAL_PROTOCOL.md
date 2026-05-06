# Evaluation Protocol

## Objective
Evaluate whether LLM-generated incident-response plans violate declared SOC
policy rules, where those violations concentrate, and how deterministic
enforcement changes the resulting plans before analyst review.

## Official frozen configuration
- Incident count: `200`
- Official models: `openai_gpt52, anthropic_sonnet46`
- Arms: `llm_zero, llm_policy_prompt`
- Approval policy mode: `remove`

## Canonical outputs
- `artifact_outputs/analysis/protocol_freeze.json`
- `artifact_outputs/analysis/summary.json`
- `artifact_outputs/analysis/analysis_bundle.json`
- `artifact_outputs/analysis/official_llm_analysis_bundle.json`
- `artifact_outputs/analysis/official_evaluation_summary.json`
- `artifact_outputs/analysis/official_pairwise_tests.json`
- `artifact_outputs/analysis/global_artifact_assessment.json`
- `artifact_outputs/analysis/global_artifact_provenance.json`
- `artifact_outputs/analysis/repeat_stability/` (when present)

## Public-bundle scope
- The packaged zero-cost bundle includes the frozen protocol manifest, canonical non-private analysis outputs, and the code needed to rerun integrity checks and dataset audits.
- `artifact_outputs/analysis/analysis_bundle.json` in this public package covers the human-baseline analysis included at packaging time.
- `artifact_outputs/analysis/official_llm_analysis_bundle.json` preserves sanitized row-level metrics from the completed official paid evaluation, without raw prompts, raw provider payloads, local run snapshots, or private lineage.
- `artifact_outputs/analysis/official_evaluation_summary.json` preserves the aggregate paid-evaluation totals used by the paper.
- `artifact_outputs/analysis/official_pairwise_tests.json` preserves the paired official contrasts used by the paper.
- `artifact_outputs/analysis/repeat_stability/`, when present, preserves non-private summaries of repeated frozen-corpus reruns used for robustness reporting.
- Reproducing the paid provider calls themselves remains outside the public zero-cost path.
- Reviewers may supply their own provider keys and run new experiments with the
  same artifact or with their own incident packages. Such runs are new execution
  lineages unless the incident slice, policy files, model registry, prompt
  template, and verifier manifest all match the reported state.

## Rule-activation interpretation
- The official summary in this package reports observed violations only for the approval-gated slice (`R3`, `R4`).
- `R1` remains part of the frozen global policy surface but is intentionally keyed to a narrow reverse-shell signature (`command_execution` plus `bash -i` and `/dev/tcp/`), which is absent from the frozen incident slice.
- `R2` remains active as an ordering constraint, but its antecedent requires restoration without earlier forensics, which did not occur in the paired baselines or official LLM trajectories.

## Inspectable frozen arm surfaces
- `src/soc_llm_policy/pipeline.py`: binds `llm_zero` to `policy_prompt_mode=none` and `llm_policy_prompt` to `policy_prompt_mode=inline_constraints`.
- `src/soc_llm_policy/llm_adapter.py`: defines the shared prompt template, JSON response contract, and inline policy-constraint block.
- `config/models.freeze.yaml`: records the frozen model registry used in the study.
- `local_redaction/action_mapping_bank.yaml`: records the frozen mapping contract used to derive the paired baseline traces.

## Reproducibility requirements
- Preserve the packaged anonymized dataset under `artifact_data/`
- Treat `artifact_outputs/analysis/protocol_freeze.json` as the official protocol manifest
- Re-run verification and dataset audit from the package root to confirm integrity before any additional analysis
