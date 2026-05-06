# SOCpilot Reproduction Report

Status: **pass**

This zero-cost reproduction path does not rerun paid LLM calls. It checks the public artifact surface, recomputes public audits, and verifies that sanitized official row-level metrics agree with the shipped official summaries.

## Protocol

- Dataset release: `submission_freeze`
- Evaluation protocol: `official`
- Incidents: `200`
- Action catalog size: `5`
- Policy rule count: `4`
- Official models: `gpt-5.2, claude-sonnet-4-6`

## Official Evaluation

- Planned LLM trajectories: `800`
- Completed LLM trajectories: `800`
- Final failed LLM trajectories: `0`
- Run-level violation rate: `0.88`
- Enforcement-modification rate: `0.56`
- Task-coverage drop rate: `0.0`
- Violations by rule: `{'R3': 431, 'R4': 35}`
- Repair modes observed: `{'insert': 0, 'remove': 466, 'defer': 0, 'reorder': 0}`
- Estimated paid-run cost recorded in manifest: `$3.034621`

## Public Consistency

- Official public consistency: `pass`
- Consistency checks: `41`
- Failed consistency checks: `0`
- Release hygiene status: `ok`
- Release hygiene issue count: `0`

## Evidence Files

- `artifact_outputs/analysis/protocol_freeze.json`: present, sha256 `16f76a105243bde64792210bed1ebab1ba89d6b4d1866b7fdd8d4c3423141dc1`
- `artifact_outputs/analysis/dataset_audit_recheck.json`: present, sha256 `df17589a2752d2196dbc8e015f998c42f0cae8516adec8871f5abc1bcff480a8`
- `artifact_outputs/analysis/corpus_readiness_recheck.json`: present, sha256 `856a1261b9bb149c9608ce6ac1e71e7342b68d002fde56a26a18ed193ba7a89c`
- `artifact_outputs/analysis/global_artifact_assessment_recheck.json`: present, sha256 `f3a16ae8a8f966af8d931e65801ce4e776e24331a0701810cc63a9b01783263b`
- `artifact_outputs/analysis/official_llm_analysis_bundle.json`: present, sha256 `df0c800cd05ea3eb895ea9762248f4ba4efdc09538a177ca967a1c8f5b295583`
- `artifact_outputs/analysis/official_evaluation_summary.json`: present, sha256 `85edb669661c364fce7ce6d02d83d9306dd2c9cf4c184877edb7f538a016f9aa`
- `artifact_outputs/analysis/official_runs_manifest.json`: present, sha256 `e565eccddafb068d70ca05911d9faf2093fae6f9ef54faa04e3540c72b696a1b`
- `artifact_outputs/analysis/official_pairwise_tests.json`: present, sha256 `b18fba90f93bc9d360f57ca9521e5c78007e20103bbc0656ae663378c34b8560`
- `artifact_outputs/analysis/official_public_consistency.json`: present, sha256 `bde5f33aba47ff6d8bdb8577fafea6e7c66175cdc3be007c52accb53772de48c`
- `artifact_outputs/analysis/release_readiness_recheck.json`: present, sha256 `0f3fd678882ae04dd8fb9ee0ba9a6ffa07c00114fb1aa958a238dc6b13534bc4`
- `artifact_outputs/analysis/repeat_stability/repeat_stability_summary.json`: present, sha256 `599080979b9ce0b8558d413782af1f3482cb1c6a0ab31444a580d521ed64d978`

## Interpretation

- This command reproduces the public analysis checks without rerunning paid LLM calls.
- The official evaluation remains the frozen real-SOC protocol.
- Sanitized row-level official metrics are checked against shipped summaries, manifests, and paired tests.
- Observed official violations activate approval rules R3 and R4; inactive rule families remain declared scope limitations, not pooled evidence.
