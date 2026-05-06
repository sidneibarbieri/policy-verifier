# Release Boundary

This package is the public artifact boundary for reproducibility. It is the
software and data package used to validate and rerun SOCpilot experiments; it is
not the manuscript and it does not include research-administration folders such
as local literature reviews, private project-framework notes, or internal
planning material.

- Contains only anonymized inputs under `artifact_data/`.
- Excludes raw incoming data and secret-bearing local environment files.
- Includes the frozen public preprocessing shim under `local_redaction/` only to support reproducible mapping and dataset-audit reruns.
- Excludes local secrets (`.env`) and developer caches.
- Excludes paper workspaces, literature folders, private notes, and other
  author-only administrative resources.
- Includes optional analysis outputs under `artifact_outputs/` when available.
- The packaged analysis outputs in `artifact_outputs/analysis/` cover the human-baseline pipeline plus zero-cost dataset-audit and release-hygiene evidence included at packaging time.
- When present, `artifact_outputs/analysis/official_llm_analysis_bundle.json` preserves sanitized non-private row-level metrics from the completed official paid evaluation.
- When present, `artifact_outputs/analysis/repeat_stability/` preserves non-private robustness summaries for repeated frozen-corpus reruns.
- Raw paid prompts, provider payloads, local run snapshots, and private incident lineage remain excluded.
