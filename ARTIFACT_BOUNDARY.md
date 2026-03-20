# Release Boundary

This package is the public artifact boundary for reproducibility.

- Contains only anonymized inputs under `artifact_data/`.
- Excludes raw incoming data and secret-bearing local environment files.
- Retains only the frozen mapping contract under `local_redaction/action_mapping_bank.yaml` to support paired-baseline auditability.
- Excludes local secrets (`.env`) and developer caches.
- Includes optional analysis outputs under `artifact_outputs/` when available.
- The packaged analysis outputs in `artifact_outputs/analysis/` cover the human-baseline pipeline plus zero-cost dataset-audit and release-hygiene evidence included at packaging time.
- The completed official LLM evaluation bundle is part of the canonical paid lineage and is intentionally not included here because reproducing it requires paid API access.
