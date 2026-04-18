# Release Boundary

This package is the public artifact boundary for reproducibility.

- Contains only anonymized inputs under `artifact_data/`.
- Excludes raw incoming data and secret-bearing local environment files.
- Includes the frozen public preprocessing shim under `local_redaction/` only to support reproducible mapping and dataset-audit reruns.
- Excludes local secrets (`.env`) and developer caches.
- Includes optional analysis outputs under `artifact_outputs/` when available.
- The packaged analysis outputs in `artifact_outputs/analysis/` cover the human-baseline pipeline, the copied official aggregate summary, the public run-accounting manifest, and the zero-cost dataset-audit and release-hygiene evidence included at packaging time.
- When present, `artifact_outputs/analysis/repeat_stability/` preserves non-private robustness summaries for repeated frozen-corpus reruns.
- The completed official LLM evaluation bundle is part of the canonical paid lineage and is intentionally not included here because reproducing it requires paid API access.
