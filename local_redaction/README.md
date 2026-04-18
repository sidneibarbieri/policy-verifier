# Local Redaction

This directory contains the local-only preprocessing step used to transform sensitive raw exports into the canonical anonymized dataset.

## Purpose

- read raw incident JSON exports from `incoming/raw/`
- write redacted staging files to `incoming/redacted/`
- write canonical anonymized incidents to `dataset/incidents/`

## Single-file mode

```bash
cd policy-verifier
.venv/bin/python local_redaction/anonymize_export.py \
  --input-json incoming/raw/incident_606407_export.json \
  --out-incidents-dir dataset/incidents \
  --staging-dir incoming/redacted \
  --mapping-rules local_redaction/action_mapping_bank.yaml
```

## Batch mode

```bash
cd policy-verifier
./local_redaction/process_incoming.sh
```

Safe preview before touching the canonical corpus:

```bash
cd policy-verifier
./local_redaction/process_incoming.sh --plan-only
```

Deliberate full refresh of already-canonical incidents:

```bash
cd policy-verifier
./local_redaction/process_incoming.sh --overwrite-existing
```

## Notes

- Do not commit raw exports or other sensitive inputs.
- The loader repairs malformed raw-export backslashes before JSON parsing and
  records the repair count in each incident `evidence/source_manifest.json`.
- Batch mode is incremental by default: complete canonical incidents already
  present under `dataset/incidents/` are skipped unless
  `--overwrite-existing` is set.
- The publishable pipeline consumes only the anonymized dataset in `dataset/`.
- Reviewers never run this step; see `../docs/OPERATING_MODES.md` for the
  maintainer-versus-reviewer split.
