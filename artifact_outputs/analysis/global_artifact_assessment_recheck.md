# Global Artifact Assessment

## Summary

This report separates what the current declared globals support strongly from what remains narrow in the official evaluation.

## Stable Evidence

- Incident count audited: 200
- Mapping support coverage: 1147 tasks, 0 zero-match, 0 ambiguous.
- Unique-match split: 579 single-keyword (0.5048) and 568 multi-keyword (0.4952).
- Human-baseline action coverage: 3/5 catalog actions.

## Narrowness That Still Matters

- Mapping rules cover 3/5 catalog actions.
- Catalog actions without mapping rules: block_egress_ip, restore_host
- Approval-required actions without proxy mapping support: restore_host

## Official Evaluation Scope

- Official runs: 800
- Observed violation rules: R3, R4
- Rules without observed violation counts in the official summary: R1, R2
- Enforcement counts: remove=466, defer=0, insert=0, reorder=0.
- Cost accounting: 734740 tokens, USD 3.034621 total, USD 0.003793 per run.

## Criticism Response Map

- The mapped human baseline is opaque and relies heavily on keyword rules.
  Response strength: partial_but_material. The artifact now exposes aggregate mapping-support evidence: zero unmatched tasks, zero ambiguous ties, complete conversion coverage, and an explicit split between single-keyword and multi-keyword unique matches.
- The global action/policy surface is narrow and may overstate generality.
  Response strength: addressed_transparently. The assessment makes the narrowness explicit instead of burying it: the human baseline covers only part of the catalog, the mapping contract covers only part of the catalog, and the constrained action surface is smaller still.
- Observed evidence is concentrated in approval governance rather than the full rule family.
  Response strength: addressed_transparently. The report states that the completed official evaluation shows violation evidence only on approval rules under this freeze, with no inserted or reordered actions.
- Approval context is only partially grounded in the mapping contract.
  Response strength: addressed_transparently. The report makes proxy scope explicit by showing which approval-required catalog actions have a mapping proxy and which do not.
- Cost accounting is unclear.
  Response strength: addressed. The official aggregate summary is now copied into canonical analysis outputs so public auditors can inspect token totals, total cost, average cost per run, and run-success rate directly.

## Interpretation Boundary

This report improves visibility into mapper robustness and global-surface narrowness, but it does not replace a human audit of task-to-action mappings, ground-truth approval logs, or broader rule-family activation.
