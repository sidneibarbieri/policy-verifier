#!/usr/bin/env python3
# ruff: noqa: E501
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must be a JSON object")
    return payload


def _safe_float(value: Any) -> float:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value.strip():
        try:
            return float(value)
        except ValueError:
            return 0.0
    return 0.0


def _safe_int(value: Any) -> int:
    return round(_safe_float(value))


def _pct(value: Any) -> str:
    return f"{_safe_float(value) * 100:.1f}%"


def _num(value: Any) -> str:
    return f"{_safe_int(value):,}"


def _money(value: Any) -> str:
    return f"${_safe_float(value):.4f}"


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _load_dashboard_data(analysis_dir: Path) -> dict[str, Any]:
    runs = _read_json(analysis_dir / "official_runs_manifest.json")
    summary = _read_json(analysis_dir / "official_evaluation_summary.json")
    pairwise = _read_json(analysis_dir / "official_pairwise_tests.json")
    readiness = _read_json(analysis_dir / "corpus_readiness.json")
    assessment = _read_json(analysis_dir / "global_artifact_assessment.json")
    consistency = _read_json(analysis_dir / "official_public_consistency.json")
    stability = _read_json(
        analysis_dir / "repeat_stability" / "repeat_stability_summary.json"
    )
    return {
        "runs": runs,
        "summary": summary,
        "pairwise": pairwise,
        "readiness": readiness,
        "assessment": assessment,
        "consistency": consistency,
        "stability": stability,
    }


def _summary_metrics(data: dict[str, Any]) -> list[tuple[str, str, str]]:
    runs = data["runs"]
    summary = data["summary"]
    readiness = data["readiness"]
    consistency = data["consistency"]
    accounting = runs.get("execution_accounting", {})
    mapping = readiness.get("mapping_quality", {})
    return [
        ("Public corpus", _num(readiness.get("incident_count")), "canonical incidents"),
        ("Completed runs", _num(accounting.get("llm_trajectories_completed")), "LLM trajectories"),
        ("Run success", _pct(accounting.get("run_success_rate")), "official manifest"),
        ("Privacy issues", _num(readiness.get("privacy_issue_count")), "release audit"),
        ("Mapping coverage", _pct(mapping.get("weighted_mapping_coverage")), "paired baseline"),
        ("Violation rate", _pct(summary.get("incident_violation_rate")), "official aggregate"),
        ("Actions removed", _num(summary.get("enforcement_actions_removed_count_total")), "approval gates"),
        ("Cost", _money(accounting.get("llm_cost_estimated_usd_total")), "reported execution"),
        ("Public checks", f"{consistency.get('failed_check_count', 0)}/{consistency.get('check_count', 0)}", "failed/total"),
    ]


def _render_quickstart_cards() -> str:
    cards = [
        (
            "1. Inspect",
            "Open this file first. It summarizes the corpus, official runs, policy coverage, paired contrasts, and replay checks from the public evidence bundle.",
            "REVIEWER_DASHBOARD.html",
        ),
        (
            "2. Reproduce",
            "Run the zero-cost path to validate manifests, rerender paper assets, rebuild this dashboard, and write the reproduction report.",
            "bash run.sh reproduce-results",
        ),
        (
            "3. Audit",
            "Follow exact source files for run accounting, pairwise tests, rule coverage, and release hygiene.",
            "artifact_outputs/analysis/",
        ),
    ]
    rendered = []
    for title, body, command in cards:
        rendered.append(
            "<div class=\"quick-card\">"
            f"<h3>{_escape(title)}</h3>"
            f"<p>{_escape(body)}</p>"
            f"<code>{_escape(command)}</code>"
            "</div>"
        )
    return "\n".join(rendered)


def _render_evidence_links() -> str:
    links = [
        ("Reproduction report", "artifact_outputs/reproduction_report.md"),
        ("Protocol freeze", "artifact_outputs/analysis/protocol_freeze.json"),
        ("Official run manifest", "artifact_outputs/analysis/official_runs_manifest.json"),
        ("Official pairwise tests", "artifact_outputs/analysis/official_pairwise_tests.json"),
        ("Official public consistency", "artifact_outputs/analysis/official_public_consistency.json"),
        ("Corpus readiness", "artifact_outputs/analysis/corpus_readiness.json"),
        ("Global artifact assessment", "artifact_outputs/analysis/global_artifact_assessment.json"),
        ("Regenerated paper assets", "artifact_outputs/reproduced_paper_assets/"),
    ]
    return "\n".join(
        f"<li><a href=\"{_escape(href)}\">{_escape(label)}</a></li>"
        for label, href in links
    )


def _render_metric_strip(metrics: list[tuple[str, str, str]]) -> str:
    rows = []
    for label, value, detail in metrics:
        rows.append(
            "<div class=\"metric\">"
            f"<div class=\"metric-label\">{_escape(label)}</div>"
            f"<div class=\"metric-value\">{_escape(value)}</div>"
            f"<div class=\"metric-detail\">{_escape(detail)}</div>"
            "</div>"
        )
    return "\n".join(rows)


def _render_model_rows(rows: list[dict[str, Any]]) -> str:
    out = []
    for row in sorted(rows, key=lambda item: (item.get("model", ""), item.get("arm", ""))):
        rate = _safe_float(row.get("run_violation_rate"))
        mod = _safe_float(row.get("enforcement_modification_rate"))
        width = max(1.0, rate * 100)
        out.append(
            "<tr data-model=\"{model}\" data-arm=\"{arm}\">"
            "<td>{model}</td><td>{arm}</td><td>{runs}</td>"
            "<td><span class=\"bar\"><span style=\"width:{width:.1f}%\"></span></span>{rate}</td>"
            "<td>{mod}</td><td>{coverage}</td><td>{jaccard}</td><td>{cost}</td>"
            "</tr>".format(
                model=_escape(row.get("model", "")),
                arm=_escape(row.get("arm", "")),
                runs=_num(row.get("completed_runs")),
                width=width,
                rate=_pct(rate),
                mod=_pct(mod),
                coverage=_pct(row.get("task_coverage_enforced_avg")),
                jaccard=f"{_safe_float(row.get('delta_jaccard_avg')):.4f}",
                cost=_money(row.get("llm_cost_estimated_usd_total")),
            )
        )
    return "\n".join(out)


def _render_pairwise_rows(rows: list[dict[str, Any]]) -> str:
    out = []
    for row in rows:
        out.append(
            "<tr>"
            f"<td>{_escape(row.get('comparison_label', ''))}</td>"
            f"<td>{_num(row.get('paired_incident_count'))}</td>"
            f"<td>{_safe_float(row.get('rate_diff_a_minus_b')):+.3f}</td>"
            f"<td>{_safe_float(row.get('cohens_h')):+.3f}</td>"
            f"<td>{_safe_float(row.get('mcnemar_p_value_holm')):.6f}</td>"
            "</tr>"
        )
    return "\n".join(out)


def _render_rule_rows(summary: dict[str, Any]) -> str:
    rule_counts = summary.get("violations_by_rule", {})
    if not isinstance(rule_counts, dict):
        rule_counts = {}
    rule_meta = {
        "R1": ("mandatory", "isolate_host", "insert"),
        "R2": ("prohibit_before", "restore_host", "insert"),
        "R3": ("require_approval", "restore_host", "remove"),
        "R4": ("require_approval", "isolate_host", "remove"),
    }
    out = []
    for rule_id, (family, action, repair) in rule_meta.items():
        count = _safe_int(rule_counts.get(rule_id, 0))
        status = "active" if count > 0 else "inactive"
        out.append(
            f"<tr data-rule-status=\"{status}\"><td>{rule_id}</td>"
            f"<td>{family}</td><td>{action}</td><td>{repair}</td>"
            f"<td>{count}</td><td>{status}</td></tr>"
        )
    return "\n".join(out)


def _render_surface_rows(assessment: dict[str, Any]) -> str:
    surface = assessment.get("global_surface", {})
    mapping = assessment.get("mapping_support", {})
    approval = assessment.get("approval_proxy_scope", {})
    rows = [
        ("Action catalog", surface.get("action_catalog_count"), ", ".join(surface.get("action_catalog_ids", []))),
        ("Mapped baseline actions", surface.get("mapping_action_count"), ", ".join(surface.get("mapping_action_ids", []))),
        ("Policy rules", surface.get("policy_rule_count"), ", ".join(surface.get("policy_rule_ids", []))),
        ("Tasks with support", mapping.get("task_count_total"), "zero unmatched; zero ambiguous"),
        ("Approval proxy coverage", len(approval.get("mapped_approval_proxy_action_ids", [])), ", ".join(approval.get("mapped_approval_proxy_action_ids", []))),
    ]
    return "\n".join(
        f"<tr><td>{_escape(label)}</td><td>{_escape(value)}</td><td>{_escape(detail)}</td></tr>"
        for label, value, detail in rows
    )


def _render_html(data: dict[str, Any]) -> str:
    model_rows = data["runs"].get("by_model_and_arm", [])
    pairwise_rows = data["pairwise"].get("rows", [])
    stability = data["stability"]
    summary = data["summary"]
    assessment = data["assessment"]
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOCpilot Audit Dashboard</title>
<style>
:root {{
  color-scheme: light;
  --bg: #f7f8fa;
  --ink: #17202a;
  --muted: #5e6a78;
  --line: #d8dee8;
  --blue: #235a8d;
  --green: #17785f;
  --red: #a43f32;
  --paper: #ffffff;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: var(--ink);
  background: var(--bg);
}}
header {{
  padding: 28px 32px 20px;
  border-bottom: 1px solid var(--line);
  background: var(--paper);
}}
h1 {{ margin: 0 0 6px; font-size: 28px; letter-spacing: 0; }}
.subtitle {{ color: var(--muted); max-width: 980px; }}
.toolbar {{
  position: sticky;
  top: 0;
  z-index: 2;
  display: flex;
  gap: 12px;
  align-items: center;
  padding: 12px 32px;
  border-bottom: 1px solid var(--line);
  background: rgba(255,255,255,.96);
}}
select, input {{
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 8px 10px;
  background: white;
  min-width: 160px;
}}
main {{ padding: 24px 32px 40px; }}
.quickstart {{
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
  margin-bottom: 20px;
}}
.quick-card {{
  background: var(--paper);
  border: 1px solid var(--line);
  border-radius: 7px;
  padding: 14px;
}}
.quick-card h3 {{ margin: 0 0 8px; font-size: 15px; }}
.quick-card p {{ margin: 0 0 10px; color: var(--muted); }}
.quick-card code {{
  display: block;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: #f1f5f8;
  border: 1px solid var(--line);
  border-radius: 5px;
  padding: 8px;
}}
.metrics {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1px;
  border: 1px solid var(--line);
  background: var(--line);
}}
.metric {{ padding: 14px; background: var(--paper); min-height: 96px; }}
.metric-label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
.metric-value {{ font-size: 25px; font-weight: 720; margin: 4px 0; }}
.metric-detail {{ color: var(--muted); font-size: 12px; }}
section {{ margin-top: 28px; }}
h2 {{ margin: 0 0 10px; font-size: 18px; }}
.note {{ color: var(--muted); margin: -4px 0 12px; }}
table {{
  width: 100%;
  border-collapse: collapse;
  background: var(--paper);
  border: 1px solid var(--line);
}}
th, td {{
  padding: 9px 10px;
  text-align: left;
  border-bottom: 1px solid var(--line);
  vertical-align: middle;
}}
th {{ font-size: 12px; color: var(--muted); text-transform: uppercase; }}
tbody tr:hover {{ background: #f1f5f8; }}
.bar {{
  display: inline-block;
  width: 96px;
  height: 8px;
  margin-right: 8px;
  background: #e8edf3;
  vertical-align: middle;
}}
.bar span {{ display: block; height: 100%; background: var(--blue); }}
.grid2 {{ display: grid; grid-template-columns: minmax(0,1fr) minmax(0,1fr); gap: 18px; }}
.evidence-list {{
  columns: 2;
  background: var(--paper);
  border: 1px solid var(--line);
  padding: 14px 18px;
}}
.evidence-list li {{ break-inside: avoid; margin: 0 0 7px; }}
.evidence-list a {{ color: var(--blue); text-decoration: none; }}
.evidence-list a:hover {{ text-decoration: underline; }}
.pill {{
  display: inline-block;
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 2px 8px;
  color: var(--muted);
  font-size: 12px;
}}
@media (max-width: 860px) {{
  header, main, .toolbar {{ padding-left: 16px; padding-right: 16px; }}
  .toolbar {{ flex-wrap: wrap; }}
  .grid2, .quickstart {{ grid-template-columns: 1fr; }}
  .evidence-list {{ columns: 1; }}
  table {{ font-size: 12px; }}
}}
</style>
</head>
<body>
<header>
  <h1>SOCpilot Audit Dashboard</h1>
  <div class="subtitle">Reviewer-facing view of the shipped public evidence: corpus readiness, run accounting, rule activation, paired contrasts, and replay consistency. All values are loaded from files in <code>artifact_outputs/analysis</code>.</div>
</header>
<div class="toolbar">
  <label>Model <select id="modelFilter"><option value="">All models</option></select></label>
  <label>Arm <select id="armFilter"><option value="">All arms</option></select></label>
  <label>Search <input id="searchBox" placeholder="table text"></label>
  <span class="pill">zero-cost public audit</span>
</div>
<main>
  <section class="quickstart" aria-label="Reviewer quickstart">
    {_render_quickstart_cards()}
  </section>

  <div class="metrics">
    {_render_metric_strip(_summary_metrics(data))}
  </div>

  <section>
    <h2>Model and Arm Outcomes</h2>
    <p class="note">Violation and enforcement rates expose the provider split; task coverage shows whether deterministic enforcement removed baseline-covered work.</p>
    <table id="outcomesTable">
      <thead><tr><th>Model</th><th>Arm</th><th>Runs</th><th>Violation</th><th>Modified</th><th>Task coverage</th><th>Delta Jaccard</th><th>Cost</th></tr></thead>
      <tbody>{_render_model_rows(model_rows)}</tbody>
    </table>
  </section>

  <section class="grid2">
    <div>
      <h2>Rule Activation</h2>
      <p class="note">The official evaluation exercises approval gates; mandatory and ordering rules remain declared but inactive in this slice.</p>
      <table><thead><tr><th>Rule</th><th>Family</th><th>Action</th><th>Repair</th><th>Violations</th><th>Status</th></tr></thead><tbody>{_render_rule_rows(summary)}</tbody></table>
    </div>
    <div>
      <h2>Protocol Surface</h2>
      <p class="note">These rows show why the claim is a declared protocol state rather than a generic SOC benchmark.</p>
      <table><thead><tr><th>Surface</th><th>Count</th><th>Evidence</th></tr></thead><tbody>{_render_surface_rows(assessment)}</tbody></table>
    </div>
  </section>

  <section>
    <h2>Paired Contrasts</h2>
    <p class="note">Each row compares the same incident set across two model/arm cells.</p>
    <table><thead><tr><th>Contrast</th><th>n</th><th>Rate diff</th><th>Cohen h</th><th>Holm p</th></tr></thead><tbody>{_render_pairwise_rows(pairwise_rows)}</tbody></table>
  </section>

  <section>
    <h2>Evidence Map</h2>
    <p class="note">Direct links to the files most reviewers need when checking the paper claims against the artifact.</p>
    <ul class="evidence-list">{_render_evidence_links()}</ul>
  </section>

  <section class="grid2">
    <div>
      <h2>Replay Stability</h2>
      <table><tbody>
        <tr><th>Repeats</th><td>{_num(stability.get("repeat_count"))}</td></tr>
        <tr><th>Violation range</th><td>{_pct(stability.get("incident_violation_rate", {}).get("min"))} to {_pct(stability.get("incident_violation_rate", {}).get("max"))}</td></tr>
        <tr><th>Modification range</th><td>{_pct(stability.get("enforcement_modification_rate", {}).get("min"))} to {_pct(stability.get("enforcement_modification_rate", {}).get("max"))}</td></tr>
        <tr><th>Task coverage drop</th><td>{_pct(stability.get("task_coverage_drop_rate", {}).get("max"))}</td></tr>
      </tbody></table>
    </div>
    <div>
      <h2>Repair Accounting</h2>
      <table><tbody>
        <tr><th>Removed</th><td>{_num(summary.get("enforcement_actions_removed_count_total"))}</td></tr>
        <tr><th>Inserted</th><td>{_num(summary.get("enforcement_actions_inserted_count_total"))}</td></tr>
        <tr><th>Reordered</th><td>{_num(summary.get("enforcement_actions_reordered_count_total"))}</td></tr>
        <tr><th>Deferred</th><td>{_num(summary.get("enforcement_actions_deferred_count_total"))}</td></tr>
      </tbody></table>
    </div>
  </section>
</main>
<script>
const rows = [...document.querySelectorAll("#outcomesTable tbody tr")];
const modelFilter = document.querySelector("#modelFilter");
const armFilter = document.querySelector("#armFilter");
const searchBox = document.querySelector("#searchBox");
for (const value of [...new Set(rows.map(row => row.dataset.model))].sort()) {{
  modelFilter.add(new Option(value, value));
}}
for (const value of [...new Set(rows.map(row => row.dataset.arm))].sort()) {{
  armFilter.add(new Option(value, value));
}}
function applyFilters() {{
  const model = modelFilter.value;
  const arm = armFilter.value;
  const query = searchBox.value.trim().toLowerCase();
  for (const row of rows) {{
    const visible = (!model || row.dataset.model === model)
      && (!arm || row.dataset.arm === arm)
      && (!query || row.innerText.toLowerCase().includes(query));
    row.style.display = visible ? "" : "none";
  }}
}}
modelFilter.addEventListener("change", applyFilters);
armFilter.addEventListener("change", applyFilters);
searchBox.addEventListener("input", applyFilters);
</script>
</body>
</html>
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render a static reviewer dashboard from public analysis outputs."
    )
    parser.add_argument(
        "--analysis-dir",
        default="artifact_outputs/analysis",
    )
    parser.add_argument(
        "--output-html",
        default="artifact_outputs/dashboard/index.html",
    )
    parser.add_argument(
        "--landing-html",
        default="REVIEWER_DASHBOARD.html",
        help="Optional reviewer-facing dashboard copy at the package root.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    analysis_dir = Path(args.analysis_dir).expanduser().resolve()
    output_html = Path(args.output_html).expanduser().resolve()
    data = _load_dashboard_data(analysis_dir)
    html_text = _render_html(data)
    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(html_text, encoding="utf-8")
    print(f"Audit dashboard written to: {output_html}")
    if args.landing_html:
        landing_html = Path(args.landing_html).expanduser()
        if not landing_html.is_absolute():
            landing_html = analysis_dir.parents[1] / landing_html
        landing_html.parent.mkdir(parents=True, exist_ok=True)
        landing_html.write_text(html_text, encoding="utf-8")
        print(f"Reviewer dashboard entry point written to: {landing_html}")


if __name__ == "__main__":
    main()
