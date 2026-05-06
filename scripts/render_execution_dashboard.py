#!/usr/bin/env python3
"""Render a maintainer dashboard for provider execution status."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan-json",
        type=Path,
        default=Path("results/analysis/provider_execution_plan.json"),
    )
    parser.add_argument(
        "--validation-json",
        type=Path,
        default=Path("results/analysis/provider_execution_plan_validation.json"),
    )
    parser.add_argument(
        "--summary-json",
        type=Path,
        default=Path("results/analysis/summary.json"),
    )
    parser.add_argument(
        "--bundle-json",
        type=Path,
        default=Path("results/analysis/analysis_bundle.json"),
    )
    parser.add_argument(
        "--failures-json",
        type=Path,
        default=Path("results/analysis/experiment_failures.json"),
    )
    parser.add_argument(
        "--fresh-clone-json",
        type=Path,
        default=Path("results/analysis/fresh_clone_reproduction.json"),
    )
    parser.add_argument(
        "--output-html",
        type=Path,
        default=Path("results/analysis/execution_dashboard.html"),
    )
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def safe_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return round(value)
    if isinstance(value, str) and value.strip():
        try:
            return round(float(value))
        except ValueError:
            return 0
    return 0


def safe_float(value: Any) -> float:
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


def metric(label: str, value: Any, detail: str = "") -> str:
    return (
        "<div class=\"metric\">"
        f"<div class=\"metric-label\">{escape(label)}</div>"
        f"<div class=\"metric-value\">{escape(value)}</div>"
        f"<div class=\"metric-detail\">{escape(detail)}</div>"
        "</div>"
    )


def status_badge(status: str) -> str:
    normalized_status = status.strip().lower() or "missing"
    css_class = "ok" if normalized_status == "ok" else "warn"
    if normalized_status in {"failed", "missing"}:
        css_class = "bad"
    return f"<span class=\"badge {css_class}\">{escape(normalized_status)}</span>"


def render_failure_rows(failures: list[Any]) -> str:
    rows: list[str] = []
    for item in failures[:200]:
        if not isinstance(item, dict):
            continue
        rows.append(
            "<tr>"
            f"<td>{escape(item.get('model', ''))}</td>"
            f"<td>{escape(item.get('arm', ''))}</td>"
            f"<td>{escape(item.get('incident_id', ''))}</td>"
            f"<td>{escape(item.get('exception_type', ''))}</td>"
            f"<td>{escape(item.get('error', ''))}</td>"
            "</tr>"
        )
    return "\n".join(rows) or "<tr><td colspan=\"5\">No failures recorded.</td></tr>"


def render_model_rows(rows: list[Any]) -> str:
    output: list[str] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        output.append(
            "<tr>"
            f"<td>{escape(item.get('model', ''))}</td>"
            f"<td>{escape(item.get('arm', ''))}</td>"
            f"<td>{escape(item.get('completed_runs', ''))}</td>"
            f"<td>{safe_float(item.get('run_violation_rate')):.4f}</td>"
            f"<td>{safe_float(item.get('enforcement_modification_rate')):.4f}</td>"
            f"<td>{safe_float(item.get('task_coverage_enforced_avg')):.4f}</td>"
            f"<td>{safe_float(item.get('llm_cost_estimated_usd_total')):.6f}</td>"
            "</tr>"
        )
    return "\n".join(output) or "<tr><td colspan=\"7\">No model rows yet.</td></tr>"


def render_html(data: dict[str, dict[str, Any]]) -> str:
    plan = data["plan"]
    validation = data["validation"]
    summary = data["summary"]
    bundle = data["bundle"]
    failures = data["failures"]
    fresh_clone = data["fresh_clone"]

    coverage = bundle.get("experiment", {}).get("coverage", {})
    model_rows = bundle.get("by_model", [])
    failure_rows = failures.get("failures", [])
    expected_runs = plan.get("expected_provider_run_count", 0)
    successful_runs = coverage.get("successful_run_count", 0)
    execution_failures = coverage.get("execution_failure_count", 0)
    preflight_failures = coverage.get("preflight_failure_count", 0)
    run_success_rate = safe_float(coverage.get("run_success_rate"))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOCpilot Provider Execution Dashboard</title>
<style>
:root {{
  --bg: #f6f7f9;
  --paper: #ffffff;
  --ink: #17202a;
  --muted: #5d6877;
  --line: #d9dee7;
  --ok: #17785f;
  --warn: #9a5b00;
  --bad: #a43f32;
  --blue: #245b91;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: var(--ink);
  background: var(--bg);
}}
header {{
  padding: 28px 32px 18px;
  background: var(--paper);
  border-bottom: 1px solid var(--line);
}}
h1 {{ margin: 0 0 6px; font-size: 28px; }}
main {{ padding: 24px 32px 40px; }}
.subtitle {{ color: var(--muted); max-width: 980px; }}
.metrics {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 1px;
  border: 1px solid var(--line);
  background: var(--line);
}}
.metric {{ background: var(--paper); padding: 14px; min-height: 96px; }}
.metric-label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
.metric-value {{ font-size: 24px; font-weight: 750; margin: 4px 0; }}
.metric-detail {{ color: var(--muted); font-size: 12px; }}
section {{ margin-top: 28px; }}
h2 {{ margin: 0 0 10px; font-size: 18px; }}
table {{
  width: 100%;
  border-collapse: collapse;
  background: var(--paper);
  border: 1px solid var(--line);
}}
th, td {{
  padding: 9px 10px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
}}
th {{ background: #eef2f7; font-size: 12px; text-transform: uppercase; color: var(--muted); }}
.badge {{
  display: inline-block;
  padding: 3px 8px;
  border-radius: 999px;
  color: white;
  font-size: 12px;
  font-weight: 700;
}}
.ok {{ background: var(--ok); }}
.warn {{ background: var(--warn); }}
.bad {{ background: var(--bad); }}
code {{ background: #eef2f7; padding: 1px 4px; border-radius: 4px; }}
</style>
</head>
<body>
<header>
<h1>SOCpilot Provider Execution Dashboard</h1>
<div class="subtitle">Maintainer-only dashboard for paid-run readiness and execution preservation. It reads local JSON outputs and does not call providers.</div>
</header>
<main>
<div class="metrics">
{metric("Plan approval", status_badge(str(plan.get("approval", {}).get("status", "missing"))), plan.get("plan_id", "no plan"))}
{metric("Plan validation", status_badge(str(validation.get("status", "missing"))), validation.get("plan_path", ""))}
{metric("Fresh clone", status_badge(str(fresh_clone.get("status", "missing"))), fresh_clone.get("ref", ""))}
{metric("Expected runs", safe_int(expected_runs), "planned provider calls")}
{metric("Successful runs", safe_int(successful_runs), f"success rate {run_success_rate:.4f}")}
{metric("Failures", safe_int(execution_failures), f"preflight {safe_int(preflight_failures)}")}
{metric("Analyzed incidents", safe_int(summary.get("incident_count")), "summary.json")}
{metric("Total cost", f"${safe_float(summary.get('llm_cost_estimated_usd_total')):.6f}", "summary.json")}
</div>

<section>
<h2>Plan</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Dataset release</td><td>{escape(plan.get("dataset_release_id", ""))}</td></tr>
<tr><td>Models</td><td>{escape(", ".join(plan.get("models", [])))}</td></tr>
<tr><td>Arms</td><td>{escape(", ".join(plan.get("arms", [])))}</td></tr>
<tr><td>Repeats</td><td>{escape(plan.get("repeats", ""))}</td></tr>
<tr><td>Incidents</td><td>{safe_int(len(plan.get("incident_ids", [])))}</td></tr>
<tr><td>Approval note</td><td>{escape(plan.get("approval", {}).get("approval_note", ""))}</td></tr>
</table>
</section>

<section>
<h2>Model And Arm Results</h2>
<table>
<thead><tr><th>Model</th><th>Arm</th><th>Runs</th><th>Violation</th><th>Modified</th><th>Coverage</th><th>Cost</th></tr></thead>
<tbody>{render_model_rows(model_rows)}</tbody>
</table>
</section>

<section>
<h2>Failures</h2>
<table>
<thead><tr><th>Model</th><th>Arm</th><th>Incident</th><th>Type</th><th>Error</th></tr></thead>
<tbody>{render_failure_rows(failure_rows)}</tbody>
</table>
</section>
</main>
</body>
</html>
"""


def main() -> None:
    args = parse_args()
    data = {
        "plan": read_json(args.plan_json),
        "validation": read_json(args.validation_json),
        "summary": read_json(args.summary_json),
        "bundle": read_json(args.bundle_json),
        "failures": read_json(args.failures_json),
        "fresh_clone": read_json(args.fresh_clone_json),
    }
    args.output_html.parent.mkdir(parents=True, exist_ok=True)
    args.output_html.write_text(render_html(data), encoding="utf-8")
    print(f"Execution dashboard written to: {args.output_html}")


if __name__ == "__main__":
    main()
