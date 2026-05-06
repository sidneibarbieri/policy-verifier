#!/usr/bin/env python3
"""Analyze remove-versus-defer approval treatment from public run metrics."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ApprovalModeRow(BaseModel):
    model_label: str = Field(..., min_length=1)
    run_count: int = Field(..., ge=0)
    removed_actions: int = Field(..., ge=0)
    imputed_deferred_actions: int = Field(..., ge=0)
    remove_precision_avg: float
    defer_precision_avg: float
    precision_delta_defer_minus_remove: float
    remove_jaccard_avg: float
    defer_jaccard_avg: float
    jaccard_delta_defer_minus_remove: float
    remove_task_coverage_avg: float
    defer_task_coverage_avg: float
    task_coverage_delta_defer_minus_remove: float


class ApprovalModeSensitivityReport(BaseModel):
    source_bundle: str
    row_count: int = Field(..., ge=0)
    interpretation: list[str]
    by_model: list[ApprovalModeRow]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle-json",
        type=Path,
        default=Path("results/analysis/official_llm_analysis_bundle.json"),
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path("results/analysis/approval_mode_sensitivity.json"),
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=Path("results/analysis/approval_mode_sensitivity.md"),
    )
    return parser.parse_args()


def read_bundle(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Bundle must be a JSON object: {path}")
    return payload


def mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return round(sum(values) / len(values), 6)


def build_report(bundle_path: Path) -> ApprovalModeSensitivityReport:
    bundle = read_bundle(bundle_path)
    rows = bundle.get("incidents", [])
    if not isinstance(rows, list):
        raise ValueError("Bundle field `incidents` must be a list.")

    grouped_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if not isinstance(row, dict):
            continue
        model_label = str(row.get("model_label", "")).strip()
        if model_label:
            grouped_rows[model_label].append(row)

    report_rows: list[ApprovalModeRow] = []
    for model_label, model_rows in sorted(grouped_rows.items()):
        remove_precision_values = [
            float(row.get("precision_enforced", 0.0) or 0.0) for row in model_rows
        ]
        defer_precision_values = [
            float(row.get("precision_raw", 0.0) or 0.0) for row in model_rows
        ]
        remove_jaccard_values = [
            float(row.get("jaccard_enforced", 0.0) or 0.0) for row in model_rows
        ]
        defer_jaccard_values = [
            float(row.get("jaccard_raw", 0.0) or 0.0) for row in model_rows
        ]
        remove_coverage_values = [
            float(row.get("task_coverage_enforced", 0.0) or 0.0)
            for row in model_rows
        ]
        defer_coverage_values = [
            float(row.get("task_coverage_raw", 0.0) or 0.0) for row in model_rows
        ]
        remove_precision = mean(remove_precision_values)
        defer_precision = mean(defer_precision_values)
        remove_jaccard = mean(remove_jaccard_values)
        defer_jaccard = mean(defer_jaccard_values)
        remove_coverage = mean(remove_coverage_values)
        defer_coverage = mean(defer_coverage_values)
        removed_actions = sum(
            int(row.get("enforcement_actions_removed_count", 0) or 0)
            for row in model_rows
        )
        report_rows.append(
            ApprovalModeRow(
                model_label=model_label,
                run_count=len(model_rows),
                removed_actions=removed_actions,
                imputed_deferred_actions=removed_actions,
                remove_precision_avg=remove_precision,
                defer_precision_avg=defer_precision,
                precision_delta_defer_minus_remove=round(
                    defer_precision - remove_precision,
                    6,
                ),
                remove_jaccard_avg=remove_jaccard,
                defer_jaccard_avg=defer_jaccard,
                jaccard_delta_defer_minus_remove=round(
                    defer_jaccard - remove_jaccard,
                    6,
                ),
                remove_task_coverage_avg=remove_coverage,
                defer_task_coverage_avg=defer_coverage,
                task_coverage_delta_defer_minus_remove=round(
                    defer_coverage - remove_coverage,
                    6,
                ),
            )
        )

    return ApprovalModeSensitivityReport(
        source_bundle=str(bundle_path),
        row_count=len(rows),
        interpretation=[
            "This is a public-metric sensitivity analysis, not a verifier replay.",
            "Under defer_to_human_approval, removed approval-gated actions are "
            "imputed as deferred actions.",
            "Because deferral preserves the proposed action sequence, the "
            "defer utility proxy uses raw action-overlap metrics.",
            "A full replay requires saved raw action outputs; those are not part "
            "of the public artifact.",
        ],
        by_model=report_rows,
    )


def write_markdown(path: Path, report: ApprovalModeSensitivityReport) -> None:
    lines = [
        "# Approval Mode Sensitivity",
        "",
        f"Source bundle: `{report.source_bundle}`",
        f"Rows analyzed: `{report.row_count}`",
        "",
        "## Interpretation",
        "",
    ]
    lines.extend(f"- {line}" for line in report.interpretation)
    lines.extend(
        [
            "",
            "## Remove vs. Defer Proxy",
            "",
            "| Model / arm | Runs | Removed | Imputed deferred | "
            "Precision remove | Precision defer | Jaccard remove | "
            "Jaccard defer | Coverage remove | Coverage defer |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in report.by_model:
        lines.append(
            f"| `{row.model_label}` | {row.run_count} | {row.removed_actions} | "
            f"{row.imputed_deferred_actions} | {row.remove_precision_avg:.4f} | "
            f"{row.defer_precision_avg:.4f} | {row.remove_jaccard_avg:.4f} | "
            f"{row.defer_jaccard_avg:.4f} | {row.remove_task_coverage_avg:.4f} | "
            f"{row.defer_task_coverage_avg:.4f} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()
    report = build_report(args.bundle_json)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    write_markdown(args.output_md, report)
    print(f"Wrote {args.output_json}")
    print(f"Wrote {args.output_md}")


if __name__ == "__main__":
    main()
