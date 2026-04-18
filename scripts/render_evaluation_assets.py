#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


def _safe_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        try:
            return int(float(value))
        except ValueError:
            return 0
    return 0


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


def _tex_escape(value: str) -> str:
    escaped = value
    escaped = escaped.replace("\\", "\\textbackslash{}")
    escaped = escaped.replace("_", "\\_")
    escaped = escaped.replace("&", "\\&")
    escaped = escaped.replace("%", "\\%")
    escaped = escaped.replace("$", "\\$")
    escaped = escaped.replace("#", "\\#")
    escaped = escaped.replace("{", "\\{")
    escaped = escaped.replace("}", "\\}")
    return escaped


def _read_bundle(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must be a JSON object")
    for key in ("summary", "by_model", "by_rule_treatment", "pairwise"):
        if key not in payload:
            raise ValueError(f"{path} missing key: {key}")
    return payload


def _default_paper_root() -> Path:
    override = os.environ.get("SOC_LLM_POLICY_PAPER_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    for candidate in (Path("../paper"), Path("../ACM CCS - Paper 1")):
        if candidate.exists():
            return candidate
    return Path("../paper")


def _merge_rows(
    primary: list[dict[str, Any]],
    fallback: list[dict[str, Any]],
    key_fn,
) -> list[dict[str, Any]]:
    merged: dict[Any, dict[str, Any]] = {}
    for row in fallback:
        merged[key_fn(row)] = row
    for row in primary:
        merged[key_fn(row)] = row
    return list(merged.values())


def _parse_model_label(label: str) -> tuple[str, str]:
    if "|" in label:
        model, arm = label.split("|", 1)
        return model.strip(), arm.strip()
    return label.strip(), "human"


def _arm_pretty(arm: str) -> str:
    mapping = {
        "llm_zero": "LLM zero",
        "llm_policy_prompt": "LLM policy",
        "human": "Human baseline",
    }
    return mapping.get(arm, arm)


def _row_pretty_label(label: str) -> str:
    model, arm = _parse_model_label(label)
    if model == "human" and arm == "human":
        return "human / Human baseline"
    return f"{model} / {_arm_pretty(arm)}"


def _compact_model(model: str) -> str:
    model_l = model.strip().lower()
    if model_l.startswith("claude-sonnet"):
        return "claude"
    if model_l == "human":
        return "human"
    return model.strip()


def _arm_short(arm: str) -> str:
    return {
        "llm_zero": "zero",
        "llm_policy_prompt": "policy",
        "human": "baseline",
    }.get(arm, arm)


def _row_compact_label(label: str) -> str:
    model, arm = _parse_model_label(label)
    if model == "human" and arm == "human":
        return "human baseline"
    return f"{_compact_model(model)} / {_arm_short(arm)}"


def _pair_compact_label(label: str) -> str:
    model, arm = _parse_model_label(label)
    return f"{_compact_model(model)}|{_arm_short(arm)}"


def _row_sort_key(row: dict[str, Any]) -> tuple[str, int, str]:
    label = str(row.get("model_label", "")).strip()
    model, arm = _parse_model_label(label)
    arm_rank = {
        "human": 0,
        "llm_zero": 1,
        "llm_policy_prompt": 2,
    }.get(arm, 9)
    return (model, arm_rank, arm)


def _rate_ci(row: dict[str, Any]) -> tuple[float, float, float]:
    rate = _safe_float(row.get("run_violation_rate"))
    lo = _safe_float(row.get("run_violation_rate_ci_low"))
    hi = _safe_float(row.get("run_violation_rate_ci_high"))
    return rate, lo, hi


def _hard_rate(row: dict[str, Any]) -> float:
    hard = _safe_int(row.get("hard_violation_count"))
    runs = _safe_int(row.get("run_count"))
    if runs <= 0:
        return 0.0
    return hard / runs


def _enforcement_rate(row: dict[str, Any]) -> float:
    return _safe_float(row.get("enforcement_modification_rate"))


def _delta_jaccard(row: dict[str, Any]) -> float:
    return _safe_float(row.get("delta_jaccard_avg"))


def _task_coverage(row: dict[str, Any]) -> float:
    return _safe_float(row.get("task_coverage_enforced_avg"))


def _llm_rows(by_model: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in by_model:
        label = str(row.get("model_label", "")).strip()
        _, arm = _parse_model_label(label)
        if arm.startswith("llm_"):
            out.append(row)
    return out


def _format_rate(value: float) -> str:
    return f"{value:.4f}"


def _format_p_value(value: float) -> str:
    if value <= 0.0:
        return "\\textless{}0.0001"
    if value < 0.0001:
        return "\\textless{}0.0001"
    return f"{value:.4f}"


def _cohens_h(p_a: float, p_b: float) -> float:
    import math

    p_a = min(max(p_a, 0.0), 1.0)
    p_b = min(max(p_b, 0.0), 1.0)
    return 2 * math.asin(math.sqrt(p_a)) - 2 * math.asin(math.sqrt(p_b))


def _format_signed_rate(value: float) -> str:
    if value < 0:
        return f"$-${_format_rate(abs(value))}"
    if value > 0:
        return f"+{_format_rate(value)}"
    return _format_rate(value)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return
    path.write_text(content, encoding="utf-8")


def _remove_if_exists(path: Path) -> None:
    if path.exists():
        path.unlink()


def _render_table_primary(by_model: list[dict[str, Any]]) -> str:
    rows = sorted(by_model, key=_row_sort_key)
    max_rate = max((_rate_ci(row)[0] for row in rows), default=0.0)
    lines = [
        "\\begin{table}[t]",
        "\\caption{Official evaluation primary outcomes by model and arm. The human baseline (shaded) anchors paired comparisons; bold marks the highest violation rate.}",
        "\\label{tab:evaluation_primary_outcomes}",
        "\\centering",
        "\\scriptsize",
        "\\setlength{\\tabcolsep}{3pt}",
        "\\resizebox{\\columnwidth}{!}{%",
        "\\begin{tabular}{p{0.42\\columnwidth}rrrrrrr}",
        "\\toprule",
        "Model/arm & Runs & Viol. rate & 95\\% CI & Hard viol./run & Enf. mod. rate & Task cov. & $\\Delta$Jaccard \\\\",
        "\\midrule",
    ]
    for row in rows:
        label = _tex_escape(_row_pretty_label(str(row.get("model_label", ""))))
        runs = _safe_int(row.get("run_count"))
        rate, lo, hi = _rate_ci(row)
        hard_rate = _hard_rate(row)
        enf = _enforcement_rate(row)
        task_cov = _task_coverage(row)
        dj = _delta_jaccard(row)
        rate_tex = _format_rate(rate)
        if abs(rate - max_rate) < 1e-9:
            rate_tex = f"\\textbf{{{rate_tex}}}"
        row_prefix = ""
        model_label_raw = str(row.get("model_label", "")).strip()
        if model_label_raw in {"human|human", "human"}:
            row_prefix = "\\rowcolor{gray!8}\n"
        lines.append(
            row_prefix
            + f"{label} & {runs} & {rate_tex} & [{_format_rate(lo)}, {_format_rate(hi)}] & "
            f"{_format_rate(hard_rate)} & {_format_rate(enf)} & {_format_rate(task_cov)} & {_format_rate(dj)} \\\\",
        )
    lines.extend(
        [
            "\\bottomrule",
            "\\end{tabular}",
            "}",
            "\\end{table}",
            "",
        ],
    )
    return "\n".join(lines)


def _render_table_pairwise(pairwise: list[dict[str, Any]], by_model: list[dict[str, Any]]) -> str:
    lines = [
        "\\begin{table}[t]",
        "\\caption{Official evaluation paired tests between arm/model configurations. Bold rows survive Holm correction at $\\alpha=0.05$; Cohen's $h$ summarizes marginal rate separation.}",
        "\\label{tab:evaluation_pairwise_tests}",
        "\\centering",
        "\\scriptsize",
        "\\setlength{\\tabcolsep}{2.5pt}",
    ]
    if not pairwise:
        lines.extend(
            [
                "\\begin{tabular}{l}",
                "\\toprule",
                "No pairwise contrasts available in current bundle. \\\\",
                "\\bottomrule",
                "\\end{tabular}",
                "\\end{table}",
                "",
            ],
        )
        return "\n".join(lines)

    lines.extend(
        [
            "\\resizebox{\\columnwidth}{!}{%",
            "\\begin{tabular}{p{0.44\\columnwidth}rrrrr}",
            "\\toprule",
            "A vs B (model|arm) & $n$ & $\\Delta$ rate & McNemar $p$ & Holm $p$ & Cohen's $h$ \\\\",
            "\\midrule",
        ],
    )
    rate_by_label = {
        str(row.get("model_label", "")).strip(): _rate_ci(row)[0]
        for row in by_model
    }
    for row in pairwise:
        model_a_raw = str(row.get("model_a", "")).strip()
        model_b_raw = str(row.get("model_b", "")).strip()
        model_a = _tex_escape(_pair_compact_label(model_a_raw))
        model_b = _tex_escape(_pair_compact_label(model_b_raw))
        n = _safe_int(row.get("paired_incident_count"))
        delta = _safe_float(row.get("rate_diff_a_minus_b"))
        p_mc = _safe_float(row.get("mcnemar_p_value_two_sided"))
        p_holm = _safe_float(row.get("mcnemar_p_value_holm"))
        h = _cohens_h(rate_by_label.get(model_a_raw, 0.0), rate_by_label.get(model_b_raw, 0.0))
        prefix = ""
        suffix = ""
        if p_holm <= 0.05:
            prefix = "\\textbf{"
            suffix = "}"
        lines.append(
            f"{prefix}{model_a} vs {model_b}{suffix} & "
            f"{prefix}{n}{suffix} & "
            f"{prefix}{_format_signed_rate(delta)}{suffix} & "
            f"{prefix}{_format_p_value(p_mc)}{suffix} & "
            f"{prefix}{_format_p_value(p_holm)}{suffix} & "
            f"{prefix}{_format_signed_rate(h)}{suffix} \\\\",
        )
    lines.extend(
        [
            "\\bottomrule",
            "\\end{tabular}",
            "}",
            "\\end{table}",
            "",
        ],
    )
    return "\n".join(lines)


def _render_table_rule_treatment(by_rule_treatment: list[dict[str, Any]]) -> str:
    rows = sorted(
        by_rule_treatment,
        key=lambda row: (str(row.get("model", "")), str(row.get("rule_id", ""))),
    )
    lines = [
        "\\begin{table}[t]",
        "\\caption{Official evaluation rule-level treatment comparison (zero vs.\\ policy prompt). Bold marks the dominant rule-family effect.}",
        "\\label{tab:evaluation_rule_treatment}",
        "\\centering",
        "\\scriptsize",
        "\\setlength{\\tabcolsep}{3pt}",
        "\\begin{tabular}{p{0.31\\columnwidth}rrrr}",
        "\\toprule",
        "Model/rule & Zero rate & Policy rate & $\\Delta$ (policy$-$zero) & Runs per arm \\\\",
        "\\midrule",
    ]
    for row in rows:
        model_raw = str(row.get("model", "")).strip()
        rule_raw = str(row.get("rule_id", "")).strip()
        label = _tex_escape(f"{_compact_model(model_raw)} / {rule_raw}")
        zr = _safe_float(row.get("llm_zero_violation_rate"))
        pr = _safe_float(row.get("llm_policy_prompt_violation_rate"))
        diff = pr - zr
        runs = _safe_int(row.get("llm_zero_run_count"))
        prefix = ""
        suffix = ""
        if model_raw == "claude-sonnet-4-6" and rule_raw == "R3":
            prefix = "\\textbf{"
            suffix = "}"
        lines.append(
            f"{prefix}{label}{suffix} & "
            f"{prefix}{_format_rate(zr)}{suffix} & "
            f"{prefix}{_format_rate(pr)}{suffix} & "
            f"{prefix}{_format_signed_rate(diff)}{suffix} & "
            f"{prefix}{runs}{suffix} \\\\",
        )
    lines.extend(
        [
            "\\bottomrule",
            "\\end{tabular}",
            "\\end{table}",
            "",
        ],
    )
    return "\n".join(lines)


def _render_table_cost(by_model: list[dict[str, Any]]) -> str:
    rows = sorted(_llm_rows(by_model), key=_row_sort_key)
    lines = [
        "\\begin{table}[t]",
        "\\caption{Official evaluation LLM token and cost breakdown by model and arm.}",
        "\\label{tab:evaluation_cost_breakdown}",
        "\\centering",
        "\\scriptsize",
        "\\setlength{\\tabcolsep}{3pt}",
        "\\begin{tabular}{p{0.31\\columnwidth}rrrr}",
        "\\toprule",
        "Model/arm & \\shortstack[c]{Prompt\\\\toks} & \\shortstack[c]{Completion\\\\toks} & \\shortstack[c]{Total\\\\toks} & USD \\\\",
        "\\midrule",
    ]
    for row in rows:
        label = _tex_escape(_row_compact_label(str(row.get("model_label", ""))))
        prompt = _safe_int(row.get("llm_prompt_tokens_total"))
        comp = _safe_int(row.get("llm_completion_tokens_total"))
        total = _safe_int(row.get("llm_total_tokens_total"))
        cost = _safe_float(row.get("llm_cost_estimated_usd_total"))
        lines.append(f"{label} & {prompt} & {comp} & {total} & {cost:.6f} \\\\")
    lines.extend(
        [
            "\\bottomrule",
            "\\end{tabular}",
            "\\end{table}",
            "",
        ],
    )
    return "\n".join(lines)


def _render_figure_violation_rates(by_model: list[dict[str, Any]]) -> str:
    rows = sorted(by_model, key=_row_sort_key)
    n = len(rows)
    spacing = 0.92
    bar_h = 0.26
    top_y = (n - 1) * spacing + 0.38 if n > 0 else 0.38
    axis_y = -0.52
    y_top_grid = top_y + 0.47
    lines = [
        "\\begin{tikzpicture}[x=5.6cm,y=1.0cm,font=\\sffamily\\small]",
        "  \\definecolor{axisGray}{HTML}{667085}",
        "  \\definecolor{llmZero}{HTML}{1A5276}",
        "  \\definecolor{llmZeroBg}{HTML}{E8F0FB}",
        "  \\definecolor{llmPolicy}{HTML}{117864}",
        "  \\definecolor{llmPolicyBg}{HTML}{E6F4F1}",
        "  \\definecolor{humanGray}{HTML}{6F7782}",
        "  \\definecolor{humanBg}{HTML}{F2F4F7}",
        f"  \\draw[->, line width=0.8pt, draw=axisGray] (0,{axis_y:.2f}) -- (1.05,{axis_y:.2f}) node[below right, text=axisGray, align=left] {{\\scriptsize run-level\\\\violation rate}};",
        "  \\foreach \\x in {0,0.2,0.4,0.6,0.8,1.0}{",
        f"    \\draw[draw=axisGray!25] (\\x,{axis_y:.2f}) -- (\\x,{y_top_grid:.2f});",
        f"    \\draw[draw=axisGray, line width=0.6pt] (\\x,{(axis_y - 0.03):.2f}) -- (\\x,{(axis_y + 0.03):.2f});",
        f"    \\node[below, text=axisGray] at (\\x,{(axis_y - 0.03):.2f}) {{\\scriptsize \\x}};",
        "  }",
    ]

    # model-pair backgrounds for LLM rows
    pair_idx = 0
    i = 0
    while i < n - 1:
        label_i = str(rows[i].get("model_label", "")).strip()
        label_j = str(rows[i + 1].get("model_label", "")).strip()
        model_i, arm_i = _parse_model_label(label_i)
        model_j, arm_j = _parse_model_label(label_j)
        if model_i == model_j and arm_i.startswith("llm_") and arm_j.startswith("llm_"):
            y_i = top_y - i * spacing
            y_j = top_y - (i + 1) * spacing
            # stronger tints than original (6/4) so model groupings are
            # actually visible at ACM-CCS print density, while still
            # alternating to separate adjacent pairs
            shade = "10" if pair_idx % 2 == 0 else "7"
            lines.append(
                f"  \\fill[axisGray!{shade}, rounded corners=2pt] (-0.015,{(y_j - 0.25):.2f}) rectangle (1.03,{(y_i + 0.25):.2f});",
            )
            pair_idx += 1
            i += 2
        else:
            i += 1

    run_count_hint = 0
    for idx, row in enumerate(rows):
        y = top_y - idx * spacing
        label = str(row.get("model_label", "")).strip()
        _, arm = _parse_model_label(label)
        if arm == "llm_zero":
            fill = "llmZeroBg"
            draw = "llmZero"
        elif arm == "llm_policy_prompt":
            fill = "llmPolicyBg"
            draw = "llmPolicy"
        else:
            fill = "humanBg"
            draw = "humanGray"

        rate, lo, hi = _rate_ci(row)
        disp = _tex_escape(_row_compact_label(label))
        run_count_hint = max(run_count_hint, _safe_int(row.get("run_count")))
        lines.extend(
            [
                f"  \\fill[{fill}, draw={draw}] (0,{(y - bar_h / 2):.2f}) rectangle ({rate:.4f},{(y + bar_h / 2):.2f});",
                f"  \\fill[{draw}] (0,{y:.2f}) circle (2.0pt);",
                f"  \\draw[{draw}, line width=1.0pt] ({lo:.4f},{y:.2f}) -- ({hi:.4f},{y:.2f});",
                f"  \\draw[{draw}, line width=1.0pt] ({lo:.4f},{(y - 0.07):.2f}) -- ({lo:.4f},{(y + 0.07):.2f});",
                f"  \\draw[{draw}, line width=1.0pt] ({hi:.4f},{(y - 0.07):.2f}) -- ({hi:.4f},{(y + 0.07):.2f});",
                f"  \\node[left, align=right] at (0,{y:.2f}) {{{disp}}};",
                f"  \\node[anchor=west, text={draw}, font=\\scriptsize\\bfseries] at ({(max(rate, hi, 0.0) + 0.012):.4f},{y:.2f}) {{{rate:.4f}}};",
            ],
        )

    if run_count_hint > 0:
        note = f"$n={run_count_hint}$ runs per row $\\cdot$ 95\\% Wilson CIs"
    else:
        note = "error bars: 95\\% Wilson confidence intervals"
    lines.extend(
        [
            f"  \\node[anchor=west, text=axisGray, font=\\scriptsize, align=left] at (0,{(axis_y - 0.43):.2f}) {{{note}}};",
            "\\end{tikzpicture}",
            "",
        ],
    )
    return "\n".join(lines)


def _render_figure_enforcement_utility(by_model: list[dict[str, Any]]) -> str:
    rows = sorted(_llm_rows(by_model), key=_row_sort_key)
    if not rows:
        return "\n".join(
            [
                "\\begin{tikzpicture}[font=\\sffamily\\footnotesize]",
                "  \\node[align=center] {No LLM rows available for enforcement-utility plot.};",
                "\\end{tikzpicture}",
                "",
            ],
        )

    by_model_arm: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        label = str(row.get("model_label", "")).strip()
        model, arm = _parse_model_label(label)
        by_model_arm.setdefault(model, {})[arm] = row

    models = sorted(by_model_arm.keys())
    spacing = 0.90
    top_y = (len(models) - 1) * spacing + 0.20
    axis_y = -0.55
    y_top_grid = top_y + 0.55

    lines = [
        "\\begin{tikzpicture}[x=4.6cm,y=1.0cm,font=\\sffamily\\small]",
        "  \\definecolor{axisGray}{HTML}{667085}",
        "  \\definecolor{llmZero}{HTML}{1A5276}",
        "  \\definecolor{llmPolicy}{HTML}{117864}",
        "  \\definecolor{linkGray}{HTML}{8A94A6}",
        f"  \\draw[->, line width=0.8pt, draw=axisGray] (0,{axis_y:.2f}) -- (1.04,{axis_y:.2f}) node[below right, text=axisGray, align=left] {{\\scriptsize enforcement-modification\\\\rate}};",
        "  \\foreach \\x in {0,0.2,0.4,0.6,0.8,1.0}{",
        f"    \\draw[draw=axisGray!25] (\\x,{axis_y:.2f}) -- (\\x,{y_top_grid:.2f});",
        f"    \\draw[draw=axisGray, line width=0.6pt] (\\x,{(axis_y - 0.03):.2f}) -- (\\x,{(axis_y + 0.03):.2f});",
        f"    \\node[below, text=axisGray] at (\\x,{(axis_y - 0.03):.2f}) {{\\scriptsize \\x}};",
        "  }",
    ]

    for idx, model in enumerate(models):
        model_rows = by_model_arm[model]
        row_zero = model_rows.get("llm_zero")
        row_policy = model_rows.get("llm_policy_prompt")
        compact_model = _tex_escape(_compact_model(model))
        y = top_y - idx * spacing

        if row_zero and row_policy:
            x0 = _enforcement_rate(row_zero)
            x1 = _enforcement_rate(row_policy)
            d0 = _delta_jaccard(row_zero)
            d1 = _delta_jaccard(row_policy)
            y0 = y
            y1 = y
            arrow_style = "-{Latex[length=5pt,width=5pt]}"
            if abs(x0 - x1) < 1e-6:
                y0 = y + 0.10
                y1 = y - 0.10
                arrow_style = "densely dashed"

            lines.extend(
                [
                    f"  \\node[anchor=east, text=axisGray] at (-0.02,{y:.2f}) {{\\scriptsize {compact_model}}};",
                    f"  \\draw[{arrow_style}, line width=1.0pt, draw=linkGray] ({x0:.4f},{y0:.2f}) -- ({x1:.4f},{y1:.2f});",
                    f"  \\fill[llmZero] ({x0:.4f},{y0:.4f}) circle (2.0pt);",
                    f"  \\fill[llmPolicy] ({x1:.4f},{y1:.4f}) +(-2.0pt,-2.0pt) rectangle +(2.0pt,2.0pt);",
                    f"  \\node[anchor=west, font=\\scriptsize, text=axisGray] at (1.06,{y:.2f}) {{$\\Delta J$: {d0:.3f} $\\rightarrow$ {d1:.3f}}};",
                ],
            )
        else:
            row = row_zero if row_zero else row_policy
            if row:
                x = _enforcement_rate(row)
                d = _delta_jaccard(row)
                lines.append(f"  \\node[anchor=east, text=axisGray] at (-0.02,{y:.2f}) {{\\scriptsize {compact_model}}};")
                if row_zero:
                    lines.append(f"  \\fill[llmZero] ({x:.4f},{y:.4f}) circle (2.0pt);")
                else:
                    lines.append(
                        f"  \\fill[llmPolicy] ({x:.4f},{y:.4f}) +(-2.0pt,-2.0pt) rectangle +(2.0pt,2.0pt);",
                    )
                lines.append(
                    f"  \\node[anchor=west, font=\\scriptsize, text=axisGray] at (1.06,{y:.2f}) {{$\\Delta J$: {d:.3f}}};",
                )

    lines.extend(
        [
            f"  \\fill[llmZero] (0.03,{(axis_y - 0.57):.2f}) circle (2.0pt);",
            f"  \\node[anchor=west, font=\\scriptsize, text=llmZero] at (0.05,{(axis_y - 0.57):.2f}) {{zero arm}};",
            f"  \\fill[llmPolicy] (0.38,{(axis_y - 0.57):.2f}) +(-2.0pt,-2.0pt) rectangle +(2.0pt,2.0pt);",
            f"  \\node[anchor=west, font=\\scriptsize, text=llmPolicy] at (0.41,{(axis_y - 0.57):.2f}) {{policy arm}};",
            f"  \\node[anchor=west, font=\\scriptsize, text=axisGray, align=left] at (0.00,{(axis_y - 0.81):.2f}) {{right labels: $\\Delta$Jaccard vs paired human baseline}};",
            "\\end{tikzpicture}",
            "",
        ],
    )
    return "\n".join(lines)


def _aggregate_rule_rates(by_rule_treatment: list[dict[str, Any]]) -> list[tuple[str, float, float, float]]:
    acc: dict[str, dict[str, float]] = {}
    for row in by_rule_treatment:
        rule = str(row.get("rule_id", "")).strip()
        if not rule:
            continue
        if rule not in acc:
            acc[rule] = {
                "zero_runs": 0.0,
                "zero_viol": 0.0,
                "policy_runs": 0.0,
                "policy_viol": 0.0,
            }
        acc[rule]["zero_runs"] += _safe_float(row.get("llm_zero_run_count"))
        acc[rule]["zero_viol"] += _safe_float(row.get("llm_zero_violation_count"))
        acc[rule]["policy_runs"] += _safe_float(row.get("llm_policy_prompt_run_count"))
        acc[rule]["policy_viol"] += _safe_float(row.get("llm_policy_prompt_violation_count"))

    # Keep canonical rule visibility even when a rule is unactivated in a slice.
    for canonical_rule in ("R1", "R2", "R3"):
        acc.setdefault(
            canonical_rule,
            {
                "zero_runs": 0.0,
                "zero_viol": 0.0,
                "policy_runs": 0.0,
                "policy_viol": 0.0,
            },
        )

    out: list[tuple[str, float, float, float]] = []
    for rule, data in sorted(acc.items()):
        zr = (data["zero_viol"] / data["zero_runs"]) if data["zero_runs"] > 0 else 0.0
        pr = (data["policy_viol"] / data["policy_runs"]) if data["policy_runs"] > 0 else 0.0
        out.append((rule, zr, pr, zr - pr))
    return out


def _render_figure_rule_treatment(by_rule_treatment: list[dict[str, Any]]) -> str:
    rules = _aggregate_rule_rates(by_rule_treatment)
    active_rules = [item for item in rules if abs(item[1]) > 1e-9 or abs(item[2]) > 1e-9]
    inactive_rules = [item[0] for item in rules if abs(item[1]) <= 1e-9 and abs(item[2]) <= 1e-9]
    rules = active_rules
    n = len(rules)
    if n == 0:
        return "\n".join(
            [
                "\\begin{tikzpicture}[font=\\sffamily\\footnotesize]",
                "  \\node[align=center] {No rule-treatment rows available.};",
                "\\end{tikzpicture}",
                "",
            ],
        )

    order = {"R1": 0, "R2": 1, "R3": 2, "R4": 3}
    rules = sorted(rules, key=lambda item: (order.get(item[0], 9), item[0]))
    spacing = 0.90
    top_y = (len(rules) - 1) * spacing + 0.20
    axis_y = -0.55
    y_top_grid = top_y + 0.55
    lines = [
        "\\begin{tikzpicture}[x=4.8cm,y=1.0cm,font=\\sffamily\\small]",
        "  \\definecolor{axisGray}{HTML}{667085}",
        "  \\definecolor{zeroBlue}{HTML}{1A5276}",
        "  \\definecolor{policyGreen}{HTML}{117864}",
        "  \\definecolor{linkGray}{HTML}{8A94A6}",
        f"  \\draw[->, line width=0.8pt, draw=axisGray] (0,{axis_y:.2f}) -- (1.05,{axis_y:.2f}) node[below right, text=axisGray, align=left] {{\\scriptsize rule-level\\\\violation rate}};",
        "  \\foreach \\x in {0,0.2,0.4,0.6,0.8,1.0}{",
        f"    \\draw[draw=axisGray!25] (\\x,{axis_y:.2f}) -- (\\x,{y_top_grid:.2f});",
        f"    \\draw[draw=axisGray, line width=0.6pt] (\\x,{(axis_y - 0.03):.2f}) -- (\\x,{(axis_y + 0.03):.2f});",
        f"    \\node[below, text=axisGray] at (\\x,{(axis_y - 0.03):.2f}) {{\\scriptsize \\x}};",
        "  }",
    ]

    for i, (rule, zr, pr, diff) in enumerate(rules):
        y = top_y - i * spacing
        rule_disp = _tex_escape(rule)
        lines.extend(
            [
                f"  \\node[anchor=east, text=axisGray] at (-0.02,{y:.2f}) {{\\scriptsize {rule_disp}}};",
                f"  \\draw[densely dashed, draw=linkGray, line width=0.8pt] ({zr:.4f},{(y + 0.10):.2f}) -- ({pr:.4f},{(y - 0.10):.2f});",
                f"  \\fill[zeroBlue] ({zr:.4f},{(y + 0.10):.2f}) circle (2.0pt);",
                f"  \\fill[policyGreen] ({pr:.4f},{(y - 0.10):.2f}) +(-2.0pt,-2.0pt) rectangle +(2.0pt,2.0pt);",
            ],
        )
        if abs(pr - zr) > 1e-9:
            lines.append(
                f"  \\node[anchor=west, font=\\scriptsize, text=axisGray] at ({min(max(zr, pr) + 0.05, 0.76):.4f},{y:.2f}) "
                f"{{policy - zero = {pr - zr:+.2f}}};",
            )

    lines.extend(
        [
            f"  \\node[font=\\scriptsize, text=axisGray, align=center] at (0.52,{(y_top_grid - 0.12):.2f}) "
            f"{{Inactive here and omitted from plot: {', '.join(inactive_rules) if inactive_rules else 'none'}}};",
            f"  \\fill[zeroBlue] (0.03,{(axis_y - 0.57):.2f}) circle (2.0pt);",
            f"  \\node[anchor=west, font=\\scriptsize, text=zeroBlue] at (0.05,{(axis_y - 0.57):.2f}) {{zero arm}};",
            f"  \\fill[policyGreen] (0.36,{(axis_y - 0.57):.2f}) +(-2.0pt,-2.0pt) rectangle +(2.0pt,2.0pt);",
            f"  \\node[anchor=west, font=\\scriptsize, text=policyGreen] at (0.39,{(axis_y - 0.57):.2f}) {{policy arm}};",
            "\\end{tikzpicture}",
            "",
        ],
    )
    return "\n".join(lines)


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    search_roots = [Path.cwd().resolve(), Path.cwd().resolve().parent]
    for root in search_roots:
        try:
            return resolved.relative_to(root).as_posix()
        except ValueError:
            continue
    return path.as_posix()


def _render_manifest(bundle_path: Path, table_dir: Path, figure_dir: Path, support_dir: Path) -> str:
    return "\n".join(
        [
            "# Official Evaluation Assets Manifest",
            "",
            f"- Source bundle: `{_display_path(bundle_path)}`",
            "",
            "## Tables",
            f"- `{_display_path(table_dir / 'evaluation_primary_outcomes_table.tex')}`",
            f"- `{_display_path(table_dir / 'evaluation_pairwise_tests_table.tex')}`",
            f"- `{_display_path(table_dir / 'evaluation_rule_treatment_table.tex')}`",
            f"- `{_display_path(table_dir / 'evaluation_cost_breakdown_table.tex')}`",
            "",
            "## Figures",
            f"- `{_display_path(figure_dir / 'evaluation_violation_rates_by_model_arm.tex')}`",
            f"- `{_display_path(figure_dir / 'evaluation_enforcement_utility_scatter.tex')}`",
            f"- `{_display_path(figure_dir / 'evaluation_rule_treatment_rates.tex')}`",
            "",
            "## Include snippet",
            f"- `{_display_path(support_dir / 'evaluation_include_snippet.tex')}`",
            "",
        ],
    )


def _render_include_snippet() -> str:
    return "\n".join(
        [
            "% Suggested insertion order for the official evaluation result section.",
            "% Figures",
            "% \\begin{figure}[!tb]",
            "% \\centering",
            "% \\resizebox{\\columnwidth}{!}{\\input{figures/evaluation_violation_rates_by_model_arm.tex}}",
            "% \\caption{Official evaluation run-level violation rates by model and arm with 95\\% Wilson intervals.}",
            "% \\label{fig:evaluation_violation_rates}",
            "% \\Description{Horizontal bars by model and arm with confidence intervals.}",
            "% \\end{figure}",
            "%",
            "% \\begin{figure}[!tb]",
            "% \\centering",
            "% \\resizebox{\\columnwidth}{!}{\\input{figures/evaluation_enforcement_utility_scatter.tex}}",
            "% \\caption{Enforcement-utility tradeoff by model and arm.}",
            "% \\label{fig:evaluation_enforcement_utility}",
            "% \\Description{Scatter of enforcement-modification rate versus delta Jaccard.}",
            "% \\end{figure}",
            "%",
            "% \\begin{figure}[!tb]",
            "% \\centering",
            "% \\resizebox{\\columnwidth}{!}{\\input{figures/evaluation_rule_treatment_rates.tex}}",
            "% \\caption{Rule-level violation rates by treatment arm.}",
            "% \\label{fig:evaluation_rule_treatment}",
            "% \\Description{Per-rule bars for zero and policy prompt arms with delta annotations.}",
            "% \\end{figure}",
            "%",
            "% Tables",
            "% \\input{results/evaluation_primary_outcomes_table.tex}",
            "% \\input{results/evaluation_pairwise_tests_table.tex}",
            "% \\input{results/evaluation_rule_treatment_table.tex}",
            "% \\input{results/evaluation_cost_breakdown_table.tex}",
            "",
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render evaluation-result LaTeX tables and figures from analysis_bundle.json",
    )
    parser.add_argument("--analysis-bundle-json", required=True)
    parser.add_argument(
        "--table-output-dir",
        default=str(_default_paper_root() / "results"),
    )
    parser.add_argument(
        "--figure-output-dir",
        default=str(_default_paper_root() / "figures"),
    )
    parser.add_argument(
        "--support-output-dir",
        default=None,
        help="Optional directory for support artifacts such as the asset manifest and include snippet.",
    )
    parser.add_argument(
        "--llm-fallback-bundle-json",
        default=None,
        help="Optional second bundle used to merge LLM rows when primary bundle lacks them.",
    )
    parser.add_argument(
        "--human-fallback-bundle-json",
        default=None,
        help="Optional second bundle used to merge human rows when primary bundle lacks them.",
    )
    args = parser.parse_args()

    bundle_path = Path(args.analysis_bundle_json).expanduser().resolve()
    table_dir = Path(args.table_output_dir).expanduser().resolve()
    figure_dir = Path(args.figure_output_dir).expanduser().resolve()
    support_dir = Path(args.support_output_dir).expanduser().resolve() if args.support_output_dir else table_dir
    payload = _read_bundle(bundle_path)

    by_model = payload.get("by_model", [])
    by_rule_treatment = payload.get("by_rule_treatment", [])
    pairwise = payload.get("pairwise", [])
    if not isinstance(by_model, list) or not isinstance(by_rule_treatment, list) or not isinstance(pairwise, list):
        raise ValueError("analysis bundle fields by_model, by_rule_treatment, and pairwise must be lists")

    if args.llm_fallback_bundle_json:
        llm_bundle_path = Path(args.llm_fallback_bundle_json).expanduser().resolve()
        llm_payload = _read_bundle(llm_bundle_path)
        llm_by_model = llm_payload.get("by_model", [])
        llm_by_rule_treatment = llm_payload.get("by_rule_treatment", [])
        llm_pairwise = llm_payload.get("pairwise", [])
        if isinstance(llm_by_model, list):
            by_model = _merge_rows(
                by_model,
                llm_by_model,
                key_fn=lambda row: str(row.get("model_label", "")).strip(),
            )
        if isinstance(llm_by_rule_treatment, list):
            by_rule_treatment = _merge_rows(
                by_rule_treatment,
                llm_by_rule_treatment,
                key_fn=lambda row: (
                    str(row.get("model", "")).strip(),
                    str(row.get("rule_id", "")).strip(),
                ),
            )
        if isinstance(llm_pairwise, list):
            pairwise = _merge_rows(
                pairwise,
                llm_pairwise,
                key_fn=lambda row: (
                    str(row.get("model_a", "")).strip(),
                    str(row.get("model_b", "")).strip(),
                ),
            )

    if args.human_fallback_bundle_json:
        human_bundle_path = Path(args.human_fallback_bundle_json).expanduser().resolve()
        human_payload = _read_bundle(human_bundle_path)
        human_by_model = human_payload.get("by_model", [])
        if isinstance(human_by_model, list):
            by_model = _merge_rows(
                by_model,
                human_by_model,
                key_fn=lambda row: str(row.get("model_label", "")).strip(),
            )

    _write(
        table_dir / "evaluation_primary_outcomes_table.tex",
        _render_table_primary(by_model),
    )
    _write(
        table_dir / "evaluation_pairwise_tests_table.tex",
        _render_table_pairwise(pairwise, by_model),
    )
    _write(
        table_dir / "evaluation_rule_treatment_table.tex",
        _render_table_rule_treatment(by_rule_treatment),
    )
    _write(
        table_dir / "evaluation_cost_breakdown_table.tex",
        _render_table_cost(by_model),
    )

    _write(
        figure_dir / "evaluation_violation_rates_by_model_arm.tex",
        _render_figure_violation_rates(by_model),
    )
    _write(
        figure_dir / "evaluation_enforcement_utility_scatter.tex",
        _render_figure_enforcement_utility(by_model),
    )
    _write(
        figure_dir / "evaluation_rule_treatment_rates.tex",
        _render_figure_rule_treatment(by_rule_treatment),
    )

    _write(
        support_dir / "evaluation_include_snippet.tex",
        _render_include_snippet(),
    )
    _write(
        support_dir / "EVALUATION_ASSETS_MANIFEST.md",
        _render_manifest(
            bundle_path=bundle_path,
            table_dir=table_dir,
            figure_dir=figure_dir,
            support_dir=support_dir,
        ),
    )
    if support_dir != table_dir:
        _remove_if_exists(table_dir / "evaluation_include_snippet.tex")
        _remove_if_exists(table_dir / "EVALUATION_ASSETS_MANIFEST.md")

    print(f"Rendered evaluation result assets from: {bundle_path}")
    print(f"Tables: {table_dir}")
    print(f"Figures: {figure_dir}")


if __name__ == "__main__":
    main()
