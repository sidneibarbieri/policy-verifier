from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from soc_llm_policy.paths import repo_relative_path
from soc_llm_policy.result_models import VerifierOutputModel

_Z_95 = 1.959963984540054


class SummaryModel(BaseModel):
    run_count: int
    incident_count: int
    incidents_with_violations: int
    incident_violation_rate: float
    mode_counts: dict[str, int]
    violations_by_rule: dict[str, int]
    violations_by_type: dict[str, int]
    violations_by_severity: dict[str, int]
    llm_only_actions: dict[str, int]
    human_only_actions: dict[str, int]
    attack_candidate_count_total: int
    attack_curated_count_total: int
    attack_ab_gap_count_total: int
    attack_curated_to_candidate_ratio: float
    attack_technique_counts: dict[str, int]
    attack_tactic_counts: dict[str, int]
    llm_prompt_tokens_total: int
    llm_completion_tokens_total: int
    llm_total_tokens_total: int
    llm_latency_ms_total: int
    llm_latency_ms_avg_per_run: float
    llm_cost_estimated_usd_total: float
    llm_cost_estimated_usd_avg_per_run: float
    llm_hallucinated_action_count_total: int
    llm_hallucination_rate_avg_per_run: float
    enforcement_actions_inserted_count_total: int
    enforcement_actions_removed_count_total: int
    enforcement_actions_deferred_count_total: int
    enforcement_actions_reordered_count_total: int
    enforcement_action_modification_count_total: int
    enforcement_modified_run_count: int
    enforcement_modification_rate: float
    task_coverage_raw_avg: float
    task_coverage_enforced_avg: float
    task_coverage_delta_avg: float
    task_coverage_drop_run_count: int
    task_coverage_drop_rate: float
    pairwise_comparison_count: int
    violation_rate_by_tactic: dict[str, float]
    violation_rate_by_technique: dict[str, float]
    support_count_by_tactic: dict[str, int]
    support_count_by_technique: dict[str, int]
    violation_rate_by_incident_type: dict[str, float]
    violation_rate_by_severity: dict[str, float]
    violation_rate_by_asset_criticality: dict[str, float]
    support_count_by_incident_type: dict[str, int]
    support_count_by_severity: dict[str, int]
    support_count_by_asset_criticality: dict[str, int]


class IncidentRowModel(BaseModel):
    incident_id: str
    incident_dir_id: str
    incident_type: str
    severity: str
    asset_criticality: str
    mode: str
    run_tag: str
    approval_policy_mode: str
    llm_deployment: str
    llm_arm: str
    model_label: str
    violation_count: int
    hard_violation_count: int
    llm_action_count: int
    human_action_count: int
    enforced_action_count: int
    llm_only_action_count: int
    human_only_action_count: int
    attack_match_count: int
    attack_candidate_count: int
    attack_ab_gap_count: int
    attack_curated_to_candidate_ratio: float
    attack_technique_count: int
    attack_tactic_count: int
    llm_prompt_tokens: int
    llm_completion_tokens: int
    llm_total_tokens: int
    llm_latency_ms: int
    llm_cost_estimated_usd: float
    llm_hallucinated_action_count: int
    llm_hallucination_rate: float
    enforcement_actions_inserted_count: int
    enforcement_actions_removed_count: int
    enforcement_actions_deferred_count: int
    enforcement_actions_reordered_count: int
    enforcement_action_modification_count: int
    enforcement_modified: bool
    precision_raw: float
    recall_raw: float
    task_coverage_raw: float
    f1_raw: float
    jaccard_raw: float
    precision_enforced: float
    recall_enforced: float
    task_coverage_enforced: float
    f1_enforced: float
    jaccard_enforced: float
    delta_jaccard: float
    task_coverage_delta: float


class ByModelRowModel(BaseModel):
    model_label: str
    run_count: int
    runs_with_violations: int
    run_violation_rate: float
    run_violation_rate_ci_low: float
    run_violation_rate_ci_high: float
    violation_count: int
    hard_violation_count: int
    llm_only_action_count: int
    human_only_action_count: int
    llm_prompt_tokens_total: int
    llm_completion_tokens_total: int
    llm_total_tokens_total: int
    llm_latency_ms_total: int
    llm_latency_ms_avg: float
    llm_cost_estimated_usd_total: float
    llm_hallucinated_action_count_total: int
    llm_hallucination_rate_avg: float
    enforcement_actions_inserted_count_total: int
    enforcement_actions_removed_count_total: int
    enforcement_actions_deferred_count_total: int
    enforcement_actions_reordered_count_total: int
    enforcement_action_modification_count_total: int
    enforcement_modified_run_count: int
    enforcement_modification_rate: float
    precision_raw_avg: float
    recall_raw_avg: float
    task_coverage_raw_avg: float
    f1_raw_avg: float
    jaccard_raw_avg: float
    precision_enforced_avg: float
    recall_enforced_avg: float
    task_coverage_enforced_avg: float
    f1_enforced_avg: float
    jaccard_enforced_avg: float
    delta_jaccard_avg: float
    task_coverage_delta_avg: float
    task_coverage_drop_run_count: int
    task_coverage_drop_rate: float


class ByRuleRowModel(BaseModel):
    model_label: str
    rule_id: str
    violation_count: int
    hard_violation_count: int


class ByRuleTreatmentRowModel(BaseModel):
    rule_id: str
    model: str
    llm_zero_run_count: int
    llm_policy_prompt_run_count: int
    llm_zero_violation_count: int
    llm_policy_prompt_violation_count: int
    llm_zero_violation_rate: float
    llm_policy_prompt_violation_rate: float
    violation_rate_diff_zero_minus_policy: float


class PairwiseRowModel(BaseModel):
    model_a: str
    model_b: str
    paired_incident_count: int
    run_count_a: int
    run_count_b: int
    violation_rate_a: float
    violation_rate_b: float
    rate_diff_a_minus_b: float
    z_score: float
    p_value_two_sided: float
    p_value_holm: float
    cohens_h: float
    cliffs_delta: float
    mcnemar_b_count: int
    mcnemar_c_count: int
    mcnemar_chi2: float
    mcnemar_p_value_two_sided: float
    mcnemar_p_value_holm: float


class AnalysisBundleModel(BaseModel):
    generated_at_utc: str = Field(..., min_length=1)
    eval_protocol_version: str = Field(..., min_length=1)
    outputs_incidents_dir: str = Field(..., min_length=1)
    incident_filter: list[str] = Field(default_factory=list)
    summary: SummaryModel
    incidents: list[IncidentRowModel]
    by_model: list[ByModelRowModel]
    by_rule: list[ByRuleRowModel]
    by_rule_treatment: list[ByRuleTreatmentRowModel]
    pairwise: list[PairwiseRowModel]


@dataclass(frozen=True)
class AnalysisBundleInput:
    eval_protocol_version: str
    repo_root: Path
    outputs_incidents_dir: Path
    incident_filter: set[str] | None
    summary: dict[str, Any]
    rows: list[dict[str, Any]]
    by_model_rows: list[dict[str, Any]]
    by_rule_rows: list[dict[str, Any]]
    by_rule_treatment_rows: list[dict[str, Any]]
    pairwise_rows: list[dict[str, Any]]


@dataclass
class _AnalyzeAccumulator:
    rows: list[dict[str, Any]]
    violations_by_rule: Counter[str]
    violations_by_type: Counter[str]
    violations_by_severity: Counter[str]
    mode_counter: Counter[str]
    llm_only_actions: Counter[str]
    human_only_actions: Counter[str]
    technique_counter: Counter[str]
    tactic_counter: Counter[str]
    violations_by_rule_and_model: Counter[tuple[str, str]]
    hard_violations_by_rule_and_model: Counter[tuple[str, str]]
    incidents_with_violations_set: set[str]
    unique_incident_ids: set[str]
    attack_summary_by_incident: dict[str, VerifierOutputModel]
    tactic_run_counter: Counter[str]
    tactic_violation_run_counter: Counter[str]
    technique_run_counter: Counter[str]
    technique_violation_run_counter: Counter[str]
    incident_type_run_counter: Counter[str]
    incident_type_violation_run_counter: Counter[str]
    severity_run_counter: Counter[str]
    severity_violation_run_counter: Counter[str]
    criticality_run_counter: Counter[str]
    criticality_violation_run_counter: Counter[str]
    run_count_by_model_arm: Counter[tuple[str, str]]
    violation_run_count_by_model_arm_rule: Counter[tuple[str, str, str]]


def _create_accumulator() -> _AnalyzeAccumulator:
    return _AnalyzeAccumulator(
        rows=[],
        violations_by_rule=Counter(),
        violations_by_type=Counter(),
        violations_by_severity=Counter(),
        mode_counter=Counter(),
        llm_only_actions=Counter(),
        human_only_actions=Counter(),
        technique_counter=Counter(),
        tactic_counter=Counter(),
        violations_by_rule_and_model=Counter(),
        hard_violations_by_rule_and_model=Counter(),
        incidents_with_violations_set=set(),
        unique_incident_ids=set(),
        attack_summary_by_incident={},
        tactic_run_counter=Counter(),
        tactic_violation_run_counter=Counter(),
        technique_run_counter=Counter(),
        technique_violation_run_counter=Counter(),
        incident_type_run_counter=Counter(),
        incident_type_violation_run_counter=Counter(),
        severity_run_counter=Counter(),
        severity_violation_run_counter=Counter(),
        criticality_run_counter=Counter(),
        criticality_violation_run_counter=Counter(),
        run_count_by_model_arm=Counter(),
        violation_run_count_by_model_arm_rule=Counter(),
    )


def _accumulate_run_verifier(
    state: _AnalyzeAccumulator,
    verifier: VerifierOutputModel,
    row: dict[str, Any],
) -> None:
    incident_key = str(
        row.get("incident_dir_id") or verifier.incident_dir_id or verifier.incident_id
    )
    state.rows.append(row)
    state.unique_incident_ids.add(incident_key)
    if incident_key not in state.attack_summary_by_incident:
        state.attack_summary_by_incident[incident_key] = verifier

    state.mode_counter[verifier.mode] += 1
    model_label = str(row.get("model_label", "unknown")) or "unknown"
    incident_type = str(row.get("incident_type", "unknown")) or "unknown"
    severity = str(row.get("severity", "unknown")) or "unknown"
    criticality = str(row.get("asset_criticality", "unknown")) or "unknown"
    state.incident_type_run_counter[incident_type] += 1
    state.severity_run_counter[severity] += 1
    state.criticality_run_counter[criticality] += 1
    if verifier.violations:
        state.incidents_with_violations_set.add(incident_key)
        state.incident_type_violation_run_counter[incident_type] += 1
        state.severity_violation_run_counter[severity] += 1
        state.criticality_violation_run_counter[criticality] += 1
    for violation in verifier.violations:
        state.violations_by_rule[violation.rule_id] += 1
        state.violations_by_type[violation.type] += 1
        state.violations_by_severity[violation.severity] += 1
        state.violations_by_rule_and_model[(model_label, violation.rule_id)] += 1
        if violation.severity == "hard":
            state.hard_violations_by_rule_and_model[
                (model_label, violation.rule_id)
            ] += 1
    llm_deployment = str(row.get("llm_deployment", "")).strip()
    llm_arm = str(row.get("llm_arm", "")).strip()
    if llm_deployment and llm_arm in {"llm_zero", "llm_policy_prompt"}:
        state.run_count_by_model_arm[(llm_deployment, llm_arm)] += 1
        violated_rules = {violation.rule_id for violation in verifier.violations}
        for violated_rule in violated_rules:
            state.violation_run_count_by_model_arm_rule[
                (llm_deployment, llm_arm, violated_rule)
            ] += 1

    human_actions = set(verifier.human_actions)
    llm_actions = set(verifier.llm_actions)
    for action in sorted(llm_actions - human_actions):
        state.llm_only_actions[action] += 1
    for action in sorted(human_actions - llm_actions):
        state.human_only_actions[action] += 1

    tactic_ids = sorted({item.tactic_id for item in verifier.attack_summary.tactics})
    technique_ids = sorted(
        {item.technique_id for item in verifier.attack_summary.techniques}
    )
    has_violation = len(verifier.violations) > 0
    for tactic_id in tactic_ids:
        state.tactic_run_counter[tactic_id] += 1
        if has_violation:
            state.tactic_violation_run_counter[tactic_id] += 1
    for technique_id in technique_ids:
        state.technique_run_counter[technique_id] += 1
        if has_violation:
            state.technique_violation_run_counter[technique_id] += 1


def _accumulate_attack_unique(
    state: _AnalyzeAccumulator,
) -> tuple[int, int, int]:
    total_candidate_count = 0
    total_curated_count = 0
    total_ab_gap_count = 0
    for verifier in state.attack_summary_by_incident.values():
        total_candidate_count += verifier.metrics.attack_candidate_count
        total_curated_count += verifier.metrics.attack_match_count
        total_ab_gap_count += max(
            verifier.metrics.attack_candidate_count
            - verifier.metrics.attack_match_count,
            0,
        )
        for item in verifier.attack_summary.technique_counts:
            state.technique_counter[item.technique_id] += item.count
        for item in verifier.attack_summary.tactic_counts:
            state.tactic_counter[item.tactic_id] += item.count
    return total_candidate_count, total_curated_count, total_ab_gap_count


def _violation_rate_by_key(
    run_counter: Counter[str],
    violation_counter: Counter[str],
) -> tuple[dict[str, float], dict[str, int]]:
    rates: dict[str, float] = {}
    support: dict[str, int] = {}
    for key in sorted(run_counter):
        total = int(run_counter[key])
        support[key] = total
        violations = int(violation_counter[key])
        rates[key] = round((violations / total) if total else 0.0, 4)
    return rates, support


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid JSON (expected object): {path}")
    return data


def _load_verifier_output(path: Path) -> VerifierOutputModel:
    return VerifierOutputModel.model_validate(_load_json(path))


def _incident_row(verifier: VerifierOutputModel) -> dict[str, Any]:
    metrics = verifier.metrics

    curated_count = metrics.attack_match_count
    candidate_count = metrics.attack_candidate_count
    ab_gap = max(candidate_count - curated_count, 0)
    ab_curated_ratio = (
        round(curated_count / candidate_count, 4) if candidate_count else 0.0
    )
    mode = verifier.mode
    approval_policy_mode = verifier.approval_policy_mode or "remove"
    llm_deployment = verifier.llm_deployment or ""
    llm_arm = verifier.llm_arm or ""
    model_label = (
        f"{llm_deployment}|{llm_arm}"
        if llm_deployment and llm_arm
        else (llm_deployment or mode or "unknown")
    )
    if approval_policy_mode != "remove":
        model_label = f"{model_label}|{approval_policy_mode}"
    llm_prompt_tokens = verifier.llm_usage.prompt_tokens if verifier.llm_usage else 0
    llm_completion_tokens = (
        verifier.llm_usage.completion_tokens if verifier.llm_usage else 0
    )
    llm_total_tokens = verifier.llm_usage.total_tokens if verifier.llm_usage else 0
    llm_latency_ms = verifier.llm_latency_ms or 0
    llm_cost_estimated = verifier.llm_cost_estimated_usd or 0.0

    return {
        "incident_id": verifier.incident_id,
        "incident_dir_id": verifier.incident_dir_id or verifier.incident_id,
        "incident_type": verifier.incident_type or "unknown",
        "severity": verifier.severity or "unknown",
        "asset_criticality": verifier.asset_criticality or "unknown",
        "mode": mode,
        "run_tag": verifier.run_tag,
        "approval_policy_mode": approval_policy_mode,
        "llm_deployment": llm_deployment,
        "llm_arm": llm_arm,
        "model_label": model_label,
        "violation_count": metrics.violation_count,
        "hard_violation_count": metrics.hard_violation_count,
        "llm_action_count": metrics.llm_action_count,
        "human_action_count": metrics.human_action_count,
        "enforced_action_count": metrics.enforced_action_count,
        "llm_only_action_count": metrics.llm_only_action_count,
        "human_only_action_count": metrics.human_only_action_count,
        "attack_match_count": metrics.attack_match_count,
        "attack_candidate_count": candidate_count,
        "attack_ab_gap_count": ab_gap,
        "attack_curated_to_candidate_ratio": ab_curated_ratio,
        "attack_technique_count": metrics.attack_technique_count,
        "attack_tactic_count": metrics.attack_tactic_count,
        "llm_prompt_tokens": llm_prompt_tokens,
        "llm_completion_tokens": llm_completion_tokens,
        "llm_total_tokens": llm_total_tokens,
        "llm_latency_ms": llm_latency_ms,
        "llm_cost_estimated_usd": round(llm_cost_estimated, 6),
        "llm_hallucinated_action_count": metrics.llm_hallucinated_action_count,
        "llm_hallucination_rate": metrics.llm_hallucination_rate,
        "enforcement_actions_inserted_count": (
            metrics.enforcement_actions_inserted_count
        ),
        "enforcement_actions_removed_count": (
            metrics.enforcement_actions_removed_count
        ),
        "enforcement_actions_deferred_count": (
            metrics.enforcement_actions_deferred_count
        ),
        "enforcement_actions_reordered_count": (
            metrics.enforcement_actions_reordered_count
        ),
        "enforcement_action_modification_count": (
            metrics.enforcement_action_modification_count
        ),
        "enforcement_modified": metrics.enforcement_modified,
        "precision_raw": metrics.precision_raw,
        "recall_raw": metrics.recall_raw,
        "task_coverage_raw": metrics.recall_raw,
        "f1_raw": metrics.f1_raw,
        "jaccard_raw": metrics.jaccard_raw,
        "precision_enforced": metrics.precision_enforced,
        "recall_enforced": metrics.recall_enforced,
        "task_coverage_enforced": metrics.recall_enforced,
        "f1_enforced": metrics.f1_enforced,
        "jaccard_enforced": metrics.jaccard_enforced,
        "delta_jaccard": metrics.delta_jaccard,
        "task_coverage_delta": round(
            metrics.recall_enforced - metrics.recall_raw,
            4,
        ),
    }


def _collect_verifier_files(
    outputs_incidents_dir: Path,
    canonical_only: bool = False,
) -> list[Path]:
    incident_dirs = sorted(
        path for path in outputs_incidents_dir.glob("INC_*") if path.is_dir()
    )
    selected: list[Path] = []
    for incident_dir in incident_dirs:
        canonical = incident_dir / "verifier_output.json"
        if canonical_only:
            if canonical.exists():
                selected.append(canonical)
            continue
        versioned = sorted(incident_dir.glob("verifier_output_*.json"))
        if versioned:
            selected.extend(versioned)
            continue
        if canonical.exists():
            selected.append(canonical)
    return selected


def _select_latest_runs_per_incident_model(
    verifier_files: list[Path],
) -> list[tuple[VerifierOutputModel, dict[str, Any]]]:
    """Keep only the latest run for each (incident_dir_id, model_label)."""
    latest: dict[tuple[str, str], tuple[str, VerifierOutputModel, dict[str, Any]]] = {}
    for path in verifier_files:
        verifier = _load_verifier_output(path)
        row = _incident_row(verifier)
        key = (str(row["incident_dir_id"]), str(row["model_label"]))
        run_tag = str(row.get("run_tag", "") or "")
        current = latest.get(key)
        if current is None or run_tag > current[0]:
            latest[key] = (run_tag, verifier, row)
    selected = [value[1:] for value in latest.values()]
    selected.sort(
        key=lambda item: (str(item[1]["incident_dir_id"]), str(item[1]["model_label"]))
    )
    return selected


def _parse_incident_filter(raw: str | None) -> set[str] | None:
    if raw is None:
        return None
    values = {item.strip() for item in raw.split(",") if item.strip()}
    return values or None


def _build_by_model_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, int]] = {}
    for row in rows:
        model = str(row.get("model_label", "unknown")) or "unknown"
        bucket = grouped.setdefault(
            model,
            {
                "run_count": 0,
                "runs_with_violations": 0,
                "violation_count": 0,
                "hard_violation_count": 0,
                "llm_only_action_count": 0,
                "human_only_action_count": 0,
                "llm_prompt_tokens_total": 0,
                "llm_completion_tokens_total": 0,
                "llm_total_tokens_total": 0,
                "llm_latency_ms_total": 0,
                "llm_cost_estimated_usd_total": 0.0,
                "llm_hallucinated_action_count_total": 0,
                "llm_hallucination_rate_sum": 0.0,
                "enforcement_actions_inserted_count_total": 0,
                "enforcement_actions_removed_count_total": 0,
                "enforcement_actions_deferred_count_total": 0,
                "enforcement_actions_reordered_count_total": 0,
                "enforcement_action_modification_count_total": 0,
                "enforcement_modified_run_count": 0,
                "precision_raw_sum": 0.0,
                "recall_raw_sum": 0.0,
                "task_coverage_raw_sum": 0.0,
                "f1_raw_sum": 0.0,
                "jaccard_raw_sum": 0.0,
                "precision_enforced_sum": 0.0,
                "recall_enforced_sum": 0.0,
                "task_coverage_enforced_sum": 0.0,
                "f1_enforced_sum": 0.0,
                "jaccard_enforced_sum": 0.0,
                "delta_jaccard_sum": 0.0,
                "task_coverage_delta_sum": 0.0,
                "task_coverage_drop_run_count": 0,
            },
        )
        bucket["run_count"] += 1
        bucket["violation_count"] += int(row.get("violation_count", 0))
        bucket["hard_violation_count"] += int(row.get("hard_violation_count", 0))
        bucket["llm_only_action_count"] += int(row.get("llm_only_action_count", 0))
        bucket["human_only_action_count"] += int(row.get("human_only_action_count", 0))
        bucket["llm_prompt_tokens_total"] += int(row.get("llm_prompt_tokens", 0))
        bucket["llm_completion_tokens_total"] += int(
            row.get("llm_completion_tokens", 0)
        )
        bucket["llm_total_tokens_total"] += int(row.get("llm_total_tokens", 0))
        bucket["llm_latency_ms_total"] += int(row.get("llm_latency_ms", 0))
        bucket["llm_cost_estimated_usd_total"] += float(
            row.get("llm_cost_estimated_usd", 0.0)
        )
        bucket["llm_hallucinated_action_count_total"] += int(
            row.get("llm_hallucinated_action_count", 0)
        )
        bucket["llm_hallucination_rate_sum"] += float(
            row.get("llm_hallucination_rate", 0.0)
        )
        bucket["enforcement_actions_inserted_count_total"] += int(
            row.get("enforcement_actions_inserted_count", 0)
        )
        bucket["enforcement_actions_removed_count_total"] += int(
            row.get("enforcement_actions_removed_count", 0)
        )
        bucket["enforcement_actions_deferred_count_total"] += int(
            row.get("enforcement_actions_deferred_count", 0)
        )
        bucket["enforcement_actions_reordered_count_total"] += int(
            row.get("enforcement_actions_reordered_count", 0)
        )
        bucket["enforcement_action_modification_count_total"] += int(
            row.get("enforcement_action_modification_count", 0)
        )
        if bool(row.get("enforcement_modified", False)):
            bucket["enforcement_modified_run_count"] += 1
        bucket["precision_raw_sum"] += float(row.get("precision_raw", 0.0))
        bucket["recall_raw_sum"] += float(row.get("recall_raw", 0.0))
        bucket["task_coverage_raw_sum"] += float(row.get("task_coverage_raw", 0.0))
        bucket["f1_raw_sum"] += float(row.get("f1_raw", 0.0))
        bucket["jaccard_raw_sum"] += float(row.get("jaccard_raw", 0.0))
        bucket["precision_enforced_sum"] += float(row.get("precision_enforced", 0.0))
        bucket["recall_enforced_sum"] += float(row.get("recall_enforced", 0.0))
        bucket["task_coverage_enforced_sum"] += float(
            row.get("task_coverage_enforced", 0.0)
        )
        bucket["f1_enforced_sum"] += float(row.get("f1_enforced", 0.0))
        bucket["jaccard_enforced_sum"] += float(row.get("jaccard_enforced", 0.0))
        bucket["delta_jaccard_sum"] += float(row.get("delta_jaccard", 0.0))
        bucket["task_coverage_delta_sum"] += float(row.get("task_coverage_delta", 0.0))
        if float(row.get("task_coverage_delta", 0.0)) < 0:
            bucket["task_coverage_drop_run_count"] += 1
        if int(row.get("violation_count", 0)) > 0:
            bucket["runs_with_violations"] += 1

    out: list[dict[str, Any]] = []
    for model in sorted(grouped):
        bucket = grouped[model]
        run_count = bucket["run_count"]
        runs_with_violations = bucket["runs_with_violations"]
        run_violation_rate = (
            round(runs_with_violations / run_count, 4) if run_count else 0.0
        )
        ci_low, ci_high = _wilson_interval(runs_with_violations, run_count)
        out.append(
            {
                "model_label": model,
                "run_count": run_count,
                "runs_with_violations": runs_with_violations,
                "run_violation_rate": run_violation_rate,
                "run_violation_rate_ci_low": ci_low,
                "run_violation_rate_ci_high": ci_high,
                "violation_count": bucket["violation_count"],
                "hard_violation_count": bucket["hard_violation_count"],
                "llm_only_action_count": bucket["llm_only_action_count"],
                "human_only_action_count": bucket["human_only_action_count"],
                "llm_prompt_tokens_total": bucket["llm_prompt_tokens_total"],
                "llm_completion_tokens_total": bucket["llm_completion_tokens_total"],
                "llm_total_tokens_total": bucket["llm_total_tokens_total"],
                "llm_latency_ms_total": bucket["llm_latency_ms_total"],
                "llm_latency_ms_avg": round(
                    bucket["llm_latency_ms_total"] / run_count,
                    2,
                ),
                "llm_cost_estimated_usd_total": round(
                    bucket["llm_cost_estimated_usd_total"], 6
                ),
                "llm_hallucinated_action_count_total": bucket[
                    "llm_hallucinated_action_count_total"
                ],
                "llm_hallucination_rate_avg": round(
                    bucket["llm_hallucination_rate_sum"] / run_count,
                    4,
                ),
                "enforcement_actions_inserted_count_total": bucket[
                    "enforcement_actions_inserted_count_total"
                ],
                "enforcement_actions_removed_count_total": bucket[
                    "enforcement_actions_removed_count_total"
                ],
                "enforcement_actions_deferred_count_total": bucket[
                    "enforcement_actions_deferred_count_total"
                ],
                "enforcement_actions_reordered_count_total": bucket[
                    "enforcement_actions_reordered_count_total"
                ],
                "enforcement_action_modification_count_total": bucket[
                    "enforcement_action_modification_count_total"
                ],
                "enforcement_modified_run_count": bucket[
                    "enforcement_modified_run_count"
                ],
                "enforcement_modification_rate": round(
                    bucket["enforcement_modified_run_count"] / run_count,
                    4,
                ),
                "precision_raw_avg": round(bucket["precision_raw_sum"] / run_count, 4),
                "recall_raw_avg": round(bucket["recall_raw_sum"] / run_count, 4),
                "task_coverage_raw_avg": round(
                    bucket["task_coverage_raw_sum"] / run_count,
                    4,
                ),
                "f1_raw_avg": round(bucket["f1_raw_sum"] / run_count, 4),
                "jaccard_raw_avg": round(bucket["jaccard_raw_sum"] / run_count, 4),
                "precision_enforced_avg": round(
                    bucket["precision_enforced_sum"] / run_count,
                    4,
                ),
                "recall_enforced_avg": round(
                    bucket["recall_enforced_sum"] / run_count,
                    4,
                ),
                "task_coverage_enforced_avg": round(
                    bucket["task_coverage_enforced_sum"] / run_count,
                    4,
                ),
                "f1_enforced_avg": round(
                    bucket["f1_enforced_sum"] / run_count,
                    4,
                ),
                "jaccard_enforced_avg": round(
                    bucket["jaccard_enforced_sum"] / run_count,
                    4,
                ),
                "delta_jaccard_avg": round(
                    bucket["delta_jaccard_sum"] / run_count,
                    4,
                ),
                "task_coverage_delta_avg": round(
                    bucket["task_coverage_delta_sum"] / run_count,
                    4,
                ),
                "task_coverage_drop_run_count": bucket["task_coverage_drop_run_count"],
                "task_coverage_drop_rate": round(
                    bucket["task_coverage_drop_run_count"] / run_count,
                    4,
                ),
            }
        )
    return out


def _build_by_rule_rows(
    rule_model_counter: Counter[tuple[str, str]],
    rule_model_hard_counter: Counter[tuple[str, str]],
) -> list[dict[str, Any]]:
    pairs = sorted(rule_model_counter)
    out: list[dict[str, Any]] = []
    for model_label, rule_id in pairs:
        total = int(rule_model_counter[(model_label, rule_id)])
        hard = int(rule_model_hard_counter[(model_label, rule_id)])
        out.append(
            {
                "model_label": model_label,
                "rule_id": rule_id,
                "violation_count": total,
                "hard_violation_count": hard,
            }
        )
    return out


def _build_by_rule_treatment_rows(
    run_count_by_model_arm: Counter[tuple[str, str]],
    violation_run_count_by_model_arm_rule: Counter[tuple[str, str, str]],
) -> list[dict[str, Any]]:
    """Compare per-rule violation rates between llm_zero and llm_policy_prompt."""
    output: list[dict[str, Any]] = []
    models = sorted({model for model, _arm in run_count_by_model_arm})
    for model in models:
        zero_runs = int(run_count_by_model_arm.get((model, "llm_zero"), 0))
        policy_runs = int(run_count_by_model_arm.get((model, "llm_policy_prompt"), 0))
        if zero_runs == 0 or policy_runs == 0:
            continue
        rule_ids = sorted(
            {
                rule
                for model_key, _arm, rule in violation_run_count_by_model_arm_rule
                if model_key == model
            }
        )
        for rule_id in rule_ids:
            zero_count = int(
                violation_run_count_by_model_arm_rule.get(
                    (model, "llm_zero", rule_id),
                    0,
                )
            )
            policy_count = int(
                violation_run_count_by_model_arm_rule.get(
                    (model, "llm_policy_prompt", rule_id),
                    0,
                )
            )
            zero_rate = round(zero_count / zero_runs, 4) if zero_runs else 0.0
            policy_rate = round(policy_count / policy_runs, 4) if policy_runs else 0.0
            output.append(
                {
                    "rule_id": rule_id,
                    "model": model,
                    "llm_zero_run_count": zero_runs,
                    "llm_policy_prompt_run_count": policy_runs,
                    "llm_zero_violation_count": zero_count,
                    "llm_policy_prompt_violation_count": policy_count,
                    "llm_zero_violation_rate": zero_rate,
                    "llm_policy_prompt_violation_rate": policy_rate,
                    "violation_rate_diff_zero_minus_policy": round(
                        zero_rate - policy_rate,
                        4,
                    ),
                }
            )
    return output


def _wilson_interval(successes: int, total: int) -> tuple[float, float]:
    if total <= 0:
        return 0.0, 0.0
    p = successes / total
    denom = 1.0 + (_Z_95**2) / total
    center = (p + (_Z_95**2) / (2 * total)) / denom
    margin = (
        _Z_95 * math.sqrt((p * (1 - p) / total) + (_Z_95**2) / (4 * (total**2))) / denom
    )
    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    return round(low, 4), round(high, 4)


def _normal_cdf(value: float) -> float:
    return 0.5 * (1.0 + math.erf(value / math.sqrt(2.0)))


def _two_proportion_ztest(
    successes_a: int,
    total_a: int,
    successes_b: int,
    total_b: int,
) -> tuple[float, float]:
    if total_a <= 0 or total_b <= 0:
        return 0.0, 1.0
    p1 = successes_a / total_a
    p2 = successes_b / total_b
    pooled = (successes_a + successes_b) / (total_a + total_b)
    denom = math.sqrt(pooled * (1 - pooled) * ((1 / total_a) + (1 / total_b)))
    if denom == 0:
        return 0.0, 1.0
    z_score = (p1 - p2) / denom
    p_value = 2 * (1 - _normal_cdf(abs(z_score)))
    return z_score, max(0.0, min(1.0, p_value))


def _cohens_h(rate_a: float, rate_b: float) -> float:
    return round(2 * (math.asin(math.sqrt(rate_a)) - math.asin(math.sqrt(rate_b))), 6)


def _cliffs_delta_binary(values_a: list[int], values_b: list[int]) -> float:
    if not values_a or not values_b:
        return 0.0
    if len(values_a) != len(values_b):
        return 0.0
    signed_sum = 0
    for a_value, b_value in zip(values_a, values_b, strict=True):
        if a_value > b_value:
            signed_sum += 1
        elif a_value < b_value:
            signed_sum -= 1
    return round(signed_sum / len(values_a), 6)


def _holm_adjust(p_values: list[float]) -> list[float]:
    n = len(p_values)
    if n == 0:
        return []
    indexed = sorted(enumerate(p_values), key=lambda item: item[1])
    adjusted = [0.0] * n
    running_max = 0.0
    for rank, (original_index, p_value) in enumerate(indexed, start=1):
        corrected = min(1.0, (n - rank + 1) * p_value)
        running_max = max(running_max, corrected)
        adjusted[original_index] = running_max
    return [round(value, 6) for value in adjusted]


def _mcnemar_test(
    b_count: int,
    c_count: int,
) -> tuple[float, float]:
    discordant = b_count + c_count
    if discordant == 0:
        return 0.0, 1.0
    chi2_stat = ((abs(b_count - c_count) - 1) ** 2) / discordant
    # chi-square(1) CDF: erf(sqrt(x/2))
    p_value = 1 - math.erf(math.sqrt(chi2_stat / 2))
    return round(chi2_stat, 6), round(max(0.0, min(1.0, p_value)), 6)


def _build_pairwise_rows_from_runs(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest_by_model_incident: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        model_label = str(row["model_label"])
        incident_key = str(row.get("incident_dir_id") or row["incident_id"])
        key = (model_label, incident_key)
        current = latest_by_model_incident.get(key)
        if current is None or str(row["run_tag"]) > str(current["run_tag"]):
            latest_by_model_incident[key] = row

    model_to_incidents: dict[str, dict[str, dict[str, Any]]] = {}
    for (model_label, incident_id), row in latest_by_model_incident.items():
        model_to_incidents.setdefault(model_label, {})[incident_id] = row

    out: list[dict[str, Any]] = []
    models = sorted(model_to_incidents)
    for i in range(len(models)):
        for j in range(i + 1, len(models)):
            model_a = models[i]
            model_b = models[j]
            incidents_a = model_to_incidents[model_a]
            incidents_b = model_to_incidents[model_b]
            common_incidents = sorted(set(incidents_a) & set(incidents_b))
            if not common_incidents:
                continue

            runs_with_violations_a = sum(
                int(incidents_a[incident_id]["violation_count"]) > 0
                for incident_id in common_incidents
            )
            runs_with_violations_b = sum(
                int(incidents_b[incident_id]["violation_count"]) > 0
                for incident_id in common_incidents
            )
            b_count = sum(
                (
                    int(incidents_a[incident_id]["violation_count"]) > 0
                    and int(incidents_b[incident_id]["violation_count"]) == 0
                )
                for incident_id in common_incidents
            )
            c_count = sum(
                (
                    int(incidents_a[incident_id]["violation_count"]) == 0
                    and int(incidents_b[incident_id]["violation_count"]) > 0
                )
                for incident_id in common_incidents
            )
            paired_count = len(common_incidents)
            binary_a = [
                int(int(incidents_a[incident_id]["violation_count"]) > 0)
                for incident_id in common_incidents
            ]
            binary_b = [
                int(int(incidents_b[incident_id]["violation_count"]) > 0)
                for incident_id in common_incidents
            ]
            z_score, p_value = _two_proportion_ztest(
                runs_with_violations_a,
                paired_count,
                runs_with_violations_b,
                paired_count,
            )
            mcnemar_chi2, mcnemar_p = _mcnemar_test(b_count, c_count)
            rate_a = runs_with_violations_a / paired_count
            rate_b = runs_with_violations_b / paired_count
            out.append(
                {
                    "model_a": model_a,
                    "model_b": model_b,
                    "paired_incident_count": paired_count,
                    "run_count_a": paired_count,
                    "run_count_b": paired_count,
                    "violation_rate_a": round(rate_a, 4),
                    "violation_rate_b": round(rate_b, 4),
                    "rate_diff_a_minus_b": round(rate_a - rate_b, 4),
                    "z_score": round(z_score, 6),
                    "p_value_two_sided": round(p_value, 6),
                    "p_value_holm": 1.0,
                    "cohens_h": _cohens_h(rate_a, rate_b),
                    "cliffs_delta": _cliffs_delta_binary(binary_a, binary_b),
                    "mcnemar_b_count": b_count,
                    "mcnemar_c_count": c_count,
                    "mcnemar_chi2": mcnemar_chi2,
                    "mcnemar_p_value_two_sided": mcnemar_p,
                    "mcnemar_p_value_holm": 1.0,
                }
            )
    if out:
        adjusted_z = _holm_adjust([float(item["p_value_two_sided"]) for item in out])
        adjusted_m = _holm_adjust(
            [float(item["mcnemar_p_value_two_sided"]) for item in out]
        )
        for row, holm_z, holm_m in zip(out, adjusted_z, adjusted_m, strict=True):
            row["p_value_holm"] = holm_z
            row["mcnemar_p_value_holm"] = holm_m
    return out


def analyze_incident_outputs_full(
    outputs_incidents_dir: Path,
    incident_filter: set[str] | None = None,
    canonical_only: bool = False,
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    verifier_files = _collect_verifier_files(
        outputs_incidents_dir,
        canonical_only=canonical_only,
    )
    if incident_filter:
        verifier_files = [
            path for path in verifier_files if path.parent.name in incident_filter
        ]
    if not verifier_files:
        raise FileNotFoundError(
            "Nenhum verifier output encontrado em "
            f"{outputs_incidents_dir}/INC_*/verifier_output*.json"
        )

    selected_runs = _select_latest_runs_per_incident_model(verifier_files)
    state = _create_accumulator()

    for verifier, row in selected_runs:
        _accumulate_run_verifier(state, verifier, row)

    total_candidate_count, total_curated_count, total_ab_gap_count = (
        _accumulate_attack_unique(state)
    )
    unique_incident_count = len(state.unique_incident_ids)
    total_prompt_tokens = sum(int(row["llm_prompt_tokens"]) for row in state.rows)
    total_completion_tokens = sum(
        int(row["llm_completion_tokens"]) for row in state.rows
    )
    total_tokens = sum(int(row["llm_total_tokens"]) for row in state.rows)
    total_latency_ms = sum(int(row.get("llm_latency_ms", 0)) for row in state.rows)
    total_estimated_cost = sum(
        float(row["llm_cost_estimated_usd"]) for row in state.rows
    )
    total_hallucinated_actions = sum(
        int(row["llm_hallucinated_action_count"]) for row in state.rows
    )
    avg_hallucination_rate = (
        round(
            sum(float(row["llm_hallucination_rate"]) for row in state.rows)
            / len(state.rows),
            4,
        )
        if state.rows
        else 0.0
    )
    total_enforcement_inserted = sum(
        int(row["enforcement_actions_inserted_count"]) for row in state.rows
    )
    total_enforcement_removed = sum(
        int(row["enforcement_actions_removed_count"]) for row in state.rows
    )
    total_enforcement_deferred = sum(
        int(row.get("enforcement_actions_deferred_count", 0)) for row in state.rows
    )
    total_enforcement_reordered = sum(
        int(row["enforcement_actions_reordered_count"]) for row in state.rows
    )
    total_enforcement_modification_count = sum(
        int(row["enforcement_action_modification_count"]) for row in state.rows
    )
    enforcement_modified_run_count = sum(
        int(bool(row["enforcement_modified"])) for row in state.rows
    )
    average_estimated_cost = (
        round(total_estimated_cost / len(state.rows), 6) if state.rows else 0.0
    )
    average_latency_ms = (
        round(total_latency_ms / len(state.rows), 2) if state.rows else 0.0
    )
    task_coverage_raw_avg = (
        round(
            sum(float(row.get("task_coverage_raw", 0.0)) for row in state.rows)
            / len(state.rows),
            4,
        )
        if state.rows
        else 0.0
    )
    task_coverage_enforced_avg = (
        round(
            sum(float(row.get("task_coverage_enforced", 0.0)) for row in state.rows)
            / len(state.rows),
            4,
        )
        if state.rows
        else 0.0
    )
    task_coverage_delta_avg = (
        round(
            sum(float(row.get("task_coverage_delta", 0.0)) for row in state.rows)
            / len(state.rows),
            4,
        )
        if state.rows
        else 0.0
    )
    task_coverage_drop_run_count = sum(
        int(float(row.get("task_coverage_delta", 0.0)) < 0) for row in state.rows
    )
    summary = {
        "run_count": len(state.rows),
        "incident_count": unique_incident_count,
        "incidents_with_violations": len(state.incidents_with_violations_set),
        "incident_violation_rate": (
            round(len(state.incidents_with_violations_set) / unique_incident_count, 4)
            if unique_incident_count
            else 0.0
        ),
        "mode_counts": dict(state.mode_counter),
        "violations_by_rule": dict(state.violations_by_rule),
        "violations_by_type": dict(state.violations_by_type),
        "violations_by_severity": dict(state.violations_by_severity),
        "llm_only_actions": dict(state.llm_only_actions),
        "human_only_actions": dict(state.human_only_actions),
        "attack_candidate_count_total": total_candidate_count,
        "attack_curated_count_total": total_curated_count,
        "attack_ab_gap_count_total": total_ab_gap_count,
        "attack_curated_to_candidate_ratio": (
            round(total_curated_count / total_candidate_count, 4)
            if total_candidate_count
            else 0.0
        ),
        "attack_technique_counts": dict(state.technique_counter),
        "attack_tactic_counts": dict(state.tactic_counter),
        "llm_prompt_tokens_total": total_prompt_tokens,
        "llm_completion_tokens_total": total_completion_tokens,
        "llm_total_tokens_total": total_tokens,
        "llm_latency_ms_total": total_latency_ms,
        "llm_latency_ms_avg_per_run": average_latency_ms,
        "llm_cost_estimated_usd_total": round(total_estimated_cost, 6),
        "llm_cost_estimated_usd_avg_per_run": average_estimated_cost,
        "llm_hallucinated_action_count_total": total_hallucinated_actions,
        "llm_hallucination_rate_avg_per_run": avg_hallucination_rate,
        "enforcement_actions_inserted_count_total": total_enforcement_inserted,
        "enforcement_actions_removed_count_total": total_enforcement_removed,
        "enforcement_actions_deferred_count_total": total_enforcement_deferred,
        "enforcement_actions_reordered_count_total": total_enforcement_reordered,
        "enforcement_action_modification_count_total": (
            total_enforcement_modification_count
        ),
        "enforcement_modified_run_count": enforcement_modified_run_count,
        "enforcement_modification_rate": (
            round(enforcement_modified_run_count / len(state.rows), 4)
            if state.rows
            else 0.0
        ),
        "task_coverage_raw_avg": task_coverage_raw_avg,
        "task_coverage_enforced_avg": task_coverage_enforced_avg,
        "task_coverage_delta_avg": task_coverage_delta_avg,
        "task_coverage_drop_run_count": task_coverage_drop_run_count,
        "task_coverage_drop_rate": (
            round(task_coverage_drop_run_count / len(state.rows), 4)
            if state.rows
            else 0.0
        ),
    }
    tactic_rates, tactic_support = _violation_rate_by_key(
        state.tactic_run_counter,
        state.tactic_violation_run_counter,
    )
    technique_rates, technique_support = _violation_rate_by_key(
        state.technique_run_counter,
        state.technique_violation_run_counter,
    )
    summary["violation_rate_by_tactic"] = tactic_rates
    summary["violation_rate_by_technique"] = technique_rates
    summary["support_count_by_tactic"] = tactic_support
    summary["support_count_by_technique"] = technique_support
    incident_type_rates, incident_type_support = _violation_rate_by_key(
        state.incident_type_run_counter,
        state.incident_type_violation_run_counter,
    )
    severity_rates, severity_support = _violation_rate_by_key(
        state.severity_run_counter,
        state.severity_violation_run_counter,
    )
    criticality_rates, criticality_support = _violation_rate_by_key(
        state.criticality_run_counter,
        state.criticality_violation_run_counter,
    )
    summary["violation_rate_by_incident_type"] = incident_type_rates
    summary["violation_rate_by_severity"] = severity_rates
    summary["violation_rate_by_asset_criticality"] = criticality_rates
    summary["support_count_by_incident_type"] = incident_type_support
    summary["support_count_by_severity"] = severity_support
    summary["support_count_by_asset_criticality"] = criticality_support
    by_model_rows = _build_by_model_rows(state.rows)
    by_rule_rows = _build_by_rule_rows(
        state.violations_by_rule_and_model,
        state.hard_violations_by_rule_and_model,
    )
    by_rule_treatment_rows = _build_by_rule_treatment_rows(
        state.run_count_by_model_arm,
        state.violation_run_count_by_model_arm_rule,
    )
    pairwise_rows = _build_pairwise_rows_from_runs(state.rows)
    summary["pairwise_comparison_count"] = len(pairwise_rows)
    return (
        summary,
        state.rows,
        by_model_rows,
        by_rule_rows,
        by_rule_treatment_rows,
        pairwise_rows,
    )


def analyze_incident_outputs(
    outputs_incidents_dir: Path,
    incident_filter: set[str] | None = None,
    canonical_only: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    (
        summary,
        rows,
        _by_model_rows,
        _by_rule_rows,
        _by_rule_treatment_rows,
        _pairwise_rows,
    ) = analyze_incident_outputs_full(
        outputs_incidents_dir,
        incident_filter,
        canonical_only=canonical_only,
    )
    return summary, rows


def _write_summary_json(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


def _build_analysis_bundle(data: AnalysisBundleInput) -> dict[str, Any]:
    bundle = AnalysisBundleModel(
        generated_at_utc=datetime.now(UTC).isoformat(),
        eval_protocol_version=data.eval_protocol_version,
        outputs_incidents_dir=repo_relative_path(
            data.outputs_incidents_dir,
            data.repo_root,
        ),
        incident_filter=sorted(data.incident_filter) if data.incident_filter else [],
        summary=SummaryModel.model_validate(data.summary),
        incidents=[IncidentRowModel.model_validate(item) for item in data.rows],
        by_model=[ByModelRowModel.model_validate(item) for item in data.by_model_rows],
        by_rule=[ByRuleRowModel.model_validate(item) for item in data.by_rule_rows],
        by_rule_treatment=[
            ByRuleTreatmentRowModel.model_validate(item)
            for item in data.by_rule_treatment_rows
        ],
        pairwise=[PairwiseRowModel.model_validate(item) for item in data.pairwise_rows],
    )
    return bundle.model_dump(mode="json")


def _write_bundle_json(path: Path, bundle: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_rows_csv(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    fieldnames: list[str] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows and fieldnames is None:
        raise ValueError("No rows available for CSV export.")
    csv_fields = fieldnames or list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=csv_fields)
        writer.writeheader()
        writer.writerows(rows)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soc_llm_policy.analyze")
    parser.add_argument(
        "--outputs-incidents-dir",
        default="results/incidents",
        help="Directory containing INC_*/verifier_output*.json subfolders.",
    )
    parser.add_argument(
        "--summary-json",
        default="results/analysis/summary.json",
        help="Path to aggregated JSON summary output.",
    )
    parser.add_argument(
        "--export-csv",
        action="store_true",
        help="Also export derived CSVs (incidents/by_model/by_rule/pairwise).",
    )
    parser.add_argument(
        "--incidents-csv",
        default="results/analysis/incidents.csv",
        help="Path to incident-level metrics CSV.",
    )
    parser.add_argument(
        "--analysis-bundle-json",
        default="results/analysis/analysis_bundle.json",
        help="Path to canonical typed JSON for analytics consumption.",
    )
    parser.add_argument(
        "--eval-protocol-version",
        default="official",
        help="Evaluation state label used to generate this bundle.",
    )
    parser.add_argument(
        "--by-model-csv",
        default="results/analysis/by_model.csv",
        help="Path to model-level aggregated CSV.",
    )
    parser.add_argument(
        "--by-rule-csv",
        default="results/analysis/by_rule.csv",
        help="Path to rule-by-model aggregated CSV.",
    )
    parser.add_argument(
        "--pairwise-csv",
        default="results/analysis/model_pairwise.csv",
        help="Path to pairwise model statistical comparison CSV.",
    )
    parser.add_argument(
        "--by-rule-treatment-csv",
        default="results/analysis/by_rule_treatment.csv",
        help="Path to per-rule treatment-effect CSV for llm_zero vs llm_policy_prompt.",
    )
    parser.add_argument(
        "--incidents",
        default=None,
        help="Optional CSV incident filter. Example: INC_001,INC_002",
    )
    parser.add_argument(
        "--canonical-only",
        action="store_true",
        help=(
            "Analyze only canonical verifier_output.json per incident, "
            "ignoring versioned histories."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    outputs_incidents_dir = Path(args.outputs_incidents_dir).resolve()
    summary_json = Path(args.summary_json).resolve()
    incidents_csv = Path(args.incidents_csv).resolve()
    analysis_bundle_json = Path(args.analysis_bundle_json).resolve()
    by_model_csv = Path(args.by_model_csv).resolve()
    by_rule_csv = Path(args.by_rule_csv).resolve()
    by_rule_treatment_csv = Path(args.by_rule_treatment_csv).resolve()
    pairwise_csv = Path(args.pairwise_csv).resolve()
    incident_filter = _parse_incident_filter(args.incidents)

    (
        summary,
        rows,
        by_model_rows,
        by_rule_rows,
        by_rule_treatment_rows,
        pairwise_rows,
    ) = analyze_incident_outputs_full(
        outputs_incidents_dir,
        incident_filter,
        canonical_only=bool(args.canonical_only),
    )
    _write_summary_json(summary_json, summary)
    bundle = _build_analysis_bundle(
        AnalysisBundleInput(
            eval_protocol_version=str(args.eval_protocol_version),
            repo_root=Path.cwd().resolve(),
            outputs_incidents_dir=outputs_incidents_dir,
            incident_filter=incident_filter,
            summary=summary,
            rows=rows,
            by_model_rows=by_model_rows,
            by_rule_rows=by_rule_rows,
            by_rule_treatment_rows=by_rule_treatment_rows,
            pairwise_rows=pairwise_rows,
        )
    )
    _write_bundle_json(analysis_bundle_json, bundle)
    if args.export_csv:
        _write_rows_csv(incidents_csv, rows)
        _write_rows_csv(by_model_csv, by_model_rows)
        _write_rows_csv(
            by_rule_csv,
            by_rule_rows,
            fieldnames=[
                "model_label",
                "rule_id",
                "violation_count",
                "hard_violation_count",
            ],
        )
        _write_rows_csv(
            by_rule_treatment_csv,
            by_rule_treatment_rows,
            fieldnames=[
                "rule_id",
                "model",
                "llm_zero_run_count",
                "llm_policy_prompt_run_count",
                "llm_zero_violation_count",
                "llm_policy_prompt_violation_count",
                "llm_zero_violation_rate",
                "llm_policy_prompt_violation_rate",
                "violation_rate_diff_zero_minus_policy",
            ],
        )
        _write_rows_csv(
            pairwise_csv,
            pairwise_rows,
            fieldnames=[
                "model_a",
                "model_b",
                "paired_incident_count",
                "run_count_a",
                "run_count_b",
                "violation_rate_a",
                "violation_rate_b",
                "rate_diff_a_minus_b",
                "z_score",
                "p_value_two_sided",
                "p_value_holm",
                "cohens_h",
                "cliffs_delta",
                "mcnemar_b_count",
                "mcnemar_c_count",
                "mcnemar_chi2",
                "mcnemar_p_value_two_sided",
                "mcnemar_p_value_holm",
            ],
        )

    print(f"Summary saved at: {summary_json}")
    print(f"Typed analysis bundle saved at: {analysis_bundle_json}")
    if args.export_csv:
        print(f"Incident CSV saved at: {incidents_csv}")
        print(f"Model CSV saved at: {by_model_csv}")
        print(f"Rule CSV saved at: {by_rule_csv}")
        print(f"Rule treatment CSV saved at: {by_rule_treatment_csv}")
        print(f"Pairwise model CSV saved at: {pairwise_csv}")
    print(
        "Incidents analyzed: "
        f"{summary['incident_count']} | "
        f"Incident violation rate: {summary['incident_violation_rate']:.2%}"
    )


if __name__ == "__main__":
    main()
