#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
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
    return value.replace("\\", "\\textbackslash{}").replace("_", "\\_")


def _macro(name: str, value: str) -> str:
    return f"\\newcommand{{\\{name}}}{{{value}}}"


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must be a JSON object")
    return payload


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _has_llm_arm_rows(by_model_rows: list[dict[str, Any]]) -> bool:
    for row in by_model_rows:
        model_label = str(row.get("model_label", "")).strip()
        if "|llm_zero" in model_label or "|llm_policy_prompt" in model_label:
            return True
    return False


def _load_llm_fallback_bundle(
    path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    payload = _read_json(path)
    summary = payload.get("summary")
    by_model = payload.get("by_model")
    by_rule_treatment = payload.get("by_rule_treatment")
    if not isinstance(summary, dict):
        raise ValueError(f"{path} missing object field 'summary'")
    if not isinstance(by_model, list):
        raise ValueError(f"{path} missing list field 'by_model'")
    if not isinstance(by_rule_treatment, list):
        raise ValueError(f"{path} missing list field 'by_rule_treatment'")
    return summary, by_model, by_rule_treatment


def _load_gate_bundle(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = _read_json(path)
    summary = payload.get("summary")
    experiment = payload.get("experiment")
    if not isinstance(summary, dict):
        raise ValueError(f"{path} missing object field 'summary'")
    if not isinstance(experiment, dict):
        raise ValueError(f"{path} missing object field 'experiment'")
    return summary, experiment


def _count_incident_privacy_issues(
    dataset_audit: dict[str, Any],
    incident_id: str,
) -> int:
    issues = dataset_audit.get("privacy_issues", [])
    if not isinstance(issues, list):
        return 0

    count = 0
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        issue_incident_id = str(issue.get("incident_id", "")).strip()
        issue_path = str(issue.get("path", "")).strip()
        if issue_incident_id == incident_id or incident_id in issue_path:
            count += 1
    return count


def _count_jsonl_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def _resolve_incident_dir(paths_root: Path, first_incident_id: str) -> Path:
    incident_dir = paths_root / "dataset" / "incidents" / first_incident_id
    if incident_dir.exists():
        return incident_dir

    candidates = sorted((paths_root / "dataset" / "incidents").glob("INC_*"))
    if candidates:
        return candidates[0]
    raise FileNotFoundError("No incident directories found in dataset/incidents")


def _pick_summary_row(
    by_model_rows: list[dict[str, str]],
    suffix: str,
) -> tuple[int, int]:
    run_count_total = 0
    runs_with_violations_total = 0
    for row in by_model_rows:
        model_label = str(row.get("model_label", ""))
        if not model_label.endswith(suffix):
            continue
        run_count_total += _safe_int(row.get("run_count"))
        runs_with_violations_total += _safe_int(row.get("runs_with_violations"))
    return run_count_total, runs_with_violations_total


def _llm_total_run_count(by_model_rows: list[dict[str, Any]]) -> int:
    zero_runs, _ = _pick_summary_row(by_model_rows, "|llm_zero")
    policy_runs, _ = _pick_summary_row(by_model_rows, "|llm_policy_prompt")
    return zero_runs + policy_runs


def _wilson_interval(successes: int, total: int) -> tuple[float, float]:
    if total <= 0:
        return 0.0, 0.0
    z = 1.959963984540054  # 95% CI
    p = successes / total
    denom = 1.0 + (z**2) / total
    center = (p + (z**2) / (2 * total)) / denom
    margin = (
        z
        * math.sqrt((p * (1 - p) / total) + (z**2) / (4 * (total**2)))
        / denom
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def _aggregate_arm_metrics(
    by_model_rows: list[dict[str, str]],
    suffix: str,
) -> dict[str, float]:
    matched_rows = [
        row
        for row in by_model_rows
        if str(row.get("model_label", "")).endswith(suffix)
    ]
    return _aggregate_row_metrics(matched_rows)


def _find_model_row(
    by_model_rows: list[dict[str, Any]],
    model_label: str,
) -> dict[str, Any]:
    for row in by_model_rows:
        if str(row.get("model_label", "")).strip() == model_label:
            return row
    return {}


def _aggregate_row_metrics(rows: list[dict[str, str]]) -> dict[str, float]:
    run_count = 0
    runs_with_violations = 0
    hard_violation_count = 0
    enforcement_modified_runs = 0
    llm_cost_usd_total = 0.0
    llm_total_tokens = 0

    for row in rows:
        run_count += _safe_int(row.get("run_count"))
        runs_with_violations += _safe_int(row.get("runs_with_violations"))
        hard_violation_count += _safe_int(row.get("hard_violation_count"))
        enforcement_modified_runs += _safe_int(row.get("enforcement_modified_run_count"))
        llm_cost_usd_total += _safe_float(row.get("llm_cost_estimated_usd_total"))
        llm_total_tokens += _safe_int(row.get("llm_total_tokens_total"))

    violation_rate = (runs_with_violations / run_count) if run_count > 0 else 0.0
    ci_low, ci_high = _wilson_interval(runs_with_violations, run_count)
    enforcement_mod_rate = (
        enforcement_modified_runs / run_count if run_count > 0 else 0.0
    )
    return {
        "run_count": float(run_count),
        "runs_with_violations": float(runs_with_violations),
        "hard_violation_count": float(hard_violation_count),
        "violation_rate": violation_rate,
        "violation_ci_low": ci_low,
        "violation_ci_high": ci_high,
        "enforcement_mod_rate": enforcement_mod_rate,
        "llm_cost_usd_total": llm_cost_usd_total,
        "llm_total_tokens": float(llm_total_tokens),
    }


def _aggregate_human_metrics(by_model_rows: list[dict[str, str]]) -> dict[str, float]:
    # Prefer canonical human baseline label first.
    human_rows = [
        row for row in by_model_rows if str(row.get("model_label", "")).strip() == "human"
    ]
    if human_rows:
        return _aggregate_row_metrics(human_rows)

    # Fallback for alternate approval-policy labels, e.g. human|defer_to_human_approval.
    fallback_rows = [
        row
        for row in by_model_rows
        if str(row.get("model_label", "")).strip().startswith("human|")
    ]
    return _aggregate_row_metrics(fallback_rows)


def _aggregate_r3_delta(by_rule_treatment_rows: list[dict[str, str]]) -> float:
    zero_runs = 0
    zero_violations = 0
    policy_runs = 0
    policy_violations = 0

    for row in by_rule_treatment_rows:
        if str(row.get("rule_id", "")).strip() != "R3":
            continue
        zero_runs += _safe_int(row.get("llm_zero_run_count"))
        zero_violations += _safe_int(row.get("llm_zero_violation_count"))
        policy_runs += _safe_int(row.get("llm_policy_prompt_run_count"))
        policy_violations += _safe_int(row.get("llm_policy_prompt_violation_count"))

    zero_rate = (zero_violations / zero_runs) if zero_runs > 0 else 0.0
    policy_rate = (policy_violations / policy_runs) if policy_runs > 0 else 0.0
    return zero_rate - policy_rate


def _observed_rule_ids(by_rule_treatment_rows: list[dict[str, str]]) -> list[str]:
    rules: set[str] = set()
    for row in by_rule_treatment_rows:
        rule_id = str(row.get("rule_id", "")).strip()
        if rule_id:
            rules.add(rule_id)
    return sorted(rules)


def build_values_tex(
    summary: dict[str, Any],
    by_model_rows: list[dict[str, str]],
    by_rule_treatment_rows: list[dict[str, str]],
    dataset_audit: dict[str, Any],
    incident_id: str,
    incident_dir: Path,
    llm_fallback_bundle: Path | None = None,
    gate_bundle: Path | None = None,
) -> str:
    conversion_quality = _read_json(incident_dir / "evidence" / "conversion_quality.json")
    source_manifest = _read_json(incident_dir / "evidence" / "source_manifest.json")
    anon = source_manifest.get("anonymization_summary", {})
    first_incident_privacy_issue_count = _count_incident_privacy_issues(
        dataset_audit=dataset_audit,
        incident_id=incident_id,
    )

    llm_summary = summary
    llm_by_model_rows: list[dict[str, Any]] = by_model_rows
    llm_by_rule_treatment_rows: list[dict[str, Any]] = by_rule_treatment_rows
    if llm_fallback_bundle is not None and llm_fallback_bundle.exists():
        fallback_summary, fallback_by_model, fallback_by_rule_treatment = (
            _load_llm_fallback_bundle(llm_fallback_bundle)
        )
        current_has_llm = _has_llm_arm_rows(by_model_rows)
        fallback_has_llm = _has_llm_arm_rows(fallback_by_model)
        if fallback_has_llm:
            current_llm_runs = _llm_total_run_count(by_model_rows) if current_has_llm else 0
            fallback_llm_runs = _llm_total_run_count(fallback_by_model)
            should_use_fallback = (not current_has_llm) or (
                fallback_llm_runs > current_llm_runs
            )
        else:
            should_use_fallback = False

        if should_use_fallback:
            llm_summary = fallback_summary
            llm_by_model_rows = fallback_by_model
            llm_by_rule_treatment_rows = fallback_by_rule_treatment

    zero_runs, zero_violations = _pick_summary_row(llm_by_model_rows, "|llm_zero")
    policy_runs, policy_violations = _pick_summary_row(
        llm_by_model_rows,
        "|llm_policy_prompt",
    )
    zero_rate = (zero_violations / zero_runs) if zero_runs > 0 else 0.0
    policy_rate = (policy_violations / policy_runs) if policy_runs > 0 else 0.0
    r3_delta = _aggregate_r3_delta(llm_by_rule_treatment_rows)
    observed_rules = _observed_rule_ids(llm_by_rule_treatment_rows)
    observed_rules_tex = ", ".join(_tex_escape(r) for r in observed_rules) or "none"
    zero_metrics = _aggregate_arm_metrics(llm_by_model_rows, "|llm_zero")
    policy_metrics = _aggregate_arm_metrics(llm_by_model_rows, "|llm_policy_prompt")
    human_metrics = _aggregate_human_metrics(by_model_rows)
    pilot_total_cost = _safe_float(llm_summary.get("llm_cost_estimated_usd_total"))
    pilot_total_tokens = _safe_int(llm_summary.get("llm_total_tokens_total"))

    gate_summary: dict[str, Any] = {}
    gate_experiment: dict[str, Any] = {}
    if gate_bundle is not None and gate_bundle.exists():
        gate_summary, gate_experiment = _load_gate_bundle(gate_bundle)

    gate_coverage = gate_experiment.get("coverage", {})
    if not isinstance(gate_coverage, dict):
        gate_coverage = {}

    gate_incident_count = _safe_int(gate_summary.get("incident_count"))
    gate_model_count = _safe_int(
        gate_coverage.get("selected_model_count") or gate_coverage.get("planned_model_count"),
    )
    gate_arm_count = _safe_int(gate_coverage.get("planned_arm_count"))
    gate_llm_trajectory_count = _safe_int(
        (gate_summary.get("mode_counts") or {}).get("LLM")
        if isinstance(gate_summary.get("mode_counts"), dict)
        else 0,
    )
    gate_llm_trajectory_success_count = _safe_int(gate_coverage.get("successful_run_count"))
    gate_preflight_failure_count = _safe_int(gate_coverage.get("preflight_failure_count"))
    gate_execution_failure_count = _safe_int(gate_coverage.get("execution_failure_count"))
    gate_runs_per_row = 0
    if gate_model_count > 0 and gate_arm_count > 0:
        gate_runs_per_row = gate_llm_trajectory_count // (gate_model_count * gate_arm_count)
    if gate_runs_per_row <= 0:
        gate_runs_per_row = gate_incident_count

    gate_llm_total_tokens = _safe_int(gate_summary.get("llm_total_tokens_total"))
    gate_llm_cost_usd_total = _safe_float(gate_summary.get("llm_cost_estimated_usd_total"))

    planned_campaign_incidents = gate_incident_count if gate_incident_count > 0 else 50
    planned_campaign_model_count = 2
    planned_campaign_arm_count = 2
    gate_campaign_projected_llm_trajectories = (
        planned_campaign_incidents
        * planned_campaign_model_count
        * planned_campaign_arm_count
        if gate_incident_count > 0
        else 0
    )
    gate_campaign_projected_human_trajectories = (
        planned_campaign_incidents if gate_incident_count > 0 else 0
    )
    gate_tokens_per_llm_trajectory = (
        gate_llm_total_tokens / gate_llm_trajectory_count
        if gate_llm_trajectory_count > 0
        else 0.0
    )
    gate_cost_per_llm_trajectory = (
        gate_llm_cost_usd_total / gate_llm_trajectory_count
        if gate_llm_trajectory_count > 0
        else 0.0
    )
    gate_campaign_projected_tokens = int(
        round(gate_tokens_per_llm_trajectory * gate_campaign_projected_llm_trajectories),
    )
    gate_campaign_projected_cost_usd = (
        gate_cost_per_llm_trajectory * gate_campaign_projected_llm_trajectories
    )
    gate_campaign_projected_tokens_conservative = int(
        round(gate_campaign_projected_tokens * 1.5),
    )
    gate_campaign_projected_cost_usd_conservative = gate_campaign_projected_cost_usd * 1.5
    llm_only_actions = gate_summary.get("llm_only_actions") or {}
    human_only_actions = gate_summary.get("human_only_actions") or {}

    claude_zero_row = _find_model_row(llm_by_model_rows, "claude-sonnet-4-6|llm_zero")
    claude_policy_row = _find_model_row(
        llm_by_model_rows,
        "claude-sonnet-4-6|llm_policy_prompt",
    )
    gpt_zero_row = _find_model_row(llm_by_model_rows, "gpt-5.2|llm_zero")
    gpt_policy_row = _find_model_row(llm_by_model_rows, "gpt-5.2|llm_policy_prompt")

    lines = [
        _macro("ValFirstIncidentId", _tex_escape(incident_id)),
        _macro("ValTaskCount", str(_safe_int(conversion_quality.get("task_count")))),
        _macro(
            "ValMappedTaskCount",
            str(_safe_int(conversion_quality.get("mapped_task_count"))),
        ),
        _macro(
            "ValUnmatchedTaskCount",
            str(_safe_int(conversion_quality.get("unmatched_task_count"))),
        ),
        _macro(
            "ValMappingCoverage",
            f"{_safe_float(conversion_quality.get('mapping_coverage')):.4f}",
        ),
        _macro(
            "ValTelemetryEvents",
            str(_count_jsonl_lines(incident_dir / "incident_telemetry.jsonl")),
        ),
        _macro(
            "ValActionCount",
            str(_safe_int(conversion_quality.get("deduplicated_action_count"))),
        ),
        _macro(
            "ValFirstIncidentPrivacyIssueCount",
            str(first_incident_privacy_issue_count),
        ),
        # Backward-compatible alias kept for templates that still reference this name.
        _macro("ValPrivacyIssueCount", str(first_incident_privacy_issue_count)),
        _macro("ValAnonEmailTokens", str(_safe_int(anon.get("email_tokens")))),
        _macro("ValAnonIpTokens", str(_safe_int(anon.get("ip_tokens")))),
        _macro("ValAnonPhoneTokens", str(_safe_int(anon.get("phone_tokens")))),
        _macro("ValAnonHostTokens", str(_safe_int(anon.get("host_tokens")))),
        _macro("ValAnonUserTokens", str(_safe_int(anon.get("user_tokens")))),
        _macro("ValPilotIncidentCount", str(_safe_int(llm_summary.get("incident_count")))),
        _macro("ValPilotLlmZeroViolationRate", f"{zero_rate:.4f}"),
        _macro("ValPilotLlmPolicyViolationRate", f"{policy_rate:.4f}"),
        _macro("ValPilotRuleRThreeDelta", f"{r3_delta:.4f}"),
        _macro(
            "ValPilotLlmHallucinatedTotal",
            str(_safe_int(llm_summary.get("llm_hallucinated_action_count_total"))),
        ),
        _macro("ValPilotLlmZeroRunCount", str(int(zero_metrics["run_count"]))),
        _macro(
            "ValPilotLlmZeroRunsWithViolations",
            str(int(zero_metrics["runs_with_violations"])),
        ),
        _macro(
            "ValPilotLlmZeroHardViolationCount",
            str(int(zero_metrics["hard_violation_count"])),
        ),
        _macro(
            "ValPilotLlmZeroViolationCiLow",
            f"{zero_metrics['violation_ci_low']:.4f}",
        ),
        _macro(
            "ValPilotLlmZeroViolationCiHigh",
            f"{zero_metrics['violation_ci_high']:.4f}",
        ),
        _macro(
            "ValPilotLlmZeroEnforcementModRate",
            f"{zero_metrics['enforcement_mod_rate']:.4f}",
        ),
        _macro(
            "ValPilotLlmZeroCostUsdTotal",
            f"{zero_metrics['llm_cost_usd_total']:.6f}",
        ),
        _macro(
            "ValPilotLlmZeroTotalTokens",
            str(int(zero_metrics["llm_total_tokens"])),
        ),
        _macro("ValPilotLlmPolicyRunCount", str(int(policy_metrics["run_count"]))),
        _macro(
            "ValPilotLlmPolicyRunsWithViolations",
            str(int(policy_metrics["runs_with_violations"])),
        ),
        _macro(
            "ValPilotLlmPolicyHardViolationCount",
            str(int(policy_metrics["hard_violation_count"])),
        ),
        _macro(
            "ValPilotLlmPolicyViolationCiLow",
            f"{policy_metrics['violation_ci_low']:.4f}",
        ),
        _macro(
            "ValPilotLlmPolicyViolationCiHigh",
            f"{policy_metrics['violation_ci_high']:.4f}",
        ),
        _macro(
            "ValPilotLlmPolicyEnforcementModRate",
            f"{policy_metrics['enforcement_mod_rate']:.4f}",
        ),
        _macro(
            "ValPilotLlmPolicyCostUsdTotal",
            f"{policy_metrics['llm_cost_usd_total']:.6f}",
        ),
        _macro(
            "ValPilotLlmPolicyTotalTokens",
            str(int(policy_metrics["llm_total_tokens"])),
        ),
        _macro("ValPilotHumanRunCount", str(int(human_metrics["run_count"]))),
        _macro(
            "ValPilotHumanRunsWithViolations",
            str(int(human_metrics["runs_with_violations"])),
        ),
        _macro(
            "ValPilotHumanHardViolationCount",
            str(int(human_metrics["hard_violation_count"])),
        ),
        _macro("ValPilotHumanViolationRate", f"{human_metrics['violation_rate']:.4f}"),
        _macro(
            "ValPilotHumanViolationCiLow",
            f"{human_metrics['violation_ci_low']:.4f}",
        ),
        _macro(
            "ValPilotHumanViolationCiHigh",
            f"{human_metrics['violation_ci_high']:.4f}",
        ),
        _macro(
            "ValPilotHumanEnforcementModRate",
            f"{human_metrics['enforcement_mod_rate']:.4f}",
        ),
        _macro("ValPilotLlmCostUsdTotal", f"{pilot_total_cost:.6f}"),
        _macro("ValPilotLlmTotalTokens", str(pilot_total_tokens)),
        _macro("ValPilotObservedRuleCount", str(len(observed_rules))),
        _macro("ValPilotObservedRuleIds", observed_rules_tex),
        _macro("ValGateIncidentCount", str(gate_incident_count)),
        _macro("ValGateModelCount", str(gate_model_count)),
        _macro("ValGateArmCount", str(gate_arm_count)),
        _macro("ValCampaignModelCount", str(planned_campaign_model_count)),
        _macro("ValCampaignArmCount", str(planned_campaign_arm_count)),
        _macro("ValGateHumanBaselineCount", str(gate_incident_count)),
        _macro("ValGateLlmTrajectoryCount", str(gate_llm_trajectory_count)),
        _macro(
            "ValGateLlmTrajectorySuccessCount",
            str(gate_llm_trajectory_success_count),
        ),
        _macro("ValGatePreflightFailureCount", str(gate_preflight_failure_count)),
        _macro("ValGateExecutionFailureCount", str(gate_execution_failure_count)),
        _macro("ValGateRunsPerRow", str(gate_runs_per_row)),
        _macro("ValGateLlmTotalTokens", str(gate_llm_total_tokens)),
        _macro("ValGateLlmCostUsdTotal", f"{gate_llm_cost_usd_total:.4f}"),
        _macro(
            "ValGateCampaignProjectedLlmTrajectories",
            str(gate_campaign_projected_llm_trajectories),
        ),
        _macro(
            "ValGateCampaignProjectedHumanTrajectories",
            str(gate_campaign_projected_human_trajectories),
        ),
        _macro(
            "ValGateCampaignProjectedTokens",
            str(gate_campaign_projected_tokens),
        ),
        _macro(
            "ValGateCampaignProjectedCostUsd",
            f"{gate_campaign_projected_cost_usd:.4f}",
        ),
        _macro(
            "ValGateCampaignProjectedTokensConservative",
            str(gate_campaign_projected_tokens_conservative),
        ),
        _macro(
            "ValGateCampaignProjectedCostUsdConservative",
            f"{gate_campaign_projected_cost_usd_conservative:.4f}",
        ),
        _macro(
            "ValOfficialClaudeZeroViolationRate",
            f"{_safe_float(claude_zero_row.get('run_violation_rate')):.4f}",
        ),
        _macro(
            "ValOfficialClaudePolicyViolationRate",
            f"{_safe_float(claude_policy_row.get('run_violation_rate')):.4f}",
        ),
        _macro(
            "ValOfficialGptZeroViolationRate",
            f"{_safe_float(gpt_zero_row.get('run_violation_rate')):.4f}",
        ),
        _macro(
            "ValOfficialGptPolicyViolationRate",
            f"{_safe_float(gpt_policy_row.get('run_violation_rate')):.4f}",
        ),
        _macro(
            "ValOfficialClaudeZeroDeltaJaccard",
            f"{_safe_float(claude_zero_row.get('delta_jaccard_avg')):.4f}",
        ),
        _macro(
            "ValOfficialClaudePolicyDeltaJaccard",
            f"{_safe_float(claude_policy_row.get('delta_jaccard_avg')):.4f}",
        ),
        _macro(
            "ValOfficialGptZeroDeltaJaccard",
            f"{_safe_float(gpt_zero_row.get('delta_jaccard_avg')):.4f}",
        ),
        _macro(
            "ValOfficialGptPolicyDeltaJaccard",
            f"{_safe_float(gpt_policy_row.get('delta_jaccard_avg')):.4f}",
        ),
        _macro(
            "ValOfficialEnforcementModificationRate",
            f"{_safe_float(gate_summary.get('enforcement_modification_rate')):.4f}",
        ),
        _macro(
            "ValOfficialTaskCoverageDropRate",
            f"{_safe_float(gate_summary.get('task_coverage_drop_rate')):.4f}",
        ),
        _macro(
            "ValOfficialViolationCountRThree",
            str(_safe_int((gate_summary.get("violations_by_rule") or {}).get("R3"))),
        ),
        _macro(
            "ValOfficialViolationCountRFour",
            str(_safe_int((gate_summary.get("violations_by_rule") or {}).get("R4"))),
        ),
        _macro(
            "ValOfficialOutOfCatalogCount",
            str(_safe_int(gate_summary.get("llm_hallucinated_action_count_total"))),
        ),
        _macro(
            "ValOfficialLlmOnlyRestoreHostCount",
            str(_safe_int(llm_only_actions.get("restore_host"))),
        ),
        _macro(
            "ValOfficialLlmOnlyBlockEgressCount",
            str(_safe_int(llm_only_actions.get("block_egress_ip"))),
        ),
        _macro(
            "ValOfficialHumanOnlyResetAdminCount",
            str(_safe_int(human_only_actions.get("reset_admin_credentials"))),
        ),
        _macro(
            "ValOfficialHumanOnlyIsolateHostCount",
            str(_safe_int(human_only_actions.get("isolate_host"))),
        ),
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--by-model-csv", required=True)
    parser.add_argument("--by-rule-treatment-csv", required=True)
    parser.add_argument("--dataset-audit-json", required=True)
    parser.add_argument("--output-tex", required=True)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--first-incident-id", default="INC_BANK_606407")
    parser.add_argument("--llm-fallback-bundle", default=None)
    parser.add_argument("--gate-bundle", default=None)
    args = parser.parse_args()

    repo_root = Path(args.repo_root).expanduser().resolve()
    incident_dir = _resolve_incident_dir(repo_root, args.first_incident_id)
    incident_id = incident_dir.name

    summary = _read_json(Path(args.summary_json).expanduser().resolve())
    dataset_audit = _read_json(Path(args.dataset_audit_json).expanduser().resolve())
    by_model_rows = _read_csv(Path(args.by_model_csv).expanduser().resolve())
    by_rule_treatment_rows = _read_csv(
        Path(args.by_rule_treatment_csv).expanduser().resolve(),
    )
    llm_fallback_bundle = (
        Path(args.llm_fallback_bundle).expanduser().resolve()
        if args.llm_fallback_bundle
        else None
    )
    gate_bundle = (
        Path(args.gate_bundle).expanduser().resolve()
        if args.gate_bundle
        else None
    )

    tex = build_values_tex(
        summary=summary,
        by_model_rows=by_model_rows,
        by_rule_treatment_rows=by_rule_treatment_rows,
        dataset_audit=dataset_audit,
        incident_id=incident_id,
        incident_dir=incident_dir,
        llm_fallback_bundle=llm_fallback_bundle,
        gate_bundle=gate_bundle,
    )
    output_path = Path(args.output_tex).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(tex, encoding="utf-8")
    print(f"Saved TeX macros at: {output_path}")


if __name__ == "__main__":
    main()
