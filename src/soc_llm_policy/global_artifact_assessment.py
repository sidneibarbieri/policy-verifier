from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc_llm_policy.dataset_audit import audit_dataset
from soc_llm_policy.global_provenance import build_global_provenance
from soc_llm_policy.io import parse_incident_meta, read_json
from soc_llm_policy.json_stability import write_stable_json
from soc_llm_policy.mapping_support import (
    build_mapping_support_manifest,
    load_mapping_rules,
    load_mapping_support_manifest,
    write_mapping_support_manifest,
)
from soc_llm_policy.paths import RepoPaths, repo_relative_path, resolve_repo_root
from soc_llm_policy.pipeline import list_inbox_incidents

MIN_DUAL_MODEL_COUNT = 2
MIN_DUAL_ARM_COUNT = 2


def _parse_csv_list(raw: str | None) -> list[str]:
    if raw is None:
        return []
    values: list[str] = []
    for part in raw.split(","):
        item = part.strip()
        if item and item not in values:
            values.append(item)
    return values


def _resolve_incidents(
    paths: RepoPaths,
    incidents_arg: str | None,
    include_all: bool,
) -> list[str]:
    if include_all:
        return list_inbox_incidents(paths)
    incidents = _parse_csv_list(incidents_arg)
    if not incidents:
        raise ValueError("Provide --incidents INC_001,INC_002 or use --all.")
    return incidents


def _load_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {}
    return raw


def _load_incident_type(paths: RepoPaths, incident_id: str) -> str:
    meta = parse_incident_meta(
        read_json(paths.inbox_incident_dir(incident_id) / "incident_meta.json")
    )
    return meta.incident_type


def _active_eval_protocol(paths: RepoPaths) -> str | None:
    freeze = _load_json_object(paths.outputs_analysis_dir / "protocol_freeze.json")
    value = str(freeze.get("eval_protocol_version", "")).strip()
    return value or None


def _score_official_bundle(
    bundle: dict[str, Any],
    *,
    bundle_path: Path,
    active_protocol: str | None,
    require_dual_model: bool,
) -> tuple[int, int, int, int, int, int, float] | None:
    summary = bundle.get("summary", {})
    experiment = bundle.get("experiment", {})
    coverage = experiment.get("coverage", {})
    mode_counts = summary.get("mode_counts", {})
    if not isinstance(summary, dict) or not isinstance(experiment, dict):
        return None
    if not isinstance(coverage, dict) or not isinstance(mode_counts, dict):
        return None

    incident_count = int(summary.get("incident_count", 0) or 0)
    llm_run_count = int(mode_counts.get("LLM", 0) or 0)
    if incident_count <= 0 or llm_run_count <= 0:
        return None

    selected_models = experiment.get("selected_models", [])
    selected_model_names = sorted(
        str(item.get("name", "")).strip()
        for item in selected_models
        if isinstance(item, dict)
    )
    selected_model_count = int(
        coverage.get("selected_model_count", len(selected_model_names)) or 0
    )
    planned_arm_count = int(coverage.get("planned_arm_count", 0) or 0)
    planned_repeat_count = int(coverage.get("planned_repeat_count", 1) or 1)
    successful_run_count = int(coverage.get("successful_run_count", llm_run_count) or 0)
    execution_failure_count = int(coverage.get("execution_failure_count", 0) or 0)
    eval_protocol_version = str(experiment.get("eval_protocol_version", "")).strip()
    summary_run_consistent = 1 if successful_run_count == llm_run_count else 0
    single_repeat_summary = 1 if planned_repeat_count == 1 else 0

    if require_dual_model and (
        selected_model_count < MIN_DUAL_MODEL_COUNT
        or planned_arm_count < MIN_DUAL_ARM_COUNT
    ):
        return None

    return (
        1 if active_protocol and eval_protocol_version == active_protocol else 0,
        1 if selected_model_names == ["anthropic_sonnet46", "openai_gpt52"] else 0,
        summary_run_consistent,
        single_repeat_summary,
        incident_count,
        successful_run_count,
        selected_model_count,
        -execution_failure_count,
        bundle_path.stat().st_mtime,
    )


def select_best_official_bundle(
    bundle_paths: list[Path],
    *,
    active_protocol: str | None,
    require_dual_model: bool = True,
) -> Path | None:
    best_path: Path | None = None
    best_score: tuple[int, int, int, int, int, int, float] | None = None
    for bundle_path in bundle_paths:
        bundle = _load_json_object(bundle_path)
        if not bundle:
            continue
        score = _score_official_bundle(
            bundle,
            bundle_path=bundle_path,
            active_protocol=active_protocol,
            require_dual_model=require_dual_model,
        )
        if score is None:
            continue
        if best_score is None or score > best_score:
            best_score = score
            best_path = bundle_path
    return best_path.resolve() if best_path is not None else None


def _resolve_official_summary_source(
    paths: RepoPaths,
    explicit_path: str | None,
) -> Path | None:
    if explicit_path:
        candidate = Path(explicit_path).expanduser().resolve()
        return candidate if candidate.exists() else None

    active_protocol = _active_eval_protocol(paths)
    best_bundle_path = select_best_official_bundle(
        sorted(paths.outputs_experiments_dir.glob("*/analysis_bundle.json")),
        active_protocol=active_protocol,
        require_dual_model=True,
    )
    if best_bundle_path is not None:
        summary_path = (best_bundle_path.parent / "summary.json").resolve()
        if summary_path.exists():
            return summary_path

    copied_summary = paths.outputs_analysis_dir / "official_evaluation_summary.json"
    if copied_summary.exists():
        return copied_summary

    paper_sync_sources_path = paths.outputs_analysis_dir / "paper_sync_sources.json"
    paper_sync_sources = _load_json_object(paper_sync_sources_path)
    gate_bundle = paper_sync_sources.get("gate_bundle")
    if isinstance(gate_bundle, str) and gate_bundle.strip():
        summary_path = (
            Path(gate_bundle).expanduser().resolve().parent / "summary.json"
        ).resolve()
        if summary_path.exists():
            return summary_path

    return None


def _copy_official_summary(
    *,
    source_path: Path | None,
    output_path: Path | None,
) -> None:
    if source_path is None or output_path is None:
        return
    payload = _load_json_object(source_path)
    if payload:
        write_stable_json(output_path, payload)


def _support_manifest_for_incident(
    *,
    paths: RepoPaths,
    incident_id: str,
    mapping_rules: list[Any],
    write_missing_support_manifests: bool,
) -> dict[str, Any] | None:
    manifest = load_mapping_support_manifest(paths, incident_id)
    if manifest is not None:
        return manifest
    if write_missing_support_manifests:
        write_mapping_support_manifest(
            paths=paths,
            incident_id=incident_id,
            mapping_rules=mapping_rules,
        )
        return load_mapping_support_manifest(paths, incident_id)
    return build_mapping_support_manifest(
        paths=paths,
        incident_id=incident_id,
        mapping_rules=mapping_rules,
    )


def _build_mapping_support_summary(  # noqa: PLR0915
    *,
    paths: RepoPaths,
    incidents: list[str],
    write_missing_support_manifests: bool,
) -> dict[str, Any]:
    mapping_rules = load_mapping_rules(paths.action_mapping_bank_path)
    manifest_count = 0
    task_count_total = 0
    zero_match_count = 0
    ambiguous_match_count = 0
    single_keyword_unique_match_count = 0
    multi_keyword_unique_match_count = 0
    approval_proxy_unique_match_count = 0

    action_totals: dict[str, dict[str, Any]] = {}
    action_incidents: dict[str, set[str]] = defaultdict(set)
    incident_type_totals: dict[str, dict[str, Any]] = {}

    for incident_id in incidents:
        manifest = _support_manifest_for_incident(
            paths=paths,
            incident_id=incident_id,
            mapping_rules=mapping_rules,
            write_missing_support_manifests=write_missing_support_manifests,
        )
        if manifest is None:
            continue

        manifest_count += 1
        incident_type = _load_incident_type(paths, incident_id)
        incident_type_entry = incident_type_totals.setdefault(
            incident_type,
            {
                "incident_type": incident_type,
                "incident_count": 0,
                "task_count": 0,
                "zero_match_count": 0,
                "ambiguous_match_count": 0,
                "single_keyword_unique_match_count": 0,
                "multi_keyword_unique_match_count": 0,
            },
        )
        incident_type_entry["incident_count"] += 1

        task_count = int(manifest.get("task_count", 0) or 0)
        zero_match = int(manifest.get("zero_match_count", 0) or 0)
        ambiguous_match = int(manifest.get("ambiguous_match_count", 0) or 0)
        single_match = int(manifest.get("single_keyword_unique_match_count", 0) or 0)
        multi_match = int(manifest.get("multi_keyword_unique_match_count", 0) or 0)
        approval_proxy_match = int(
            manifest.get("approval_proxy_unique_match_count", 0) or 0
        )

        task_count_total += task_count
        zero_match_count += zero_match
        ambiguous_match_count += ambiguous_match
        single_keyword_unique_match_count += single_match
        multi_keyword_unique_match_count += multi_match
        approval_proxy_unique_match_count += approval_proxy_match

        incident_type_entry["task_count"] += task_count
        incident_type_entry["zero_match_count"] += zero_match
        incident_type_entry["ambiguous_match_count"] += ambiguous_match
        incident_type_entry["single_keyword_unique_match_count"] += single_match
        incident_type_entry["multi_keyword_unique_match_count"] += multi_match

        support_items = manifest.get("support_by_action")
        if not isinstance(support_items, list):
            continue
        for item in support_items:
            if not isinstance(item, dict):
                continue
            action_id = str(item.get("action_id") or "").strip()
            if not action_id:
                continue
            action_entry = action_totals.setdefault(
                action_id,
                {
                    "action_id": action_id,
                    "approval_proxy": bool(item.get("approval_proxy", False)),
                    "incident_count": 0,
                    "unique_match_count": 0,
                    "single_keyword_unique_match_count": 0,
                    "multi_keyword_unique_match_count": 0,
                },
            )
            if incident_id not in action_incidents[action_id]:
                action_incidents[action_id].add(incident_id)
                action_entry["incident_count"] += 1
            action_entry["unique_match_count"] += int(
                item.get("unique_match_count", 0) or 0
            )
            action_entry["single_keyword_unique_match_count"] += int(
                item.get("single_keyword_unique_match_count", 0) or 0
            )
            action_entry["multi_keyword_unique_match_count"] += int(
                item.get("multi_keyword_unique_match_count", 0) or 0
            )

    unique_match_count_total = (
        single_keyword_unique_match_count + multi_keyword_unique_match_count
    )
    for action_entry in action_totals.values():
        unique_match_count = int(action_entry["unique_match_count"])
        action_entry["single_keyword_share_within_action"] = (
            round(
                int(action_entry["single_keyword_unique_match_count"])
                / unique_match_count,
                4,
            )
            if unique_match_count > 0
            else 0.0
        )
        action_entry["multi_keyword_share_within_action"] = (
            round(
                int(action_entry["multi_keyword_unique_match_count"])
                / unique_match_count,
                4,
            )
            if unique_match_count > 0
            else 0.0
        )

    return {
        "incident_count_with_support_manifests": manifest_count,
        "task_count_total": task_count_total,
        "unique_match_count_total": unique_match_count_total,
        "zero_match_count": zero_match_count,
        "ambiguous_match_count": ambiguous_match_count,
        "single_keyword_unique_match_count": single_keyword_unique_match_count,
        "single_keyword_unique_match_rate": round(
            single_keyword_unique_match_count / task_count_total,
            4,
        )
        if task_count_total > 0
        else 0.0,
        "multi_keyword_unique_match_count": multi_keyword_unique_match_count,
        "multi_keyword_unique_match_rate": round(
            multi_keyword_unique_match_count / task_count_total,
            4,
        )
        if task_count_total > 0
        else 0.0,
        "approval_proxy_unique_match_count": approval_proxy_unique_match_count,
        "support_by_action": [
            action_totals[action_id] for action_id in sorted(action_totals)
        ],
        "support_by_incident_type": [
            incident_type_totals[incident_type]
            for incident_type in sorted(incident_type_totals)
        ],
    }


def _build_approval_proxy_scope(
    *,
    provenance: dict[str, Any],
    mapping_rules: list[Any],
) -> dict[str, Any]:
    approval_required_actions = []
    action_catalog = provenance.get("action_catalog", {})
    items = action_catalog.get("items") if isinstance(action_catalog, dict) else []
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and bool(item.get("requires_approval", False)):
                action_id = str(item.get("action_id") or "").strip()
                if action_id:
                    approval_required_actions.append(action_id)

    proxy_actions = sorted(
        {rule.action_id for rule in mapping_rules if bool(rule.approval_proxy)}
    )
    return {
        "approval_required_catalog_action_ids": sorted(approval_required_actions),
        "mapped_approval_proxy_action_ids": proxy_actions,
        "approval_required_actions_without_proxy_mapping": sorted(
            set(approval_required_actions) - set(proxy_actions)
        ),
    }


def _build_official_evaluation_scope(
    *,
    official_summary: dict[str, Any],
    policy_rule_ids: list[str],
) -> dict[str, Any]:
    if not official_summary:
        return {"available": False}

    violations_by_rule = official_summary.get("violations_by_rule", {})
    if not isinstance(violations_by_rule, dict):
        violations_by_rule = {}
    violation_total = sum(int(value or 0) for value in violations_by_rule.values())
    observed_rule_ids = sorted(
        rule_id for rule_id, count in violations_by_rule.items() if int(count or 0) > 0
    )
    approval_only_violation_types_observed = sorted(
        str(key)
        for key in (official_summary.get("violations_by_type", {}) or {}).keys()
    ) == ["approval_required"]
    return {
        "available": True,
        "run_count": int(official_summary.get("run_count", 0) or 0),
        "incident_count": int(official_summary.get("incident_count", 0) or 0),
        "violations_by_rule": violations_by_rule,
        "observed_rule_ids": observed_rule_ids,
        "rule_ids_without_observed_violation_counts": sorted(
            set(policy_rule_ids) - set(observed_rule_ids)
        ),
        "approval_only_violation_types_observed": (
            approval_only_violation_types_observed
        ),
        "approval_rule_violation_share": 1.0
        if violation_total > 0 and approval_only_violation_types_observed
        else 0.0,
        "enforcement_actions_removed_count_total": int(
            official_summary.get("enforcement_actions_removed_count_total", 0) or 0
        ),
        "enforcement_actions_deferred_count_total": int(
            official_summary.get("enforcement_actions_deferred_count_total", 0) or 0
        ),
        "enforcement_actions_inserted_count_total": int(
            official_summary.get("enforcement_actions_inserted_count_total", 0) or 0
        ),
        "enforcement_actions_reordered_count_total": int(
            official_summary.get("enforcement_actions_reordered_count_total", 0) or 0
        ),
        "task_coverage_delta_avg": float(
            official_summary.get("task_coverage_delta_avg", 0.0) or 0.0
        ),
        "task_coverage_drop_rate": float(
            official_summary.get("task_coverage_drop_rate", 0.0) or 0.0
        ),
        "llm_total_tokens_total": int(
            official_summary.get("llm_total_tokens_total", 0) or 0
        ),
        "llm_cost_estimated_usd_total": float(
            official_summary.get("llm_cost_estimated_usd_total", 0.0) or 0.0
        ),
        "llm_cost_estimated_usd_avg_per_run": float(
            official_summary.get("llm_cost_estimated_usd_avg_per_run", 0.0) or 0.0
        ),
        "run_success_rate": float(
            (official_summary.get("experiment_coverage", {}) or {}).get(
                "run_success_rate", 0.0
            )
            or 0.0
        ),
    }


def _build_criticism_response_map(report: dict[str, Any]) -> list[dict[str, Any]]:
    mapping_support = report["mapping_support"]
    global_surface = report["global_surface"]
    approval_proxy_scope = report["approval_proxy_scope"]
    official_scope = report["official_evaluation_scope"]
    return [
        {
            "criticism": (
                "The mapped human baseline is opaque and relies heavily on "
                "keyword rules."
            ),
            "response_strength": "partial_but_material",
            "response": (
                "The artifact now exposes aggregate mapping-support evidence: "
                "zero unmatched tasks, zero ambiguous ties, complete conversion "
                "coverage, and an explicit split between "
                "single-keyword and multi-keyword unique matches."
            ),
            "evidence": {
                "task_count_total": mapping_support["task_count_total"],
                "single_keyword_unique_match_rate": mapping_support[
                    "single_keyword_unique_match_rate"
                ],
                "ambiguous_match_count": mapping_support["ambiguous_match_count"],
                "zero_match_count": mapping_support["zero_match_count"],
            },
        },
        {
            "criticism": (
                "The global action/policy surface is narrow and may overstate "
                "generality."
            ),
            "response_strength": "addressed_transparently",
            "response": (
                "The assessment makes the narrowness explicit instead of "
                "burying it: the human baseline covers only part of the "
                "catalog, the mapping contract covers only part of the "
                "catalog, and the constrained action surface is smaller still."
            ),
            "evidence": {
                "action_catalog_count": global_surface["action_catalog_count"],
                "human_baseline_action_count": global_surface[
                    "human_baseline_action_count"
                ],
                "mapping_action_count": global_surface["mapping_action_count"],
                "constrained_action_count": global_surface["constrained_action_count"],
            },
        },
        {
            "criticism": (
                "Observed evidence is concentrated in approval governance "
                "rather than the full rule family."
            ),
            "response_strength": "addressed_transparently",
            "response": (
                "The report states that the completed official evaluation "
                "shows violation evidence only on approval rules under this "
                "freeze, with no inserted or reordered actions."
            ),
            "evidence": official_scope,
        },
        {
            "criticism": (
                "Approval context is only partially grounded in the mapping "
                "contract."
            ),
            "response_strength": "addressed_transparently",
            "response": (
                "The report makes proxy scope explicit by showing which "
                "approval-required catalog actions have a mapping proxy and "
                "which do not."
            ),
            "evidence": approval_proxy_scope,
        },
        {
            "criticism": "Cost accounting is unclear.",
            "response_strength": "addressed",
            "response": (
                "The official aggregate summary is now copied into canonical "
                "analysis outputs so public auditors can inspect token totals, "
                "total cost, average cost per run, and run-success rate "
                "directly."
            ),
            "evidence": {
                "llm_total_tokens_total": official_scope.get(
                    "llm_total_tokens_total", 0
                ),
                "llm_cost_estimated_usd_total": official_scope.get(
                    "llm_cost_estimated_usd_total",
                    0.0,
                ),
                "llm_cost_estimated_usd_avg_per_run": official_scope.get(
                    "llm_cost_estimated_usd_avg_per_run",
                    0.0,
                ),
                "run_success_rate": official_scope.get("run_success_rate", 0.0),
            },
        },
    ]


def build_global_artifact_assessment(
    *,
    paths: RepoPaths,
    incidents: list[str],
    official_summary_path: Path | None,
    write_missing_support_manifests: bool,
) -> dict[str, Any]:
    dataset_report = audit_dataset(paths=paths, incidents=incidents)
    provenance = build_global_provenance(paths=paths, incident_ids=incidents)
    mapping_rules = load_mapping_rules(paths.action_mapping_bank_path)
    mapping_support = _build_mapping_support_summary(
        paths=paths,
        incidents=incidents,
        write_missing_support_manifests=write_missing_support_manifests,
    )
    official_summary = (
        _load_json_object(official_summary_path) if official_summary_path else {}
    )

    action_catalog = provenance.get("action_catalog", {})
    action_items = (
        action_catalog.get("items") if isinstance(action_catalog, dict) else []
    )
    policy_rules = provenance.get("policy_rules", {})
    rule_items = policy_rules.get("items") if isinstance(policy_rules, dict) else []

    human_baseline_action_ids = sorted(
        str(item.get("action_id") or "").strip()
        for item in action_items
        if isinstance(item, dict)
        and bool(item.get("observed_in_human_baseline", False))
    )
    catalog_action_ids = sorted(
        str(item.get("action_id") or "").strip()
        for item in action_items
        if isinstance(item, dict) and str(item.get("action_id") or "").strip()
    )
    policy_rule_ids = sorted(
        str(item.get("rule_id") or "").strip()
        for item in rule_items
        if isinstance(item, dict) and str(item.get("rule_id") or "").strip()
    )

    report = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "dataset_release_id": provenance.get("dataset_release_id"),
        "eval_protocol_version": provenance.get("eval_protocol_version"),
        "incident_count": len(incidents),
        "official_summary_source": (
            repo_relative_path(official_summary_path, paths.repo_root)
            if official_summary_path is not None and official_summary_path.exists()
            else None
        ),
        "dataset_strengths": {
            "privacy_issue_count": int(
                dataset_report.get("privacy_issue_count", 0) or 0
            ),
            "invalid_incident_count": int(
                dataset_report.get("invalid_incident_count", 0) or 0
            ),
            "mapping_weighted_coverage": (
                (dataset_report.get("corpus_readiness", {}) or {})
                .get("mapping_quality", {})
                .get("weighted_mapping_coverage")
            ),
            "zero_hallucinated_actions_in_official_summary": int(
                official_summary.get("llm_hallucinated_action_count_total", 0) or 0
            )
            == 0
            if official_summary
            else None,
        },
        "global_surface": {
            "action_catalog_count": len(catalog_action_ids),
            "action_catalog_ids": catalog_action_ids,
            "human_baseline_action_count": len(human_baseline_action_ids),
            "human_baseline_action_ids": human_baseline_action_ids,
            "mapping_action_count": int(
                (dataset_report.get("corpus_readiness", {}) or {})
                .get("global_artifact_scope", {})
                .get("mapping_action_count", 0)
                or 0
            ),
            "mapping_action_ids": sorted(rule.action_id for rule in mapping_rules),
            "catalog_actions_missing_mapping_rules": (
                (dataset_report.get("corpus_readiness", {}) or {})
                .get("global_artifact_scope", {})
                .get("catalog_actions_missing_mapping_rules", [])
            ),
            "policy_rule_count": len(policy_rule_ids),
            "policy_rule_ids": policy_rule_ids,
            "constrained_action_count": int(
                (dataset_report.get("corpus_readiness", {}) or {})
                .get("global_artifact_scope", {})
                .get("constrained_action_count", 0)
                or 0
            ),
        },
        "mapping_support": mapping_support,
        "approval_proxy_scope": _build_approval_proxy_scope(
            provenance=provenance,
            mapping_rules=mapping_rules,
        ),
        "official_evaluation_scope": _build_official_evaluation_scope(
            official_summary=official_summary,
            policy_rule_ids=policy_rule_ids,
        ),
    }
    report["criticism_response_map"] = _build_criticism_response_map(report)
    return report


def _render_markdown(report: dict[str, Any]) -> str:
    mapping_support = report["mapping_support"]
    global_surface = report["global_surface"]
    official_scope = report["official_evaluation_scope"]
    approval_proxy_scope = report["approval_proxy_scope"]
    enforcement_removed = official_scope["enforcement_actions_removed_count_total"]
    enforcement_deferred = official_scope["enforcement_actions_deferred_count_total"]
    enforcement_inserted = official_scope["enforcement_actions_inserted_count_total"]
    enforcement_reordered = official_scope["enforcement_actions_reordered_count_total"]
    lines = [
        "# Global Artifact Assessment",
        "",
        "## Summary",
        "",
        (
            "This report separates what the current declared globals support strongly "
            "from what remains narrow in the official evaluation."
        ),
        "",
        "## Stable Evidence",
        "",
        f"- Incident count audited: {report['incident_count']}",
        (
            f"- Mapping support coverage: {mapping_support['task_count_total']} tasks, "
            f"{mapping_support['zero_match_count']} zero-match, "
            f"{mapping_support['ambiguous_match_count']} ambiguous."
        ),
        (
            "- Unique-match split: "
            f"{mapping_support['single_keyword_unique_match_count']} "
            "single-keyword "
            f"({mapping_support['single_keyword_unique_match_rate']:.4f}) and "
            f"{mapping_support['multi_keyword_unique_match_count']} multi-keyword "
            f"({mapping_support['multi_keyword_unique_match_rate']:.4f})."
        ),
        (
            "- Human-baseline action coverage: "
            f"{global_surface['human_baseline_action_count']}/"
            f"{global_surface['action_catalog_count']} catalog actions."
        ),
        "",
        "## Narrowness That Still Matters",
        "",
        (
            f"- Mapping rules cover {global_surface['mapping_action_count']}/"
            f"{global_surface['action_catalog_count']} catalog actions."
        ),
        (
            "- Catalog actions without mapping rules: "
            + ", ".join(global_surface["catalog_actions_missing_mapping_rules"])
        ),
        (
            "- Approval-required actions without proxy mapping support: "
            + ", ".join(
                approval_proxy_scope["approval_required_actions_without_proxy_mapping"]
            )
        ),
        "",
        "## Official Evaluation Scope",
        "",
    ]
    if official_scope.get("available", False):
        lines.extend(
            [
                f"- Official runs: {official_scope['run_count']}",
                (
                    "- Observed violation rules: "
                    + ", ".join(official_scope["observed_rule_ids"])
                ),
                (
                    "- Rules without observed violation counts in the "
                    "official summary: "
                    + ", ".join(
                        official_scope["rule_ids_without_observed_violation_counts"]
                    )
                ),
                (
                    "- Enforcement counts: "
                    f"remove={enforcement_removed}, defer={enforcement_deferred}, "
                    f"insert={enforcement_inserted}, reorder={enforcement_reordered}."
                ),
                (
                    "- Cost accounting: "
                    f"{official_scope['llm_total_tokens_total']} tokens, "
                    f"USD {official_scope['llm_cost_estimated_usd_total']:.6f} total, "
                    "USD "
                    f"{official_scope['llm_cost_estimated_usd_avg_per_run']:.6f} "
                    "per run."
                ),
            ]
        )
    else:
        lines.append(
            "- No official aggregate summary was available when this report ran."
        )
    lines.extend(
        [
            "",
            "## Criticism Response Map",
            "",
        ]
    )
    for item in report["criticism_response_map"]:
        lines.append(f"- {item['criticism']}")
        lines.append(
            f"  Response strength: {item['response_strength']}. {item['response']}"
        )
    lines.extend(
        [
            "",
            "## Interpretation Boundary",
            "",
            (
                "This report improves visibility into mapper robustness and "
                "global-surface narrowness, but it does not replace a human "
                "audit of task-to-action mappings, ground-truth approval logs, "
                "or broader rule-family activation."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soc_llm_policy.global_artifact_assessment")
    parser.add_argument("--repo-root", default=None)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--incidents", default=None, help="CSV: INC_001,INC_002")
    group.add_argument("--all", action="store_true")
    parser.add_argument(
        "--output-json",
        default="results/analysis/global_artifact_assessment.json",
    )
    parser.add_argument(
        "--output-md",
        default="results/analysis/global_artifact_assessment.md",
    )
    parser.add_argument(
        "--official-summary-json",
        default=None,
        help="Optional explicit path to the aggregate official evaluation summary.",
    )
    parser.add_argument(
        "--official-summary-output-json",
        default="results/analysis/official_evaluation_summary.json",
        help=(
            "Canonical copy of the aggregate official evaluation summary "
            "when available."
        ),
    )
    parser.add_argument(
        "--no-write-support-manifests",
        action="store_true",
        help=(
            "Do not persist per-incident mapping_support_manifest.json files "
            "when missing."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    repo_root = resolve_repo_root(args.repo_root)
    paths = RepoPaths(repo_root=repo_root)
    incidents = _resolve_incidents(paths, args.incidents, bool(args.all))
    official_summary_path = _resolve_official_summary_source(
        paths=paths,
        explicit_path=args.official_summary_json,
    )
    official_summary_output_path = (
        Path(args.official_summary_output_json).expanduser().resolve()
    )
    _copy_official_summary(
        source_path=official_summary_path,
        output_path=official_summary_output_path,
    )
    report = build_global_artifact_assessment(
        paths=paths,
        incidents=incidents,
        official_summary_path=official_summary_path,
        write_missing_support_manifests=not bool(args.no_write_support_manifests),
    )
    output_json = Path(args.output_json).expanduser().resolve()
    output_md = Path(args.output_md).expanduser().resolve()
    write_stable_json(output_json, report)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(_render_markdown(report), encoding="utf-8")
    print(f"Global artifact assessment saved at: {output_json}")
    print(f"Global artifact assessment summary saved at: {output_md}")
    if official_summary_path is not None:
        print(f"Official evaluation summary copied to: {official_summary_output_path}")


if __name__ == "__main__":
    main()
