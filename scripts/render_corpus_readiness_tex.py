#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
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


def _macro(name: str, value: str) -> str:
    return f"\\newcommand{{\\{name}}}{{{value}}}"


def _tex_escape(value: str) -> str:
    return value.replace("\\", "\\textbackslash{}").replace("_", "\\_")


def _join_tex_list(values: list[str]) -> str:
    if not values:
        return "none"
    return ", ".join(_tex_escape(value) for value in values)


def _find_action_support(
    support_rows: list[dict[str, Any]],
    action_id: str,
) -> dict[str, Any]:
    for row in support_rows:
        if str(row.get("action_id", "")).strip() == action_id:
            return row
    return {}


def build_tex(
    payload: dict[str, Any],
    global_assessment: dict[str, Any] | None = None,
) -> str:
    global_scope = payload.get("global_artifact_scope", {})
    mapping = payload.get("mapping_quality", {})
    mitre = payload.get("mitre_technique_diversity", {})
    incident_type_counts = payload.get("incident_type_counts", {})
    global_assessment = global_assessment or {}
    mapping_support = global_assessment.get("mapping_support", {})
    if not isinstance(mapping_support, dict):
        mapping_support = {}
    support_by_action = mapping_support.get("support_by_action", [])
    if not isinstance(support_by_action, list):
        support_by_action = []
    global_surface = global_assessment.get("global_surface", {})
    if not isinstance(global_surface, dict):
        global_surface = {}
    approval_proxy_scope = global_assessment.get("approval_proxy_scope", {})
    if not isinstance(approval_proxy_scope, dict):
        approval_proxy_scope = {}

    collect_forensics_support = _find_action_support(
        support_by_action,
        "collect_forensics",
    )
    isolate_host_support = _find_action_support(support_by_action, "isolate_host")
    reset_admin_support = _find_action_support(
        support_by_action,
        "reset_admin_credentials",
    )
    catalog_actions_missing_mapping_rules = global_surface.get(
        "catalog_actions_missing_mapping_rules",
        [],
    )
    if not isinstance(catalog_actions_missing_mapping_rules, list):
        catalog_actions_missing_mapping_rules = []
    mapped_approval_proxy_action_ids = approval_proxy_scope.get(
        "mapped_approval_proxy_action_ids",
        [],
    )
    if not isinstance(mapped_approval_proxy_action_ids, list):
        mapped_approval_proxy_action_ids = []
    approval_required_actions_without_proxy_mapping = approval_proxy_scope.get(
        "approval_required_actions_without_proxy_mapping",
        [],
    )
    if not isinstance(approval_required_actions_without_proxy_mapping, list):
        approval_required_actions_without_proxy_mapping = []

    incident_type_summary = "none"
    if isinstance(incident_type_counts, dict) and incident_type_counts:
        parts: list[str] = []
        for key in sorted(incident_type_counts):
            label = _tex_escape(str(key))
            count = _safe_int(incident_type_counts.get(key))
            parts.append(f"{label}={count}")
        incident_type_summary = ", ".join(parts)

    lines = [
        _macro("ValCorpusIncidentCount", str(_safe_int(payload.get("incident_count")))),
        _macro("ValCorpusValidIncidentCount", str(_safe_int(payload.get("valid_incident_count")))),
        _macro("ValCorpusInvalidIncidentCount", str(_safe_int(payload.get("invalid_incident_count")))),
        _macro("ValCorpusPrivacyIssueCount", str(_safe_int(payload.get("privacy_issue_count")))),
        _macro("ValCorpusPrivacyPassRate", f"{_safe_float(payload.get('privacy_pass_rate')):.4f}"),
        _macro("ValCorpusEventCountTotal", str(_safe_int(payload.get("event_count_total")))),
        _macro("ValCorpusEventCountMin", str(_safe_int(payload.get("event_count_min")))),
        _macro("ValCorpusEventCountMax", str(_safe_int(payload.get("event_count_max")))),
        _macro("ValCorpusActionCountTotal", str(_safe_int(payload.get("action_count_total")))),
        _macro("ValCorpusActionCountMin", str(_safe_int(payload.get("action_count_min")))),
        _macro("ValCorpusActionCountMax", str(_safe_int(payload.get("action_count_max")))),
        _macro("ValCorpusEventsPerIncidentAvg", f"{_safe_float(payload.get('events_per_incident_avg')):.4f}"),
        _macro("ValCorpusActionsPerIncidentAvg", f"{_safe_float(payload.get('actions_per_incident_avg')):.4f}"),
        _macro(
            "ValCorpusIncidentTypeCount",
            str(
                len(incident_type_counts)
                if isinstance(incident_type_counts, dict)
                else 0
            ),
        ),
        _macro("ValCorpusIncidentTypeSummary", incident_type_summary),
        _macro(
            "ValCatalogActionCount",
            str(_safe_int(global_scope.get("action_catalog_count"))),
        ),
        _macro(
            "ValCatalogRequiresApprovalActionCount",
            str(_safe_int(global_scope.get("requires_approval_action_count"))),
        ),
        _macro(
            "ValCatalogReversibleActionCount",
            str(_safe_int(global_scope.get("reversible_action_count"))),
        ),
        _macro(
            "ValMappingRuleCount",
            str(_safe_int(global_scope.get("mapping_rule_count"))),
        ),
        _macro(
            "ValMappingActionCount",
            str(_safe_int(global_scope.get("mapping_action_count"))),
        ),
        _macro(
            "ValMappingActionCoverageOverCatalog",
            f"{_safe_float(global_scope.get('mapping_action_coverage_over_catalog')):.4f}",
        ),
        _macro(
            "ValPolicyRuleCount",
            str(_safe_int(global_scope.get("policy_rule_count"))),
        ),
        _macro(
            "ValPolicyConstrainedActionCount",
            str(_safe_int(global_scope.get("constrained_action_count"))),
        ),
        _macro(
            "ValPolicyActionCoverageOverCatalog",
            f"{_safe_float(global_scope.get('policy_action_coverage_over_catalog')):.4f}",
        ),
        _macro(
            "ValCorpusMappingCoverage",
            f"{_safe_float(mapping.get('weighted_mapping_coverage')):.4f}",
        ),
        _macro(
            "ValCorpusMappedTaskCount",
            str(_safe_int(mapping.get("mapped_task_count_total"))),
        ),
        _macro(
            "ValCorpusTaskCount",
            str(_safe_int(mapping.get("task_count_total"))),
        ),
        _macro(
            "ValCorpusUnmatchedTaskCount",
            str(_safe_int(mapping.get("unmatched_task_count_total"))),
        ),
        _macro(
            "ValCorpusFallbackUsedCount",
            str(_safe_int(mapping.get("fallback_used_count"))),
        ),
        _macro(
            "ValCorpusFallbackUsageRate",
            f"{_safe_float(mapping.get('fallback_usage_rate')):.4f}",
        ),
        _macro(
            "ValCorpusTasksPerIncidentAvg",
            f"{_safe_float(mapping.get('tasks_per_incident_avg')):.4f}",
        ),
        _macro(
            "ValCorpusSensitivityTaskCount",
            str(_safe_int(mapping.get("sensitivity_task_count_total"))),
        ),
        _macro(
            "ValCorpusAmbiguousMatchCount",
            str(_safe_int(mapping.get("ambiguous_match_count"))),
        ),
        _macro(
            "ValCorpusAmbiguousMatchRate",
            f"{_safe_float(mapping.get('ambiguous_match_rate')):.4f}",
        ),
        _macro(
            "ValCorpusSingleKeywordMatchCount",
            str(_safe_int(mapping.get("single_keyword_unique_match_count"))),
        ),
        _macro(
            "ValCorpusSingleKeywordMatchRate",
            f"{_safe_float(mapping.get('single_keyword_unique_match_rate')):.4f}",
        ),
        _macro(
            "ValBaselineSupportedActionCount",
            str(_safe_int(global_surface.get("human_baseline_action_count"))),
        ),
        _macro(
            "ValBaselineUnsupportedActionCount",
            str(len(catalog_actions_missing_mapping_rules)),
        ),
        _macro(
            "ValBaselineUnsupportedActionIds",
            _join_tex_list(
                [str(value) for value in catalog_actions_missing_mapping_rules],
            ),
        ),
        _macro(
            "ValApprovalProxyCoveredActionIds",
            _join_tex_list([str(value) for value in mapped_approval_proxy_action_ids]),
        ),
        _macro(
            "ValApprovalProxyMissingActionIds",
            _join_tex_list(
                [
                    str(value)
                    for value in approval_required_actions_without_proxy_mapping
                ],
            ),
        ),
        _macro(
            "ValSupportCollectForensicsIncidentCount",
            str(_safe_int(collect_forensics_support.get("incident_count"))),
        ),
        _macro(
            "ValSupportCollectForensicsMatchCount",
            str(_safe_int(collect_forensics_support.get("unique_match_count"))),
        ),
        _macro(
            "ValSupportCollectForensicsSingleKeywordShare",
            f"{_safe_float(collect_forensics_support.get('single_keyword_share_within_action')):.4f}",
        ),
        _macro(
            "ValSupportIsolateHostIncidentCount",
            str(_safe_int(isolate_host_support.get("incident_count"))),
        ),
        _macro(
            "ValSupportIsolateHostMatchCount",
            str(_safe_int(isolate_host_support.get("unique_match_count"))),
        ),
        _macro(
            "ValSupportIsolateHostSingleKeywordShare",
            f"{_safe_float(isolate_host_support.get('single_keyword_share_within_action')):.4f}",
        ),
        _macro(
            "ValSupportResetAdminIncidentCount",
            str(_safe_int(reset_admin_support.get("incident_count"))),
        ),
        _macro(
            "ValSupportResetAdminMatchCount",
            str(_safe_int(reset_admin_support.get("unique_match_count"))),
        ),
        _macro(
            "ValSupportResetAdminSingleKeywordShare",
            f"{_safe_float(reset_admin_support.get('single_keyword_share_within_action')):.4f}",
        ),
        _macro(
            "ValCorpusMitreTechniqueIdCount",
            str(_safe_int(mitre.get("technique_id_count"))),
        ),
        _macro(
            "ValCorpusMitreTechniqueLabelCount",
            str(_safe_int(mitre.get("technique_label_count"))),
        ),
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-json", required=True)
    parser.add_argument("--global-assessment-json", default=None)
    parser.add_argument("--output-tex", required=True)
    args = parser.parse_args()

    input_path = Path(args.input_json).expanduser().resolve()
    output_path = Path(args.output_tex).expanduser().resolve()

    payload = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("corpus_readiness.json must be a JSON object")

    global_assessment = None
    if args.global_assessment_json:
        global_assessment_path = Path(args.global_assessment_json).expanduser().resolve()
        global_assessment = json.loads(global_assessment_path.read_text(encoding="utf-8"))
        if not isinstance(global_assessment, dict):
            raise ValueError("global_artifact_assessment.json must be a JSON object")

    tex = build_tex(payload, global_assessment=global_assessment)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(tex, encoding="utf-8")
    print(f"Saved TeX macros at: {output_path}")


if __name__ == "__main__":
    main()
