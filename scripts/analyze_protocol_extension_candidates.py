#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc_llm_policy.engine import (
    EnforcementRequest,
    enforce_policy,
    telemetry_matches_scope,
    validate_rule_consistency,
)
from soc_llm_policy.io import (
    ActionCatalogItem,
    HumanAction,
    PolicyRule,
    TelemetryEvent,
    parse_action_catalog,
    parse_human_actions_strict_order,
    parse_rules,
    parse_telemetry,
    read_jsonl,
    read_yaml_list,
)

MIN_MANDATORY_SUPPORT = 10
MIN_SUPPORTED_MANDATORY_RULES = 3
MIN_ORDER_CHAIN_REPAIRS = 2


@dataclass(frozen=True)
class IncidentBundle:
    incident_id: str
    telemetry: list[TelemetryEvent]
    human_actions: list[HumanAction]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze zero-cost activation for a protocol extension."
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("dataset/incidents"),
        help="Directory containing canonical incident packages.",
    )
    parser.add_argument(
        "--policy-dir",
        type=Path,
        default=Path("protocol_extensions/expanded_policy_surface_candidate"),
        help="Directory containing candidate action_catalog.yaml and constraints.yaml.",
    )
    parser.add_argument(
        "--official-policy-dir",
        type=Path,
        default=Path("policy"),
        help="Directory containing the current official policy surface.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path("results/analysis/protocol_extension_activation_report.json"),
        help="JSON report path.",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=Path("results/analysis/protocol_extension_activation_report.md"),
        help="Markdown report path.",
    )
    return parser.parse_args()


def load_catalog(policy_dir: Path) -> list[ActionCatalogItem]:
    return parse_action_catalog(read_yaml_list(policy_dir / "action_catalog.yaml"))


def load_rules(policy_dir: Path) -> list[PolicyRule]:
    rules = parse_rules(read_yaml_list(policy_dir / "constraints.yaml"))
    validate_rule_consistency(rules)
    return rules


def load_incidents(dataset_dir: Path) -> list[IncidentBundle]:
    incidents: list[IncidentBundle] = []
    for incident_dir in sorted(dataset_dir.iterdir()):
        if not incident_dir.is_dir():
            continue

        telemetry = parse_telemetry(
            read_jsonl(incident_dir / "incident_telemetry.jsonl")
        )
        human_actions = parse_human_actions_strict_order(
            read_jsonl(incident_dir / "incident_human_actions.jsonl")
        )
        incidents.append(
            IncidentBundle(
                incident_id=incident_dir.name,
                telemetry=telemetry,
                human_actions=human_actions,
            )
        )
    return incidents


def rule_scope_matches(rule: PolicyRule, incident: IncidentBundle) -> bool:
    scope = rule.scope or {}
    if scope.get("global") is True:
        return True
    return telemetry_matches_scope(incident.telemetry, scope)


def action_ids(actions: Iterable[HumanAction]) -> list[str]:
    return [action.action_id for action in actions]


def probe_mandatory_rule(
    rule: PolicyRule,
    catalog: list[ActionCatalogItem],
    rules: list[PolicyRule],
    incident: IncidentBundle,
) -> list[str]:
    proposal = [
        action
        for action in action_ids(incident.human_actions)
        if action != rule.action
    ]
    violations, _enforced = enforce_policy(
        EnforcementRequest(
            llm_actions=proposal,
            telemetry=incident.telemetry,
            rules=rules,
            catalog=catalog,
            approval_policy_mode="defer_to_human_approval",
        )
    )
    return [
        violation.repair
        for violation in violations
        if violation.rule_id == rule.rule_id
    ]


def probe_order_rule(
    rule: PolicyRule,
    catalog: list[ActionCatalogItem],
    rules: list[PolicyRule],
    incident: IncidentBundle,
) -> list[str]:
    violations, _enforced = enforce_policy(
        EnforcementRequest(
            llm_actions=[rule.action],
            telemetry=incident.telemetry,
            rules=rules,
            catalog=catalog,
            approval_policy_mode="defer_to_human_approval",
        )
    )
    return [
        violation.repair
        for violation in violations
        if violation.rule_id == rule.rule_id
    ]


def probe_approval_rule(
    rule: PolicyRule,
    catalog: list[ActionCatalogItem],
    rules: list[PolicyRule],
    incident: IncidentBundle,
    approval_policy_mode: str,
) -> list[str]:
    violations, _enforced = enforce_policy(
        EnforcementRequest(
            llm_actions=[rule.action],
            telemetry=incident.telemetry,
            rules=rules,
            catalog=catalog,
            approval_policy_mode=approval_policy_mode,  # type: ignore[arg-type]
        )
    )
    return [
        violation.repair
        for violation in violations
        if violation.rule_id == rule.rule_id
    ]


def probe_order_chain(
    catalog: list[ActionCatalogItem],
    rules: list[PolicyRule],
    incidents: list[IncidentBundle],
) -> dict[str, Any]:
    order_actions = sorted(
        {
            rule.action
            for rule in rules
            if rule.type == "prohibit_before" and rule.condition_action
        }
    )
    best: dict[str, Any] = {
        "max_order_repairs_in_single_probe": 0,
        "action": None,
        "incident_id": None,
        "rule_ids": [],
        "enforced_actions": [],
    }
    if not incidents:
        return best

    for action in order_actions:
        for incident in incidents:
            violations, enforced = enforce_policy(
                EnforcementRequest(
                    llm_actions=[action],
                    telemetry=incident.telemetry,
                    rules=rules,
                    catalog=catalog,
                    approval_policy_mode="defer_to_human_approval",
                )
            )
            order_violations = [
                violation
                for violation in violations
                if violation.type == "order_violation"
            ]
            if len(order_violations) > best["max_order_repairs_in_single_probe"]:
                best = {
                    "max_order_repairs_in_single_probe": len(order_violations),
                    "action": action,
                    "incident_id": incident.incident_id,
                    "rule_ids": [violation.rule_id for violation in order_violations],
                    "enforced_actions": enforced,
                }
    return best


def validate_policy_surface(
    catalog: list[ActionCatalogItem],
    rules: list[PolicyRule],
) -> list[str]:
    catalog_ids = {item.action_id for item in catalog}
    errors: list[str] = []
    for rule in rules:
        if rule.action not in catalog_ids:
            errors.append(f"{rule.rule_id}: action not in catalog: {rule.action}")
        if rule.condition_action and rule.condition_action not in catalog_ids:
            errors.append(
                f"{rule.rule_id}: condition action not in catalog: "
                f"{rule.condition_action}"
            )
    return errors


def summarize_rule_activation(
    catalog: list[ActionCatalogItem],
    rules: list[PolicyRule],
    incidents: list[IncidentBundle],
) -> tuple[list[dict[str, Any]], Counter[str]]:
    repair_modes: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []

    for rule in rules:
        matched_incidents = [
            incident for incident in incidents if rule_scope_matches(rule, incident)
        ]
        probe_incidents = matched_incidents if rule.type == "mandatory" else incidents
        repair_counter: Counter[str] = Counter()
        repair_incidents: list[str] = []

        for incident in probe_incidents:
            if rule.type == "mandatory":
                repairs = probe_mandatory_rule(rule, catalog, rules, incident)
            elif rule.type == "prohibit_before":
                repairs = probe_order_rule(rule, catalog, rules, incident)
            elif rule.type == "require_approval":
                remove_repairs = probe_approval_rule(
                    rule, catalog, rules, incident, "remove"
                )
                defer_repairs = probe_approval_rule(
                    rule, catalog, rules, incident, "defer_to_human_approval"
                )
                repairs = [*remove_repairs, *defer_repairs]
            else:
                repairs = []

            if repairs:
                repair_incidents.append(incident.incident_id)
                repair_counter.update(repairs)
                repair_modes.update(repairs)

        rows.append(
            {
                "rule_id": rule.rule_id,
                "type": rule.type,
                "action": rule.action,
                "condition_action": rule.condition_action,
                "scope_matched_incident_count": len(matched_incidents),
                "probe_incident_count": len(probe_incidents),
                "repair_observed_incident_count": len(repair_incidents),
                "repair_counts": dict(sorted(repair_counter.items())),
                "example_incidents": repair_incidents[:8],
            }
        )

    return rows, repair_modes


def summarize_action_surface(
    catalog: list[ActionCatalogItem],
    official_catalog: list[ActionCatalogItem],
    incidents: list[IncidentBundle],
) -> dict[str, Any]:
    catalog_ids = {item.action_id for item in catalog}
    official_ids = {item.action_id for item in official_catalog}
    baseline_counts: Counter[str] = Counter()
    baseline_incidents: defaultdict[str, set[str]] = defaultdict(set)

    for incident in incidents:
        for action in incident.human_actions:
            baseline_counts[action.action_id] += 1
            baseline_incidents[action.action_id].add(incident.incident_id)

    return {
        "candidate_action_count": len(catalog_ids),
        "official_action_count": len(official_ids),
        "new_action_count": len(catalog_ids - official_ids),
        "new_action_ids": sorted(catalog_ids - official_ids),
        "candidate_actions_requiring_approval": sorted(
            item.action_id for item in catalog if item.requires_approval
        ),
        "baseline_action_support": [
            {
                "action_id": action_id,
                "human_action_count": baseline_counts[action_id],
                "incident_count": len(baseline_incidents[action_id]),
            }
            for action_id in sorted(catalog_ids)
        ],
    }


def readiness_status(
    rule_rows: list[dict[str, Any]],
    repair_modes: Counter[str],
    order_chain: dict[str, Any],
    policy_errors: list[str],
) -> dict[str, Any]:
    mandatory_rules = [row for row in rule_rows if row["type"] == "mandatory"]
    mandatory_with_support = [
        row
        for row in mandatory_rules
        if row["scope_matched_incident_count"] >= MIN_MANDATORY_SUPPORT
    ]
    required_modes = {"insert", "insert_before", "remove", "defer_to_human_approval"}
    observed_modes = set(repair_modes)
    ready = (
        not policy_errors
        and len(mandatory_with_support) >= MIN_SUPPORTED_MANDATORY_RULES
        and order_chain["max_order_repairs_in_single_probe"]
        >= MIN_ORDER_CHAIN_REPAIRS
        and required_modes.issubset(observed_modes)
    )
    status = "manual_review_ready" if ready else "needs_more_zero_cost_work"
    return {
        "status": status,
        "paid_execution_authorized": False,
        "mandatory_rules_with_at_least_10_matching_incidents": len(
            mandatory_with_support
        ),
        "required_repair_modes": sorted(required_modes),
        "observed_repair_modes": sorted(observed_modes),
        "policy_surface_error_count": len(policy_errors),
        "rationale": (
            "Zero-cost gates support manual review before any paid provider run."
            if ready
            else "One or more zero-cost gates need more evidence before paid execution."
        ),
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    catalog = load_catalog(args.policy_dir)
    rules = load_rules(args.policy_dir)
    official_catalog = load_catalog(args.official_policy_dir)
    incidents = load_incidents(args.dataset_dir)

    policy_errors = validate_policy_surface(catalog, rules)
    rule_rows, repair_modes = summarize_rule_activation(catalog, rules, incidents)
    order_chain = probe_order_chain(catalog, rules, incidents)

    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "dataset_dir": str(args.dataset_dir),
        "policy_dir": str(args.policy_dir),
        "incident_count": len(incidents),
        "action_surface": summarize_action_surface(
            catalog, official_catalog, incidents
        ),
        "policy_surface": {
            "rule_count": len(rules),
            "rule_count_by_type": dict(
                sorted(Counter(rule.type for rule in rules).items())
            ),
            "errors": policy_errors,
        },
        "rule_activation": rule_rows,
        "repair_modes_observed": dict(sorted(repair_modes.items())),
        "order_chain_probe": order_chain,
        "paid_execution_readiness": readiness_status(
            rule_rows, repair_modes, order_chain, policy_errors
        ),
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", "utf-8")


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _header in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    readiness = report["paid_execution_readiness"]
    action_surface = report["action_surface"]
    order_chain = report["order_chain_probe"]
    rule_rows = report["rule_activation"]

    rule_table = markdown_table(
        [
            "Rule",
            "Type",
            "Action",
            "Matched incidents",
            "Repair incidents",
            "Repairs",
        ],
        [
            [
                row["rule_id"],
                row["type"],
                row["action"],
                str(row["scope_matched_incident_count"]),
                str(row["repair_observed_incident_count"]),
                ", ".join(
                    f"{name}={count}"
                    for name, count in row["repair_counts"].items()
                )
                or "-",
            ]
            for row in rule_rows
        ],
    )

    lines = [
        "# Protocol Extension Activation Report",
        "",
        f"Generated: `{report['generated_at_utc']}`",
        "",
        "## Summary",
        "",
        f"- Incidents scanned: `{report['incident_count']}`",
        f"- Candidate actions: `{action_surface['candidate_action_count']}`",
        f"- New candidate actions: `{action_surface['new_action_count']}`",
        f"- Candidate rules: `{report['policy_surface']['rule_count']}`",
        "- Observed zero-cost repair modes: "
        f"`{', '.join(readiness['observed_repair_modes'])}`",
        "- Paid execution status: "
        f"`{readiness['status']}`; provider execution remains unauthorized.",
        "",
        "## Order-Chain Probe",
        "",
        "- Maximum ordering repairs in one deterministic probe: "
        f"`{order_chain['max_order_repairs_in_single_probe']}`",
        f"- Probe action: `{order_chain['action']}`",
        f"- Probe incident: `{order_chain['incident_id']}`",
        f"- Triggered rules: `{', '.join(order_chain['rule_ids'])}`",
        "",
        "## Rule Activation",
        "",
        rule_table,
        "",
        "## Interpretation",
        "",
        "This report is a zero-cost readiness check. It shows whether the current "
        "public corpus and candidate policy surface can exercise richer verifier "
        "behavior before any paid provider call. It does not update the official "
        "freeze and does not establish new model results.",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), "utf-8")


def main() -> None:
    args = parse_args()
    report = build_report(args)
    write_json(args.output_json, report)
    write_markdown(args.output_md, report)
    print(f"Wrote JSON report: {args.output_json}")
    print(f"Wrote Markdown report: {args.output_md}")
    print(
        "Paid execution readiness: "
        f"{report['paid_execution_readiness']['status']}"
    )


if __name__ == "__main__":
    main()
