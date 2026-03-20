from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from soc_llm_policy.engine import telemetry_has_indicator
from soc_llm_policy.io import (
    parse_action_catalog,
    parse_human_actions,
    parse_rules,
    parse_telemetry,
    read_jsonl,
    read_yaml_list,
)
from soc_llm_policy.json_stability import write_stable_json
from soc_llm_policy.paths import RepoPaths, repo_relative_path, resolve_repo_root
from soc_llm_policy.pipeline import list_inbox_incidents


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {}
    return raw


def _load_mapping_rules(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = raw.get("rules") if isinstance(raw, dict) else None
    if not isinstance(rules, list):
        return []
    out: list[dict[str, Any]] = []
    for item in rules:
        if not isinstance(item, dict):
            continue
        action_id = str(item.get("action_id") or "").strip()
        keywords = item.get("keywords")
        if not action_id or not isinstance(keywords, list):
            continue
        out.append(
            {
                "action_id": action_id,
                "approval_proxy": bool(item.get("approval_proxy", item.get("approval", False))),
                "match_policy": str(item.get("match_policy", "any_keyword")).strip()
                or "any_keyword",
                "priority": int(item.get("priority", 0) or 0),
                "keywords": [str(keyword) for keyword in keywords if str(keyword).strip()],
            }
        )
    return out


def _incident_ids(paths: RepoPaths, include_all: bool, incidents_csv: str | None) -> list[str]:
    if include_all:
        return list_inbox_incidents(paths)
    if not incidents_csv:
        raise ValueError("Provide --incidents or --all.")
    values = [part.strip() for part in incidents_csv.split(",") if part.strip()]
    return sorted(set(values))


def _build_action_stats(paths: RepoPaths, incident_ids: list[str]) -> dict[str, Any]:
    action_counts: Counter[str] = Counter()
    action_incidents: dict[str, set[str]] = defaultdict(set)
    approval_counts: Counter[str] = Counter()
    approval_incidents: dict[str, set[str]] = defaultdict(set)
    ordered_actions_by_incident: dict[str, list[str]] = {}
    telemetry_by_incident: dict[str, list[Any]] = {}
    verifier_by_incident: dict[str, dict[str, Any]] = {}

    for incident_id in incident_ids:
        incident_dir = paths.inbox_incident_dir(incident_id)
        human_actions = parse_human_actions(read_jsonl(incident_dir / "incident_human_actions.jsonl", strict=True))
        telemetry = parse_telemetry(read_jsonl(incident_dir / "incident_telemetry.jsonl", strict=True))
        ordered_actions = [action.action_id for action in human_actions]
        ordered_actions_by_incident[incident_id] = ordered_actions
        telemetry_by_incident[incident_id] = telemetry
        verifier_path = paths.outputs_incident_dir(incident_id) / "verifier_output.json"
        verifier_by_incident[incident_id] = _read_json_object(verifier_path)

        for action in human_actions:
            action_counts[action.action_id] += 1
            action_incidents[action.action_id].add(incident_id)
            if bool(action.approval):
                approval_counts[action.action_id] += 1
                approval_incidents[action.action_id].add(incident_id)

    return {
        "action_counts": action_counts,
        "action_incidents": action_incidents,
        "approval_counts": approval_counts,
        "approval_incidents": approval_incidents,
        "ordered_actions_by_incident": ordered_actions_by_incident,
        "telemetry_by_incident": telemetry_by_incident,
        "verifier_by_incident": verifier_by_incident,
    }


def build_global_provenance(
    *,
    paths: RepoPaths,
    incident_ids: list[str],
) -> dict[str, Any]:
    freeze_manifest = _read_json_object(paths.outputs_analysis_dir / "protocol_freeze.json")
    summary = _read_json_object(paths.outputs_analysis_dir / "summary.json")
    catalog = parse_action_catalog(read_yaml_list(paths.inbox_action_catalog_path))
    rules = parse_rules(read_yaml_list(paths.inbox_constraints_path))
    mapping_rules = _load_mapping_rules(paths.action_mapping_bank_path)
    stats = _build_action_stats(paths, incident_ids)

    constrained_actions: dict[str, list[str]] = defaultdict(list)
    for rule in rules:
        constrained_actions[rule.action].append(rule.rule_id)

    mapped_actions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rule in mapping_rules:
        mapped_actions[str(rule["action_id"])].append(rule)

    action_items: list[dict[str, Any]] = []
    for item in catalog:
        action_items.append(
            {
                "action_id": item.action_id,
                "requires_approval": item.requires_approval,
                "reversible": item.reversible,
                "observed_in_human_baseline": item.action_id in stats["action_incidents"],
                "observed_incident_count": len(stats["action_incidents"].get(item.action_id, set())),
                "observed_action_count": int(stats["action_counts"].get(item.action_id, 0)),
                "approved_incident_count": len(stats["approval_incidents"].get(item.action_id, set())),
                "approved_action_count": int(stats["approval_counts"].get(item.action_id, 0)),
                "constrained_by_rule_ids": sorted(constrained_actions.get(item.action_id, [])),
                "covered_by_mapping_rule": item.action_id in mapped_actions,
                "mapping_rule_count": len(mapped_actions.get(item.action_id, [])),
                "provenance_basis": [
                    "institution_authored_global_artifact",
                    "corpus_audit_51_incidents",
                    "manual_versioned_freeze",
                ],
            }
        )

    rule_items: list[dict[str, Any]] = []
    for rule in rules:
        applicable_incidents = 0
        human_violation_incidents = 0
        human_action_incidents = 0
        approval_context_incidents = 0

        for incident_id in incident_ids:
            ordered_actions = stats["ordered_actions_by_incident"][incident_id]
            telemetry = stats["telemetry_by_incident"][incident_id]
            action_present = rule.action in ordered_actions
            if action_present:
                human_action_incidents += 1

            if rule.type == "mandatory":
                scope = rule.scope or {}
                event_type_contains = scope.get("event_type_contains") or []
                command_contains = scope.get("command_contains") or []
                if telemetry_has_indicator(
                    telemetry=telemetry,
                    event_type_contains=event_type_contains if isinstance(event_type_contains, list) else [],
                    command_contains=command_contains if isinstance(command_contains, list) else [],
                ):
                    applicable_incidents += 1
                    if not action_present:
                        human_violation_incidents += 1
            elif rule.type == "prohibit_before":
                if action_present:
                    applicable_incidents += 1
                    condition_action = rule.condition_action or ""
                    if condition_action not in ordered_actions:
                        human_violation_incidents += 1
                    else:
                        if ordered_actions.index(condition_action) > ordered_actions.index(rule.action):
                            human_violation_incidents += 1
            elif rule.type == "require_approval":
                if action_present:
                    applicable_incidents += 1
                    verifier_output = stats["verifier_by_incident"].get(incident_id, {})
                    approved_actions = verifier_output.get("incident_approved_actions", [])
                    if isinstance(approved_actions, list) and rule.action in approved_actions:
                        approval_context_incidents += 1
                    else:
                        human_violation_incidents += 1

        provenance_basis = [
            "institution_authored_global_artifact",
            "manual_versioned_freeze",
        ]
        decision_record = None
        if rule.rule_id == "R4":
            provenance_basis.append("corpus_audit_candidate_promoted_after_manual_review")
            decision_record = "docs/EVAL_PROTOCOL.md"
        else:
            provenance_basis.append("institutional_policy_rule")

        rule_items.append(
            {
                "rule_id": rule.rule_id,
                "type": rule.type,
                "severity": rule.severity,
                "action": rule.action,
                "condition_action": rule.condition_action,
                "scope": rule.scope or {},
                "applicable_incident_count": applicable_incidents,
                "human_action_incident_count": human_action_incidents,
                "human_violation_incident_count": human_violation_incidents,
                "approval_context_incident_count": approval_context_incidents,
                "decision_record": decision_record,
                "provenance_basis": provenance_basis,
            }
        )

    mapping_items: list[dict[str, Any]] = []
    for rule in mapping_rules:
        action_id = str(rule["action_id"])
        mapping_items.append(
            {
                "action_id": action_id,
                "match_policy": rule["match_policy"],
                "priority": int(rule["priority"]),
                "approval_proxy": bool(rule["approval_proxy"]),
                "keyword_count": len(rule["keywords"]),
                "keywords": rule["keywords"],
                "mapped_incident_count": len(stats["action_incidents"].get(action_id, set())),
                "mapped_action_count": int(stats["action_counts"].get(action_id, 0)),
                "provenance_basis": [
                    "institution_authored_mapping_contract",
                    "manual_keyword_curation",
                    "corpus_audit_coverage_review",
                ],
            }
        )

    attack_raw = yaml.safe_load(paths.attack_mapping_path.read_text(encoding="utf-8"))
    attack_rule_items = attack_raw if isinstance(attack_raw, list) else []
    attack_techniques = {
        str(item.get("technique_id"))
        for item in attack_rule_items
        if isinstance(item, dict) and str(item.get("technique_id") or "").strip()
    }
    attack_tactics = {
        str(item.get("tactic_id"))
        for item in attack_rule_items
        if isinstance(item, dict) and str(item.get("tactic_id") or "").strip()
    }
    attack_summary = summary.get("attack_technique_counts", {}) if isinstance(summary, dict) else {}
    if isinstance(attack_summary, dict):
        matched_technique_ids = {
            str(technique_id).strip()
            for technique_id in attack_summary.keys()
            if str(technique_id).strip()
        }
    else:
        matched_technique_ids = {
            str(item.get("technique_id"))
            for item in attack_summary
            if isinstance(item, dict) and str(item.get("technique_id") or "").strip()
        }
    tactic_summary = summary.get("attack_tactic_counts", {}) if isinstance(summary, dict) else {}
    if isinstance(tactic_summary, dict):
        matched_tactic_ids = {
            str(tactic_id).strip()
            for tactic_id in tactic_summary.keys()
            if str(tactic_id).strip()
        }
    else:
        matched_tactic_ids = {
            str(item.get("tactic_id"))
            for item in tactic_summary
            if isinstance(item, dict) and str(item.get("tactic_id") or "").strip()
        }

    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "dataset_release_id": freeze_manifest.get("dataset_release_id", "unknown"),
        "eval_protocol_version": freeze_manifest.get("eval_protocol_version", "unknown"),
        "incident_count": len(incident_ids),
        "input_hashes": {
            "action_catalog": _sha256_file(paths.inbox_action_catalog_path),
            "constraints": _sha256_file(paths.inbox_constraints_path),
            "action_mapping_bank": _sha256_file(paths.action_mapping_bank_path),
            "attack_mapping": _sha256_file(paths.attack_mapping_path),
        },
        "global_artifact_scope": {
            "action_catalog_count": len(action_items),
            "policy_rule_count": len(rule_items),
            "mapping_rule_count": len(mapping_items),
            "attack_mapping_rule_count": len(attack_rule_items),
            "attack_mapping_technique_count": len(attack_techniques),
            "attack_mapping_tactic_count": len(attack_tactics),
            "corpus_matched_attack_technique_count": len(matched_technique_ids),
            "corpus_matched_attack_tactic_count": len(matched_tactic_ids),
        },
        "action_catalog": {
            "path": repo_relative_path(paths.inbox_action_catalog_path, paths.repo_root),
            "items": action_items,
        },
        "policy_rules": {
            "path": repo_relative_path(paths.inbox_constraints_path, paths.repo_root),
            "items": rule_items,
        },
        "mapping_rules": {
            "path": repo_relative_path(paths.action_mapping_bank_path, paths.repo_root),
            "items": mapping_items,
        },
        "attack_mapping": {
            "path": repo_relative_path(paths.attack_mapping_path, paths.repo_root),
            "heuristic_status": "coverage_enrichment_only",
            "matched_signal_note": "ATT&CK remains heuristic enrichment over normalized event type, category, and case-note text.",
            "rule_count": len(attack_rule_items),
            "technique_count": len(attack_techniques),
            "tactic_count": len(attack_tactics),
            "corpus_matched_technique_count": len(matched_technique_ids),
            "corpus_matched_tactic_count": len(matched_tactic_ids),
        },
        "notes": [
            "Global artifacts are institution-authored and versioned; the corpus provides evidence for coverage review and candidate gaps, not automatic promotion.",
            "This provenance manifest is intended to make action, rule, and mapping scope auditable under the active freeze.",
        ],
    }


def _render_markdown(report: dict[str, Any]) -> str:
    scope = report.get("global_artifact_scope", {})
    lines = [
        "# Global Artifact Provenance",
        "",
        f"- Dataset release: `{report.get('dataset_release_id', 'unknown')}`",
        f"- Protocol version: `{report.get('eval_protocol_version', 'unknown')}`",
        f"- Incident count audited: `{report.get('incident_count', 0)}`",
        f"- Action catalog entries: `{scope.get('action_catalog_count', 0)}`",
        f"- Policy rules: `{scope.get('policy_rule_count', 0)}`",
        f"- Mapping rules: `{scope.get('mapping_rule_count', 0)}`",
        f"- ATT&CK mapping rules: `{scope.get('attack_mapping_rule_count', 0)}`",
        "",
        "## Action catalog",
    ]
    for item in report.get("action_catalog", {}).get("items", []):
        lines.append(
            f"- `{item['action_id']}`: observed in {item['observed_incident_count']} incidents "
            f"({item['observed_action_count']} mapped actions), "
            f"approval-gated={str(item['requires_approval']).lower()}, "
            f"constrained by {item['constrained_by_rule_ids'] or '[]'}"
        )
    lines.extend(["", "## Policy rules"])
    for item in report.get("policy_rules", {}).get("items", []):
        lines.append(
            f"- `{item['rule_id']}` ({item['type']} -> `{item['action']}`): "
            f"applicable to {item['applicable_incident_count']} incidents, "
            f"human-baseline violations={item['human_violation_incident_count']}"
        )
    lines.extend(
        [
            "",
            "## Mapping rules",
        ]
    )
    for item in report.get("mapping_rules", {}).get("items", []):
        lines.append(
            f"- `{item['action_id']}` mapping: {item['keyword_count']} keywords, "
            f"match policy `{item['match_policy']}`, observed in {item['mapped_incident_count']} incidents"
        )
    lines.extend(
        [
            "",
            "## ATT&CK layer",
            f"- Rule count: `{report.get('attack_mapping', {}).get('rule_count', 0)}`",
            f"- Techniques covered by mapping: `{report.get('attack_mapping', {}).get('technique_count', 0)}`",
            f"- Tactics covered by mapping: `{report.get('attack_mapping', {}).get('tactic_count', 0)}`",
            f"- Corpus-matched techniques: `{report.get('attack_mapping', {}).get('corpus_matched_technique_count', 0)}`",
            f"- Corpus-matched tactics: `{report.get('attack_mapping', {}).get('corpus_matched_tactic_count', 0)}`",
            "- Status: heuristic coverage enrichment only, not technique-level ground truth.",
        ]
    )
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc_llm_policy.global_provenance",
        description="Write a canonical provenance report for the active global artifacts.",
    )
    parser.add_argument("--repo-root", default=None)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--incidents", default=None)
    parser.add_argument(
        "--output-json",
        default="results/analysis/global_artifact_provenance.json",
    )
    parser.add_argument(
        "--output-md",
        default="results/analysis/global_artifact_provenance.md",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = resolve_repo_root(args.repo_root)
    paths = RepoPaths(repo_root=repo_root)
    incident_ids = _incident_ids(paths, bool(args.all), args.incidents)
    report = build_global_provenance(paths=paths, incident_ids=incident_ids)

    output_json = Path(args.output_json)
    if not output_json.is_absolute():
        output_json = repo_root / output_json
    write_stable_json(output_json, report)

    output_md = Path(args.output_md)
    if not output_md.is_absolute():
        output_md = repo_root / output_md
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(_render_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
