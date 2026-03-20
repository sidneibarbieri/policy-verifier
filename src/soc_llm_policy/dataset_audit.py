from __future__ import annotations

import argparse
import html
import json
import re
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from soc_llm_policy.json_stability import write_stable_json
from soc_llm_policy.io import (
    parse_action_catalog,
    parse_human_actions,
    parse_human_actions_strict_order,
    parse_incident_meta,
    parse_rules,
    parse_telemetry,
    read_json,
    read_jsonl,
    read_yaml_list,
)
from soc_llm_policy.paths import (
    RepoPaths,
    repo_relative_path,
    resolve_repo_relative_path,
    resolve_repo_root,
)
from soc_llm_policy.pipeline import list_inbox_incidents
from soc_llm_policy.privacy_audit import scan_dataset_privacy

_MITRE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", flags=re.IGNORECASE)


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
    all_incidents: bool,
) -> list[str]:
    if all_incidents:
        return list_inbox_incidents(paths)
    incidents = _parse_csv_list(incidents_arg)
    if not incidents:
        raise ValueError("Provide --incidents INC_001,INC_002 or use --all.")
    return incidents


def _safe_validate_global(paths: RepoPaths) -> list[str]:
    errors: list[str] = []
    try:
        parse_action_catalog(read_yaml_list(paths.inbox_action_catalog_path))
    except Exception as exc:
        errors.append(f"invalid action_catalog: {exc}")
    try:
        parse_rules(read_yaml_list(paths.inbox_constraints_path))
    except Exception as exc:
        errors.append(f"invalid constraints: {exc}")
    return errors


def _validate_incident(paths: RepoPaths, incident_id: str) -> dict[str, Any]:
    incident_dir = paths.inbox_incident_dir(incident_id)
    errors: list[str] = []
    warnings: list[str] = []

    if not incident_dir.exists():
        return {
            "incident_id": incident_id,
            "ok": False,
            "errors": [f"missing directory: {incident_dir}"],
            "warnings": [],
            "event_count": 0,
            "action_count": 0,
            "incident_type": None,
        }

    meta_path = incident_dir / "incident_meta.json"
    human_path = incident_dir / "incident_human_actions.jsonl"
    telemetry_path = incident_dir / "incident_telemetry.jsonl"
    datasets_dir = incident_dir / "datasets"

    incident_type: str | None = None
    event_count = 0
    action_count = 0

    if not meta_path.exists():
        errors.append("missing file: incident_meta.json")
    else:
        try:
            meta = parse_incident_meta(read_json(meta_path))
            incident_type = meta.incident_type
        except Exception as exc:
            errors.append(f"invalid incident_meta: {exc}")

    if not human_path.exists():
        errors.append("missing file: incident_human_actions.jsonl")
    else:
        try:
            human_raw = read_jsonl(human_path, strict=True)
            actions = parse_human_actions(human_raw)
            parse_human_actions_strict_order(human_raw)
            action_count = len(actions)
            if action_count == 0:
                warnings.append("incident_human_actions is empty")
        except Exception as exc:
            errors.append(f"invalid incident_human_actions: {exc}")

    has_datasets = datasets_dir.exists() and any(datasets_dir.glob("*.json"))
    if telemetry_path.exists():
        try:
            telemetry = parse_telemetry(read_jsonl(telemetry_path, strict=True))
            event_count = len(telemetry)
            if event_count == 0:
                warnings.append("incident_telemetry is empty")
        except Exception as exc:
            errors.append(f"invalid incident_telemetry: {exc}")
    elif not has_datasets:
        errors.append("missing telemetry: incident_telemetry.jsonl or datasets/*.json")
    else:
        warnings.append("telemetry will be generated from datasets (ETL)")

    return {
        "incident_id": incident_id,
        "ok": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "event_count": event_count,
        "action_count": action_count,
        "incident_type": incident_type,
    }


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


def _safe_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value.strip():
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _privacy_incident_ids(privacy_issues: list[dict[str, Any]]) -> set[str]:
    incident_ids: set[str] = set()
    markers = ("/dataset/incidents/", "/artifact_data/dataset/")
    for issue in privacy_issues:
        file_path = str(issue.get("file", ""))
        for marker in markers:
            if marker not in file_path:
                continue
            trailing = file_path.split(marker, 1)[1]
            incident_id = trailing.split("/", 1)[0].strip()
            if incident_id:
                incident_ids.add(incident_id)
            break
    return incident_ids


def _load_conversion_quality(
    paths: RepoPaths,
    incident_id: str,
) -> dict[str, Any] | None:
    quality_path = paths.inbox_incident_dir(incident_id) / "evidence" / "conversion_quality.json"
    if not quality_path.exists():
        return None
    try:
        raw = json.loads(quality_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    return raw


def _load_source_manifest(
    paths: RepoPaths,
    incident_id: str,
) -> dict[str, Any] | None:
    manifest_path = paths.inbox_incident_dir(incident_id) / "evidence" / "source_manifest.json"
    if not manifest_path.exists():
        return None
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    return raw


def _normalize_for_match(text: str) -> str:
    out = html.unescape(text)
    out = re.sub(r"<[^>]+>", " ", out)
    out = " ".join(out.lower().split())
    out = unicodedata.normalize("NFKD", out)
    return "".join(ch for ch in out if not unicodedata.combining(ch))


def _load_mapping_rules(paths: RepoPaths) -> list[dict[str, Any]]:
    mapping_path = paths.action_mapping_bank_path
    if not mapping_path.exists():
        return []
    try:
        raw = yaml.safe_load(mapping_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    rules_raw = raw.get("rules") if isinstance(raw, dict) else None
    if not isinstance(rules_raw, list):
        return []
    rules: list[dict[str, Any]] = []
    for item in rules_raw:
        if not isinstance(item, dict):
            continue
        action_id = str(item.get("action_id") or "").strip()
        keywords_raw = item.get("keywords")
        if not action_id or not isinstance(keywords_raw, list):
            continue
        keywords: list[str] = []
        seen_keywords: set[str] = set()
        for raw_keyword in keywords_raw:
            candidate = _normalize_for_match(str(raw_keyword))
            if not candidate or candidate in seen_keywords:
                continue
            keywords.append(candidate)
            seen_keywords.add(candidate)
        if not keywords:
            continue
        rules.append(
            {
                "action_id": action_id,
                "keywords": keywords,
                "match_policy": str(item.get("match_policy", "any_keyword")).strip()
                or "any_keyword",
                "priority": int(item.get("priority", 0)),
            }
        )
    return rules


def _load_global_artifact_scope(paths: RepoPaths) -> dict[str, Any]:
    catalog = parse_action_catalog(read_yaml_list(paths.inbox_action_catalog_path))
    rules = parse_rules(read_yaml_list(paths.inbox_constraints_path))
    mapping_rules = _load_mapping_rules(paths)

    catalog_actions = sorted({item.action_id for item in catalog})
    mapping_actions = sorted(
        {
            str(rule.get("action_id", "")).strip()
            for rule in mapping_rules
            if str(rule.get("action_id", "")).strip()
        }
    )
    constrained_actions = sorted({rule.action for rule in rules})

    rule_type_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for rule in rules:
        rule_type_counts[rule.type] = rule_type_counts.get(rule.type, 0) + 1
        severity_counts[rule.severity] = severity_counts.get(rule.severity, 0) + 1

    catalog_action_count = len(catalog_actions)
    mapping_action_coverage = (
        round(len(set(mapping_actions) & set(catalog_actions)) / catalog_action_count, 4)
        if catalog_action_count > 0
        else 0.0
    )
    constrained_action_coverage = (
        round(
            len(set(constrained_actions) & set(catalog_actions)) / catalog_action_count,
            4,
        )
        if catalog_action_count > 0
        else 0.0
    )

    return {
        "action_catalog_count": catalog_action_count,
        "requires_approval_action_count": sum(
            1 for item in catalog if item.requires_approval
        ),
        "reversible_action_count": sum(1 for item in catalog if item.reversible),
        "mapping_rule_count": len(mapping_rules),
        "mapping_action_count": len(mapping_actions),
        "mapping_action_coverage_over_catalog": mapping_action_coverage,
        "catalog_actions_missing_mapping_rules": sorted(
            set(catalog_actions) - set(mapping_actions)
        ),
        "policy_rule_count": len(rules),
        "policy_rule_type_counts": rule_type_counts,
        "policy_severity_counts": severity_counts,
        "constrained_action_count": len(constrained_actions),
        "policy_action_coverage_over_catalog": constrained_action_coverage,
    }


def _load_redacted_tasks(
    paths: RepoPaths,
    incident_id: str,
) -> list[dict[str, Any]] | None:
    manifest = _load_source_manifest(paths, incident_id)
    if manifest is None:
        return None
    redacted_export = manifest.get("redacted_export")
    if not isinstance(redacted_export, str) or not redacted_export.strip():
        return None
    export_path = resolve_repo_relative_path(redacted_export, paths.repo_root)
    if not export_path.exists():
        return None
    try:
        raw = json.loads(export_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    tasks = raw.get("extracted_tasks")
    if not isinstance(tasks, list):
        return None
    return [task for task in tasks if isinstance(task, dict)]


def _task_text(task: dict[str, Any]) -> str:
    return _normalize_for_match(
        " ".join(
            [
                str(task.get("name") or ""),
                str(task.get("description") or ""),
                str(task.get("instructions") or ""),
                str(task.get("instr_text") or ""),
            ]
        )
    )


def _audit_mapping_sensitivity(
    *,
    tasks: list[dict[str, Any]],
    mapping_rules: list[dict[str, Any]],
) -> dict[str, int]:
    metrics = {
        "task_count": 0,
        "zero_match_count": 0,
        "ambiguous_match_count": 0,
        "single_keyword_unique_match_count": 0,
        "multi_keyword_unique_match_count": 0,
    }
    for task in tasks:
        text = _task_text(task)
        if not text:
            continue
        metrics["task_count"] += 1
        ranked: list[tuple[int, int, int]] = []
        for rule in mapping_rules:
            keywords = [keyword for keyword in rule["keywords"] if keyword in text]
            if not keywords:
                continue
            score = len(keywords)
            if str(rule.get("match_policy", "any_keyword")) == "all_keywords":
                score = len(rule["keywords"]) if score == len(rule["keywords"]) else 0
            if score <= 0:
                continue
            ranked.append((score, int(rule.get("priority", 0)), len(keywords)))
        if not ranked:
            metrics["zero_match_count"] += 1
            continue

        ranked.sort(key=lambda row: (-row[0], -row[1], -row[2]))
        top = ranked[0]
        if len(ranked) > 1 and ranked[1][0] == top[0] and ranked[1][1] == top[1]:
            metrics["ambiguous_match_count"] += 1
            continue

        matched_keyword_count = top[2]
        if matched_keyword_count == 1:
            metrics["single_keyword_unique_match_count"] += 1
        else:
            metrics["multi_keyword_unique_match_count"] += 1
    return metrics


def _walk_strings(value: Any) -> list[str]:
    out: list[str] = []
    stack: list[Any] = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            out.append(current)
            continue
        if isinstance(current, dict):
            stack.extend(current.values())
            continue
        if isinstance(current, list):
            stack.extend(current)
            continue
    return out


def _extract_mitre_features(event: dict[str, Any]) -> tuple[set[str], set[str]]:
    mitre_ids: set[str] = set()
    mitre_labels: set[str] = set()

    text_pool = _walk_strings(event)
    for text in text_pool:
        for match in _MITRE_ID_RE.findall(text):
            mitre_ids.add(match.upper())

    for key, value in event.items():
        if "mitre" in str(key).lower():
            for text in _walk_strings(value):
                label = text.strip()
                if label:
                    mitre_labels.add(label)
    details = event.get("details")
    if isinstance(details, dict):
        for key, value in details.items():
            if "technique" in str(key).lower() and isinstance(value, str):
                label = value.strip()
                if label:
                    mitre_labels.add(label)
            if "mitre" in str(key).lower():
                for text in _walk_strings(value):
                    label = text.strip()
                    if label:
                        mitre_labels.add(label)
    return mitre_ids, mitre_labels


def _load_incident_telemetry_events(paths: RepoPaths, incident_id: str) -> list[dict[str, Any]]:
    telemetry_path = paths.inbox_incident_dir(incident_id) / "incident_telemetry.jsonl"
    if not telemetry_path.exists():
        return []
    try:
        rows = read_jsonl(telemetry_path, strict=True)
    except Exception:
        return []
    if not isinstance(rows, list):
        return []
    return [item for item in rows if isinstance(item, dict)]


def _build_corpus_readiness(
    *,
    incidents: list[str],
    incident_results: list[dict[str, Any]],
    incident_type_counts: dict[str, int],
    privacy_issues: list[dict[str, Any]],
    paths: RepoPaths,
) -> dict[str, Any]:
    global_scope = _load_global_artifact_scope(paths)
    valid_incidents = [item for item in incident_results if bool(item.get("ok"))]
    event_counts = [int(item.get("event_count", 0)) for item in valid_incidents]
    action_counts = [int(item.get("action_count", 0)) for item in valid_incidents]
    privacy_incident_ids = _privacy_incident_ids(privacy_issues)

    conversion_coverages: list[float] = []
    conversion_count = 0
    missing_conversion_count = 0
    task_count_total = 0
    mapped_task_count_total = 0
    unmatched_task_count_total = 0
    fallback_used_count = 0
    deduplicated_action_count_total = 0
    sensitivity_incident_count = 0
    sensitivity_task_count_total = 0
    ambiguous_match_count_total = 0
    zero_match_count_total = 0
    single_keyword_unique_match_count_total = 0
    multi_keyword_unique_match_count_total = 0
    mitre_technique_ids: set[str] = set()
    mitre_technique_labels: set[str] = set()
    mapping_rules = _load_mapping_rules(paths)
    for incident_id in incidents:
        for event in _load_incident_telemetry_events(paths, incident_id):
            ids, labels = _extract_mitre_features(event)
            mitre_technique_ids.update(ids)
            mitre_technique_labels.update(labels)
        if mapping_rules:
            redacted_tasks = _load_redacted_tasks(paths, incident_id)
            if redacted_tasks is not None:
                sensitivity = _audit_mapping_sensitivity(
                    tasks=redacted_tasks,
                    mapping_rules=mapping_rules,
                )
                sensitivity_incident_count += 1
                sensitivity_task_count_total += sensitivity["task_count"]
                ambiguous_match_count_total += sensitivity["ambiguous_match_count"]
                zero_match_count_total += sensitivity["zero_match_count"]
                single_keyword_unique_match_count_total += sensitivity[
                    "single_keyword_unique_match_count"
                ]
                multi_keyword_unique_match_count_total += sensitivity[
                    "multi_keyword_unique_match_count"
                ]
        quality = _load_conversion_quality(paths, incident_id)
        if quality is None:
            missing_conversion_count += 1
            continue
        conversion_count += 1
        task_count_total += _safe_int(quality.get("task_count"))
        mapped_task_count_total += _safe_int(quality.get("mapped_task_count"))
        unmatched_task_count_total += _safe_int(quality.get("unmatched_task_count"))
        if bool(quality.get("fallback_used", False)):
            fallback_used_count += 1
        deduplicated_action_count_total += _safe_int(
            quality.get("deduplicated_action_count")
        )
        coverage = _safe_float(quality.get("mapping_coverage"))
        if coverage is not None:
            conversion_coverages.append(coverage)

    weighted_mapping_coverage = (
        round(mapped_task_count_total / task_count_total, 4)
        if task_count_total > 0
        else None
    )
    privacy_pass_rate = (
        round((len(incidents) - len(privacy_incident_ids)) / len(incidents), 4)
        if incidents
        else 0.0
    )
    events_per_incident_avg = (
        round(sum(event_counts) / len(valid_incidents), 4) if valid_incidents else 0.0
    )
    actions_per_incident_avg = (
        round(sum(action_counts) / len(valid_incidents), 4) if valid_incidents else 0.0
    )
    tasks_per_incident_avg = (
        round(task_count_total / conversion_count, 4) if conversion_count > 0 else 0.0
    )
    mapped_tasks_per_incident_avg = (
        round(mapped_task_count_total / conversion_count, 4)
        if conversion_count > 0
        else 0.0
    )
    fallback_usage_rate = (
        round(fallback_used_count / conversion_count, 4) if conversion_count > 0 else 0.0
    )
    unmatched_tasks_per_incident_avg = (
        round(unmatched_task_count_total / conversion_count, 4)
        if conversion_count > 0
        else 0.0
    )
    ambiguous_match_rate = (
        round(ambiguous_match_count_total / sensitivity_task_count_total, 4)
        if sensitivity_task_count_total > 0
        else 0.0
    )
    zero_match_rate = (
        round(zero_match_count_total / sensitivity_task_count_total, 4)
        if sensitivity_task_count_total > 0
        else 0.0
    )
    single_keyword_unique_match_rate = (
        round(
            single_keyword_unique_match_count_total / sensitivity_task_count_total,
            4,
        )
        if sensitivity_task_count_total > 0
        else 0.0
    )
    multi_keyword_unique_match_rate = (
        round(
            multi_keyword_unique_match_count_total / sensitivity_task_count_total,
            4,
        )
        if sensitivity_task_count_total > 0
        else 0.0
    )

    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "incident_count": len(incidents),
        "valid_incident_count": len(valid_incidents),
        "invalid_incident_count": len(incidents) - len(valid_incidents),
        "privacy_issue_count": len(privacy_issues),
        "privacy_incident_count": len(privacy_incident_ids),
        "privacy_pass_rate": privacy_pass_rate,
        "events_per_incident_avg": events_per_incident_avg,
        "actions_per_incident_avg": actions_per_incident_avg,
        "mitre_technique_diversity": {
            "technique_id_count": len(mitre_technique_ids),
            "technique_label_count": len(mitre_technique_labels),
            "technique_ids": sorted(mitre_technique_ids),
        },
        "event_count_total": sum(event_counts),
        "event_count_min": min(event_counts) if event_counts else 0,
        "event_count_max": max(event_counts) if event_counts else 0,
        "action_count_total": sum(action_counts),
        "action_count_min": min(action_counts) if action_counts else 0,
        "action_count_max": max(action_counts) if action_counts else 0,
        "incident_type_counts": incident_type_counts,
        "global_artifact_scope": global_scope,
        "mapping_quality": {
            "incidents_with_conversion_quality": conversion_count,
            "incidents_missing_conversion_quality": missing_conversion_count,
            "task_count_total": task_count_total,
            "mapped_task_count_total": mapped_task_count_total,
            "unmatched_task_count_total": unmatched_task_count_total,
            "fallback_used_count": fallback_used_count,
            "fallback_usage_rate": fallback_usage_rate,
            "deduplicated_action_count_total": deduplicated_action_count_total,
            "weighted_mapping_coverage": weighted_mapping_coverage,
            "tasks_per_incident_avg": tasks_per_incident_avg,
            "mapped_tasks_per_incident_avg": mapped_tasks_per_incident_avg,
            "unmatched_tasks_per_incident_avg": unmatched_tasks_per_incident_avg,
            "sensitivity_incident_count": sensitivity_incident_count,
            "sensitivity_task_count_total": sensitivity_task_count_total,
            "ambiguous_match_count": ambiguous_match_count_total,
            "ambiguous_match_rate": ambiguous_match_rate,
            "zero_match_count": zero_match_count_total,
            "zero_match_rate": zero_match_rate,
            "single_keyword_unique_match_count": single_keyword_unique_match_count_total,
            "single_keyword_unique_match_rate": single_keyword_unique_match_rate,
            "multi_keyword_unique_match_count": multi_keyword_unique_match_count_total,
            "multi_keyword_unique_match_rate": multi_keyword_unique_match_rate,
            "coverage_min": round(min(conversion_coverages), 4)
            if conversion_coverages
            else None,
            "coverage_max": round(max(conversion_coverages), 4)
            if conversion_coverages
            else None,
            "coverage_avg": round(
                sum(conversion_coverages) / len(conversion_coverages), 4
            )
            if conversion_coverages
            else None,
        },
    }


def audit_dataset(
    *,
    paths: RepoPaths,
    incidents: list[str],
) -> dict[str, Any]:
    global_errors = _safe_validate_global(paths)
    incident_results = [
        _validate_incident(paths, incident_id) for incident_id in incidents
    ]
    invalid_incidents = [
        item["incident_id"] for item in incident_results if not item["ok"]
    ]
    warning_count = sum(len(item["warnings"]) for item in incident_results)

    incident_type_counts: dict[str, int] = {}
    for item in incident_results:
        incident_type = item["incident_type"]
        if isinstance(incident_type, str) and incident_type:
            incident_type_counts[incident_type] = (
                incident_type_counts.get(incident_type, 0) + 1
            )
    privacy_report = scan_dataset_privacy(paths=paths, incidents=incidents)
    privacy_issues = list(privacy_report["issues"])
    corpus_readiness = _build_corpus_readiness(
        incidents=incidents,
        incident_results=incident_results,
        incident_type_counts=incident_type_counts,
        privacy_issues=privacy_issues,
        paths=paths,
    )

    return {
        "ok": (
            len(global_errors) == 0
            and len(invalid_incidents) == 0
            and len(privacy_issues) == 0
        ),
        "global_errors": global_errors,
        "incident_count": len(incidents),
        "invalid_incident_count": len(invalid_incidents),
        "invalid_incidents": invalid_incidents,
        "warning_count": warning_count,
        "incident_type_counts": incident_type_counts,
        "privacy_policy_path": repo_relative_path(
            Path(privacy_report["policy_path"]),
            paths.repo_root,
        ),
        "forbidden_terms": privacy_report["forbidden_terms"],
        "privacy_issue_count": privacy_report["issue_count"],
        "privacy_issues": privacy_issues,
        "corpus_readiness": corpus_readiness,
        "incidents": incident_results,
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    write_stable_json(path, payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soc_llm_policy.dataset_audit")
    parser.add_argument("--repo-root", default=None)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--incidents", default=None, help="CSV: INC_001,INC_002")
    group.add_argument("--all", action="store_true")
    parser.add_argument(
        "--output-json",
        default="results/analysis/dataset_audit.json",
    )
    parser.add_argument(
        "--readiness-json",
        default="results/analysis/corpus_readiness.json",
        help="Path for aggregated corpus readiness report.",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Return exit code 1 when validation errors are present.",
    )
    parser.add_argument(
        "--fail-on-pii",
        action="store_true",
        help="Return exit code 1 when privacy/anonymization issues are detected.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    repo_root = resolve_repo_root(args.repo_root)
    paths = RepoPaths(repo_root=repo_root)
    incidents = _resolve_incidents(paths, args.incidents, bool(args.all))
    report = audit_dataset(paths=paths, incidents=incidents)
    output_path = Path(args.output_json).expanduser().resolve()
    readiness_path = Path(args.readiness_json).expanduser().resolve()
    _write_json(output_path, report)
    _write_json(readiness_path, report["corpus_readiness"])
    print(f"Report saved at: {output_path}")
    print(f"Corpus readiness saved at: {readiness_path}")
    if report["ok"]:
        print(f"Dataset audit OK ({report['incident_count']} incidents).")
        return
    print(
        "Dataset audit found issues: "
        f"{report['invalid_incident_count']} invalid incident(s), "
        f"{len(report['global_errors'])} global error(s)."
    )
    pii_issue_count = int(report.get("privacy_issue_count", 0))
    if pii_issue_count > 0:
        print(f"Privacy issues found: {pii_issue_count}")
    if args.fail_on_error:
        raise SystemExit(1)
    if args.fail_on_pii and pii_issue_count > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
