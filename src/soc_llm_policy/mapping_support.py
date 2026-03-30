from __future__ import annotations

import hashlib
import html
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from soc_llm_policy.json_stability import write_stable_json
from soc_llm_policy.paths import RepoPaths, repo_relative_path, resolve_repo_relative_path


_SUPPORT_TYPES = {
    "zero_match",
    "ambiguous_match",
    "single_keyword_unique_match",
    "multi_keyword_unique_match",
}


@dataclass(frozen=True)
class MappingRule:
    action_id: str
    approval_proxy: bool
    match_policy: str
    priority: int
    keywords: tuple[str, ...]


def normalize_for_match(text: str) -> str:
    normalized = html.unescape(text)
    normalized = re.sub(r"<[^>]+>", " ", normalized)
    normalized = " ".join(normalized.lower().split())
    normalized = unicodedata.normalize("NFKD", normalized)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


def task_text(task: dict[str, Any]) -> str:
    return normalize_for_match(
        " ".join(
            [
                str(task.get("name") or ""),
                str(task.get("description") or ""),
                str(task.get("instructions") or ""),
                str(task.get("instr_text") or ""),
            ]
        )
    )


def load_mapping_rules(mapping_path: Path) -> list[MappingRule]:
    if not mapping_path.exists():
        return []
    raw = yaml.safe_load(mapping_path.read_text(encoding="utf-8"))
    rules_raw = raw.get("rules") if isinstance(raw, dict) else None
    if not isinstance(rules_raw, list):
        return []

    rules: list[MappingRule] = []
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
            candidate = normalize_for_match(str(raw_keyword))
            if not candidate or candidate in seen_keywords:
                continue
            keywords.append(candidate)
            seen_keywords.add(candidate)
        if not keywords:
            continue

        rules.append(
            MappingRule(
                action_id=action_id,
                approval_proxy=bool(
                    item.get("approval_proxy", item.get("approval", False))
                ),
                match_policy=str(item.get("match_policy", "any_keyword")).strip()
                or "any_keyword",
                priority=int(item.get("priority", 0) or 0),
                keywords=tuple(keywords),
            )
        )
    return rules


def load_mapping_support_manifest(
    paths: RepoPaths,
    incident_id: str,
) -> dict[str, Any] | None:
    manifest_path = (
        paths.inbox_incident_dir(incident_id) / "evidence" / "mapping_support_manifest.json"
    )
    if not manifest_path.exists():
        return None
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return None
    return raw


def load_redacted_tasks(
    paths: RepoPaths,
    incident_id: str,
) -> list[dict[str, Any]] | None:
    source_manifest_path = (
        paths.inbox_incident_dir(incident_id) / "evidence" / "source_manifest.json"
    )
    if not source_manifest_path.exists():
        return None
    source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    if not isinstance(source_manifest, dict):
        return None
    redacted_export = source_manifest.get("redacted_export")
    if not isinstance(redacted_export, str) or not redacted_export.strip():
        return None
    export_path = resolve_repo_relative_path(redacted_export, paths.repo_root)
    if not export_path.exists():
        return None
    raw = json.loads(export_path.read_text(encoding="utf-8"))
    tasks = raw.get("extracted_tasks")
    if not isinstance(tasks, list):
        return None
    return [task for task in tasks if isinstance(task, dict)]


def build_mapping_support_manifest(
    *,
    paths: RepoPaths,
    incident_id: str,
    mapping_rules: list[MappingRule] | None = None,
) -> dict[str, Any] | None:
    rules = mapping_rules if mapping_rules is not None else load_mapping_rules(paths.action_mapping_bank_path)
    if not rules:
        return None

    tasks = load_redacted_tasks(paths, incident_id)
    if tasks is None:
        return None

    totals = {
        "task_count": 0,
        "zero_match_count": 0,
        "ambiguous_match_count": 0,
        "single_keyword_unique_match_count": 0,
        "multi_keyword_unique_match_count": 0,
        "approval_proxy_unique_match_count": 0,
    }
    support_by_action: dict[str, dict[str, Any]] = {}

    for task in tasks:
        text = task_text(task)
        if not text:
            continue
        totals["task_count"] += 1
        ranked: list[tuple[int, int, int, MappingRule]] = []
        for rule in rules:
            matched_keywords = [keyword for keyword in rule.keywords if keyword in text]
            if not matched_keywords:
                continue
            score = len(matched_keywords)
            if rule.match_policy == "all_keywords":
                score = len(rule.keywords) if score == len(rule.keywords) else 0
            if score <= 0:
                continue
            ranked.append((score, rule.priority, len(matched_keywords), rule))

        if not ranked:
            totals["zero_match_count"] += 1
            continue

        ranked.sort(key=lambda row: (-row[0], -row[1], -row[2], row[3].action_id))
        top = ranked[0]
        if len(ranked) > 1 and ranked[1][0] == top[0] and ranked[1][1] == top[1]:
            totals["ambiguous_match_count"] += 1
            continue

        matched_keyword_count = top[2]
        rule = top[3]
        support_key = (
            "single_keyword_unique_match_count"
            if matched_keyword_count == 1
            else "multi_keyword_unique_match_count"
        )
        totals[support_key] += 1
        if rule.approval_proxy:
            totals["approval_proxy_unique_match_count"] += 1

        action_support = support_by_action.setdefault(
            rule.action_id,
            {
                "action_id": rule.action_id,
                "approval_proxy": rule.approval_proxy,
                "unique_match_count": 0,
                "single_keyword_unique_match_count": 0,
                "multi_keyword_unique_match_count": 0,
            },
        )
        action_support["unique_match_count"] += 1
        action_support[support_key] += 1

    mapping_rules_sha256 = hashlib.sha256(
        paths.action_mapping_bank_path.read_bytes()
    ).hexdigest()
    support_by_action_items = [
        support_by_action[action_id]
        for action_id in sorted(support_by_action)
    ]

    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "incident_id": incident_id,
        "mapping_rules_path": repo_relative_path(
            paths.action_mapping_bank_path,
            paths.repo_root,
        ),
        "mapping_rules_sha256": mapping_rules_sha256,
        **totals,
        "support_by_action": support_by_action_items,
    }


def write_mapping_support_manifest(
    *,
    paths: RepoPaths,
    incident_id: str,
    mapping_rules: list[MappingRule] | None = None,
) -> Path | None:
    manifest = build_mapping_support_manifest(
        paths=paths,
        incident_id=incident_id,
        mapping_rules=mapping_rules,
    )
    if manifest is None:
        return None
    output_path = (
        paths.inbox_incident_dir(incident_id) / "evidence" / "mapping_support_manifest.json"
    )
    write_stable_json(output_path, manifest)
    return output_path

