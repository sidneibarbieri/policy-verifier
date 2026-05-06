#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from soc_llm_policy.paths import repo_relative_path, resolve_repo_root
from soc_llm_policy.raw_json import load_json_object_with_invalid_escape_repair

MAX_TASK_SAMPLE_NAMES = 3

_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "com",
    "como",
    "da",
    "das",
    "de",
    "do",
    "dos",
    "e",
    "em",
    "for",
    "from",
    "in",
    "is",
    "na",
    "no",
    "nos",
    "of",
    "on",
    "or",
    "os",
    "para",
    "por",
    "the",
    "to",
    "um",
    "uma",
}


def _read_json(path: Path) -> dict[str, Any]:
    payload, _repair_count = load_json_object_with_invalid_escape_repair(path)
    return payload


def _read_yaml(path: Path) -> Any:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return payload


def _normalize_text(value: str) -> str:
    out = html.unescape(value)
    out = re.sub(r"<[^>]+>", " ", out)
    out = " ".join(out.lower().split())
    out = unicodedata.normalize("NFKD", out)
    out = "".join(ch for ch in out if not unicodedata.combining(ch))
    return out


def _task_text(task: dict[str, Any]) -> str:
    base = " ".join(
        [
            str(task.get("name") or ""),
            str(task.get("description") or ""),
            str(task.get("instructions") or ""),
            str(task.get("instr_text") or ""),
        ]
    )
    return _normalize_text(base)


def _safe_slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug or "unknown"


def _load_mapping_rules(path: Path) -> list[dict[str, Any]]:
    payload = _read_yaml(path)
    if not isinstance(payload, dict) or not isinstance(payload.get("rules"), list):
        raise ValueError(f"Invalid mapping rules format: {path}")

    rules: list[dict[str, Any]] = []
    for item in payload["rules"]:
        if not isinstance(item, dict):
            continue
        action_id = str(item.get("action_id") or "").strip()
        keywords_raw = item.get("keywords")
        if not action_id or not isinstance(keywords_raw, list):
            continue
        keywords: list[str] = []
        seen_keywords: set[str] = set()
        for raw_keyword in keywords_raw:
            candidate = _normalize_text(str(raw_keyword))
            if not candidate or candidate in seen_keywords:
                continue
            keywords.append(candidate)
            seen_keywords.add(candidate)
        if not keywords:
            continue
        rules.append(
            {
                "action_id": action_id,
                "approval": bool(
                    item.get("approval_proxy", item.get("approval", False))
                ),
                "keywords": keywords,
            }
        )
    return rules


def _map_task_to_action(
    task: dict[str, Any],
    mapping_rules: list[dict[str, Any]],
) -> tuple[str, bool] | None:
    text = _task_text(task)
    if not text:
        return None
    for rule in mapping_rules:
        keywords = rule["keywords"]
        if any(keyword in text for keyword in keywords):
            return str(rule["action_id"]), bool(rule["approval"])
    return None


def _tokenize(text: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9_]{3,}", text)
    out: list[str] = []
    for token in tokens:
        if token in _STOPWORDS:
            continue
        if token.isdigit():
            continue
        out.append(token)
    return out


def _incident_id_from_raw(raw_data: dict[str, Any], source_path: Path) -> str:
    raw_id = str(raw_data.get("id") or source_path.stem)
    digits = "".join(ch for ch in raw_id if ch.isdigit()) or "000000"
    return f"INC_BANK_{digits}"


def _infer_action_from_cluster(text: str) -> tuple[str, bool]:
    checks: list[tuple[tuple[str, ...], str, bool]] = [
        (("restore", "recuper"), "restore_host", True),
        (("contain", "conten", "isola", "isolat", "erradic"), "isolate_host", True),
        (
            ("forens", "detec", "triag", "cadeia", "binar", "investig"),
            "collect_forensics",
            False,
        ),
        (
            ("credencial", "credential", "identity", "senha", "password"),
            "reset_admin_credentials",
            False,
        ),
        (("egress", "outbound", "saida", "bloque"), "block_egress_ip", False),
    ]

    for prefixes, action_id, approval in checks:
        if any(prefix in text for prefix in prefixes):
            return action_id, approval

    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
    return f"review_task_{digest}", False


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_yaml(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(payload, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:  # noqa: PLR0915
    parser = argparse.ArgumentParser(
        description="Generate safe suggestions for global policy artifacts.",
    )
    parser.add_argument(
        "--raw-incoming-dir",
        default="incoming/raw",
    )
    parser.add_argument(
        "--mapping-rules",
        default="local_redaction/action_mapping_bank.yaml",
    )
    parser.add_argument(
        "--action-catalog",
        default="policy/action_catalog.yaml",
    )
    parser.add_argument(
        "--constraints",
        default="policy/constraints.yaml",
    )
    parser.add_argument(
        "--output-dir",
        default="results/analysis/global_policy_suggestions",
    )
    parser.add_argument(
        "--min-unmapped-frequency",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--max-keywords-per-candidate",
        type=int,
        default=6,
    )
    parser.add_argument(
        "--repo-root",
        default=".",
    )
    args = parser.parse_args()

    repo_root = resolve_repo_root(args.repo_root)
    raw_incoming_dir = Path(args.raw_incoming_dir).expanduser().resolve()
    mapping_rules_path = Path(args.mapping_rules).expanduser().resolve()
    action_catalog_path = Path(args.action_catalog).expanduser().resolve()
    constraints_path = Path(args.constraints).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()

    mapping_rules = _load_mapping_rules(mapping_rules_path)

    action_catalog_raw = _read_yaml(action_catalog_path)
    if not isinstance(action_catalog_raw, list):
        raise ValueError(f"Invalid action catalog format: {action_catalog_path}")
    existing_actions = {
        str(item.get("action_id", "")).strip()
        for item in action_catalog_raw
        if isinstance(item, dict)
    }
    existing_actions.discard("")
    requires_approval_actions = {
        str(item.get("action_id", "")).strip()
        for item in action_catalog_raw
        if isinstance(item, dict) and bool(item.get("requires_approval", False))
    }
    requires_approval_actions.discard("")

    constraints_raw = _read_yaml(constraints_path)
    if not isinstance(constraints_raw, list):
        raise ValueError(f"Invalid constraints format: {constraints_path}")
    require_approval_rules = {
        str(item.get("action", "")).strip()
        for item in constraints_raw
        if isinstance(item, dict)
        and str(item.get("type", "")).strip() == "require_approval"
    }
    require_approval_rules.discard("")

    task_cluster_counter: Counter[str] = Counter()
    task_cluster_tokens: dict[str, Counter[str]] = defaultdict(Counter)
    task_cluster_incidents: dict[str, set[str]] = defaultdict(set)
    task_cluster_samples: dict[str, list[str]] = defaultdict(list)
    mapped_action_counter: Counter[str] = Counter()

    total_incidents = 0
    total_tasks = 0
    mapped_tasks = 0
    unmapped_tasks = 0

    raw_files = sorted(raw_incoming_dir.glob("*.json"))
    for raw_file in raw_files:
        data = _read_json(raw_file)
        incident_id = _incident_id_from_raw(data, raw_file)
        total_incidents += 1
        tasks = data.get("extracted_tasks", [])
        if not isinstance(tasks, list):
            continue

        for task in tasks:
            if not isinstance(task, dict):
                continue
            total_tasks += 1
            mapped = _map_task_to_action(task, mapping_rules)
            if mapped is not None:
                mapped_tasks += 1
                mapped_action_counter[mapped[0]] += 1
                continue

            unmapped_tasks += 1
            task_name = _normalize_text(str(task.get("name") or "")).strip()
            if not task_name:
                task_name = "unnamed_task"
            task_text = _task_text(task)

            task_cluster_counter[task_name] += 1
            task_cluster_incidents[task_name].add(incident_id)
            task_cluster_tokens[task_name].update(_tokenize(task_text))

            sample_name = str(task.get("name") or "").strip()
            if sample_name and sample_name not in task_cluster_samples[task_name]:
                if len(task_cluster_samples[task_name]) < MAX_TASK_SAMPLE_NAMES:
                    task_cluster_samples[task_name].append(sample_name)

    clusters_sorted = sorted(
        task_cluster_counter.items(),
        key=lambda item: (-item[1], item[0]),
    )

    cluster_rows: list[dict[str, Any]] = []
    mapping_candidates: list[dict[str, Any]] = []
    action_catalog_candidates: list[dict[str, Any]] = []
    seen_action_candidates: set[str] = set()

    for cluster_name, count in clusters_sorted:
        token_counter = task_cluster_tokens[cluster_name]
        top_tokens = [token for token, _ in token_counter.most_common(12)]
        hint_text = " ".join([cluster_name, *top_tokens])
        suggested_action_id, suggested_approval = _infer_action_from_cluster(hint_text)
        suggested_keywords = top_tokens[: max(1, int(args.max_keywords_per_candidate))]
        incident_examples = sorted(task_cluster_incidents[cluster_name])
        sample_names = task_cluster_samples[cluster_name]

        cluster_rows.append(
            {
                "normalized_task_name": cluster_name,
                "observed_count": count,
                "incident_examples": ";".join(incident_examples),
                "sample_names": ";".join(sample_names),
                "suggested_action_id": suggested_action_id,
                "suggested_requires_approval": str(suggested_approval).lower(),
                "suggested_keywords": ";".join(suggested_keywords),
                "top_tokens": ";".join(top_tokens),
            }
        )

        if count < int(args.min_unmapped_frequency):
            continue
        if not suggested_keywords:
            continue

        mapping_candidates.append(
            {
                "action_id": suggested_action_id,
                "approval": suggested_approval,
                "keywords": suggested_keywords,
                "source_unmapped_task": cluster_name,
                "observed_count": count,
                "incident_examples": incident_examples,
            }
        )

        if (
            suggested_action_id not in existing_actions
            and suggested_action_id not in seen_action_candidates
        ):
            seen_action_candidates.add(suggested_action_id)
            reversible = suggested_action_id != "restore_host"
            action_catalog_candidates.append(
                {
                    "action_id": suggested_action_id,
                    "requires_approval": suggested_approval,
                    "reversible": reversible,
                }
            )
            if suggested_approval:
                requires_approval_actions.add(suggested_action_id)

    require_approval_candidates: list[dict[str, Any]] = []
    candidate_actions = sorted(requires_approval_actions)
    for action_id in candidate_actions:
        if action_id in require_approval_rules:
            continue
        rule_id = f"AUTO_REQAPP_{_safe_slug(action_id).upper()}"
        require_approval_candidates.append(
            {
                "rule_id": rule_id,
                "type": "require_approval",
                "action": action_id,
                "scope": {"global": True},
                "severity": "hard",
                "notes": "candidate generated from catalog/mapping approval gap",
            }
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(
        output_dir / "unmapped_task_clusters.csv",
        rows=cluster_rows,
        fieldnames=[
            "normalized_task_name",
            "observed_count",
            "incident_examples",
            "sample_names",
            "suggested_action_id",
            "suggested_requires_approval",
            "suggested_keywords",
            "top_tokens",
        ],
    )
    _write_yaml(
        output_dir / "mapping_rule_candidates.yaml", {"rules": mapping_candidates}
    )
    _write_yaml(
        output_dir / "action_catalog_candidates.yaml", action_catalog_candidates
    )
    _write_yaml(output_dir / "constraints_candidates.yaml", require_approval_candidates)

    summary = {
        "raw_incoming_dir": repo_relative_path(raw_incoming_dir, repo_root),
        "mapping_rules_path": repo_relative_path(mapping_rules_path, repo_root),
        "action_catalog_path": repo_relative_path(action_catalog_path, repo_root),
        "constraints_path": repo_relative_path(constraints_path, repo_root),
        "output_dir": repo_relative_path(output_dir, repo_root),
        "incident_count": total_incidents,
        "task_count_total": total_tasks,
        "task_count_mapped": mapped_tasks,
        "task_count_unmapped": unmapped_tasks,
        "mapping_coverage": round((mapped_tasks / total_tasks), 4)
        if total_tasks
        else 0.0,
        "unmapped_cluster_count": len(task_cluster_counter),
        "mapping_rule_candidate_count": len(mapping_candidates),
        "action_catalog_candidate_count": len(action_catalog_candidates),
        "constraints_candidate_count": len(require_approval_candidates),
        "mapped_action_distribution": dict(sorted(mapped_action_counter.items())),
    }
    _write_json(output_dir / "summary.json", summary)

    readme_text = "\n".join(
        [
            "# Global Policy Suggestions",
            "",
            "This directory contains safe suggestions only.",
            "No global file was auto-modified.",
            "",
            "## Files",
            "- `summary.json`: aggregate counts and coverage",
            (
                "- `unmapped_task_clusters.csv`: unmapped task clusters from "
                "raw incoming incidents"
            ),
            (
                "- `mapping_rule_candidates.yaml`: candidate extensions for "
                "`local_redaction/action_mapping_bank.yaml`"
            ),
            (
                "- `action_catalog_candidates.yaml`: candidate actions not "
                "present in `policy/action_catalog.yaml`"
            ),
            (
                "- `constraints_candidates.yaml`: candidate `require_approval` "
                "rules missing from `policy/constraints.yaml`"
            ),
            "",
            "## Suggested review workflow",
            (
                "1. Review `unmapped_task_clusters.csv` and keep only "
                "high-confidence clusters."
            ),
            "2. Promote selected entries to `action_mapping_bank.yaml`.",
            "3. If new action IDs are accepted, promote to `action_catalog.yaml`.",
            (
                "4. For approval-gated actions, promote matching rules to "
                "`constraints.yaml`."
            ),
            "5. Re-run anonymization and dataset audit before evaluation execution.",
            "",
        ]
    )
    (output_dir / "README.md").write_text(readme_text + "\n", encoding="utf-8")

    print(f"Suggestions generated at: {output_dir}")
    print(
        "Coverage snapshot: "
        f"incidents={total_incidents}, tasks={total_tasks}, "
        f"mapped={mapped_tasks}, unmapped={unmapped_tasks}, "
        f"coverage={summary['mapping_coverage']:.4f}"
    )


if __name__ == "__main__":
    main()
