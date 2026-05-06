#!/usr/bin/env python3
from __future__ import annotations

import argparse
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

from soc_llm_policy.paths import repo_relative_path, resolve_repo_root
from soc_llm_policy.raw_json import load_json_object_with_invalid_escape_repair

MIN_RANKED_CANDIDATES_FOR_TIE = 2
MAX_MAPPING_QUALITY_EXAMPLES = 5
LEGACY_CONVERT_ONE_PATH_COUNT = 4

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
PHONE_RE = re.compile(
    r"(?:\b\d{4}\s*\(\d{2}\)\s*\d{8,9}\b)|"
    r"(?:\+?\d{1,3}\s*\(?\d{2}\)?\s*\d{4,5}[-\s]?\d{4})"
)
WINDOWS_USER_RE = re.compile(r"(?i)([A-Z]:\\Users\\)[^\\\s]+")
POSIX_USER_RE = re.compile(r"(?i)(/Users/|/home/)[^/\s]+")
CONTACT_NOTE_HINTS = (
    "contatos operacionais",
    "contato 1",
    "regras operacionais",
    "fora do expediente",
    "central - contatos",
    "agencia - contatos",
)

FORBIDDEN_TERMS = ["banco"]


class TokenMaps:
    def __init__(self) -> None:
        self.email: dict[str, str] = {}
        self.ip: dict[str, str] = {}
        self.phone: dict[str, str] = {}
        self.host: dict[str, str] = {}
        self.user: dict[str, str] = {}


@dataclass(frozen=True)
class MappingRule:
    action_id: str
    keywords: list[str]
    approval_proxy: bool
    match_policy: str = "any_keyword"
    priority: int = 0


@dataclass(frozen=True)
class ConversionRequest:
    input_json: Path
    out_incidents_dir: Path
    staging_dir: Path
    mapping_rules_path: Path
    repo_root: Path
    skip_existing_complete: bool = False


def _normalize_for_match(text: str) -> str:
    """Normalize free text for robust keyword matching across noisy exports."""
    out = html.unescape(text)
    out = re.sub(r"<[^>]+>", " ", out)
    out = " ".join(out.lower().split())
    # Remove accents/diacritics so ASCII keywords match Portuguese text.
    out = unicodedata.normalize("NFKD", out)
    out = "".join(ch for ch in out if not unicodedata.combining(ch))
    return out


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_raw_json(input_json: Path) -> tuple[dict[str, Any], int]:
    return load_json_object_with_invalid_escape_repair(input_json)


def _load_mapping_rules(path: Path) -> list[MappingRule]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
        raise ValueError(f"Invalid mapping rules file: {path}")
    out: list[MappingRule] = []
    for item in raw["rules"]:
        if not isinstance(item, dict):
            continue
        action_id = str(item.get("action_id") or "").strip()
        keywords_raw = item.get("keywords")
        if not action_id or not isinstance(keywords_raw, list):
            continue
        keywords: list[str] = []
        seen_keywords: set[str] = set()
        for raw_keyword in keywords_raw:
            candidate = _normalize_for_match(str(raw_keyword).strip())
            if not candidate or candidate in seen_keywords:
                continue
            keywords.append(candidate)
            seen_keywords.add(candidate)
        if not keywords:
            continue
        out.append(
            MappingRule(
                action_id=action_id,
                keywords=keywords,
                approval_proxy=bool(
                    item.get("approval_proxy", item.get("approval", False))
                ),
                match_policy=str(item.get("match_policy", "any_keyword")).strip()
                or "any_keyword",
                priority=int(item.get("priority", 0)),
            )
        )
    if not out:
        raise ValueError(f"No valid mapping rules loaded from: {path}")
    return out


def _epoch_ms_to_iso(value: Any) -> str | None:
    if not isinstance(value, (int, float)):
        return None
    try:
        return (
            datetime.fromtimestamp(value / 1000, tz=UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except Exception:
        return None


def _safe_slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug or "unknown"


def _normalize_severity(raw: Any) -> str:
    val = str(raw or "medium").strip().lower()
    allowed = {"low", "medium", "high", "critical"}
    return val if val in allowed else "medium"


def _replace_terms(text: str) -> str:
    out = text
    for term in FORBIDDEN_TERMS:
        out = re.sub(rf"\b{re.escape(term)}\b", "bank", out, flags=re.IGNORECASE)
    return out


def _mask_emails(text: str, maps: TokenMaps) -> str:
    def repl(match: re.Match[str]) -> str:
        raw = match.group(0)
        if raw not in maps.email:
            maps.email[raw] = f"user_{len(maps.email) + 1:04d}@bank.local"
        return maps.email[raw]

    return EMAIL_RE.sub(repl, text)


def _mask_ips(text: str, maps: TokenMaps) -> str:
    def repl(match: re.Match[str]) -> str:
        raw = match.group(0)
        if raw not in maps.ip:
            maps.ip[raw] = (
                f"10.255.{(len(maps.ip) // 250) + 1}.{(len(maps.ip) % 250) + 1}"
            )
        return maps.ip[raw]

    return IPV4_RE.sub(repl, text)


def _mask_phones(text: str, maps: TokenMaps) -> str:
    def repl(match: re.Match[str]) -> str:
        raw = match.group(0)
        if raw not in maps.phone:
            maps.phone[raw] = f"<phone_{len(maps.phone) + 1:04d}>"
        return maps.phone[raw]

    return PHONE_RE.sub(repl, text)


def _mask_user_paths(text: str) -> str:
    out = WINDOWS_USER_RE.sub(r"\1user_home", text)
    out = POSIX_USER_RE.sub(r"\1user_home", out)
    return out


def _summarize_case_note(text: str) -> str:
    normalized = _normalize_for_match(text)
    if any(hint in normalized for hint in CONTACT_NOTE_HINTS):
        return "[redacted operational contact note]"
    return text


def _sanitize_text(text: str, maps: TokenMaps) -> str:
    out = _replace_terms(text)
    out = _mask_emails(out, maps)
    out = _mask_ips(out, maps)
    out = _mask_phones(out, maps)
    out = _mask_user_paths(out)
    return out


def _sanitize_obj(value: Any, maps: TokenMaps) -> Any:
    if isinstance(value, dict):
        return {k: _sanitize_obj(v, maps) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_obj(v, maps) for v in value]
    if isinstance(value, str):
        return _sanitize_text(value, maps)
    return value


def _anon_host(raw: Any, maps: TokenMaps) -> str:
    key = str(raw or "host_unknown").strip() or "host_unknown"
    if key not in maps.host:
        maps.host[key] = f"host_{len(maps.host) + 1:04d}"
    return maps.host[key]


def _anon_user(raw: Any, maps: TokenMaps) -> str:
    key = str(raw or "user_unknown").strip() or "user_unknown"
    if key not in maps.user:
        maps.user[key] = f"user_{len(maps.user) + 1:04d}"
    return maps.user[key]


def _build_meta(
    data: dict[str, Any], maps: TokenMaps, incident_dir_id: str
) -> dict[str, Any]:
    props = (
        data.get("properties", {}) if isinstance(data.get("properties"), dict) else {}
    )
    incident_types = data.get("incident_type_ids", [])
    incident_type_raw = (
        incident_types[0]
        if isinstance(incident_types, list) and incident_types
        else "suspicious_activity"
    )

    start = _epoch_ms_to_iso(data.get("start_date")) or _epoch_ms_to_iso(
        data.get("inc_start")
    )
    end = _epoch_ms_to_iso(data.get("end_date")) or _epoch_ms_to_iso(
        data.get("inc_last_modified_date")
    )
    if start is None:
        start = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    if end is None:
        end = start

    severity = _normalize_severity(
        data.get("severity_code") or props.get("cs_severity")
    )
    status_raw = str(
        data.get("resolution_id") or props.get("status_do_incidente") or "unknown"
    )
    final_status = _safe_slug(_sanitize_text(status_raw, maps))

    host = _anon_host(props.get("cs_hostname"), maps)

    return {
        "incident_id": incident_dir_id,
        "incident_type": _safe_slug(_sanitize_text(str(incident_type_raw), maps)),
        "severity": severity,
        "asset_criticality": severity,
        "asset_role": "bank_endpoint",
        "time_window_start": start,
        "time_window_end": end,
        "final_status": final_status,
        "asset_host": host,
    }


def _build_telemetry(data: dict[str, Any], maps: TokenMaps) -> list[dict[str, Any]]:
    props = (
        data.get("properties", {}) if isinstance(data.get("properties"), dict) else {}
    )
    out: list[dict[str, Any]] = []

    event_time = _epoch_ms_to_iso(data.get("discovered_date")) or _epoch_ms_to_iso(
        data.get("start_date")
    )
    host = _anon_host(props.get("cs_hostname"), maps)
    user = _anon_user(props.get("cs_username"), maps)
    command = _sanitize_text(str(props.get("cs_command_line") or ""), maps)
    detection_label = _sanitize_text(
        str(data.get("description") or data.get("name") or "detection"), maps
    )

    out.append(
        {
            "event_type": "command_execution_attempt",
            "category": _safe_slug(detection_label),
            "timestamp": event_time,
            "source_type": "SOAR_EXPORT",
            "source_ip": _sanitize_text(str(props.get("cs_source_ip") or ""), maps)
            or None,
            "dest_ip": None,
            "username": user,
            "details": {
                "command": command or None,
                "severity": _normalize_severity(props.get("cs_severity")),
                "log_source": "soar_export",
                "source_summary": {
                    "detection_name": detection_label,
                    "description": _sanitize_text(
                        str(data.get("description") or ""), maps
                    ),
                    "host": host,
                },
            },
        }
    )

    notes = data.get("extracted_notes", [])
    if isinstance(notes, list):
        for note in notes:
            if not isinstance(note, dict):
                continue
            text = _sanitize_text(str(note.get("text") or ""), maps)
            text = re.sub(r"<[^>]+>", " ", text)
            text = " ".join(text.split())
            text = _summarize_case_note(text)
            if not text:
                continue
            ts = _epoch_ms_to_iso(note.get("create_date"))
            out.append(
                {
                    "event_type": "case_note",
                    "category": "soar_note",
                    "timestamp": ts,
                    "source_type": "SOAR_EXPORT",
                    "source_ip": None,
                    "dest_ip": None,
                    "username": _anon_user(note.get("user_name"), maps),
                    "details": {
                        "command": text[:220],
                        "severity": None,
                        "log_source": "soar_note",
                        "source_summary": {"note_id": note.get("id")},
                    },
                }
            )

    return out


def _task_text(task: dict[str, Any], maps: TokenMaps) -> str:
    base = " ".join(
        [
            str(task.get("name") or ""),
            str(task.get("description") or ""),
            str(task.get("instructions") or ""),
            str(task.get("instr_text") or ""),
        ]
    )
    return _normalize_for_match(_sanitize_text(base, maps))


def _rule_match_score(text: str, rule: MappingRule) -> int:
    if rule.match_policy == "all_keywords":
        return len(rule.keywords) if all(k in text for k in rule.keywords) else 0
    return sum(1 for keyword in rule.keywords if keyword in text)


def _map_task_to_action(
    task: dict[str, Any],
    maps: TokenMaps,
    rules: list[MappingRule],
) -> tuple[str, bool] | None:
    text = _task_text(task, maps)
    if not text:
        return None
    ranked: list[tuple[int, int, str, bool]] = []
    for rule in rules:
        score = _rule_match_score(text, rule)
        if score <= 0:
            continue
        ranked.append((score, rule.priority, rule.action_id, rule.approval_proxy))

    if not ranked:
        return None

    ranked.sort(key=lambda row: (-row[0], -row[1], row[2]))
    top = ranked[0]
    if len(ranked) > 1:
        second = ranked[1]
        # If the top two candidates are tied on match evidence and explicit
        # rule priority, keep the task unmapped and force manual review.
        if top[0] == second[0] and top[1] == second[1]:
            return None
    return top[2], top[3]


def _task_has_tied_top_candidates(
    task: dict[str, Any],
    maps: TokenMaps,
    rules: list[MappingRule],
) -> bool:
    text = _task_text(task, maps)
    if not text:
        return False
    ranked: list[tuple[int, int]] = []
    for rule in rules:
        score = _rule_match_score(text, rule)
        if score <= 0:
            continue
        ranked.append((score, rule.priority))
    if len(ranked) < MIN_RANKED_CANDIDATES_FOR_TIE:
        return False
    ranked.sort(key=lambda row: (-row[0], -row[1]))
    return ranked[0] == ranked[1]


def _build_human_actions(
    data: dict[str, Any],
    maps: TokenMaps,
    rules: list[MappingRule],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    tasks = data.get("extracted_tasks", [])
    candidates: list[tuple[str, str | None, bool, int]] = []
    unmatched_count = 0
    unmatched_examples: list[str] = []
    ambiguous_tie_count = 0
    ambiguous_tie_examples: list[str] = []

    if isinstance(tasks, list):
        for idx, task in enumerate(tasks, start=1):
            if not isinstance(task, dict):
                continue
            ts = _epoch_ms_to_iso(task.get("init_date")) or _epoch_ms_to_iso(
                task.get("closed_date")
            )
            mapped = _map_task_to_action(task, maps, rules)
            if mapped is None:
                unmatched_count += 1
                name = _normalize_for_match(str(task.get("name") or "")).strip()
                if (
                    name
                    and name not in unmatched_examples
                    and len(unmatched_examples) < MAX_MAPPING_QUALITY_EXAMPLES
                ):
                    unmatched_examples.append(name)
                if _task_has_tied_top_candidates(task, maps, rules):
                    ambiguous_tie_count += 1
                    if (
                        name
                        and name not in ambiguous_tie_examples
                        and len(ambiguous_tie_examples)
                        < MAX_MAPPING_QUALITY_EXAMPLES
                    ):
                        ambiguous_tie_examples.append(name)
                continue
            action_id, approval = mapped
            candidates.append((action_id, ts, approval, idx))

    dedup: list[tuple[str, str | None, bool, int]] = []
    seen: set[str] = set()
    for action, ts, approval, src_idx in candidates:
        if action not in seen:
            dedup.append((action, ts, approval, src_idx))
            seen.add(action)

    fallback_used = False
    if not dedup:
        fallback_used = True
        dedup = [
            (
                "collect_forensics",
                _epoch_ms_to_iso(data.get("start_date")),
                False,
                0,
            )
        ]

    out: list[dict[str, Any]] = []
    for order, (action, ts, approval, _src_idx) in enumerate(dedup, start=1):
        out.append(
            {
                "action_id": action,
                "timestamp": ts,
                "approval": approval,
                "order": order,
            }
        )

    task_count = len(tasks) if isinstance(tasks, list) else 0
    mapped_count = len(candidates)
    coverage = round(mapped_count / task_count, 4) if task_count else 0.0
    quality = {
        "task_count": task_count,
        "mapped_task_count": mapped_count,
        "unmatched_task_count": unmatched_count,
        "unmatched_task_examples": unmatched_examples,
        "ambiguous_tie_count": ambiguous_tie_count,
        "ambiguous_tie_examples": ambiguous_tie_examples,
        "deduplicated_action_count": len(out),
        "fallback_used": fallback_used,
        "mapping_coverage": coverage,
    }
    return out, quality


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _incident_dir_id_from_raw(raw_data: dict[str, Any], input_json: Path) -> str:
    raw_id = str(raw_data.get("id") or input_json.stem)
    digits = "".join(ch for ch in raw_id if ch.isdigit()) or "000000"
    return f"INC_BANK_{digits}"


def _incident_dir_is_complete(incident_dir: Path) -> bool:
    required = [
        incident_dir / "incident_meta.json",
        incident_dir / "incident_telemetry.jsonl",
        incident_dir / "incident_human_actions.jsonl",
        incident_dir / "evidence" / "source_manifest.json",
        incident_dir / "evidence" / "conversion_quality.json",
    ]
    return all(path.exists() for path in required)


def _coerce_conversion_request(
    request: ConversionRequest | Path,
    *legacy_paths: Path,
    skip_existing_complete: bool = False,
) -> ConversionRequest:
    if isinstance(request, ConversionRequest):
        return request
    if len(legacy_paths) != LEGACY_CONVERT_ONE_PATH_COUNT:
        raise TypeError(
            "convert_one requires either a ConversionRequest or all legacy path "
            "arguments."
        )
    out_incidents_dir, staging_dir, mapping_rules_path, repo_root = legacy_paths
    return ConversionRequest(
        input_json=request,
        out_incidents_dir=out_incidents_dir,
        staging_dir=staging_dir,
        mapping_rules_path=mapping_rules_path,
        repo_root=repo_root,
        skip_existing_complete=skip_existing_complete,
    )


def convert_one(
    request: ConversionRequest | Path,
    *legacy_paths: Path,
    skip_existing_complete: bool = False,
) -> Path:
    conversion_request = _coerce_conversion_request(
        request,
        *legacy_paths,
        skip_existing_complete=skip_existing_complete,
    )
    input_json = conversion_request.input_json
    out_incidents_dir = conversion_request.out_incidents_dir
    staging_dir = conversion_request.staging_dir
    mapping_rules_path = conversion_request.mapping_rules_path
    repo_root = conversion_request.repo_root

    rules = _load_mapping_rules(mapping_rules_path)
    maps = TokenMaps()
    raw_data, parse_repair_count = _load_raw_json(input_json)
    sanitized_raw = _sanitize_obj(raw_data, maps)

    incident_dir_id = _incident_dir_id_from_raw(raw_data, input_json)
    incident_dir = out_incidents_dir / incident_dir_id
    if conversion_request.skip_existing_complete and _incident_dir_is_complete(
        incident_dir
    ):
        return incident_dir
    incident_dir.mkdir(parents=True, exist_ok=True)

    meta = _build_meta(sanitized_raw, maps, incident_dir_id)
    telemetry = _build_telemetry(sanitized_raw, maps)
    actions, quality = _build_human_actions(sanitized_raw, maps, rules)

    _write_json(incident_dir / "incident_meta.json", meta)
    _write_jsonl(incident_dir / "incident_telemetry.jsonl", telemetry)
    _write_jsonl(incident_dir / "incident_human_actions.jsonl", actions)

    redacted_export = staging_dir / f"{input_json.stem}.redacted.json"
    _write_json(redacted_export, sanitized_raw)

    _write_json(
        incident_dir / "evidence" / "source_manifest.json",
        {
            "source_raw_file": repo_relative_path(input_json, repo_root),
            "redacted_export": repo_relative_path(redacted_export, repo_root),
            "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "incident_dir": repo_relative_path(incident_dir, repo_root),
            "mapping_rules_path": repo_relative_path(mapping_rules_path, repo_root),
            "mapping_rules_sha256": _sha256_file(mapping_rules_path),
            "anonymization_summary": {
                "email_tokens": len(maps.email),
                "ip_tokens": len(maps.ip),
                "phone_tokens": len(maps.phone),
                "host_tokens": len(maps.host),
                "user_tokens": len(maps.user),
            },
            "action_mapping_quality": quality,
            "input_parse_repairs": {
                "invalid_backslash_escape_count": parse_repair_count,
            },
        },
    )
    _write_json(incident_dir / "evidence" / "conversion_quality.json", quality)

    return incident_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="local_redaction.anonymize_export")
    parser.add_argument("--input-json", required=True)
    parser.add_argument("--out-incidents-dir", default="dataset/incidents")
    parser.add_argument("--staging-dir", default="incoming/redacted")
    parser.add_argument(
        "--mapping-rules",
        default="local_redaction/action_mapping_bank.yaml",
    )
    parser.add_argument("--repo-root", default=".")
    parser.add_argument(
        "--skip-existing-complete",
        action="store_true",
        help=(
            "Return without rewriting when the canonical incident directory "
            "is already complete."
        ),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    out_dir = Path(args.out_incidents_dir).expanduser().resolve()
    staging_dir = Path(args.staging_dir).expanduser().resolve()
    mapping_rules = Path(args.mapping_rules).expanduser().resolve()
    repo_root = resolve_repo_root(args.repo_root)
    incident_dir = convert_one(
        ConversionRequest(
            input_json=Path(args.input_json).expanduser().resolve(),
            out_incidents_dir=out_dir,
            staging_dir=staging_dir,
            mapping_rules_path=mapping_rules,
            repo_root=repo_root,
            skip_existing_complete=bool(args.skip_existing_complete),
        )
    )
    print(f"Anonymized incident ready: {incident_dir}")


if __name__ == "__main__":
    main()
