from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_FORBIDDEN_PATH_PARTS = {
    ".env",
    "raw",
    "redacted",
    "private",
}
_LOCAL_TRANSIENT_DIR_NAMES = {
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
_LOCAL_TRANSIENT_SUFFIXES = {".pyc"}
_LOCAL_TRANSIENT_FILE_NAMES = {"release_candidate_checklist.json"}
_LOCAL_TRANSIENT_FILE_SUFFIXES = {"_recheck.json"}
_FORBIDDEN_TEXT_MARKERS = {
    "/" + "Users" + "/",
    "private/derived",
    "internal/candidates",
    "dataset_release_id\": \"financial_",
    "\"source_raw_file\": \"/",
    "\"redacted_export\": \"/",
    "\"incident_dir\": \"/",
    "\"mapping_rules_path\": \"/",
    "\"repo_root\": \"/",
    "\"legacy_root\": \"/",
}
_FORBIDDEN_VENUE_MARKERS = (
    "".join(("n", "dss")),
    "".join(("us", "enix")),
    "".join(("i", "eee")),
    "".join(("c", "cs")),
    "".join(("a", "cm")),
    "".join(("s", "&", "p")),
    " ".join(("security", "symposium")),
    " ".join(("network", "and", "distributed")),
    " ".join(("computer", "and", "communications", "security")),
)
_FORBIDDEN_VENUE_PATTERN = re.compile(
    r"\b(?:"
    + "|".join(re.escape(marker) for marker in _FORBIDDEN_VENUE_MARKERS)
    + r")\b",
    flags=re.IGNORECASE,
)


def _is_local_transient_path(rel_path: Path) -> bool:
    parts = set(rel_path.parts)
    if any(name in parts for name in _LOCAL_TRANSIENT_DIR_NAMES):
        return True
    if rel_path.name in _LOCAL_TRANSIENT_FILE_NAMES:
        return True
    if any(rel_path.name.endswith(suffix) for suffix in _LOCAL_TRANSIENT_FILE_SUFFIXES):
        return True
    return rel_path.suffix in _LOCAL_TRANSIENT_SUFFIXES


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_forbidden_paths(package_root: Path) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    for path in package_root.rglob("*"):
        rel_path = path.relative_to(package_root)
        if _is_local_transient_path(rel_path):
            continue
        rel = rel_path.as_posix()
        parts = set(rel.split("/"))
        if any(name in parts for name in _FORBIDDEN_PATH_PARTS):
            issues.append(
                {
                    "code": "forbidden_path",
                    "path": rel,
                    "message": (
                        "Forbidden path/component found inside artifact package."
                    ),
                }
            )
            continue
    return issues


def _check_required_structure(package_root: Path) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    required_files = [
        package_root / "artifact_manifest.json",
        package_root / "ARTIFACT_BOUNDARY.md",
        package_root / "ARTIFACT_README.md",
        package_root / "artifact_data" / "global" / "action_catalog.yaml",
        package_root / "artifact_data" / "global" / "constraints.yaml",
        package_root / "artifact_outputs" / "analysis" / "protocol_freeze.json",
        package_root / "local_redaction" / "action_mapping_bank.yaml",
    ]
    for file_path in required_files:
        if not file_path.exists():
            issues.append(
                {
                    "code": "missing_required_file",
                    "path": str(file_path.relative_to(package_root)),
                    "message": "Required artifact file is missing.",
                }
            )

    dataset_root = package_root / "artifact_data" / "dataset"
    incidents = sorted(path for path in dataset_root.glob("INC_*") if path.is_dir())
    if not incidents:
        issues.append(
            {
                "code": "missing_incidents",
                "path": "artifact_data/dataset",
                "message": "No incident folders found in artifact_data/dataset.",
            }
        )
        return issues

    for incident_dir in incidents:
        meta = incident_dir / "incident_meta.json"
        human = incident_dir / "incident_human_actions.jsonl"
        if not meta.exists():
            issues.append(
                {
                    "code": "missing_incident_meta",
                    "path": str(meta.relative_to(package_root)),
                    "message": "Incident metadata file is missing.",
                }
            )
        if not human.exists():
            issues.append(
                {
                    "code": "missing_incident_human_actions",
                    "path": str(human.relative_to(package_root)),
                    "message": "Incident human actions file is missing.",
                }
            )
    return issues


def _check_protocol_freeze(package_root: Path) -> list[dict[str, str]]:
    freeze_path = (
        package_root / "artifact_outputs" / "analysis" / "protocol_freeze.json"
    )
    if not freeze_path.exists():
        return []
    try:
        payload = json.loads(freeze_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return [
            {
                "code": "invalid_protocol_freeze_json",
                "path": "artifact_outputs/analysis/protocol_freeze.json",
                "message": "Protocol freeze manifest is not valid JSON.",
            }
        ]
    if not isinstance(payload, dict):
        return [
            {
                "code": "invalid_protocol_freeze_shape",
                "path": "artifact_outputs/analysis/protocol_freeze.json",
                "message": "Protocol freeze manifest must be a JSON object.",
            }
        ]

    issues: list[dict[str, str]] = []
    required_keys = [
        "dataset_release_id",
        "eval_protocol_version",
        "official_models",
        "incident_count",
        "input_hashes",
    ]
    for key in required_keys:
        if key not in payload:
            issues.append(
                {
                    "code": "missing_protocol_freeze_field",
                    "path": "artifact_outputs/analysis/protocol_freeze.json",
                    "message": (
                        "Protocol freeze manifest is missing required field "
                        f"`{key}`."
                    ),
                }
            )

    official_models = payload.get("official_models")
    if isinstance(official_models, list) and not official_models:
        issues.append(
            {
                "code": "empty_official_models",
                "path": "artifact_outputs/analysis/protocol_freeze.json",
                "message": (
                    "Protocol freeze manifest must list at least one official "
                    "model."
                ),
            }
        )
    input_hashes = payload.get("input_hashes")
    if isinstance(input_hashes, dict):
        for name, entry in input_hashes.items():
            if not isinstance(entry, dict):
                issues.append(
                    {
                        "code": "invalid_protocol_freeze_input_hash_entry",
                        "path": "artifact_outputs/analysis/protocol_freeze.json",
                        "message": (
                            "Protocol freeze input hash entry "
                            f"`{name}` must be an object."
                        ),
                    }
                )
                continue
            rel = entry.get("path")
            checksum = entry.get("sha256")
            if not isinstance(rel, str) or not isinstance(checksum, str):
                issues.append(
                    {
                        "code": "invalid_protocol_freeze_input_hash_fields",
                        "path": "artifact_outputs/analysis/protocol_freeze.json",
                        "message": (
                            f"Protocol freeze input hash entry `{name}` must define "
                            "string `path` and `sha256` fields."
                        ),
                    }
                )
                continue
            file_path = package_root / rel
            if not file_path.exists():
                issues.append(
                    {
                        "code": "protocol_freeze_missing_input_file",
                        "path": rel,
                        "message": (
                            "Protocol freeze input hash entry "
                            f"`{name}` points to a missing file."
                        ),
                    }
                )
                continue
            if _sha256_file(file_path) != checksum:
                issues.append(
                    {
                        "code": "protocol_freeze_input_hash_mismatch",
                        "path": rel,
                        "message": (
                            "Protocol freeze input hash entry "
                            f"`{name}` does not match file content."
                        ),
                    }
                )
    return issues


def _check_textual_leaks(package_root: Path) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    for path in package_root.rglob("*"):
        rel_path = path.relative_to(package_root)
        if _is_local_transient_path(rel_path):
            continue
        if not path.is_file():
            continue
        if path.suffix not in {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".sh"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for marker in _FORBIDDEN_TEXT_MARKERS:
            if marker not in text:
                continue
            issues.append(
                {
                    "code": "forbidden_text_marker",
                    "path": str(rel_path),
                    "message": f"Artifact text contains forbidden marker `{marker}`.",
                }
            )
            break
        if _FORBIDDEN_VENUE_PATTERN.search(text):
            issues.append(
                {
                    "code": "forbidden_venue_marker",
                    "path": str(rel_path),
                    "message": "Artifact text contains publication-venue language.",
                }
            )
    return issues


def _check_manifest_integrity(package_root: Path) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    manifest_path = package_root / "artifact_manifest.json"
    if not manifest_path.exists():
        return issues
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return [
            {
                "code": "invalid_manifest_json",
                "path": "artifact_manifest.json",
                "message": "artifact_manifest.json is not valid JSON.",
            }
        ]

    entries = manifest.get("files", [])
    if not isinstance(entries, list):
        return [
            {
                "code": "invalid_manifest_files",
                "path": "artifact_manifest.json",
                "message": "Manifest 'files' must be a list.",
            }
        ]

    expected_count = manifest.get("file_count")
    if isinstance(expected_count, int) and expected_count != len(entries):
        issues.append(
            {
                "code": "manifest_file_count_mismatch",
                "path": "artifact_manifest.json",
                "message": "Manifest file_count does not match files list length.",
            }
        )

    for entry in entries:
        if not isinstance(entry, dict):
            issues.append(
                {
                    "code": "invalid_manifest_entry",
                    "path": "artifact_manifest.json",
                    "message": "Manifest entry must be an object with path and sha256.",
                }
            )
            continue
        rel = entry.get("path")
        checksum = entry.get("sha256")
        if not isinstance(rel, str) or not isinstance(checksum, str):
            issues.append(
                {
                    "code": "invalid_manifest_entry_fields",
                    "path": "artifact_manifest.json",
                    "message": "Manifest entry missing valid path/sha256.",
                }
            )
            continue
        file_path = package_root / rel
        if not file_path.exists():
            issues.append(
                {
                    "code": "manifest_missing_file",
                    "path": rel,
                    "message": "Manifest references a file that does not exist.",
                }
            )
            continue
        if _sha256_file(file_path) != checksum:
            issues.append(
                {
                    "code": "manifest_sha256_mismatch",
                    "path": rel,
                    "message": "Manifest SHA-256 does not match file content.",
                }
            )
    return issues


def verify_artifact_package(package_root: Path) -> dict[str, Any]:
    issues = [
        *_check_required_structure(package_root),
        *_check_protocol_freeze(package_root),
        *_check_forbidden_paths(package_root),
        *_check_textual_leaks(package_root),
        *_check_manifest_integrity(package_root),
    ]
    status = "ok" if not issues else "failed"
    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "status": status,
        "issue_count": len(issues),
        "issues": issues,
    }


def _stabilize_timestamp(
    existing: dict[str, Any],
    report: dict[str, Any],
) -> dict[str, Any]:
    comparable_existing = {
        key: value for key, value in existing.items() if key != "generated_at_utc"
    }
    comparable_report = {
        key: value for key, value in report.items() if key != "generated_at_utc"
    }
    if comparable_existing == comparable_report and isinstance(
        existing.get("generated_at_utc"), str
    ):
        report = dict(report)
        report["generated_at_utc"] = existing["generated_at_utc"]
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc_llm_policy.artifact_verify",
        description="Verify release-candidate artifact package integrity and boundary.",
    )
    parser.add_argument("--package-root", required=True)
    parser.add_argument(
        "--output-json",
        default="release_candidate_checklist.json",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    package_root = Path(args.package_root).expanduser().resolve()
    report = verify_artifact_package(package_root)
    output_path = Path(args.output_json)
    if not output_path.is_absolute():
        output_path = package_root / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        try:
            existing = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            existing = None
        if isinstance(existing, dict):
            report = _stabilize_timestamp(existing, report)
    output_text = json.dumps(report, ensure_ascii=False, indent=2)
    if output_path.exists():
        try:
            if output_path.read_text(encoding="utf-8") == output_text:
                return 0 if report["status"] == "ok" else 1
        except OSError:
            pass
    output_path.write_text(output_text, encoding="utf-8")
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
