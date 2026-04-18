from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc_llm_policy.paths import RepoPaths, repo_relative_path, resolve_repo_root
from soc_llm_policy.pipeline import list_inbox_incidents


@dataclass(frozen=True)
class ProtocolFreezeOptions:
    dataset_release_id: str
    protocol_version: str
    model_names: list[str]
    smoke_model_names: list[str]
    arm_names: list[str]
    approval_policy_mode: str
    output_json: Path
    include_all_incidents: bool


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return payload


def _git_commit(repo_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


def _incident_ids(paths: RepoPaths, include_all: bool) -> list[str]:
    if not include_all:
        return []
    return list_inbox_incidents(paths)


def build_protocol_freeze_manifest(
    *,
    paths: RepoPaths,
    options: ProtocolFreezeOptions,
) -> dict[str, Any]:
    incident_ids = _incident_ids(paths, options.include_all_incidents)
    dataset_audit_path = paths.outputs_analysis_dir / "dataset_audit.json"
    corpus_readiness_path = paths.outputs_analysis_dir / "corpus_readiness.json"
    release_readiness_path = paths.outputs_analysis_dir / "release_readiness.json"
    dataset_audit = _read_json(dataset_audit_path) if dataset_audit_path.exists() else {}
    corpus_readiness = (
        _read_json(corpus_readiness_path) if corpus_readiness_path.exists() else {}
    )
    global_artifact_scope = corpus_readiness.get("global_artifact_scope", {})
    if not isinstance(global_artifact_scope, dict):
        global_artifact_scope = {}
    release_readiness = (
        _read_json(release_readiness_path) if release_readiness_path.exists() else {}
    )

    hashed_inputs = [
        ("action_catalog", paths.inbox_action_catalog_path),
        ("constraints", paths.inbox_constraints_path),
        ("action_mapping_bank", paths.action_mapping_bank_path),
        ("models_registry", paths.models_freeze_path),
        ("attack_mapping", paths.attack_mapping_path),
        ("anonymization_policy", paths.anonymization_policy_path),
        ("dataset_audit", dataset_audit_path),
        ("corpus_readiness", corpus_readiness_path),
        ("release_readiness", release_readiness_path),
        (
            "official_evaluation_summary",
            paths.outputs_analysis_dir / "official_evaluation_summary.json",
        ),
        (
            "official_runs_manifest",
            paths.outputs_analysis_dir / "official_runs_manifest.json",
        ),
    ]
    input_hashes: dict[str, dict[str, str]] = {}
    for name, path in hashed_inputs:
        if not path.exists():
            continue
        input_hashes[name] = {
            "path": repo_relative_path(path, paths.repo_root),
            "sha256": _sha256_file(path),
        }

    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "git_commit": _git_commit(paths.repo_root),
        "dataset_release_id": options.dataset_release_id,
        "eval_protocol_version": options.protocol_version,
        "approval_policy_mode": options.approval_policy_mode,
        "official_models": options.model_names,
        "smoke_models": options.smoke_model_names,
        "arms": options.arm_names,
        "incident_count": len(incident_ids),
        "incident_ids": incident_ids,
        "policy_rule_count": int(global_artifact_scope.get("policy_rule_count", 0) or 0),
        "action_catalog_count": int(
            global_artifact_scope.get("action_catalog_count", 0) or 0
        ),
        "mapping_rule_count": int(
            global_artifact_scope.get("mapping_rule_count", 0) or 0
        ),
        "release_readiness_status": str(release_readiness.get("status", "unknown")),
        "dataset_audit_status": "ok" if dataset_audit else "missing",
        "input_hashes": input_hashes,
        "notes": [
            "This manifest defines the single canonical protocol freeze for future paid runs.",
            "Exploratory bundles are excluded from the official experimental provenance.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc_llm_policy.protocol_freeze",
        description="Write a canonical protocol-freeze manifest with hashes and official settings.",
    )
    parser.add_argument("--repo-root", default=None)
    parser.add_argument("--dataset-release-id", required=True)
    parser.add_argument("--protocol-version", required=True)
    parser.add_argument("--models", required=True)
    parser.add_argument("--smoke-models", required=True)
    parser.add_argument("--arms", required=True)
    parser.add_argument(
        "--approval-policy-mode",
        default="remove",
        choices=["remove", "defer_to_human_approval"],
    )
    parser.add_argument(
        "--output-json",
        default="results/analysis/protocol_freeze.json",
    )
    parser.add_argument("--all", action="store_true")
    return parser


def _parse_csv(value: str) -> list[str]:
    items: list[str] = []
    for part in value.split(","):
        item = part.strip()
        if item and item not in items:
            items.append(item)
    return items


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = resolve_repo_root(args.repo_root)
    paths = RepoPaths(repo_root=repo_root)
    output_json = Path(args.output_json)
    if not output_json.is_absolute():
        output_json = repo_root / output_json
    output_json.parent.mkdir(parents=True, exist_ok=True)

    manifest = build_protocol_freeze_manifest(
        paths=paths,
        options=ProtocolFreezeOptions(
            dataset_release_id=str(args.dataset_release_id).strip(),
            protocol_version=str(args.protocol_version).strip(),
            model_names=_parse_csv(args.models),
            smoke_model_names=_parse_csv(args.smoke_models),
            arm_names=_parse_csv(args.arms),
            approval_policy_mode=str(args.approval_policy_mode).strip(),
            output_json=output_json,
            include_all_incidents=bool(args.all),
        ),
    )
    output_json.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
