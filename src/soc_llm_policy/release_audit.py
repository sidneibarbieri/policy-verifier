from __future__ import annotations

import argparse
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc_llm_policy.json_stability import write_stable_json
from soc_llm_policy.paths import RepoPaths, resolve_repo_root

_TRANSIENT_DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
}
_TRANSIENT_DIR_PREFIXES = ("tmp_test_outputs",)
_TRANSIENT_FILE_SUFFIXES = (".pyc",)
_TRANSIENT_FILE_NAMES = {".DS_Store"}
_SENSITIVE_FILE_PREFIXES = (".env",)
_PRIVATE_COMPONENTS = {
    "local_redaction",
}
_NON_PUBLIC_DATA_DIRS = {
    "incoming/raw",
    "incoming/redacted",
    "dataset",
    "results",
    "private",
}
_TRACKED_SENSITIVE_FILE_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
_TRACKED_LOCAL_OVERRIDE_SUFFIXES = (".local.yaml", ".local.yml", ".local.json", ".local.toml")


def _is_release_bundle(repo_root: Path) -> bool:
    return (repo_root / "artifact_manifest.json").exists()


@dataclass(frozen=True)
class AuditIssue:
    severity: str
    code: str
    path: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }


def _is_non_hidden(path: Path) -> bool:
    return not any(part.startswith(".") for part in path.parts)


def _scan_sensitive_files(
    repo_root: Path,
    *,
    allow_local_env: bool,
) -> list[AuditIssue]:
    issues: list[AuditIssue] = []
    for entry in repo_root.iterdir():
        if not entry.is_file():
            continue
        if any(entry.name == prefix or entry.name.startswith(f"{prefix}.") for prefix in _SENSITIVE_FILE_PREFIXES):
            severity = "low" if allow_local_env else "high"
            issues.append(
                AuditIssue(
                    severity=severity,
                    code="sensitive_file_present",
                    path=str(entry),
                    message=(
                        "Sensitive environment file found in repository root. "
                        "Rotate credentials and keep this file out of release artifacts."
                    ),
                )
            )
    return issues


def _scan_transient_artifacts(repo_root: Path) -> list[AuditIssue]:
    issues: list[AuditIssue] = []
    for path in repo_root.rglob("*"):
        if not _is_non_hidden(path.relative_to(repo_root)):
            continue
        name = path.name
        if path.is_dir():
            if name in _TRANSIENT_DIR_NAMES or any(
                name.startswith(prefix) for prefix in _TRANSIENT_DIR_PREFIXES
            ):
                issues.append(
                    AuditIssue(
                        severity="medium",
                        code="transient_dir_present",
                        path=str(path),
                        message="Transient directory should be removed before release packaging.",
                    )
                )
            continue
        if name in _TRANSIENT_FILE_NAMES or path.suffix in _TRANSIENT_FILE_SUFFIXES:
            issues.append(
                AuditIssue(
                    severity="medium",
                    code="transient_file_present",
                    path=str(path),
                    message="Transient file should be removed before release packaging.",
                )
            )
    return issues


def _scan_private_components(repo_root: Path) -> list[AuditIssue]:
    if _is_release_bundle(repo_root):
        return []
    issues: list[AuditIssue] = []
    for rel in _PRIVATE_COMPONENTS:
        path = repo_root / rel
        if path.exists():
            issues.append(
                AuditIssue(
                    severity="medium",
                    code="private_component_in_repo",
                    path=str(path),
                    message=(
                        "Private preprocessing component is inside repository. "
                        "Keep it outside the public artifact boundary."
                    ),
                )
            )
    return issues


def _scan_non_public_data(repo_root: Path) -> list[AuditIssue]:
    issues: list[AuditIssue] = []
    for rel in _NON_PUBLIC_DATA_DIRS:
        path = repo_root / rel
        if not path.exists() or not path.is_dir():
            continue
        has_files = any(item.is_file() for item in path.rglob("*"))
        if not has_files:
            continue
        issues.append(
            AuditIssue(
                severity="medium",
                code="non_public_data_present",
                path=str(path),
                message=(
                    "Directory contains data generated or managed outside the public artifact. "
                    "Ensure release package excludes it."
                ),
            )
        )
    return issues


def _git_tracked_paths(repo_root: Path) -> tuple[Path, list[str]] | None:
    git_root_result = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if git_root_result.returncode != 0:
        return None
    git_root = Path(git_root_result.stdout.strip()).resolve()
    ls_files_result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z"],
        capture_output=True,
        text=False,
        check=False,
    )
    if ls_files_result.returncode != 0:
        return None
    tracked_paths = [
        item.decode("utf-8")
        for item in ls_files_result.stdout.split(b"\x00")
        if item
    ]
    return git_root, tracked_paths


def _is_tracked_sensitive_path(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    name = Path(normalized).name
    if normalized == ".env":
        return True
    if name.startswith(".env.") and name != ".env.example":
        return True
    if normalized.endswith(_TRACKED_SENSITIVE_FILE_SUFFIXES):
        return True
    if normalized.endswith(_TRACKED_LOCAL_OVERRIDE_SUFFIXES):
        return True
    return False


def _scan_tracked_sensitive_files(repo_root: Path) -> list[AuditIssue]:
    if _is_release_bundle(repo_root):
        return []
    tracked = _git_tracked_paths(repo_root)
    if tracked is None:
        return []
    git_root, tracked_paths = tracked
    issues: list[AuditIssue] = []
    for rel_path in tracked_paths:
        if not _is_tracked_sensitive_path(rel_path):
            continue
        path = (git_root / rel_path).resolve()
        issues.append(
            AuditIssue(
                severity="high",
                code="tracked_sensitive_file",
                path=str(path),
                message=(
                    "Sensitive or local-override file is tracked by git. "
                    "Keep secrets and local overrides out of the published repository."
                ),
            )
        )
    return issues


def audit_release(
    paths: RepoPaths,
    *,
    allow_local_env: bool = False,
) -> dict[str, Any]:
    repo_root = paths.repo_root
    issues = [
        *_scan_sensitive_files(repo_root, allow_local_env=allow_local_env),
        *_scan_transient_artifacts(repo_root),
        *_scan_private_components(repo_root),
        *_scan_non_public_data(repo_root),
        *_scan_tracked_sensitive_files(repo_root),
    ]
    issue_dicts = [issue.as_dict() for issue in issues]
    by_severity: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for issue in issues:
        by_severity[issue.severity] = by_severity.get(issue.severity, 0) + 1

    status = "failed" if by_severity.get("high", 0) > 0 else "warning"
    if not issue_dicts:
        status = "ok"

    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "status": status,
        "issue_count": len(issue_dicts),
        "issues_by_severity": by_severity,
        "issues": issue_dicts,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit release hygiene (secrets, transient artifacts, private boundaries)."
    )
    parser.add_argument("--repo-root", default=None)
    parser.add_argument(
        "--output-json",
        default="results/analysis/release_readiness.json",
    )
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Exit with non-zero code also when medium-severity issues exist.",
    )
    parser.add_argument(
        "--allow-local-env",
        action="store_true",
        help="Treat local .env presence as low-severity warning (for local development).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = resolve_repo_root(args.repo_root)
    paths = RepoPaths(repo_root=repo_root)
    report = audit_release(paths, allow_local_env=args.allow_local_env)
    output_path = Path(args.output_json)
    if not output_path.is_absolute():
        output_path = repo_root / output_path
    write_stable_json(output_path, report)
    if report["status"] == "failed":
        return 1
    if args.fail_on_warning and report["status"] == "warning":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
