#!/usr/bin/env python3
"""Validate the reviewer path from a freshly cloned repository."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--ref", default="")
    parser.add_argument("--artifact-subdir", default="policy-verifier/artifact")
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path("results/analysis/fresh_clone_reproduction.json"),
    )
    parser.add_argument("--keep-workdir", action="store_true")
    return parser.parse_args()


def run_command(command: list[str], cwd: Path | None = None) -> dict[str, Any]:
    started_at = datetime.now(UTC)
    result = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )
    finished_at = datetime.now(UTC)
    return {
        "command": command,
        "cwd": str(cwd) if cwd else "",
        "returncode": result.returncode,
        "started_at_utc": started_at.isoformat(),
        "finished_at_utc": finished_at.isoformat(),
        "stdout_tail": result.stdout[-8000:],
        "stderr_tail": result.stderr[-8000:],
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    args = parse_args()
    output_path = args.output_json.resolve()
    temp_root = Path(tempfile.mkdtemp(prefix="socpilot_fresh_clone_"))
    clone_dir = temp_root / "repo"
    commands: list[dict[str, Any]] = []
    status = "failed"

    try:
        commands.append(run_command(["git", "clone", args.repo_url, str(clone_dir)]))
        if commands[-1]["returncode"] != 0:
            raise SystemExit(2)

        if args.ref:
            commands.append(run_command(["git", "checkout", args.ref], cwd=clone_dir))
            if commands[-1]["returncode"] != 0:
                raise SystemExit(2)

        artifact_dir = clone_dir / args.artifact_subdir
        if not artifact_dir.exists():
            commands.append(
                {
                    "command": ["test", "-d", str(artifact_dir)],
                    "cwd": str(clone_dir),
                    "returncode": 2,
                    "stdout_tail": "",
                    "stderr_tail": f"artifact directory not found: {artifact_dir}",
                }
            )
            raise SystemExit(2)

        commands.append(run_command(["bash", "run.sh", "reproduce-results"], cwd=artifact_dir))
        if commands[-1]["returncode"] != 0:
            raise SystemExit(2)
        status = "ok"
    finally:
        report = {
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "status": status,
            "repo_url": args.repo_url,
            "ref": args.ref,
            "artifact_subdir": args.artifact_subdir,
            "workdir": str(temp_root),
            "workdir_preserved": bool(args.keep_workdir),
            "commands": commands,
        }
        write_report(output_path, report)
        if not args.keep_workdir:
            shutil.rmtree(temp_root, ignore_errors=True)

    if status != "ok":
        raise SystemExit(f"Fresh-clone reproduction failed: {output_path}")
    print(f"Fresh-clone reproduction OK: {output_path}")


if __name__ == "__main__":
    main()
