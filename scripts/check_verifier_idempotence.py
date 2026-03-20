#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from soc_llm_policy.engine import enforce_policy
from soc_llm_policy.io import (
    parse_action_catalog,
    parse_rules,
    read_jsonl,
    read_yaml_list,
)


def _iter_verifier_outputs(incidents_root: Path) -> list[Path]:
    files = sorted(incidents_root.glob("INC_*/verifier_output_*_*.json"))
    files.extend(sorted(incidents_root.glob("INC_*/verifier_output.json")))
    # Preserve deterministic order and remove duplicates.
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in files:
        if path in seen:
            continue
        seen.add(path)
        unique.append(path)
    return unique


def run_check(repo_root: Path) -> dict[str, Any]:
    outputs_root = repo_root / "results"
    incidents_root = outputs_root / "incidents"
    rules_path = outputs_root / "global" / "constraints.yaml"
    catalog_path = outputs_root / "global" / "action_catalog.yaml"

    rules = parse_rules(read_yaml_list(rules_path))
    catalog = parse_action_catalog(read_yaml_list(catalog_path))

    files = _iter_verifier_outputs(incidents_root)
    checked = 0
    changed = 0
    second_pass_violations = 0
    errors: list[dict[str, str]] = []

    for path in files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            incident_id = str(payload.get("incident_dir_id") or "").strip()
            if not incident_id:
                raise ValueError("missing incident_dir_id in verifier output")
            enforced = list(payload.get("enforced_actions", []))
            approval_mode = str(payload.get("approval_policy_mode", "remove")).strip()
            telemetry_path = incidents_root / incident_id / "incident_telemetry.jsonl"
            telemetry = read_jsonl(telemetry_path, strict=False)
            violations2, enforced2 = enforce_policy(
                llm_actions=enforced,
                telemetry=telemetry,
                rules=rules,
                catalog=catalog,
                approval_policy_mode=approval_mode,  # type: ignore[arg-type]
            )
            checked += 1
            if enforced2 != enforced:
                changed += 1
            if violations2:
                second_pass_violations += 1
        except Exception as exc:  # noqa: BLE001
            errors.append({"file": str(path), "error": str(exc)})

    return {
        "files_checked": checked,
        "changed_after_second_pass": changed,
        "nonempty_violations_on_second_pass": second_pass_violations,
        "errors": errors,
        "idempotence_pass": checked > 0
        and changed == 0
        and second_pass_violations == 0
        and len(errors) == 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="check_verifier_idempotence",
        description=(
            "Re-apply policy enforcement to already enforced plans and report "
            "whether a second pass changes outputs."
        ),
    )
    parser.add_argument("--repo-root", default=".")
    parser.add_argument(
        "--output-json",
        default="results/analysis/idempotence_sanity.json",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).expanduser().resolve()
    report = run_check(repo_root)
    output_path = Path(args.output_json).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Saved idempotence report: {output_path}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
