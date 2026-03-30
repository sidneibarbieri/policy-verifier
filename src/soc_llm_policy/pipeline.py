from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from soc_llm_policy.attack import (
    load_attack_rules,
    summarize_attack_candidates,
    summarize_attack_context,
)
from soc_llm_policy.engine import Violation, enforce_policy
from soc_llm_policy.ingest import merge_datasets_to_telemetry
from soc_llm_policy.interfaces import LLMFactory, LLMPort
from soc_llm_policy.io import (
    ActionCatalogItem,
    HumanAction,
    IncidentMeta,
    PolicyRule,
    TelemetryEvent,
    parse_action_catalog,
    parse_human_actions,
    parse_human_actions_strict_order,
    parse_incident_meta,
    parse_rules,
    parse_telemetry,
    read_json,
    read_jsonl,
    read_yaml_list,
    require_exists,
)
from soc_llm_policy.metrics import IncidentMetricInput, build_incident_metrics
from soc_llm_policy.mitre import read_mitre_manifest
from soc_llm_policy.paths import RepoPaths, resolve_repo_root
from soc_llm_policy.result_models import (
    AttackCandidatesSummary,
    AttackContextSummary,
    AttackReference,
    IncidentMetrics,
    LLMUsage,
    VerifierOutputModel,
)

# Maximum reasoning preview length displayed in terminal output.
_REASONING_PREVIEW_LEN = 120


@dataclass(frozen=True)
class VerifierResult:
    """Complete result of one policy-verifier execution.

    Stores human-vs-LLM columns for comparative analysis in the paper.
    """

    incident_id: str
    incident_dir_id: str
    incident_type: str
    severity: str
    asset_criticality: str
    mode: str  # "LLM" | "human"
    approval_policy_mode: Literal["remove", "defer_to_human_approval"]
    human_actions: list[str]
    incident_approved_actions: list[str]
    llm_actions: list[str]
    violations: list[Violation]
    enforced_actions: list[str]
    approval_pending_actions: list[str]
    attack_reference: AttackReference
    attack_candidates: AttackCandidatesSummary
    attack_summary: AttackContextSummary
    metrics: IncidentMetrics
    llm_usage: LLMUsage | None
    llm_latency_ms: int | None
    llm_cost_estimated_usd: float | None
    run_tag: str
    llm_deployment: str | None = None
    llm_arm: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "incident_dir_id": self.incident_dir_id,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "asset_criticality": self.asset_criticality,
            "mode": self.mode,
            "run_tag": self.run_tag,
            "approval_policy_mode": self.approval_policy_mode,
            "llm_deployment": self.llm_deployment,
            "llm_arm": self.llm_arm,
            "human_actions": self.human_actions,
            "incident_approved_actions": self.incident_approved_actions,
            "llm_actions": self.llm_actions,
            "violations": [v.to_dict() for v in self.violations],
            "enforced_actions": self.enforced_actions,
            "approval_pending_actions": self.approval_pending_actions,
            "attack_reference": self.attack_reference.model_dump(mode="json"),
            "attack_candidates": self.attack_candidates.model_dump(mode="json"),
            "attack_summary": self.attack_summary.model_dump(mode="json"),
            "metrics": self.metrics.model_dump(mode="json"),
            "llm_usage": (
                self.llm_usage.model_dump(mode="json")
                if self.llm_usage is not None
                else None
            ),
            "llm_latency_ms": self.llm_latency_ms,
            "llm_cost_estimated_usd": self.llm_cost_estimated_usd,
        }


@dataclass(frozen=True)
class ProcessOptions:
    """Execution flags grouped to reduce signature-level coupling."""

    clean_target: bool
    etl_only: bool
    strict_data: bool
    llm_mode: bool
    llm_arm: str
    approval_policy_mode: Literal["remove", "defer_to_human_approval"]
    llm_factory: LLMFactory


@dataclass(frozen=True)
class VerifierRunOptions:
    run_tag: str
    strict_data: bool
    approval_policy_mode: Literal["remove", "defer_to_human_approval"]
    write_canonical_output: bool = True
    llm_actions: list[str] | None = None
    llm_deployment: str | None = None
    llm_arm: str | None = None
    llm_usage: LLMUsage | None = None
    llm_latency_ms: int | None = None
    llm_cost_estimated_usd: float | None = None


@dataclass(frozen=True)
class LLMRunResult:
    """LLM response with metadata for versioned persistence."""

    actions: list[str]
    deployment: str
    reasoning: str
    arm: str
    hallucinated_actions: list[str]
    input_snapshot: dict[str, Any]
    prompt_messages: list[dict[str, str]] | None
    prompt_sha256: str | None
    usage: LLMUsage | None = None
    latency_ms: int | None = None
    estimated_cost_usd: float | None = None


def _sep(char: str = "-", width: int = 60) -> None:
    print(char * width)


def _header(title: str) -> None:
    _sep("=")
    print(f"  {title}")
    _sep("=")


def _step(_marker: str, msg: str) -> None:
    print(f"\n{msg}")


def _item(msg: str) -> None:
    print(f"     {msg}")


def _ok(msg: str) -> None:
    print(f"   [ok] {msg}")


def _warn(msg: str) -> None:
    print(f"   [warn] {msg}")


def _done(msg: str) -> None:
    print(f"\nDone: {msg}")
    _sep()


def _sanitize_tag_component(value: str) -> str:
    safe = "".join(ch if (ch.isalnum() or ch in {"-", "_"}) else "_" for ch in value)
    return safe.strip("_") or "unknown"


def _utc_run_suffix() -> str:
    # Include microseconds to avoid run_tag collisions in fast consecutive runs.
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")


def _build_run_tag(
    mode: str,
    deployment: str | None = None,
    approval_policy_mode: Literal["remove", "defer_to_human_approval"] = "remove",
) -> str:
    mode_tag = _sanitize_tag_component(mode.lower())
    approval_tag = (
        f"_approval_{_sanitize_tag_component(approval_policy_mode)}"
        if approval_policy_mode != "remove"
        else ""
    )
    if deployment:
        deployment_tag = _sanitize_tag_component(deployment.lower())
        return f"{mode_tag}_{deployment_tag}{approval_tag}_{_utc_run_suffix()}"
    return f"{mode_tag}{approval_tag}_{_utc_run_suffix()}"


def ingest_globals(paths: RepoPaths) -> None:
    paths.outputs_global_dir.mkdir(parents=True, exist_ok=True)
    require_exists(paths.inbox_action_catalog_path)
    require_exists(paths.inbox_constraints_path)
    require_exists(paths.attack_mapping_path)
    require_exists(paths.mitre_manifest_path)

    paths.outputs_action_catalog_path.write_text(
        paths.inbox_action_catalog_path.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    paths.outputs_constraints_path.write_text(
        paths.inbox_constraints_path.read_text(encoding="utf-8"),
        encoding="utf-8",
    )


def _copytree_merge(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        d = dst / item.name
        if item.is_dir():
            _copytree_merge(item, d)
        else:
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, d)


def ingest_incident(
    paths: RepoPaths,
    incident_id: str,
    clean_target: bool,
    strict_data: bool,
) -> None:
    src = paths.inbox_incident_dir(incident_id)
    dst = paths.outputs_incident_dir(incident_id)

    require_exists(src / "incident_meta.json")
    require_exists(src / "incident_human_actions.jsonl")

    if clean_target and dst.exists():
        shutil.rmtree(dst)

    _copytree_merge(src, dst)

    # ETL: convert SIEM datasets into incident_telemetry.jsonl
    #
    # Accept two telemetry formats in the incident inbox:
    #
    #   Form 1 — already normalized JSONL file (legacy):
    #     dataset/incidents/INC_XXX/incident_telemetry.jsonl
    #
    #   Mode 2 - one or more raw dataset JSON files (preferred):
    #     dataset/incidents/INC_XXX/datasets/*.json
    #
    # If both exist, datasets take precedence and are merged.

    telemetry_dst = paths.outputs_incident_telemetry_path(incident_id)
    datasets_src_dir = src / "datasets"

    if datasets_src_dir.exists() and any(datasets_src_dir.glob("*.json")):
        dataset_files = sorted(datasets_src_dir.glob("*.json"))
        _step("", f"Found {len(dataset_files)} SIEM dataset file(s)")
        for dataset_file in dataset_files:
            _item(f"· {dataset_file.name}")

        _step("", "Running ETL to normalize raw events...")
        count = merge_datasets_to_telemetry(
            dataset_files,
            telemetry_dst,
            overwrite=True,
            strict=strict_data,
        )
        _ok(f"{count} normalized events -> {telemetry_dst.name}")

    elif not telemetry_dst.exists():
        raw_telemetry = src / "incident_telemetry.jsonl"
        _step("", "Using legacy JSONL telemetry...")
        require_exists(raw_telemetry)


def build_llm_port() -> LLMPort:
    """Resolve the concrete LLM adapter at the pipeline composition root."""
    from soc_llm_policy.llm_adapter import LLMAdapter  # noqa: PLC0415

    return LLMAdapter.from_env()


def run_llm(
    paths: RepoPaths,
    incident_id: str,
    llm_factory: LLMFactory,
    strict_data: bool,
    llm_arm: str,
) -> LLMRunResult:
    """
    Call the LLM to recommend incident-response actions.

    Reads credentials from the canonical project .env via LLMAdapter.from_env().
    Returns actions/deployment/reasoning for versioned persistence.
    """
    from soc_llm_policy.dotenv_utils import load_project_dotenv  # noqa: PLC0415

    load_project_dotenv(paths.repo_root)

    _step("", f"Querying LLM for response recommendations ({llm_arm})...")

    meta = parse_incident_meta(read_json(paths.outputs_incident_meta_path(incident_id)))
    telemetry = parse_telemetry(
        read_jsonl(
            paths.outputs_incident_telemetry_path(incident_id),
            strict=strict_data,
        )
    )
    catalog = parse_action_catalog(read_yaml_list(paths.outputs_action_catalog_path))
    rules = parse_rules(read_yaml_list(paths.outputs_constraints_path))

    adapter = llm_factory()
    policy_prompt_mode = (
        "inline_constraints" if llm_arm == "llm_policy_prompt" else "none"
    )
    recommendation = adapter.recommend(
        meta,
        telemetry,
        catalog,
        policy_rules=rules,
        policy_prompt_mode=policy_prompt_mode,
    )
    snapshot = {
        "incident_id": incident_id,
        "llm_arm": llm_arm,
        "policy_prompt_mode": policy_prompt_mode,
        "meta": meta.model_dump(mode="json"),
        "telemetry_event_count": len(telemetry),
        "telemetry_preview": [
            event.model_dump(mode="json") for event in telemetry[:40]
        ],
        "catalog_action_ids": [item.action_id for item in catalog],
        "hallucinated_actions": recommendation.hallucinated_actions or [],
        "latency_ms": recommendation.latency_ms,
        "policy_rules": [
            {
                "rule_id": rule.rule_id,
                "type": rule.type,
                "action": rule.action,
                "severity": rule.severity,
            }
            for rule in rules
        ],
        "prompt_messages": recommendation.prompt_messages or [],
        "prompt_sha256": recommendation.prompt_sha256,
        "input_file_hashes": {
            "incident_meta_json": _sha256_file(
                paths.outputs_incident_meta_path(incident_id)
            ),
            "incident_telemetry_jsonl": _sha256_file(
                paths.outputs_incident_telemetry_path(incident_id)
            ),
            "action_catalog_yaml": _sha256_file(paths.outputs_action_catalog_path),
            "constraints_yaml": _sha256_file(paths.outputs_constraints_path),
        },
    }

    _ok(f"LLM recommended {len(recommendation.actions)} action(s):")
    for i, a in enumerate(recommendation.actions, 1):
        _item(f"{i}. {a}")
    preview = recommendation.reasoning[:_REASONING_PREVIEW_LEN]
    suffix = "..." if len(recommendation.reasoning) > _REASONING_PREVIEW_LEN else ""
    _item(f"Reasoning: {preview}{suffix}")
    if recommendation.usage is not None:
        _item(
            "Token usage: "
            f"prompt={recommendation.usage.prompt_tokens}, "
            f"completion={recommendation.usage.completion_tokens}, "
            f"total={recommendation.usage.total_tokens}"
        )
    if recommendation.estimated_cost_usd is not None:
        _item(f"Estimated cost: USD {recommendation.estimated_cost_usd:.6f}")
    if recommendation.latency_ms is not None:
        _item(f"End-to-end latency: {recommendation.latency_ms} ms")

    return LLMRunResult(
        actions=recommendation.actions,
        deployment=adapter.deployment,
        reasoning=recommendation.reasoning,
        arm=llm_arm,
        hallucinated_actions=recommendation.hallucinated_actions or [],
        input_snapshot=snapshot,
        prompt_messages=recommendation.prompt_messages,
        prompt_sha256=recommendation.prompt_sha256,
        usage=recommendation.usage,
        latency_ms=recommendation.latency_ms,
        estimated_cost_usd=recommendation.estimated_cost_usd,
    )


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _save_llm_raw_output(
    paths: RepoPaths,
    incident_id: str,
    run_tag: str,
    llm_result: LLMRunResult,
) -> None:
    """Persiste a resposta bruta do LLM para rastreabilidade."""
    raw_output: dict[str, Any] = {
        "incident_id": incident_id,
        "model": llm_result.deployment,
        "arm": llm_result.arm,
        "actions": llm_result.actions,
        "hallucinated_actions": llm_result.hallucinated_actions,
        "reasoning": llm_result.reasoning,
        "prompt_sha256": llm_result.prompt_sha256,
        "usage": (
            llm_result.usage.model_dump(mode="json")
            if llm_result.usage is not None
            else None
        ),
        "latency_ms": llm_result.latency_ms,
        "estimated_cost_usd": llm_result.estimated_cost_usd,
    }
    _write_json(paths.outputs_llm_actions_path(incident_id), raw_output)
    _write_json(
        paths.outputs_llm_actions_versioned_path(incident_id, run_tag),
        raw_output,
    )


def _save_llm_input_snapshot(
    paths: RepoPaths,
    incident_id: str,
    run_tag: str,
    snapshot: dict[str, Any],
) -> None:
    _write_json(paths.outputs_llm_input_snapshot_path(incident_id), snapshot)
    _write_json(
        paths.outputs_llm_input_snapshot_versioned_path(incident_id, run_tag),
        snapshot,
    )


# Incident listing


def list_inbox_incidents(paths: RepoPaths) -> list[str]:
    if not paths.inbox_incidents_dir.exists():
        raise FileNotFoundError(
            f"Incidents directory does not exist: {paths.inbox_incidents_dir}"
        )

    out = [
        p.name for p in sorted(paths.inbox_incidents_dir.glob("INC_*")) if p.is_dir()
    ]

    if not out:
        raise FileNotFoundError(
            f"No incidents found in {paths.inbox_incidents_dir}/INC_*"
        )
    return out


# Verifier helpers


def _load_verifier_inputs(
    paths: RepoPaths,
    incident_id: str,
    strict_data: bool,
) -> tuple[
    list[TelemetryEvent],
    list[ActionCatalogItem],
    list[PolicyRule],
    IncidentMeta,
]:
    """Load telemetry, catalog, and rules; print progress to the terminal."""
    meta = parse_incident_meta(read_json(paths.outputs_incident_meta_path(incident_id)))

    _step("", "Loading normalized telemetry...")
    telemetry = parse_telemetry(
        read_jsonl(
            paths.outputs_incident_telemetry_path(incident_id),
            strict=strict_data,
        )
    )
    _ok(f"{len(telemetry)} events loaded")

    _step("", "Loading action catalog and policy rules...")
    catalog = parse_action_catalog(read_yaml_list(paths.outputs_action_catalog_path))
    rules = parse_rules(read_yaml_list(paths.outputs_constraints_path))
    _ok(f"{len(catalog)} actions in catalog  |  {len(rules)} policy rules")

    return telemetry, catalog, rules, meta


def _read_human_actions(
    paths: RepoPaths,
    incident_id: str,
    strict_data: bool,
) -> list[HumanAction]:
    """Extract ordered action_id list from human JSONL actions file."""
    raw_actions = read_jsonl(
        paths.outputs_incident_human_actions_path(incident_id),
        strict=strict_data,
    )
    if strict_data:
        return parse_human_actions_strict_order(raw_actions)
    return parse_human_actions(raw_actions)


def _action_ids(actions: list[HumanAction]) -> list[str]:
    return [action.action_id for action in actions]


def _approved_action_ids(actions: list[HumanAction]) -> list[str]:
    return sorted(
        {
            action.action_id
            for action in actions
            if action.approval is True
        }
    )


def _print_rule_results(rules: list[PolicyRule], violations: list[Violation]) -> None:
    """Print compliance status by policy rule."""
    print()
    _sep()
    for rule in rules:
        rid = rule.rule_id
        matched = [v for v in violations if v.rule_id == rid]
        if matched:
            for v in matched:
                if v.type == "missing_mandatory":
                    _warn(
                        f"[{rid}] Missing mandatory action: '{v.action}' -> inserted automatically"  # noqa: E501
                    )
                elif v.type == "order_violation":
                    _warn(
                        f"[{rid}] Order violation: '{v.action}' requires '{v.missing_before}' first -> corrected"  # noqa: E501
                    )
                elif v.type == "approval_required":
                    _warn(
                        f"[{rid}] Approval required: '{v.action}' removed from plan"
                    )
        else:
            _ok(f"[{rid}] OK")
    _sep()


def _print_summary(
    violations: list[Violation],
    enforced: list[str],
    llm_actions: list[str] | None,
    human_actions: list[str],
    attack_summary: AttackContextSummary,
) -> None:
    """Print violation summary, corrected plan, and LLM-vs-human divergence."""
    _step("", "Summary:")
    if not violations:
        _item("Violations:       none")
    else:
        _item(f"Violations:       {len(violations)} detected")
    _item(f"Corrected plan:   {' -> '.join(enforced) if enforced else '(empty)'}")

    if llm_actions is None:
        return

    only_llm = sorted(set(llm_actions) - set(human_actions))
    only_human = sorted(set(human_actions) - set(llm_actions))
    if only_llm or only_human:
        _step("", "LLM vs Human divergence:")
        if only_llm:
            _item(f"Only LLM recommended: {only_llm}")
        if only_human:
            _item(f"Only human executed:  {only_human}")
    else:
        _step("", "LLM vs Human divergence: none - identical actions")

    tactics = attack_summary.tactics
    techniques = attack_summary.techniques
    if tactics or techniques:
        _step("", "Inferred ATT&CK context:")
        if tactics:
            tactic_names = [item.tactic_name for item in tactics]
            _item(f"Tactics:          {', '.join(tactic_names)}")
        if techniques:
            technique_labels = [item.technique_id for item in techniques]
            _item(f"Techniques:       {', '.join(technique_labels)}")


def _save_verifier_result(
    paths: RepoPaths,
    incident_dir_id: str,
    run_tag: str,
    result: VerifierResult,
    *,
    write_canonical_output: bool = True,
) -> dict[str, Any]:
    """Serialize and persist verifier result; return the resulting dict."""
    output_path = paths.outputs_verifier_output_path(incident_dir_id)
    output_path_versioned = paths.outputs_verifier_output_versioned_path(
        incident_dir_id,
        run_tag,
    )
    data = VerifierOutputModel.model_validate(result.to_dict()).model_dump(mode="json")
    if write_canonical_output:
        _write_json(output_path, data)
    _write_json(output_path_versioned, data)
    if write_canonical_output:
        _step("", f"Result saved at: {output_path.relative_to(paths.repo_root)}")
    else:
        _step(
            "",
            "Replay result saved without overwriting canonical output:",
        )
    _item(f"History saved at:    {output_path_versioned.relative_to(paths.repo_root)}")
    return data


# Verifier entrypoint


def run_verifier(
    paths: RepoPaths,
    incident_id: str,
    options: VerifierRunOptions,
) -> dict[str, Any]:
    """
    Verify action compliance against policy rules.

    If llm_actions is provided (--llm-mode), those actions are verified.
    Otherwise, actions are loaded from incident_human_actions.jsonl (legacy mode).

    Output always stores both columns for paper comparison:
      - human_actions: what the human analyst executed
      - llm_actions:   what the LLM recommended
    """
    require_exists(paths.outputs_incident_dir(incident_id))

    telemetry, catalog, rules, meta = _load_verifier_inputs(
        paths,
        incident_id,
        options.strict_data,
    )
    human_action_rows = _read_human_actions(paths, incident_id, options.strict_data)
    human_actions = _action_ids(human_action_rows)
    incident_approved_actions = _approved_action_ids(human_action_rows)
    attack_rules = load_attack_rules(paths.attack_mapping_path)
    attack_reference = AttackReference.model_validate(
        read_mitre_manifest(paths.mitre_manifest_path)
    )
    attack_candidates = AttackCandidatesSummary.model_validate(
        summarize_attack_candidates(telemetry, attack_rules)
    )
    attack_summary = AttackContextSummary.model_validate(
        summarize_attack_context(telemetry, attack_rules)
    )

    actions_to_verify = (
        options.llm_actions if options.llm_actions is not None else human_actions
    )
    mode = "LLM" if options.llm_actions is not None else "human"

    _step("", f"Actions to verify (source: {mode}):")
    for i, a in enumerate(actions_to_verify, 1):
        _item(f"{i}. {a}")

    _step("", "Verifying policy compliance...")
    violations, enforced = enforce_policy(
        llm_actions=actions_to_verify,
        telemetry=telemetry,
        rules=rules,
        catalog=catalog,
        incident_approved_actions=set(incident_approved_actions),
        approval_policy_mode=options.approval_policy_mode,
    )

    _print_rule_results(rules, violations)
    _print_summary(
        violations,
        enforced,
        options.llm_actions,
        human_actions,
        attack_summary,
    )

    effective_llm_actions = (
        options.llm_actions if options.llm_actions is not None else human_actions
    )
    llm_hallucinated_actions = 0
    if options.llm_actions is not None:
        llm_raw_output_path = paths.outputs_llm_actions_path(incident_id)
        if llm_raw_output_path.exists():
            llm_raw_output = read_json(llm_raw_output_path)
            raw_hallucinated_actions = llm_raw_output.get("hallucinated_actions", [])
            if isinstance(raw_hallucinated_actions, list):
                llm_hallucinated_actions = len(raw_hallucinated_actions)

    metrics = build_incident_metrics(
        IncidentMetricInput(
            human_actions=human_actions,
            llm_actions=effective_llm_actions,
            enforced_actions=enforced,
            violations=violations,
            attack_candidates=attack_candidates,
            attack_summary=attack_summary,
            llm_hallucinated_actions=llm_hallucinated_actions,
        )
    )
    approval_pending_actions = sorted(
        {
            violation.action
            for violation in violations
            if violation.type == "approval_deferred"
        }
    )

    result = VerifierResult(
        incident_id=meta.incident_id,
        incident_dir_id=incident_id,
        incident_type=meta.incident_type,
        severity=meta.severity,
        asset_criticality=meta.asset_criticality,
        mode=mode,
        approval_policy_mode=options.approval_policy_mode,
        run_tag=options.run_tag,
        llm_deployment=options.llm_deployment,
        llm_arm=options.llm_arm,
        human_actions=human_actions,
        incident_approved_actions=incident_approved_actions,
        llm_actions=effective_llm_actions,
        violations=violations,
        enforced_actions=enforced,
        approval_pending_actions=approval_pending_actions,
        attack_reference=attack_reference,
        attack_candidates=attack_candidates,
        attack_summary=attack_summary,
        metrics=metrics,
        llm_usage=options.llm_usage,
        llm_latency_ms=options.llm_latency_ms,
        llm_cost_estimated_usd=options.llm_cost_estimated_usd,
    )
    return _save_verifier_result(
        paths,
        incident_id,
        options.run_tag,
        result,
        write_canonical_output=options.write_canonical_output,
    )


# CLI


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="soc_llm_policy.pipeline")
    p.add_argument("--repo-root", default=None)
    p.add_argument("--clean-target", action="store_true")
    sub = p.add_mutually_exclusive_group(required=True)
    sub.add_argument("--incident", default=None, metavar="INC_ID")
    sub.add_argument("--all", action="store_true")
    p.add_argument(
        "--etl-only",
        action="store_true",
        help="Run ETL only (datasets -> telemetry.jsonl), skip policy verification.",
    )
    p.add_argument(
        "--llm-mode",
        action="store_true",
        help="Call the LLM to recommend actions before policy verification.",
    )
    p.add_argument(
        "--llm-arm",
        default="llm_zero",
        choices=["llm_zero", "llm_policy_prompt"],
        help="Prompt experimental arm for LLM-mode execution.",
    )
    p.add_argument(
        "--approval-policy-mode",
        default="remove",
        choices=["remove", "defer_to_human_approval"],
        help=(
            "How to handle approval-gated actions: remove from enforced plan "
            "(default) or keep as deferred for human approval."
        ),
    )
    p.add_argument(
        "--strict-data",
        action="store_true",
        help="Enable fail-fast for ETL/JSONL (recommended for paper runs).",
    )
    return p


def _process_incident(
    paths: RepoPaths,
    incident_id: str,
    options: ProcessOptions,
) -> None:
    _header(f"Incident: {incident_id}")
    ingest_incident(
        paths,
        incident_id,
        clean_target=options.clean_target,
        strict_data=options.strict_data,
    )

    if options.etl_only:
        _done(f"ETL finished: {incident_id}")
        return

    llm_result = (
        run_llm(
            paths,
            incident_id,
            options.llm_factory,
            strict_data=options.strict_data,
            llm_arm=options.llm_arm,
        )
        if options.llm_mode
        else None
    )
    run_tag = (
        _build_run_tag(
            f"LLM_{llm_result.arm}",
            llm_result.deployment,
            approval_policy_mode=options.approval_policy_mode,
        )
        if llm_result is not None
        else _build_run_tag(
            "human",
            approval_policy_mode=options.approval_policy_mode,
        )
    )
    if llm_result is not None:
        _save_llm_raw_output(
            paths=paths,
            incident_id=incident_id,
            run_tag=run_tag,
            llm_result=llm_result,
        )
        _save_llm_input_snapshot(
            paths=paths,
            incident_id=incident_id,
            run_tag=run_tag,
            snapshot=llm_result.input_snapshot,
        )
    run_verifier(
        paths,
        incident_id,
        options=VerifierRunOptions(
            run_tag=run_tag,
            strict_data=options.strict_data,
            approval_policy_mode=options.approval_policy_mode,
            llm_actions=llm_result.actions if llm_result is not None else None,
            llm_deployment=llm_result.deployment if llm_result is not None else None,
            llm_arm=llm_result.arm if llm_result is not None else None,
            llm_usage=llm_result.usage if llm_result is not None else None,
            llm_latency_ms=llm_result.latency_ms if llm_result is not None else None,
            llm_cost_estimated_usd=(
                llm_result.estimated_cost_usd if llm_result is not None else None
            ),
        ),
    )
    _done(f"Completed: {incident_id}")


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    repo_root = resolve_repo_root(args.repo_root)
    paths = RepoPaths(repo_root=repo_root)

    for d in (
        paths.inbox_dir,
        paths.inbox_global_dir,
        paths.inbox_incidents_dir,
        paths.outputs_incidents_dir,
        paths.outputs_global_dir,
    ):
        d.mkdir(parents=True, exist_ok=True)

    ingest_globals(paths)

    options = ProcessOptions(
        clean_target=bool(args.clean_target),
        etl_only=bool(args.etl_only),
        strict_data=bool(args.strict_data),
        llm_mode=bool(args.llm_mode),
        llm_arm=str(args.llm_arm),
        approval_policy_mode=cast(
            Literal["remove", "defer_to_human_approval"],
            args.approval_policy_mode,
        ),
        llm_factory=build_llm_port,
    )

    if args.all:
        incidents = list_inbox_incidents(paths)
        for incident_id in incidents:
            _process_incident(
                paths,
                incident_id,
                options=options,
            )
        print(f"\n[ok] {len(incidents)} incident(s) processed.")
        return

    _process_incident(
        paths,
        str(args.incident),
        options=options,
    )


if __name__ == "__main__":
    main()
