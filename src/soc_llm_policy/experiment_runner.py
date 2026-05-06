from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import traceback
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from soc_llm_policy.analyze import main as analyze_main
from soc_llm_policy.dotenv_utils import load_project_dotenv
from soc_llm_policy.io import (
    parse_human_actions,
    parse_human_actions_strict_order,
    parse_incident_meta,
    read_json,
    read_jsonl,
)
from soc_llm_policy.models_registry import (
    ModelProfile,
    load_model_registry,
    select_model_profiles,
)
from soc_llm_policy.paths import RepoPaths, resolve_repo_root
from soc_llm_policy.pipeline import list_inbox_incidents
from soc_llm_policy.pipeline import main as pipeline_main

type MainFn = Callable[[list[str] | None], None]
type PreflightFn = Callable[[ModelProfile], tuple[bool, str]]
_HTTP_RATE_LIMIT = 429
_HTTP_BAD_REQUEST = 400


@dataclass(frozen=True)
class ExperimentRunConfig:
    paths: RepoPaths
    incidents: list[str]
    model_profiles: list[ModelProfile]
    arms: list[str]
    repeats: int
    run_id: str
    dataset_release_id: str
    min_incidents: int
    clean_target: bool
    fail_fast: bool
    preflight: bool
    preflight_data: bool
    strict_data: bool
    archive_run: bool
    eval_protocol_version: str
    data_preflight_json: Path
    data_quality_json: Path
    summary_json: Path
    analysis_bundle_json: Path
    failures_csv: Path
    failures_json: Path
    export_failures_csv: bool
    approval_policy_mode: str = "remove"


@dataclass(frozen=True)
class ExperimentMetadataInput:
    summary_path: Path
    bundle_path: Path
    data_preflight_path: Path
    data_quality_path: Path
    failures_path: Path
    profiles: list[ModelProfile]
    selected_profiles: list[ModelProfile]
    arms: list[str]
    repeats: int
    run_id: str
    dataset_release_id: str
    preflight: bool
    preflight_data: bool
    strict_data: bool
    fail_fast: bool
    archive_run: bool
    eval_protocol_version: str
    git_commit: str
    incident_count: int
    successful_run_count: int
    preflight_failure_count: int
    execution_failure_count: int


def _build_experiment_coverage(data: ExperimentMetadataInput) -> dict[str, object]:
    planned_model_count = len(data.profiles)
    selected_model_count = len(data.selected_profiles)
    planned_arm_count = len(data.arms)
    planned_run_count = (
        data.incident_count * selected_model_count * planned_arm_count * data.repeats
    )
    attempted_run_count = data.successful_run_count + data.execution_failure_count
    run_success_rate = (
        round(data.successful_run_count / attempted_run_count, 4)
        if attempted_run_count
        else 0.0
    )
    return {
        "planned_model_count": planned_model_count,
        "selected_model_count": selected_model_count,
        "planned_arm_count": planned_arm_count,
        "planned_repeat_count": data.repeats,
        "preflight_failure_count": data.preflight_failure_count,
        "preflight_data_enabled": data.preflight_data,
        "incident_count_input": data.incident_count,
        "planned_run_count": planned_run_count,
        "attempted_run_count": attempted_run_count,
        "successful_run_count": data.successful_run_count,
        "execution_failure_count": data.execution_failure_count,
        "run_success_rate": run_success_rate,
    }


def _read_json_if_exists(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return {}
    return payload


def _build_failure_summary(path: Path) -> dict[str, object]:
    payload = _read_json_if_exists(path)
    failures = payload.get("failures", [])
    if not isinstance(failures, list):
        failures = []

    by_exception: dict[str, int] = {}
    by_model: dict[str, int] = {}
    preflight_failure_count = 0
    parse_failure_count = 0

    for item in failures:
        if not isinstance(item, dict):
            continue
        exception_type = str(item.get("exception_type", "UnknownError"))
        model = str(item.get("model", "unknown"))
        by_exception[exception_type] = by_exception.get(exception_type, 0) + 1
        by_model[model] = by_model.get(model, 0) + 1
        if exception_type == "PreflightError":
            preflight_failure_count += 1
        if exception_type == "LLMResponseParseError":
            parse_failure_count += 1

    return {
        "failure_count": int(payload.get("failure_count", len(failures))),
        "failure_count_by_exception_type": by_exception,
        "failure_count_by_model": by_model,
        "preflight_failure_count": preflight_failure_count,
        "parse_failure_count": parse_failure_count,
        "failure_log_present": path.exists(),
    }


def _sanitize_run_component(value: str) -> str:
    safe = "".join(ch if (ch.isalnum() or ch in {"-", "_"}) else "_" for ch in value)
    return safe.strip("_") or "unknown"


def _default_run_id() -> str:
    return datetime.now(UTC).strftime("exp_%Y%m%dT%H%M%S%fZ")


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
    if not incidents_arg:
        raise ValueError("Provide --incidents INC_001,INC_002 or use --all.")
    incidents = _parse_csv_list(incidents_arg)
    if not incidents:
        raise ValueError("Empty incident list after parsing --incidents.")
    return incidents


@contextmanager
def _temporary_env(var_name: str, value: str) -> Iterator[None]:
    previous = os.environ.get(var_name)
    os.environ[var_name] = value
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(var_name, None)
        else:
            os.environ[var_name] = previous


@contextmanager
def _temporary_env_map(values: dict[str, str]) -> Iterator[None]:
    previous: dict[str, str | None] = {key: os.environ.get(key) for key in values}
    for key, value in values.items():
        os.environ[key] = value
    try:
        yield
    finally:
        for key, old_value in previous.items():
            if old_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_value


def _clean_selected_outputs(paths: RepoPaths, incidents: list[str]) -> None:
    for incident_id in incidents:
        target = paths.outputs_incident_dir(incident_id)
        if target.exists():
            shutil.rmtree(target)


def _validate_incident_inputs(
    paths: RepoPaths,
    incidents: list[str],
) -> dict[str, object]:
    details: list[dict[str, object]] = []
    missing_total = 0
    parse_error_total = 0
    approval_missing_total = 0
    order_missing_total = 0
    for incident_id in incidents:
        incident_dir = paths.inbox_incident_dir(incident_id)
        missing_files: list[str] = []
        parse_errors: list[str] = []
        approval_missing_count = 0
        order_missing_count = 0
        if not incident_dir.exists():
            missing_files.append(str(incident_dir))
        else:
            for req in ("incident_meta.json", "incident_human_actions.jsonl"):
                candidate = incident_dir / req
                if not candidate.exists():
                    missing_files.append(str(candidate))
            if not missing_files:
                try:
                    parse_incident_meta(read_json(incident_dir / "incident_meta.json"))
                except Exception as exc:
                    parse_errors.append(f"invalid incident_meta: {exc}")
                try:
                    actions_path = incident_dir / "incident_human_actions.jsonl"
                    actions = parse_human_actions(read_jsonl(actions_path, strict=True))
                    approval_missing_count = sum(
                        action.approval is None for action in actions
                    )
                    order_missing_count = sum(
                        action.order is None for action in actions
                    )
                    parse_human_actions_strict_order(
                        read_jsonl(actions_path, strict=True)
                    )
                except Exception as exc:
                    parse_errors.append(f"invalid incident_human_actions: {exc}")
        details.append(
            {
                "incident_id": incident_id,
                "ok": len(missing_files) == 0 and len(parse_errors) == 0,
                "missing_files": missing_files,
                "parse_errors": parse_errors,
                "approval_missing_count": approval_missing_count,
                "order_missing_count": order_missing_count,
            }
        )
        missing_total += len(missing_files)
        parse_error_total += len(parse_errors)
        approval_missing_total += approval_missing_count
        order_missing_total += order_missing_count
    return {
        "incident_count": len(incidents),
        "missing_file_count": missing_total,
        "parse_error_count": parse_error_total,
        "approval_missing_total": approval_missing_total,
        "order_missing_total": order_missing_total,
        "incidents": details,
    }


def _write_data_preflight_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def _build_data_quality_report(preflight: dict[str, object]) -> dict[str, object]:
    incident_count = int(preflight.get("incident_count", 0))
    approval_missing_total = int(preflight.get("approval_missing_total", 0))
    order_missing_total = int(preflight.get("order_missing_total", 0))
    parse_error_count = int(preflight.get("parse_error_count", 0))
    return {
        "incident_count": incident_count,
        "parse_error_count": parse_error_count,
        "approval_missing_total": approval_missing_total,
        "order_missing_total": order_missing_total,
        "data_quality_ok": (
            int(preflight.get("missing_file_count", 0)) == 0 and parse_error_count == 0
        ),
    }


def _write_data_quality_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def _resolve_git_commit(repo_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def _load_dotenv_if_available() -> None:
    load_project_dotenv()


def _normalize_provider(provider: str) -> str:
    normalized = provider.strip().lower()
    if not normalized:
        return "azure_openai"
    if normalized not in {"azure_openai", "openai", "anthropic"}:
        raise ValueError(
            "Invalid model provider in the configured model registry: "
            f"{provider!r}. Expected one of: azure_openai, openai, anthropic."
        )
    return normalized


def _build_llm_env_values(profile: ModelProfile) -> dict[str, str]:
    provider = _normalize_provider(profile.provider)
    deployment = profile.deployment.strip()
    if not deployment:
        raise ValueError(f"Model profile {profile.name!r} has empty deployment.")

    env_values = {
        "SOC_LLM_PROVIDER": provider,
        "SOC_LLM_PROMPT_PRICE_PER_1K_USD": str(profile.prompt_price_per_1k_usd),
        "SOC_LLM_COMPLETION_PRICE_PER_1K_USD": str(profile.completion_price_per_1k_usd),
    }
    if provider == "azure_openai":
        env_values["AZURE_OPENAI_DEPLOYMENT"] = deployment
        if profile.api_version:
            env_values["AZURE_OPENAI_API_VERSION"] = profile.api_version
    elif provider == "openai":
        env_values["OPENAI_MODEL"] = deployment
    else:
        env_values["ANTHROPIC_MODEL"] = deployment
        if profile.api_version:
            env_values["ANTHROPIC_API_VERSION"] = profile.api_version
    return env_values


def _check_deployment_available(profile: ModelProfile) -> tuple[bool, str]:
    provider = _normalize_provider(profile.provider)
    model = profile.deployment
    unavailable: tuple[bool, str] | None = None
    if provider == "azure_openai":
        endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").strip()
        api_key = os.environ.get("AZURE_OPENAI_API_KEY", "").strip()
        api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")
        if not endpoint or not api_key:
            unavailable = (
                False,
                "AZURE_OPENAI_ENDPOINT/API_KEY missing for preflight",
            )
        else:
            url = (
                f"{endpoint.rstrip('/')}/openai/deployments/{model}"
                f"/chat/completions?api-version={api_version}"
            )
            payload = json.dumps(
                {
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                    "temperature": 0,
                }
            ).encode("utf-8")
            headers = {"Content-Type": "application/json", "api-key": api_key}
    elif provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        endpoint = os.environ.get(
            "OPENAI_API_BASE", "https://api.openai.com/v1"
        ).strip()
        if not api_key:
            unavailable = (False, "OPENAI_API_KEY missing for preflight")
        else:
            url = f"{endpoint.rstrip('/')}/chat/completions"
            payload = json.dumps(
                {
                    "model": model,
                    "messages": [{"role": "user", "content": "ping"}],
                    # Some frontier models reject very small caps during preflight.
                    # Keep this low-cost but above strict minimums.
                    "max_completion_tokens": 16,
                    "temperature": 0,
                }
            ).encode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            }
    else:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        endpoint = os.environ.get(
            "ANTHROPIC_API_BASE",
            "https://api.anthropic.com/v1",
        ).strip()
        api_version = os.environ.get("ANTHROPIC_API_VERSION", "2023-06-01")
        if not api_key:
            unavailable = (False, "ANTHROPIC_API_KEY missing for preflight")
        else:
            url = f"{endpoint.rstrip('/')}/messages"
            payload = json.dumps(
                {
                    "model": model,
                    "max_tokens": 1,
                    "temperature": 0,
                    "messages": [{"role": "user", "content": "ping"}],
                }
            ).encode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": api_version,
            }

    if unavailable is not None:
        return unavailable

    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=20):
            return True, "ok"
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if exc.code == _HTTP_RATE_LIMIT:
            return True, "rate_limited_but_available"
        if provider == "openai" and exc.code == _HTTP_BAD_REQUEST:
            lowered = body.lower()
            if "max_tokens" in lowered and "output limit" in lowered:
                return True, "max_tokens_guard_but_available"
        return False, f"HTTP {exc.code}: {body}"
    except urllib.error.URLError as exc:
        return False, f"connection_error: {exc.reason}"


def _execute_model_runs(
    config: ExperimentRunConfig,
    profile: ModelProfile,
    run_pipeline: MainFn,
) -> tuple[int, int, list[dict[str, str]]]:
    model = profile.name
    deployment = profile.deployment
    provider = _normalize_provider(profile.provider)
    failures: list[dict[str, str]] = []
    success_count = 0
    execution_failure_count = 0

    env_values = _build_llm_env_values(profile)
    print(f"\n=== Model: {model} (provider={provider}, deployment={deployment}) ===")
    with _temporary_env_map(env_values):
        for arm in config.arms:
            for repeat_index in range(1, config.repeats + 1):
                for incident_id in config.incidents:
                    try:
                        run_pipeline(
                            [
                                "--repo-root",
                                str(config.paths.repo_root),
                                "--incident",
                                incident_id,
                                "--llm-mode",
                                "--llm-arm",
                                arm,
                                "--approval-policy-mode",
                                config.approval_policy_mode,
                                *(["--strict-data"] if config.strict_data else []),
                            ]
                        )
                        success_count += 1
                    except Exception as exc:
                        message = str(exc).replace("\n", " ").strip()
                        tb_text = traceback.format_exc()
                        failures.append(
                            {
                                "model": model,
                                "deployment": deployment,
                                "arm": arm,
                                "repeat_index": str(repeat_index),
                                "run_id": config.run_id,
                                "incident_id": incident_id,
                                "error": message,
                                "exception_type": exc.__class__.__name__,
                                "traceback": tb_text,
                            }
                        )
                        execution_failure_count += 1
                        print(
                            "Failure in "
                            "model="
                            f"{model} arm={arm} repeat={repeat_index} "
                            f"incident={incident_id}: {message}"
                        )
                        if config.fail_fast:
                            raise
    return success_count, execution_failure_count, failures


def _run_data_preflight(config: ExperimentRunConfig) -> None:
    data_preflight = _validate_incident_inputs(config.paths, config.incidents)
    _write_data_preflight_report(config.data_preflight_json, data_preflight)
    data_quality = _build_data_quality_report(data_preflight)
    _write_data_quality_report(config.data_quality_json, data_quality)

    missing_total = int(data_preflight.get("missing_file_count", 0))
    parse_error_total = int(data_preflight.get("parse_error_count", 0))
    if missing_total > 0 or parse_error_total > 0:
        raise FileNotFoundError(
            f"Data preflight failed. See: {config.data_preflight_json}"
        )
    print(f"Data preflight OK: {config.data_preflight_json}")


def _select_models_for_execution(
    config: ExperimentRunConfig,
    preflight_check: PreflightFn,
) -> tuple[list[ModelProfile], list[dict[str, str]], int]:
    models_to_run: list[ModelProfile] = []
    failure_rows: list[dict[str, str]] = []
    preflight_failure_count = 0

    for profile in config.model_profiles:
        deployment = profile.deployment
        provider = _normalize_provider(profile.provider)
        env_values = _build_llm_env_values(profile)
        if not config.preflight:
            models_to_run.append(profile)
            continue

        with _temporary_env_map(env_values):
            ok, reason = preflight_check(profile)

        if ok:
            print(
                "Preflight OK for model="
                f"{profile.name} (provider={provider}, "
                f"deployment={deployment}, {reason})"
            )
            models_to_run.append(profile)
            continue

        message = f"preflight_failed: {reason}"
        preflight_failure_count += 1
        failure_rows.append(
            {
                "model": profile.name,
                "deployment": deployment,
                "arm": "__all__",
                "repeat_index": "0",
                "run_id": config.run_id,
                "incident_id": "__preflight__",
                "error": message,
                "exception_type": "PreflightError",
                "traceback": "",
            }
        )
        print(
            "Preflight failed for model="
            f"{profile.name} (provider={provider}, deployment={deployment}): {reason}"
        )

    return models_to_run, failure_rows, preflight_failure_count


def run_experiments(
    config: ExperimentRunConfig,
    run_pipeline: MainFn = pipeline_main,
    run_analyze: MainFn = analyze_main,
    preflight_check: PreflightFn = _check_deployment_available,
) -> None:
    if config.preflight_data:
        _run_data_preflight(config)

    if config.clean_target:
        _clean_selected_outputs(config.paths, config.incidents)

    models_to_run, failure_rows, preflight_failure_count = _select_models_for_execution(
        config,
        preflight_check,
    )
    success_count = 0
    execution_failure_count = 0

    for profile in models_to_run:
        model_success_count, model_failure_count, model_failures = _execute_model_runs(
            config,
            profile,
            run_pipeline,
        )
        success_count += model_success_count
        execution_failure_count += model_failure_count
        failure_rows.extend(model_failures)

    if failure_rows:
        _write_failures_json(config.failures_json, failure_rows)
        if config.export_failures_csv:
            _write_failures_csv(config.failures_csv, failure_rows)
            print(f"Failures saved at: {config.failures_csv}")
        else:
            print(f"Failures saved at: {config.failures_json}")
    else:
        # Prevent stale failure artifacts from previous runs from being misread
        # as failures of the current run.
        if config.failures_json.exists():
            config.failures_json.unlink()
        if config.failures_csv.exists():
            config.failures_csv.unlink()

    if success_count == 0:
        raise RuntimeError("No successful execution in experiment_runner.")

    run_analyze(
        [
            "--outputs-incidents-dir",
            str(config.paths.outputs_incidents_dir),
            "--summary-json",
            str(config.summary_json),
            "--analysis-bundle-json",
            str(config.analysis_bundle_json),
            "--eval-protocol-version",
            config.eval_protocol_version,
            "--incidents",
            ",".join(config.incidents),
        ]
    )
    _attach_experiment_metadata(
        ExperimentMetadataInput(
            summary_path=config.summary_json,
            bundle_path=config.analysis_bundle_json,
            data_preflight_path=config.data_preflight_json,
            data_quality_path=config.data_quality_json,
            failures_path=config.failures_json,
            profiles=config.model_profiles,
            selected_profiles=models_to_run,
            arms=config.arms,
            repeats=config.repeats,
            run_id=config.run_id,
            dataset_release_id=config.dataset_release_id,
            preflight=config.preflight,
            preflight_data=config.preflight_data,
            strict_data=config.strict_data,
            fail_fast=config.fail_fast,
            archive_run=config.archive_run,
            eval_protocol_version=config.eval_protocol_version,
            git_commit=_resolve_git_commit(config.paths.repo_root),
            incident_count=len(config.incidents),
            successful_run_count=success_count,
            preflight_failure_count=preflight_failure_count,
            execution_failure_count=execution_failure_count,
        )
    )
    incident_count = _resolve_analyzed_incident_count(config)
    if incident_count < config.min_incidents:
        raise RuntimeError(
            "Analyzed incident count below minimum threshold: "
            f"{incident_count} < {config.min_incidents}"
        )
    if config.archive_run:
        _archive_experiment_outputs(config)


def _write_failures_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "model",
                "deployment",
                "arm",
                "repeat_index",
                "run_id",
                "incident_id",
                "error",
                "exception_type",
                "traceback",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def _write_failures_json(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"failure_count": len(rows), "failures": rows}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _attach_experiment_metadata(data: ExperimentMetadataInput) -> None:
    coverage = _build_experiment_coverage(data)
    data_preflight = _read_json_if_exists(data.data_preflight_path)
    data_quality = _read_json_if_exists(data.data_quality_path)
    failure_summary = _build_failure_summary(data.failures_path)
    if data.summary_path.exists():
        summary_data = json.loads(data.summary_path.read_text(encoding="utf-8"))
        summary_data["experiment_coverage"] = coverage
        data.summary_path.write_text(
            json.dumps(summary_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    if not data.bundle_path.exists():
        return
    bundle_data = json.loads(data.bundle_path.read_text(encoding="utf-8"))
    bundle_data["experiment"] = {
        "run_id": data.run_id,
        "dataset_release_id": data.dataset_release_id,
        "eval_protocol_version": data.eval_protocol_version,
        "git_commit": data.git_commit,
        "preflight_enabled": data.preflight,
        "preflight_data_enabled": data.preflight_data,
        "strict_data_enabled": data.strict_data,
        "fail_fast_enabled": data.fail_fast,
        "archive_run_enabled": data.archive_run,
        "arms": data.arms,
        "repeats": data.repeats,
        "coverage": coverage,
        "data_preflight": data_preflight,
        "data_quality": data_quality,
        "failure_summary": failure_summary,
        "registry_models": [
            profile.model_dump(mode="json") for profile in data.profiles
        ],
        "selected_models": [
            profile.model_dump(mode="json") for profile in data.selected_profiles
        ],
    }
    data.bundle_path.write_text(
        json.dumps(bundle_data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _archive_experiment_outputs(config: ExperimentRunConfig) -> None:
    run_dir = config.paths.outputs_experiment_dir(config.run_id)
    run_dir.mkdir(parents=True, exist_ok=True)

    if config.summary_json.exists():
        shutil.copy2(config.summary_json, run_dir / "summary.json")
    if config.analysis_bundle_json.exists():
        shutil.copy2(config.analysis_bundle_json, run_dir / "analysis_bundle.json")
    if config.failures_json.exists():
        shutil.copy2(config.failures_json, run_dir / "experiment_failures.json")
    if config.data_preflight_json.exists():
        shutil.copy2(config.data_preflight_json, run_dir / "data_preflight.json")
    if config.data_quality_json.exists():
        shutil.copy2(config.data_quality_json, run_dir / "data_quality_report.json")
    if config.export_failures_csv and config.failures_csv.exists():
        shutil.copy2(config.failures_csv, run_dir / "experiment_failures.csv")

    manifest = {
        "run_id": config.run_id,
        "dataset_release_id": config.dataset_release_id,
        "eval_protocol_version": config.eval_protocol_version,
        "incidents": config.incidents,
        "models": [profile.name for profile in config.model_profiles],
        "deployments": [profile.deployment for profile in config.model_profiles],
        "arms": config.arms,
        "repeats": config.repeats,
        "strict_data": config.strict_data,
        "approval_policy_mode": config.approval_policy_mode,
        "preflight": config.preflight,
        "preflight_data": config.preflight_data,
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Reproducibility snapshot saved at: {run_dir}")


def _resolve_analyzed_incident_count(config: ExperimentRunConfig) -> int:
    if not config.summary_json.exists():
        return len(config.incidents)
    summary_data = json.loads(config.summary_json.read_text(encoding="utf-8"))
    count = int(summary_data.get("incident_count", 0))
    if count > 0:
        return count
    return len(config.incidents)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soc_llm_policy.experiment_runner")
    parser.add_argument("--repo-root", default=None)
    parser.add_argument(
        "--models",
        default=None,
        help="CSV list of models/deployments. Optional override over registry.",
    )
    parser.add_argument(
        "--arms",
        default="llm_zero,llm_policy_prompt",
        help="CSV list of LLM arms. Example: llm_zero,llm_policy_prompt",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=1,
        help="Number of repeats per combination (model x arm x incident).",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Unique experiment ID. If omitted, UTC timestamp is generated.",
    )
    parser.add_argument(
        "--dataset-release-id",
        default="unknown",
        help="Identificador da release do dataset usada no experimento.",
    )
    parser.add_argument(
        "--min-incidents",
        type=int,
        default=1,
        help="Minimum analyzed incidents required to consider the run valid.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--incidents",
        default=None,
        help="CSV incident list. Example: INC_001,INC_002",
    )
    group.add_argument("--all", action="store_true")
    parser.add_argument("--clean-target", action="store_true")
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop on first execution error (default: continue and record).",
    )
    parser.add_argument(
        "--no-preflight",
        action="store_true",
        help="Disable preflight deployment checks before experiment execution.",
    )
    parser.add_argument(
        "--no-preflight-data",
        action="store_true",
        help="Disable input file preflight validation for incidents.",
    )
    parser.add_argument(
        "--no-strict-data",
        action="store_true",
        help="Disable pipeline fail-fast data mode (not recommended for paper runs).",
    )
    parser.add_argument(
        "--approval-policy-mode",
        default="remove",
        choices=["remove", "defer_to_human_approval"],
        help=("Approval handling mode forwarded to pipeline runs."),
    )
    parser.add_argument(
        "--summary-json",
        default="results/analysis/summary.json",
    )
    parser.add_argument(
        "--data-preflight-json",
        default="results/analysis/data_preflight.json",
    )
    parser.add_argument(
        "--data-quality-json",
        default="results/analysis/data_quality_report.json",
    )
    parser.add_argument(
        "--analysis-bundle-json",
        default="results/analysis/analysis_bundle.json",
    )
    parser.add_argument(
        "--eval-protocol-version",
        default="official",
        help="Evaluation state label recorded in the final bundle.",
    )
    parser.add_argument(
        "--no-archive-run",
        action="store_true",
        help="Disable run snapshot in results/experiments/<run_id>/.",
    )
    parser.add_argument(
        "--failures-csv",
        default="results/analysis/experiment_failures.csv",
    )
    parser.add_argument(
        "--failures-json",
        default="results/analysis/experiment_failures.json",
    )
    parser.add_argument(
        "--export-failures-csv",
        action="store_true",
        help="Export failures to CSV as well (default: JSON only).",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    _load_dotenv_if_available()
    args = build_parser().parse_args(argv)
    repo_root = resolve_repo_root(args.repo_root)
    paths = RepoPaths(repo_root=repo_root)

    profiles = load_model_registry(paths.models_registry_path)
    model_selectors = _parse_csv_list(args.models)
    model_profiles = select_model_profiles(
        profiles,
        model_selectors if model_selectors else None,
    )
    arms = _parse_csv_list(args.arms)
    allowed_arms = {"llm_zero", "llm_policy_prompt"}
    invalid_arms = [arm for arm in arms if arm not in allowed_arms]
    if invalid_arms:
        raise ValueError(f"Invalid arms in --arms: {invalid_arms}")
    if not arms:
        raise ValueError("No arm specified in --arms.")
    if int(args.repeats) <= 0:
        raise ValueError("--repeats must be >= 1.")
    if int(args.min_incidents) <= 0:
        raise ValueError("--min-incidents must be >= 1.")
    run_id = (
        _sanitize_run_component(str(args.run_id)) if args.run_id else _default_run_id()
    )
    dataset_release_id = _sanitize_run_component(str(args.dataset_release_id))
    incidents = _resolve_incidents(paths, args.incidents, bool(args.all))

    run_experiments(
        ExperimentRunConfig(
            paths=paths,
            incidents=incidents,
            model_profiles=model_profiles,
            arms=arms,
            repeats=int(args.repeats),
            run_id=run_id,
            dataset_release_id=dataset_release_id,
            min_incidents=int(args.min_incidents),
            clean_target=bool(args.clean_target),
            fail_fast=bool(args.fail_fast),
            preflight=not bool(args.no_preflight),
            preflight_data=not bool(args.no_preflight_data),
            strict_data=not bool(args.no_strict_data),
            approval_policy_mode=str(args.approval_policy_mode),
            archive_run=not bool(args.no_archive_run),
            eval_protocol_version=str(args.eval_protocol_version),
            data_preflight_json=(repo_root / args.data_preflight_json).resolve(),
            data_quality_json=(repo_root / args.data_quality_json).resolve(),
            summary_json=(repo_root / args.summary_json).resolve(),
            analysis_bundle_json=(repo_root / args.analysis_bundle_json).resolve(),
            failures_csv=(repo_root / args.failures_csv).resolve(),
            failures_json=(repo_root / args.failures_json).resolve(),
            export_failures_csv=bool(args.export_failures_csv),
        )
    )


if __name__ == "__main__":
    main()
