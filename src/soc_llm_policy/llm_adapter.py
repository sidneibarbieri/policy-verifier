"""
LLM adapter for multiple providers.

Supported providers:
  - azure_openai
  - openai
  - anthropic

Single responsibility: receive incident metadata + telemetry, build the prompt,
call the provider API, and return a list of action_ids.

It does not handle filesystem operations, policy enforcement, or engine logic.
That orchestration belongs to pipeline.py.

Usage:
    from soc_llm_policy.llm_adapter import LLMAdapter

    adapter = LLMAdapter.from_env()
    rec = adapter.recommend(meta, telemetry, catalog)
    # rec.actions -> ["isolate_host", "collect_forensics", "reset_admin_credentials"]
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Literal, cast

from soc_llm_policy.interfaces import LLMRecommendation
from soc_llm_policy.io import (
    ActionCatalogItem,
    IncidentMeta,
    PolicyRule,
    TelemetryEvent,
)
from soc_llm_policy.result_models import LLMUsage

class LLMAdapterError(Exception):
    """Generic error raised by the LLM adapter."""


class LLMResponseParseError(LLMAdapterError):
    """The LLM replied, but valid action_ids could not be extracted."""


@dataclass(frozen=True)
class LLMConfig:
    """Connection and generation settings for the provider adapter."""

    endpoint: str
    deployment: str
    api_key: str
    provider: Literal["azure_openai", "openai", "anthropic"] = "azure_openai"
    api_version: str = "2024-02-15-preview"
    max_tokens: int = 512
    temperature: float = 0.0
    # Maximum number of telemetry events sent to the LLM.
    # Large datasets (1000+ events) can exceed token limits.
    # Truncation preserves the most relevant events (see _truncate).
    max_telemetry_events: int = 40
    # Automatic retry on rate limit (429).
    max_retries: int = 3
    retry_wait_seconds: int = 65
    # Pricing used to estimate cost per run (USD per 1k tokens).
    prompt_price_per_1k_usd: float = 0.0
    completion_price_per_1k_usd: float = 0.0

    @classmethod
    def from_env(cls) -> LLMConfig:
        """
        Load credentials from environment variables.

        Common variable:
            SOC_LLM_PROVIDER         one of: azure_openai, openai, anthropic

        Provider-specific variables:
            azure_openai:
              AZURE_OPENAI_ENDPOINT
              AZURE_OPENAI_DEPLOYMENT
              AZURE_OPENAI_API_KEY
              AZURE_OPENAI_API_VERSION (optional)
            openai:
              OPENAI_API_KEY
              OPENAI_MODEL
              OPENAI_API_BASE (optional, default https://api.openai.com/v1)
            anthropic:
              ANTHROPIC_API_KEY
              ANTHROPIC_MODEL
              ANTHROPIC_API_BASE (optional, default https://api.anthropic.com/v1)
              ANTHROPIC_API_VERSION (optional, default 2023-06-01)
        """
        provider = os.environ.get("SOC_LLM_PROVIDER", "azure_openai").strip().lower()
        if provider not in {"azure_openai", "openai", "anthropic"}:
            raise LLMAdapterError(
                "SOC_LLM_PROVIDER must be one of: azure_openai, openai, anthropic."
            )

        max_retries_raw = os.environ.get("SOC_LLM_MAX_RETRIES", "3").strip()
        retry_wait_raw = os.environ.get("SOC_LLM_RETRY_WAIT_SECONDS", "65").strip()
        prompt_price = float(os.environ.get("SOC_LLM_PROMPT_PRICE_PER_1K_USD", "0"))
        completion_price = float(
            os.environ.get("SOC_LLM_COMPLETION_PRICE_PER_1K_USD", "0")
        )
        try:
            max_retries = int(max_retries_raw)
            retry_wait_seconds = int(retry_wait_raw)
        except ValueError as exc:
            raise LLMAdapterError(
                "SOC_LLM_MAX_RETRIES and SOC_LLM_RETRY_WAIT_SECONDS must be integers."
            ) from exc
        if max_retries < 1 or retry_wait_seconds < 0:
            raise LLMAdapterError(
                "SOC_LLM_MAX_RETRIES must be >= 1 and SOC_LLM_RETRY_WAIT_SECONDS >= 0."
            )

        endpoint = ""
        deployment = ""
        api_key = ""
        api_version = ""
        missing: list[str] = []

        if provider == "azure_openai":
            endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").strip()
            deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "").strip()
            api_key = os.environ.get("AZURE_OPENAI_API_KEY", "").strip()
            api_version = os.environ.get(
                "AZURE_OPENAI_API_VERSION",
                "2024-02-15-preview",
            ).strip()
            missing = [
                k
                for k, v in {
                    "AZURE_OPENAI_ENDPOINT": endpoint,
                    "AZURE_OPENAI_DEPLOYMENT": deployment,
                    "AZURE_OPENAI_API_KEY": api_key,
                }.items()
                if not v
            ]
        elif provider == "openai":
            endpoint = os.environ.get(
                "OPENAI_API_BASE",
                "https://api.openai.com/v1",
            ).strip()
            deployment = os.environ.get("OPENAI_MODEL", "").strip()
            api_key = os.environ.get("OPENAI_API_KEY", "").strip()
            missing = [
                k
                for k, v in {
                    "OPENAI_MODEL": deployment,
                    "OPENAI_API_KEY": api_key,
                }.items()
                if not v
            ]
        else:
            endpoint = os.environ.get(
                "ANTHROPIC_API_BASE",
                "https://api.anthropic.com/v1",
            ).strip()
            deployment = os.environ.get("ANTHROPIC_MODEL", "").strip()
            api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
            api_version = os.environ.get(
                "ANTHROPIC_API_VERSION",
                "2023-06-01",
            ).strip()
            missing = [
                k
                for k, v in {
                    "ANTHROPIC_MODEL": deployment,
                    "ANTHROPIC_API_KEY": api_key,
                }.items()
                if not v
            ]

        if missing:
            provider_hint = f" (provider={provider})"
            raise LLMAdapterError(
                f"Missing environment variables{provider_hint}: {', '.join(missing)}\n"
                "Set them in the repository-root .env or export them in your shell before running."
            )

        return cls(
            provider=cast(
                Literal["azure_openai", "openai", "anthropic"],
                provider,
            ),
            endpoint=endpoint,
            deployment=deployment,
            api_key=api_key,
            api_version=api_version,
            max_retries=max_retries,
            retry_wait_seconds=retry_wait_seconds,
            prompt_price_per_1k_usd=prompt_price,
            completion_price_per_1k_usd=completion_price,
        )


_HTTP_RATE_LIMIT = 429


@dataclass(frozen=True)
class _LLMAPIResponse:
    content: str
    usage: LLMUsage | None
    latency_ms: int | None

# Adapter


class LLMAdapter:
    """Provider-agnostic LLM adapter.

    Receives an LLMConfig with all connection and generation settings.
    """

    def __init__(self, config: LLMConfig) -> None:
        self._config = config

    @classmethod
    def from_env(cls) -> LLMAdapter:
        """Build adapter from environment variables via LLMConfig."""
        return cls(LLMConfig.from_env())

    @property
    def deployment(self) -> str:
        """Model or deployment identifier used for traceability."""
        return self._config.deployment

    def _truncate_telemetry(
        self,
        telemetry: list[TelemetryEvent],
    ) -> tuple[list[TelemetryEvent], bool]:
        """
        Limit telemetry to max_telemetry_events.

        Strategy: prioritize events with relevant command signals (bash, tcp,
        passwd, privilege), then fill with remaining events up to the limit.
        This keeps critical context even for large datasets.

        Returns (selected_events, was_truncated).
        """
        limit = self._config.max_telemetry_events
        if len(telemetry) <= limit:
            return telemetry, False

        # Keywords that indicate high-relevance SOC events.
        priority_keywords = [
            "bash",
            "/dev/tcp",
            "passwd",
            "shadow",
            "credential",
            "escalat",
            "lateral",
            "exfil",
            "ransom",
            "malware",
            "c2",
            "beacon",
            "inject",
            "persistence",
        ]

        priority: list[TelemetryEvent] = []
        rest: list[TelemetryEvent] = []

        for event in telemetry:
            cmd = (event.details.command or "").lower()
            et = event.event_type.lower()
            combined = cmd + " " + et
            if any(kw in combined for kw in priority_keywords):
                priority.append(event)
            else:
                rest.append(event)

        selected = (priority + rest)[:limit]
        return selected, True

    def _build_prompt(
        self,
        meta: IncidentMeta,
        telemetry: list[TelemetryEvent],
        catalog: list[ActionCatalogItem],
        total_events: int,
        *,
        policy_constraints_block: str = "",
    ) -> list[dict[str, str]]:
        """Build the chat messages sent to the provider API."""
        valid_actions = [item.action_id for item in catalog]
        catalog_str = "\n".join(f"  - {a}" for a in valid_actions)

        telemetry_lines = []
        for event in telemetry:
            et = event.event_type
            cmd = event.details.command or ""
            ts = (event.timestamp or "")[:19]
            line = f"  [{ts}] {et}"
            if cmd:
                line += f" -> {cmd[:80]}"
            telemetry_lines.append(line)

        telemetry_str = "\n".join(telemetry_lines)

        truncation_note = ""
        if total_events > len(telemetry):
            truncation_note = (
                f"\n(Sample: {len(telemetry)} of {total_events} total events,"
                " prioritizing the most relevant SOC context)"
            )

        time_window = f"{meta.time_window_start} -> {meta.time_window_end}"

        system_prompt = (
            "You are a senior SOC (Security Operations Center) analyst focused "
            "on incident response. Your task is to recommend response actions "
            "based on observed telemetry. Reply ONLY with a valid JSON object "
            "without additional text, explanations, or markdown."
        )

        user_prompt = f"""
Analyze the incident below and recommend appropriate response actions.

## Incident metadata
- ID:               {meta.incident_id}
- Type:             {meta.incident_type}
- Severity:         {meta.severity}
- Asset criticality:{meta.asset_criticality}
- Asset role:       {meta.asset_role}
- Time window:      {time_window}

## Correlated telemetry ({len(telemetry)} events){truncation_note}
{telemetry_str}

## Available actions in the SOC catalog
{catalog_str}

## Operational rules (when provided)
{policy_constraints_block or "No additional rules provided in prompt."}

## Your task
Reply ONLY with JSON using this exact format:
{{
  "recommended_actions": ["action_id_1", "action_id_2", "action_id_3"],
  "reasoning": "Brief rationale with one sentence per recommended action."
}}

Rules:
- Use ONLY action_ids from the list above
- Order actions by recommended execution sequence
- Do not invent action_ids not present in the list
""".strip()

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

    def _build_policy_constraints_block(self, rules: list[PolicyRule]) -> str:
        lines = []
        for rule in rules:
            line = f"- [{rule.rule_id}] {rule.type}: action={rule.action}"
            if rule.condition_action:
                line += f", prerequisite_action={rule.condition_action}"
            lines.append(line)
        return "\n".join(lines)

    def _openai_url(self) -> str:
        endpoint = self._config.endpoint.rstrip("/")
        if endpoint.endswith("/chat/completions"):
            return endpoint
        return f"{endpoint}/chat/completions"

    def _anthropic_url(self) -> str:
        endpoint = self._config.endpoint.rstrip("/")
        if endpoint.endswith("/messages"):
            return endpoint
        return f"{endpoint}/messages"

    def _extract_openai_content(self, body: dict[str, object]) -> str:
        try:
            content_obj = body["choices"][0]["message"]["content"]  # type: ignore[index]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMAdapterError(f"Unexpected OpenAI response format: {body}") from exc

        if isinstance(content_obj, str):
            return content_obj
        if isinstance(content_obj, list):
            parts: list[str] = []
            for block in content_obj:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
            if parts:
                return "\n".join(parts)
        raise LLMAdapterError(f"Unexpected OpenAI content format: {content_obj}")

    def _extract_anthropic_content(self, body: dict[str, object]) -> str:
        content_obj = body.get("content")
        if not isinstance(content_obj, list):
            raise LLMAdapterError(f"Unexpected Anthropic response format: {body}")
        parts: list[str] = []
        for block in content_obj:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
        if not parts:
            raise LLMAdapterError(f"No text blocks in Anthropic response: {body}")
        return "\n".join(parts)

    def _parse_anthropic_usage(self, usage_raw: object) -> LLMUsage | None:
        if not isinstance(usage_raw, dict):
            return None
        prompt_tokens = usage_raw.get("input_tokens")
        completion_tokens = usage_raw.get("output_tokens")
        if not (
            isinstance(prompt_tokens, int) and isinstance(completion_tokens, int)
        ):
            return None
        return LLMUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )

    def _to_anthropic_payload(
        self,
        messages: list[dict[str, str]],
    ) -> dict[str, object]:
        system_parts: list[str] = []
        convo: list[dict[str, str]] = []
        for message in messages:
            role = message.get("role", "").strip()
            content = str(message.get("content", ""))
            if role == "system":
                system_parts.append(content)
                continue
            if role in {"user", "assistant"}:
                convo.append({"role": role, "content": content})
        if not convo:
            convo = [{"role": "user", "content": "Return valid JSON only."}]

        payload: dict[str, object] = {
            "model": self._config.deployment,
            "max_tokens": self._config.max_tokens,
            "temperature": self._config.temperature,
            "messages": convo,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        return payload

    def _call_api(self, messages: list[dict[str, str]]) -> _LLMAPIResponse:
        """Call the configured provider API with automatic retry on HTTP 429."""
        cfg = self._config
        last_error: Exception | None = None
        started_at = time.perf_counter()
        for attempt in range(1, cfg.max_retries + 1):
            try:
                if cfg.provider == "azure_openai":
                    url = (
                        f"{cfg.endpoint.rstrip('/')}/openai/deployments/{cfg.deployment}"
                        f"/chat/completions?api-version={cfg.api_version}"
                    )
                    payload = json.dumps(
                        {
                            "messages": messages,
                            "max_tokens": cfg.max_tokens,
                            "temperature": cfg.temperature,
                        }
                    ).encode("utf-8")
                    req = urllib.request.Request(
                        url,
                        data=payload,
                        headers={
                            "Content-Type": "application/json",
                            "api-key": cfg.api_key,
                        },
                        method="POST",
                    )
                elif cfg.provider == "openai":
                    payload = json.dumps(
                        {
                            "model": cfg.deployment,
                            "messages": messages,
                            "max_completion_tokens": cfg.max_tokens,
                            "temperature": cfg.temperature,
                        }
                    ).encode("utf-8")
                    req = urllib.request.Request(
                        self._openai_url(),
                        data=payload,
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {cfg.api_key}",
                        },
                        method="POST",
                    )
                else:
                    payload = json.dumps(
                        self._to_anthropic_payload(messages)
                    ).encode("utf-8")
                    req = urllib.request.Request(
                        self._anthropic_url(),
                        data=payload,
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": cfg.api_key,
                            "anthropic-version": cfg.api_version or "2023-06-01",
                        },
                        method="POST",
                    )

                with urllib.request.urlopen(req, timeout=30) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                if cfg.provider in {"azure_openai", "openai"}:
                    content = self._extract_openai_content(body)
                    usage = self._parse_usage(body.get("usage"))
                else:
                    content = self._extract_anthropic_content(body)
                    usage = self._parse_anthropic_usage(body.get("usage"))
                latency_ms = int(round((time.perf_counter() - started_at) * 1000))
                return _LLMAPIResponse(
                    content=content,
                    usage=usage,
                    latency_ms=latency_ms,
                )

            except urllib.error.HTTPError as exc:
                error_body = exc.read().decode("utf-8", errors="replace")
                if exc.code == _HTTP_RATE_LIMIT and attempt < cfg.max_retries:
                    print(
                        f"   [warn] Rate limit (429) - waiting {cfg.retry_wait_seconds}s"
                        f" before attempt {attempt + 1}/{cfg.max_retries}..."
                    )
                    time.sleep(cfg.retry_wait_seconds)
                    last_error = LLMAdapterError(
                        f"{cfg.provider} HTTP {exc.code}: {error_body}"
                    )
                    continue
                raise LLMAdapterError(
                    f"{cfg.provider} HTTP {exc.code}: {error_body}"
                ) from exc

            except urllib.error.URLError as exc:
                raise LLMAdapterError(f"Connection error: {exc.reason}") from exc

        raise LLMAdapterError(
            f"Maximum retry attempts reached ({cfg.max_retries}x)."
        ) from last_error

    def _parse_usage(self, usage_raw: object) -> LLMUsage | None:
        if not isinstance(usage_raw, dict):
            return None
        prompt_tokens = usage_raw.get("prompt_tokens")
        completion_tokens = usage_raw.get("completion_tokens")
        total_tokens = usage_raw.get("total_tokens")
        if not all(
            isinstance(value, int)
            for value in (prompt_tokens, completion_tokens, total_tokens)
        ):
            return None
        return LLMUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
        )

    def _estimate_cost_usd(self, usage: LLMUsage | None) -> float | None:
        if usage is None:
            return None
        cfg = self._config
        prompt_cost = (usage.prompt_tokens / 1000) * cfg.prompt_price_per_1k_usd
        completion_cost = (
            usage.completion_tokens / 1000
        ) * cfg.completion_price_per_1k_usd
        return round(prompt_cost + completion_cost, 6)

    def _prompt_sha256(self, messages: list[dict[str, str]]) -> str:
        payload = json.dumps(messages, ensure_ascii=False, sort_keys=True).encode(
            "utf-8"
        )
        return hashlib.sha256(payload).hexdigest()

    def _parse_response(
        self,
        raw: str,
        valid_actions: set[str],
    ) -> tuple[list[str], str, list[str]]:
        """Extract recommended_actions and reasoning from the LLM JSON response.

        Returns (action_ids, reasoning, hallucinated_action_ids).
        Filters action_ids not present in the catalog.
        """
        text = raw.strip()
        if text.startswith("```"):
            text = "\n".join(
                line for line in text.splitlines() if not line.strip().startswith("```")
            ).strip()

        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMResponseParseError(
                f"LLM did not return valid JSON.\nRaw response: {raw}\nError: {exc}"
            ) from exc

        if "recommended_actions" not in obj:
            raise LLMResponseParseError(
                f"Missing 'recommended_actions' key in response.\nJSON: {obj}"
            )

        raw_actions = obj["recommended_actions"]
        if not isinstance(raw_actions, list):
            raise LLMResponseParseError(
                f"'recommended_actions' must be a list, got: {type(raw_actions)}"
            )

        # PLW2901: raw_action is the original item; action is the sanitized value.
        seen: set[str] = set()
        actions: list[str] = []
        skipped: list[str] = []
        for raw_action in raw_actions:
            action = str(raw_action).strip()
            if action in valid_actions and action not in seen:
                actions.append(action)
                seen.add(action)
            elif action not in valid_actions:
                skipped.append(action)

        if skipped:
            print(f"   [warn] LLM suggested out-of-catalog actions (ignored): {skipped}")

        reasoning = str(obj.get("reasoning", ""))
        return actions, reasoning, skipped

    def recommend(
        self,
        meta: IncidentMeta,
        telemetry: list[TelemetryEvent],
        catalog: list[ActionCatalogItem],
        *,
        policy_rules: list[PolicyRule] | None = None,
        policy_prompt_mode: Literal["none", "inline_constraints"] = "none",
    ) -> LLMRecommendation:
        """Request incident-response recommendations from the LLM.

        Args:
            meta: incident metadata parsed from incident_meta.json
            telemetry: list of events from incident_telemetry.jsonl
            catalog: list of action catalog items from action_catalog.yaml

        Returns:
            LLMRecommendation with actions, reasoning, usage, and estimated cost.
        """
        total_events = len(telemetry)
        truncated, was_truncated = self._truncate_telemetry(telemetry)

        if was_truncated:
            print(
                f"   [INFO] Telemetry truncated: {total_events} -> {len(truncated)} events"  # noqa: E501
                " (prioritizing high-relevance events)"
            )

        valid_actions = {item.action_id for item in catalog}
        policy_constraints_block = ""
        if policy_prompt_mode == "inline_constraints" and policy_rules:
            policy_constraints_block = self._build_policy_constraints_block(
                policy_rules
            )
        messages = self._build_prompt(
            meta,
            truncated,
            catalog,
            total_events,
            policy_constraints_block=policy_constraints_block,
        )
        api_response = self._call_api(messages)
        actions, reasoning, hallucinated_actions = self._parse_response(
            api_response.content,
            valid_actions,
        )
        return LLMRecommendation(
            actions=actions,
            reasoning=reasoning,
            hallucinated_actions=hallucinated_actions,
            usage=api_response.usage,
            latency_ms=api_response.latency_ms,
            estimated_cost_usd=self._estimate_cost_usd(api_response.usage),
            prompt_messages=messages,
            prompt_sha256=self._prompt_sha256(messages),
        )
