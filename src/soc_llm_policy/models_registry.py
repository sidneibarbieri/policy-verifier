from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from soc_llm_policy.io import read_yaml_list, require_exists


class ModelProfile(BaseModel):
    name: str = Field(..., min_length=1)
    deployment: str = Field(..., min_length=1)
    provider: str = "azure_openai"
    model: str = ""
    api_version: str = ""
    enabled: bool = True
    prompt_price_per_1k_usd: float = Field(default=0.0, ge=0.0)
    completion_price_per_1k_usd: float = Field(default=0.0, ge=0.0)


def load_model_registry(path: Path) -> list[ModelProfile]:
    require_exists(path)
    raw = read_yaml_list(path)
    return [ModelProfile.model_validate(item) for item in raw]


def select_model_profiles(
    profiles: list[ModelProfile],
    selectors: list[str] | None,
) -> list[ModelProfile]:
    if selectors is None:
        enabled = [profile for profile in profiles if profile.enabled]
        if not enabled:
            raise ValueError("No enabled model in the configured model registry.")
        return enabled

    selected: list[ModelProfile] = []
    for selector in selectors:
        matched = next(
            (
                profile
                for profile in profiles
                if selector in (profile.name, profile.deployment)
            ),
            None,
        )
        if matched is not None:
            selected.append(matched)
            continue
        selected.append(
            ModelProfile(
                name=selector,
                deployment=selector,
                provider="azure_openai",
                model="",
                api_version="",
                enabled=True,
            )
        )
    return selected
