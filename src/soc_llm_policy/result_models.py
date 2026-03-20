from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ViolationOutput(BaseModel):
    rule_id: str = Field(..., min_length=1)
    severity: Literal["hard", "soft", "warning"]
    type: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    repair: str | None = None
    missing_before: str | None = None


class AttackTechniqueRef(BaseModel):
    technique_id: str = Field(..., min_length=1)
    technique_name: str = Field(..., min_length=1)


class AttackTacticRef(BaseModel):
    tactic_id: str = Field(..., min_length=1)
    tactic_name: str = Field(..., min_length=1)


class AttackTechniqueCount(BaseModel):
    technique_id: str = Field(..., min_length=1)
    technique_name: str = Field(..., min_length=1)
    count: int = Field(..., ge=0)


class AttackTacticCount(BaseModel):
    tactic_id: str = Field(..., min_length=1)
    tactic_name: str = Field(..., min_length=1)
    count: int = Field(..., ge=0)


class AttackCandidate(BaseModel):
    rule_id: str = Field(..., min_length=1)
    technique_id: str = Field(..., min_length=1)
    technique_name: str = Field(..., min_length=1)
    tactic_id: str = Field(..., min_length=1)
    tactic_name: str = Field(..., min_length=1)
    event_type: str = Field(..., min_length=1)
    score: float = Field(..., ge=0.0, le=1.0)
    matched_signals: list[str] = Field(default_factory=list)
    evidence: str = Field(..., min_length=1)


class AttackMatch(BaseModel):
    rule_id: str = Field(..., min_length=1)
    technique_id: str = Field(..., min_length=1)
    technique_name: str = Field(..., min_length=1)
    tactic_id: str = Field(..., min_length=1)
    tactic_name: str = Field(..., min_length=1)
    event_type: str = Field(..., min_length=1)
    confidence: float = Field(..., ge=0.0, le=1.0)
    matched_signals: list[str] = Field(default_factory=list)
    evidence: str = Field(..., min_length=1)


class AttackReference(BaseModel):
    stix_path: str = Field(..., min_length=1)
    sha256: str = Field(..., min_length=1)
    object_count: int = Field(..., ge=0)
    technique_count: int = Field(..., ge=0)
    tactic_count: int = Field(..., ge=0)
    latest_modified: str = Field(..., min_length=1)


class AttackCandidatesSummary(BaseModel):
    rule_count: int = Field(..., ge=0)
    candidate_count: int = Field(..., ge=0)
    average_score: float = Field(..., ge=0.0, le=1.0)
    technique_counts: list[AttackTechniqueCount] = Field(default_factory=list)
    tactic_counts: list[AttackTacticCount] = Field(default_factory=list)
    candidates: list[AttackCandidate] = Field(default_factory=list)


class AttackContextSummary(BaseModel):
    rule_count: int = Field(..., ge=0)
    match_count: int = Field(..., ge=0)
    high_confidence_match_count: int = Field(..., ge=0)
    techniques: list[AttackTechniqueRef] = Field(default_factory=list)
    tactics: list[AttackTacticRef] = Field(default_factory=list)
    technique_counts: list[AttackTechniqueCount] = Field(default_factory=list)
    tactic_counts: list[AttackTacticCount] = Field(default_factory=list)
    matches: list[AttackMatch] = Field(default_factory=list)


class IncidentMetrics(BaseModel):
    human_action_count: int = Field(..., ge=0)
    llm_action_count: int = Field(..., ge=0)
    enforced_action_count: int = Field(..., ge=0)
    violation_count: int = Field(..., ge=0)
    hard_violation_count: int = Field(..., ge=0)
    soft_violation_count: int = Field(..., ge=0)
    warning_violation_count: int = Field(..., ge=0)
    llm_only_action_count: int = Field(..., ge=0)
    human_only_action_count: int = Field(..., ge=0)
    attack_match_count: int = Field(..., ge=0)
    attack_high_confidence_match_count: int = Field(..., ge=0)
    attack_candidate_count: int = Field(..., ge=0)
    attack_technique_count: int = Field(..., ge=0)
    attack_tactic_count: int = Field(..., ge=0)
    enforcement_actions_inserted_count: int = Field(default=0, ge=0)
    enforcement_actions_removed_count: int = Field(default=0, ge=0)
    enforcement_actions_deferred_count: int = Field(default=0, ge=0)
    enforcement_actions_reordered_count: int = Field(default=0, ge=0)
    enforcement_action_modification_count: int = Field(default=0, ge=0)
    enforcement_modified: bool = False
    llm_hallucinated_action_count: int = Field(default=0, ge=0)
    llm_hallucination_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    precision_raw: float = Field(default=0.0, ge=0.0, le=1.0)
    recall_raw: float = Field(default=0.0, ge=0.0, le=1.0)
    f1_raw: float = Field(default=0.0, ge=0.0, le=1.0)
    jaccard_raw: float = Field(default=0.0, ge=0.0, le=1.0)
    precision_enforced: float = Field(default=0.0, ge=0.0, le=1.0)
    recall_enforced: float = Field(default=0.0, ge=0.0, le=1.0)
    f1_enforced: float = Field(default=0.0, ge=0.0, le=1.0)
    jaccard_enforced: float = Field(default=0.0, ge=0.0, le=1.0)
    delta_jaccard: float = Field(default=0.0, ge=-1.0, le=1.0)


class LLMUsage(BaseModel):
    prompt_tokens: int = Field(..., ge=0)
    completion_tokens: int = Field(..., ge=0)
    total_tokens: int = Field(..., ge=0)


class VerifierOutputModel(BaseModel):
    incident_id: str = Field(..., min_length=1)
    incident_dir_id: str | None = None
    incident_type: str | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    asset_criticality: Literal["low", "medium", "high", "critical"] | None = None
    mode: Literal["LLM", "human"]
    run_tag: str = Field(..., min_length=1)
    approval_policy_mode: Literal["remove", "defer_to_human_approval"] | None = None
    llm_deployment: str | None = None
    llm_arm: Literal["llm_zero", "llm_policy_prompt"] | None = None
    human_actions: list[str] = Field(default_factory=list)
    incident_approved_actions: list[str] = Field(default_factory=list)
    llm_actions: list[str] = Field(default_factory=list)
    violations: list[ViolationOutput] = Field(default_factory=list)
    enforced_actions: list[str] = Field(default_factory=list)
    approval_pending_actions: list[str] = Field(default_factory=list)
    attack_reference: AttackReference
    attack_candidates: AttackCandidatesSummary
    attack_summary: AttackContextSummary
    metrics: IncidentMetrics
    llm_usage: LLMUsage | None = None
    llm_latency_ms: int | None = Field(default=None, ge=0)
    llm_cost_estimated_usd: float | None = None

    @field_validator("mode", mode="before")
    @classmethod
    def normalize_legacy_mode(cls, value: object) -> object:
        if value == "humano":
            return "human"
        return value
