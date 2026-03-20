from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from soc_llm_policy.io import ActionCatalogItem, PolicyRule, TelemetryEvent


@dataclass(frozen=True)
class Violation:
    """A policy-rule violation detected in the action plan."""

    rule_id: str
    severity: str
    type: str
    action: str
    repair: str
    missing_before: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "type": self.type,
            "action": self.action,
            "repair": self.repair,
        }
        if self.missing_before is not None:
            d["missing_before"] = self.missing_before
        return d


def _find_order_cycle(edges: dict[str, set[str]]) -> list[str] | None:
    """Return one cycle path if found, otherwise None."""
    visiting: set[str] = set()
    visited: set[str] = set()
    stack: list[str] = []

    def dfs(node: str) -> list[str] | None:
        if node in visiting:
            if node in stack:
                start = stack.index(node)
                return stack[start:] + [node]
            return [node, node]
        if node in visited:
            return None

        visiting.add(node)
        stack.append(node)
        for nxt in sorted(edges.get(node, set())):
            found = dfs(nxt)
            if found is not None:
                return found
        stack.pop()
        visiting.remove(node)
        visited.add(node)
        return None

    for node in sorted(edges):
        found = dfs(node)
        if found is not None:
            return found
    return None


def validate_rule_consistency(rules: list[PolicyRule]) -> None:
    """Fail fast on policy-rule conflicts that make deterministic repair unsound.

    Current checks:
      1) Self-dependency in order constraints.
      2) Cycles in the partial-order graph from prohibit_before rules.
    """
    errors: list[str] = []
    edges: dict[str, set[str]] = {}

    for rule in rules:
        if rule.type == "mandatory":
            continue

        if rule.type == "require_approval":
            continue

        if rule.type != "prohibit_before" or not rule.condition_action:
            continue

        if rule.action == rule.condition_action:
            errors.append(
                "invalid_order_rule:"
                f" rule_id={rule.rule_id} has self-dependency ({rule.action})"
            )
            continue

        edges.setdefault(rule.condition_action, set()).add(rule.action)

    cycle = _find_order_cycle(edges)
    if cycle is not None:
        cycle_path = " -> ".join(cycle)
        errors.append(f"order_cycle_detected: {cycle_path}")

    if errors:
        raise ValueError("Inconsistent policy rules: " + " | ".join(errors))


def _normalize_telemetry(
    telemetry: list[TelemetryEvent | dict[str, Any]],
) -> list[TelemetryEvent]:
    return [
        event
        if isinstance(event, TelemetryEvent)
        else TelemetryEvent.model_validate(event)
        for event in telemetry
    ]


def telemetry_has_indicator(
    telemetry: list[TelemetryEvent | dict[str, Any]],
    event_type_contains: list[str],
    command_contains: list[str],
) -> bool:
    """Check whether telemetry events satisfy the rule indicator set."""
    et_needles = [x.lower() for x in event_type_contains if x]
    cmd_needles = [y.lower() for y in command_contains if y]

    for event in _normalize_telemetry(telemetry):
        et = event.event_type.lower()
        cmd = (event.details.command or "").lower()

        if any(x in et for x in et_needles) and all(y in cmd for y in cmd_needles):
            return True
    return False


def validate_catalog(
    action_ids: list[str],
    catalog: list[ActionCatalogItem],
) -> list[str]:
    """Filter action_ids that are not present in the catalog."""
    allowed = {a.action_id for a in catalog}
    return [a for a in action_ids if a in allowed]


def approvals_map(catalog: list[ActionCatalogItem]) -> Mapping[str, bool]:
    """Return action_id -> requires_approval mapping."""
    return {a.action_id: a.requires_approval for a in catalog}


def _apply_mandatory_rules(
    filtered: list[str],
    telemetry: list[TelemetryEvent | dict[str, Any]],
    rules: list[PolicyRule],
) -> tuple[list[str], list[Violation]]:
    """Step 1: missing mandatory actions when indicator is present."""
    violations: list[Violation] = []

    for rule in rules:
        if rule.type != "mandatory":
            continue
        scope = rule.scope or {}
        etc: list[str] = scope.get("event_type_contains") or []
        cc: list[str] = scope.get("command_contains") or []

        if not telemetry_has_indicator(
            telemetry=telemetry,
            event_type_contains=etc if isinstance(etc, list) else [],
            command_contains=cc if isinstance(cc, list) else [],
        ):
            continue

        if rule.action not in filtered:
            violations.append(
                Violation(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    type="missing_mandatory",
                    action=rule.action,
                    repair="insert",
                )
            )
            filtered = [rule.action, *filtered]

    return filtered, violations


def _apply_order_rules(
    filtered: list[str],
    rules: list[PolicyRule],
) -> tuple[list[str], list[Violation]]:
    """Step 2: action-order violations (prohibit_before)."""
    violations: list[Violation] = []

    for rule in rules:
        if rule.type != "prohibit_before":
            continue
        if not rule.condition_action:
            continue
        if rule.action not in filtered:
            continue

        idx = filtered.index(rule.action)
        if rule.condition_action not in filtered[:idx]:
            violations.append(
                Violation(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    type="order_violation",
                    action=rule.action,
                    repair="insert_before",
                    missing_before=rule.condition_action,
                )
            )
            filtered.insert(idx, rule.condition_action)

    return filtered, violations


def _apply_approval_rules(
    filtered: list[str],
    rules: list[PolicyRule],
    catalog: list[ActionCatalogItem],
    incident_approved_actions: set[str] | None = None,
    approval_policy_mode: Literal["remove", "defer_to_human_approval"] = "remove",
) -> tuple[list[str], list[Violation]]:
    """Step 3: enforce approval-gated actions.

    Modes:
      - remove: drop approval-gated actions from enforced plan.
      - defer_to_human_approval: keep action, mark as deferred for human approval.
    """
    if approval_policy_mode not in {"remove", "defer_to_human_approval"}:
        raise ValueError(f"Invalid approval_policy_mode: {approval_policy_mode}")

    violations: list[Violation] = []
    approvals = approvals_map(catalog)
    approved_actions = incident_approved_actions or set()

    for rule in rules:
        if rule.type != "require_approval":
            continue
        if (
            rule.action in filtered
            and approvals.get(rule.action, False)
            and rule.action not in approved_actions
        ):
            if approval_policy_mode == "remove":
                violations.append(
                    Violation(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        type="approval_required",
                        action=rule.action,
                        repair="remove",
                    )
                )
                filtered = [x for x in filtered if x != rule.action]
            else:
                violations.append(
                    Violation(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        type="approval_deferred",
                        action=rule.action,
                        repair="defer_to_human_approval",
                    )
                )

    return filtered, violations


def _deduplicate(actions: list[str]) -> list[str]:
    """Remove duplicates while preserving insertion order."""
    seen: set[str] = set()
    result: list[str] = []
    for action in actions:
        if action not in seen:
            result.append(action)
            seen.add(action)
    return result


# Public entrypoint


def enforce_policy(
    llm_actions: list[str],
    telemetry: list[TelemetryEvent | dict[str, Any]],
    rules: list[PolicyRule],
    catalog: list[ActionCatalogItem],
    incident_approved_actions: set[str] | None = None,
    approval_policy_mode: Literal["remove", "defer_to_human_approval"] = "remove",
) -> tuple[list[Violation], list[str]]:
    """Verify and correct an LLM action plan against policy rules.

    Applies three sequential steps: mandatory -> order -> approval.
    Each step can add violations and modify the plan.

    Returns:
        Tuple (violations, enforced_actions).
    """
    validate_rule_consistency(rules)

    filtered = list(validate_catalog(llm_actions, catalog))
    normalized_telemetry = _normalize_telemetry(telemetry)

    filtered, mandatory_violations = _apply_mandatory_rules(
        filtered,
        normalized_telemetry,
        rules,
    )
    filtered, order_violations = _apply_order_rules(filtered, rules)
    filtered, approval_violations = _apply_approval_rules(
        filtered,
        rules,
        catalog,
        incident_approved_actions=incident_approved_actions,
        approval_policy_mode=approval_policy_mode,
    )

    violations = mandatory_violations + order_violations + approval_violations
    enforced = _deduplicate(validate_catalog(filtered, catalog))

    return violations, enforced
