from __future__ import annotations

import json
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


@dataclass(frozen=True)
class EnforcementRequest:
    llm_actions: list[str]
    telemetry: list[TelemetryEvent | dict[str, Any]]
    rules: list[PolicyRule]
    catalog: list[ActionCatalogItem]
    incident_approved_actions: set[str] | None = None
    approval_policy_mode: Literal["remove", "defer_to_human_approval"] = "remove"


def _find_order_cycle(edges: dict[str, set[str]]) -> list[str] | None:
    """Return one cycle path if found, otherwise None."""
    visiting: set[str] = set()
    visited: set[str] = set()
    stack: list[str] = []

    def dfs(node: str) -> list[str] | None:
        if node in visiting:
            if node in stack:
                start = stack.index(node)
                return [*stack[start:], node]
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


def _normalized_needles(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value).lower() for value in values if value]


def _contains_any(text: str | None, needles: list[str]) -> bool:
    if not needles:
        return True
    haystack = (text or "").lower()
    return any(needle in haystack for needle in needles)


def _contains_all(text: str | None, needles: list[str]) -> bool:
    if not needles:
        return True
    haystack = (text or "").lower()
    return all(needle in haystack for needle in needles)


def _details_text(event: TelemetryEvent) -> str:
    details = event.details.model_dump(mode="json")
    return json.dumps(details, sort_keys=True, ensure_ascii=True).lower()


def _event_matches_scope(event: TelemetryEvent, scope: dict[str, Any]) -> bool:
    event_type_needles = _normalized_needles(scope.get("event_type_contains"))
    category_needles = _normalized_needles(scope.get("category_contains"))
    command_needles = _normalized_needles(scope.get("command_contains"))
    details_needles = _normalized_needles(scope.get("details_text_contains"))
    severity_needles = _normalized_needles(scope.get("severity_contains"))

    has_predicate = any(
        [
            event_type_needles,
            category_needles,
            command_needles,
            details_needles,
            severity_needles,
        ]
    )
    if not has_predicate:
        return False

    return (
        _contains_any(event.event_type, event_type_needles)
        and _contains_any(event.category, category_needles)
        and _contains_all(event.details.command, command_needles)
        and _contains_any(_details_text(event), details_needles)
        and _contains_any(event.details.severity, severity_needles)
    )


def telemetry_matches_scope(
    telemetry: list[TelemetryEvent | dict[str, Any]],
    scope: dict[str, Any] | None,
) -> bool:
    """Check whether any telemetry event satisfies a typed rule scope."""
    if not scope:
        return False

    for event in _normalize_telemetry(telemetry):
        if _event_matches_scope(event, scope):
            return True
    return False


def telemetry_has_indicator(
    telemetry: list[TelemetryEvent | dict[str, Any]],
    event_type_contains: list[str],
    command_contains: list[str],
) -> bool:
    """Check whether telemetry events satisfy the legacy indicator set."""
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

        if not telemetry_matches_scope(telemetry=telemetry, scope=rule.scope):
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
    """Step 2: action-order violations (prohibit_before).

    Order constraints can form acyclic chains. Apply them to a fixed point so
    a missing prerequisite introduced by one rule can itself trigger another
    prerequisite in the same enforcement pass.
    """
    violations: list[Violation] = []
    emitted: set[tuple[str, str, str]] = set()
    order_rules = [
        rule
        for rule in rules
        if rule.type == "prohibit_before" and rule.condition_action
    ]
    if not order_rules:
        return filtered, violations

    repair_limit = len(order_rules) * max(1, len(filtered) + len(order_rules) + 1)
    repair_count = 0
    changed = True
    while changed:
        changed = False
        for rule in order_rules:
            if rule.action not in filtered:
                continue

            idx = filtered.index(rule.action)
            condition_action = str(rule.condition_action)
            if condition_action in filtered[:idx]:
                continue

            signature = (rule.rule_id, rule.action, condition_action)
            if signature not in emitted:
                violations.append(
                    Violation(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        type="order_violation",
                        action=rule.action,
                        repair="insert_before",
                        missing_before=condition_action,
                    )
                )
                emitted.add(signature)

            if condition_action in filtered:
                filtered = [action for action in filtered if action != condition_action]
                idx = filtered.index(rule.action)
            filtered.insert(idx, condition_action)
            changed = True
            repair_count += 1
            if repair_count > repair_limit:
                raise ValueError("Order repair did not converge")

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


def _coerce_enforcement_request(
    request: EnforcementRequest | None,
    kwargs: dict[str, Any],
) -> EnforcementRequest:
    if request is not None:
        if kwargs:
            raise TypeError("Do not mix EnforcementRequest with legacy keyword args.")
        return request
    if not kwargs:
        raise TypeError("enforce_policy requires an EnforcementRequest.")
    return EnforcementRequest(
        llm_actions=kwargs.pop("llm_actions"),
        telemetry=kwargs.pop("telemetry"),
        rules=kwargs.pop("rules"),
        catalog=kwargs.pop("catalog"),
        incident_approved_actions=kwargs.pop("incident_approved_actions", None),
        approval_policy_mode=kwargs.pop("approval_policy_mode", "remove"),
    )


def enforce_policy(
    request: EnforcementRequest | None = None,
    **kwargs: Any,
) -> tuple[list[Violation], list[str]]:
    """Verify and correct an LLM action plan against policy rules.

    Applies three sequential steps: mandatory -> order -> approval.
    Each step can add violations and modify the plan.

    Returns:
        Tuple (violations, enforced_actions).
    """
    request = _coerce_enforcement_request(request, kwargs)
    validate_rule_consistency(request.rules)

    filtered = list(validate_catalog(request.llm_actions, request.catalog))
    normalized_telemetry = _normalize_telemetry(request.telemetry)

    filtered, mandatory_violations = _apply_mandatory_rules(
        filtered,
        normalized_telemetry,
        request.rules,
    )
    filtered, order_violations = _apply_order_rules(filtered, request.rules)
    filtered, approval_violations = _apply_approval_rules(
        filtered,
        request.rules,
        request.catalog,
        incident_approved_actions=request.incident_approved_actions,
        approval_policy_mode=request.approval_policy_mode,
    )

    violations = mandatory_violations + order_violations + approval_violations
    enforced = _deduplicate(validate_catalog(filtered, request.catalog))

    return violations, enforced
