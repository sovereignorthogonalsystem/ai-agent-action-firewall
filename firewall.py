from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class FirewallCondition:
    name: str
    passed: bool
    detail: str
    weight: float = 1.0
    severity: str = "medium"


@dataclass
class FirewallResult:
    decision: str
    safety_score: float
    passed_conditions: List[str] = field(default_factory=list)
    failed_conditions: List[str] = field(default_factory=list)
    failure_report: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


POLICY_PROFILES = {
    "strict": {
        "max_cost_usd": 1.00,
        "allow_external_side_effect_without_approval": False,
        "allow_sensitive_data_without_redaction": False,
        "allow_destructive_action_without_approval": False,
    },
    "balanced": {
        "max_cost_usd": 10.00,
        "allow_external_side_effect_without_approval": False,
        "allow_sensitive_data_without_redaction": False,
        "allow_destructive_action_without_approval": False,
    },
    "permissive": {
        "max_cost_usd": 100.00,
        "allow_external_side_effect_without_approval": False,
        "allow_sensitive_data_without_redaction": False,
        "allow_destructive_action_without_approval": False,
    },
}


def get_policy_profile(name: str | None) -> Dict[str, Any]:
    profile_name = (name or "balanced").lower().strip()
    profile = POLICY_PROFILES.get(profile_name, POLICY_PROFILES["balanced"]).copy()
    profile["profile"] = profile_name if profile_name in POLICY_PROFILES else "balanced"
    return profile


class AgentActionFirewall:
    def __init__(self, pass_threshold: float = 0.85, review_threshold: float = 0.60):
        if not 0 <= review_threshold <= pass_threshold <= 1:
            raise ValueError("Thresholds must satisfy 0 <= review <= pass <= 1.")

        self.pass_threshold = pass_threshold
        self.review_threshold = review_threshold

    def evaluate(
        self,
        conditions: List[FirewallCondition],
        metadata: Dict[str, Any],
    ) -> FirewallResult:
        if not conditions:
            return FirewallResult(
                decision="REVIEW",
                safety_score=0.0,
                failure_report=["No firewall conditions supplied."],
                metadata=metadata,
            )

        total_weight = sum(max(c.weight, 0.0) for c in conditions)

        if total_weight == 0:
            return FirewallResult(
                decision="REVIEW",
                safety_score=0.0,
                failure_report=["All firewall condition weights are zero."],
                metadata=metadata,
            )

        passed_weight = sum(c.weight for c in conditions if c.passed and c.weight > 0)
        safety_score = passed_weight / total_weight

        passed = [c.name for c in conditions if c.passed]
        failed = [c.name for c in conditions if not c.passed]

        failure_report = [
            f"[{c.severity.upper()}] {c.name}: {c.detail}"
            for c in conditions
            if not c.passed
        ]

        critical_failed = any(
            (not c.passed) and c.severity.lower() == "critical"
            for c in conditions
        )

        if critical_failed:
            decision = "BLOCK"
        elif safety_score >= self.pass_threshold and not failed:
            decision = "PASS"
        elif safety_score >= self.review_threshold:
            decision = "REVIEW"
        else:
            decision = "BLOCK"

        return FirewallResult(
            decision=decision,
            safety_score=round(safety_score, 4),
            passed_conditions=passed,
            failed_conditions=failed,
            failure_report=failure_report,
            metadata=metadata,
        )


def verify_action(payload: Dict[str, Any]) -> FirewallResult:
    policy = get_policy_profile(payload.get("policy_profile"))

    action_type = str(payload.get("action_type", "unknown"))
    risk_level = str(payload.get("risk_level", "medium")).lower()

    requires_external_side_effect = bool(payload.get("requires_external_side_effect", False))
    has_user_approval = bool(payload.get("has_user_approval", False))

    contains_sensitive_data = bool(payload.get("contains_sensitive_data", False))
    sensitive_data_redacted = bool(payload.get("sensitive_data_redacted", False))

    destructive_action = bool(payload.get("destructive_action", False))
    estimated_cost_usd = float(payload.get("estimated_cost_usd", 0.0))

    conditions = [
        FirewallCondition(
            name="known_action_type",
            passed=action_type != "unknown",
            detail="Action type is unknown.",
            weight=1.0,
            severity="medium",
        ),
        FirewallCondition(
            name="external_side_effect_approval",
            passed=(
                not requires_external_side_effect
                or has_user_approval
                or policy["allow_external_side_effect_without_approval"]
            ),
            detail="External side-effect requires user approval.",
            weight=4.0,
            severity="critical",
        ),
        FirewallCondition(
            name="sensitive_data_redaction",
            passed=(
                not contains_sensitive_data
                or sensitive_data_redacted
                or policy["allow_sensitive_data_without_redaction"]
            ),
            detail="Sensitive data must be redacted before action execution.",
            weight=4.0,
            severity="critical",
        ),
        FirewallCondition(
            name="destructive_action_approval",
            passed=(
                not destructive_action
                or has_user_approval
                or policy["allow_destructive_action_without_approval"]
            ),
            detail="Destructive actions require explicit user approval.",
            weight=5.0,
            severity="critical",
        ),
        FirewallCondition(
            name="cost_ceiling",
            passed=estimated_cost_usd <= policy["max_cost_usd"],
            detail=(
                f"Estimated cost ${estimated_cost_usd:.2f} exceeds policy limit "
                f"${policy['max_cost_usd']:.2f}."
            ),
            weight=2.0,
            severity="high",
        ),
        FirewallCondition(
            name="high_risk_requires_approval",
            passed=(risk_level != "high" or has_user_approval),
            detail="High-risk actions require user approval.",
            weight=3.0,
            severity="critical",
        ),
    ]

    firewall = AgentActionFirewall()

    return firewall.evaluate(
        conditions,
        metadata={
            "agent_id": payload.get("agent_id"),
            "policy_profile": policy["profile"],
            "action_type": action_type,
            "risk_level": risk_level,
            "requires_external_side_effect": requires_external_side_effect,
            "has_user_approval": has_user_approval,
            "contains_sensitive_data": contains_sensitive_data,
            "sensitive_data_redacted": sensitive_data_redacted,
            "destructive_action": destructive_action,
            "estimated_cost_usd": estimated_cost_usd,
        },
    )


def verify_tool_call(payload: Dict[str, Any]) -> FirewallResult:
    policy = get_policy_profile(payload.get("policy_profile"))

    tool_name = str(payload.get("tool_name", "unknown"))
    tool_category = str(payload.get("tool_category", "unknown")).lower()

    has_user_approval = bool(payload.get("has_user_approval", False))
    contains_sensitive_data = bool(payload.get("contains_sensitive_data", False))
    sensitive_data_redacted = bool(payload.get("sensitive_data_redacted", False))

    estimated_cost_usd = float(payload.get("estimated_cost_usd", 0.0))
    external_side_effect = bool(payload.get("external_side_effect", False))

    dangerous_tools = {
        "send_email",
        "delete_file",
        "transfer_funds",
        "execute_trade",
        "submit_transaction",
        "post_social",
        "external_api_call",
    }

    financial_tools = {
        "transfer_funds",
        "execute_trade",
        "submit_transaction",
        "swap_tokens",
        "withdraw",
    }

    destructive_tools = {
        "delete_file",
        "drop_database",
        "revoke_access",
        "terminate_server",
    }

    tool_is_dangerous = tool_name in dangerous_tools or tool_category in {
        "financial",
        "destructive",
        "external",
    }

    tool_is_financial = tool_name in financial_tools or tool_category == "financial"
    tool_is_destructive = tool_name in destructive_tools or tool_category == "destructive"

    conditions = [
        FirewallCondition(
            name="known_tool_name",
            passed=tool_name != "unknown",
            detail="Tool name is unknown.",
            weight=1.0,
            severity="medium",
        ),
        FirewallCondition(
            name="dangerous_tool_requires_approval",
            passed=not tool_is_dangerous or has_user_approval,
            detail=f"Dangerous tool call '{tool_name}' requires user approval.",
            weight=4.0,
            severity="critical",
        ),
        FirewallCondition(
            name="financial_tool_requires_approval",
            passed=not tool_is_financial or has_user_approval,
            detail=f"Financial tool call '{tool_name}' requires user approval.",
            weight=5.0,
            severity="critical",
        ),
        FirewallCondition(
            name="destructive_tool_requires_approval",
            passed=not tool_is_destructive or has_user_approval,
            detail=f"Destructive tool call '{tool_name}' requires user approval.",
            weight=5.0,
            severity="critical",
        ),
        FirewallCondition(
            name="external_side_effect_approval",
            passed=not external_side_effect or has_user_approval,
            detail="External side-effect tool call requires user approval.",
            weight=4.0,
            severity="critical",
        ),
        FirewallCondition(
            name="sensitive_data_redaction",
            passed=not contains_sensitive_data or sensitive_data_redacted,
            detail="Sensitive data must be redacted before tool execution.",
            weight=4.0,
            severity="critical",
        ),
        FirewallCondition(
            name="cost_ceiling",
            passed=estimated_cost_usd <= policy["max_cost_usd"],
            detail=(
                f"Estimated tool cost ${estimated_cost_usd:.2f} exceeds policy limit "
                f"${policy['max_cost_usd']:.2f}."
            ),
            weight=2.0,
            severity="high",
        ),
    ]

    firewall = AgentActionFirewall()

    return firewall.evaluate(
        conditions,
        metadata={
            "agent_id": payload.get("agent_id"),
            "policy_profile": policy["profile"],
            "tool_name": tool_name,
            "tool_category": tool_category,
            "has_user_approval": has_user_approval,
            "contains_sensitive_data": contains_sensitive_data,
            "sensitive_data_redacted": sensitive_data_redacted,
            "estimated_cost_usd": estimated_cost_usd,
            "external_side_effect": external_side_effect,
            "tool_is_dangerous": tool_is_dangerous,
            "tool_is_financial": tool_is_financial,
            "tool_is_destructive": tool_is_destructive,
        },
    )
