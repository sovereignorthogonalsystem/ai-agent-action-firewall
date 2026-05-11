import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from firewall import AgentActionFirewall, FirewallCondition, get_policy_profile, verify_action


def test_firewall_passes_clean_conditions():
    firewall = AgentActionFirewall()

    conditions = [
        FirewallCondition("a", True, "ok", weight=1.0),
        FirewallCondition("b", True, "ok", weight=1.0),
    ]

    result = firewall.evaluate(conditions, metadata={})

    assert result.decision == "PASS"
    assert result.safety_score == 1.0


def test_policy_profiles():
    strict = get_policy_profile("strict")
    unknown = get_policy_profile("does-not-exist")

    assert strict["profile"] == "strict"
    assert unknown["profile"] == "balanced"


def test_action_blocks_missing_approval_and_sensitive_data():
    payload = {
        "agent_id": "research-agent-001",
        "policy_profile": "balanced",
        "action_type": "send_email",
        "risk_level": "medium",
        "requires_external_side_effect": True,
        "has_user_approval": False,
        "contains_sensitive_data": True,
        "sensitive_data_redacted": False,
        "destructive_action": False,
        "estimated_cost_usd": 0.0,
    }

    result = verify_action(payload)

    assert result.decision == "BLOCK"
    assert "external_side_effect_approval" in result.failed_conditions
    assert "sensitive_data_redaction" in result.failed_conditions


def test_action_passes_safe_summary():
    payload = {
        "agent_id": "research-agent-002",
        "policy_profile": "balanced",
        "action_type": "summarize_document",
        "risk_level": "low",
        "requires_external_side_effect": False,
        "has_user_approval": False,
        "contains_sensitive_data": False,
        "sensitive_data_redacted": True,
        "destructive_action": False,
        "estimated_cost_usd": 0.0,
    }

    result = verify_action(payload)

    assert result.decision == "PASS"