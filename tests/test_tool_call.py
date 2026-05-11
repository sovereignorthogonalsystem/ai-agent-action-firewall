import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from firewall import verify_tool_call


def test_tool_call_blocks_unsafe_email():
    payload = {
        "agent_id": "tool-agent-001",
        "policy_profile": "balanced",
        "tool_name": "send_email",
        "tool_category": "external",
        "has_user_approval": False,
        "contains_sensitive_data": True,
        "sensitive_data_redacted": False,
        "estimated_cost_usd": 0.0,
        "external_side_effect": True,
    }

    result = verify_tool_call(payload)

    assert result.decision == "BLOCK"
    assert "dangerous_tool_requires_approval" in result.failed_conditions
    assert "external_side_effect_approval" in result.failed_conditions
    assert "sensitive_data_redaction" in result.failed_conditions


def test_tool_call_passes_safe_internal_tool():
    payload = {
        "agent_id": "tool-agent-002",
        "policy_profile": "balanced",
        "tool_name": "summarize_text",
        "tool_category": "internal",
        "has_user_approval": False,
        "contains_sensitive_data": False,
        "sensitive_data_redacted": True,
        "estimated_cost_usd": 0.01,
        "external_side_effect": False,
    }

    result = verify_tool_call(payload)

    assert result.decision == "PASS"
    assert result.metadata["tool_name"] == "summarize_text"