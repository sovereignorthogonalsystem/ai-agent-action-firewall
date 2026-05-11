import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from usage_meter import get_usage_event_by_request_id, log_usage_event, usage_summary


def test_usage_meter_logs_and_summarizes():
    result = {
        "request_id": "usage-test-request",
        "decision": "PASS",
        "safety_score": 1.0,
        "metadata": {
            "agent_id": "usage-test-agent",
            "request_id": "usage-test-request",
            "endpoint": "/verify/action",
        },
    }

    log_usage_event("/verify/action", result, api_key_label="test")
    summary = usage_summary()

    assert "total_events" in summary
    assert "by_endpoint" in summary
    assert "by_decision" in summary
    assert any(item["endpoint"] == "/verify/action" for item in summary["by_endpoint"])


def test_usage_meter_lookup_by_request_id():
    result = {
        "request_id": "lookup-test-request",
        "decision": "BLOCK",
        "safety_score": 0.25,
        "metadata": {
            "agent_id": "lookup-test-agent",
            "request_id": "lookup-test-request",
            "endpoint": "/verify/action",
        },
    }

    log_usage_event("/verify/action", result, api_key_label="test")
    event = get_usage_event_by_request_id("lookup-test-request")

    assert event is not None
    assert event["request_id"] == "lookup-test-request"
    assert event["decision"] == "BLOCK"
    assert event["agent_id"] == "lookup-test-agent"
