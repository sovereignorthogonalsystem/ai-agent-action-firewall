from __future__ import annotations

import os
from dataclasses import asdict
from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from firewall import POLICY_PROFILES, verify_action, verify_tool_call
from usage_meter import get_usage_event_by_request_id, log_usage_event, usage_summary


app = FastAPI(
    title="AI Agent Action Firewall",
    description="Policy and audit middleware for autonomous AI agent actions.",
    version="0.1.0",
)


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    expected_key = os.getenv("AI_AGENT_FIREWALL_API_KEY")

    if not expected_key:
        return

    if x_api_key != expected_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


class ActionVerificationRequest(BaseModel):
    agent_id: str = Field(default="demo-agent")
    policy_profile: str = Field(default="balanced")

    action_type: str = Field(default="unknown")
    risk_level: str = Field(default="medium")

    requires_external_side_effect: bool = False
    has_user_approval: bool = False

    contains_sensitive_data: bool = False
    sensitive_data_redacted: bool = False

    destructive_action: bool = False
    estimated_cost_usd: float = 0.0


class ToolCallVerificationRequest(BaseModel):
    agent_id: str = Field(default="demo-agent")
    policy_profile: str = Field(default="balanced")

    tool_name: str = Field(default="unknown")
    tool_category: str = Field(default="unknown")

    has_user_approval: bool = False
    contains_sensitive_data: bool = False
    sensitive_data_redacted: bool = False

    estimated_cost_usd: float = 0.0
    external_side_effect: bool = False


def attach_request_id(response: Dict[str, Any], endpoint: str) -> Dict[str, Any]:
    request_id = str(uuid4())
    response["request_id"] = request_id
    response["endpoint"] = endpoint

    metadata = response.setdefault("metadata", {})
    metadata["request_id"] = request_id
    metadata["endpoint"] = endpoint

    return response


def api_key_label() -> str:
    return "configured" if os.getenv("AI_AGENT_FIREWALL_API_KEY") else "local-dev"


@app.get("/")
def root() -> Dict[str, str]:
    return {
        "name": "AI Agent Action Firewall",
        "status": "running",
        "health": "/health",
        "policies": "/policies",
        "verify_action": "/verify/action",
        "verify_tool_call": "/verify/tool-call",
        "usage_summary": "/usage/summary",
        "audit_request_lookup": "/audit/request/{request_id}",
    }


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/policies")
def policies() -> Dict[str, Any]:
    return {
        "default": "balanced",
        "profiles": POLICY_PROFILES,
    }


@app.post("/verify/action")
def verify_action_endpoint(
    payload: ActionVerificationRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Dict[str, Any]:
    require_api_key(x_api_key)

    result = verify_action(payload.model_dump())
    response = attach_request_id(asdict(result), "/verify/action")

    log_usage_event("/verify/action", response, api_key_label=api_key_label())

    return response


@app.post("/verify/tool-call")
def verify_tool_call_endpoint(
    payload: ToolCallVerificationRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Dict[str, Any]:
    require_api_key(x_api_key)

    result = verify_tool_call(payload.model_dump())
    response = attach_request_id(asdict(result), "/verify/tool-call")

    log_usage_event("/verify/tool-call", response, api_key_label=api_key_label())

    return response


@app.get("/usage/summary")
def usage_summary_endpoint(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Dict[str, Any]:
    require_api_key(x_api_key)
    return usage_summary()


@app.get("/audit/request/{request_id}")
def audit_request_endpoint(
    request_id: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Dict[str, Any]:
    require_api_key(x_api_key)

    event = get_usage_event_by_request_id(request_id)

    if event is None:
        raise HTTPException(status_code=404, detail="Request ID not found.")

    return event