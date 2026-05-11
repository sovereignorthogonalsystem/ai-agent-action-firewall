from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict
from uuid import uuid4

from fastapi import FastAPI
from pydantic import BaseModel, Field

from firewall import POLICY_PROFILES, verify_action


app = FastAPI(
    title="AI Agent Action Firewall",
    description="Policy and audit middleware for autonomous AI agent actions.",
    version="0.1.0",
)


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


def attach_request_id(response: Dict[str, Any], endpoint: str) -> Dict[str, Any]:
    request_id = str(uuid4())
    response["request_id"] = request_id
    response["endpoint"] = endpoint

    metadata = response.setdefault("metadata", {})
    metadata["request_id"] = request_id
    metadata["endpoint"] = endpoint

    return response


@app.get("/")
def root() -> Dict[str, str]:
    return {
        "name": "AI Agent Action Firewall",
        "status": "running",
        "health": "/health",
        "policies": "/policies",
        "verify_action": "/verify/action",
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
def verify_action_endpoint(payload: ActionVerificationRequest) -> Dict[str, Any]:
    result = verify_action(payload.model_dump())
    response = attach_request_id(asdict(result), "/verify/action")
    return response