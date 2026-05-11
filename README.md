# AI Agent Action Firewall

Policy and audit middleware for autonomous AI agent actions.

## Purpose

AI Agent Action Firewall checks proposed agent actions before execution.

It returns PASS, BLOCK, or REVIEW with a safety score, failed conditions, failure report, request ID, and metadata.

## Current MVP

- action verification
- policy profiles
- external side-effect approval checks
- sensitive data redaction checks
- destructive action approval checks
- cost ceiling checks
- request IDs
- tests

## Endpoints

- GET /
- GET /health
- GET /policies
- POST /verify/action

## Run Locally

pip install -r requirements.txt
uvicorn main:app --reload --port 8100

Open:

http://127.0.0.1:8100/docs

## Test With Curl

curl -X POST "http://127.0.0.1:8100/verify/action" -H "Content-Type: application/json" -d @examples/action_block.json

## Run Tests

pytest

## Status

Experimental portfolio project. Not legal, security, financial, or professional advice.

## API Key Authentication

For hosted deployments, set:

AI_AGENT_FIREWALL_API_KEY=your-secret-key

Then call protected endpoints with:

X-API-Key: your-secret-key

If AI_AGENT_FIREWALL_API_KEY is unset, the API allows local development without a key.

## Tool-Call Verification

The firewall can verify proposed AI-agent tool calls before execution.

Endpoint:

- POST /verify/tool-call

Checks include:

- dangerous tool approval
- financial tool approval
- destructive tool approval
- external side-effect approval
- sensitive data redaction
- estimated cost ceiling

Example:

curl -X POST "http://127.0.0.1:8100/verify/tool-call" -H "Content-Type: application/json" -d @examples/tool_call_block.json

## Docker

Build and run:

```bash
docker build -t ai-agent-action-firewall .
docker run -p 8100:8100 ai-agent-action-firewall
```

Or with Docker Compose:

```bash
docker compose up --build
```

## Project Brief

See PROJECT_BRIEF.md for the product overview, problem, solution, endpoints, core checks, policy profiles, and resume signal.
