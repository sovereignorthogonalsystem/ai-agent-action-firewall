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
