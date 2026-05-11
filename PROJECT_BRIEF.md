# AI Agent Action Firewall: Policy Middleware for Autonomous Agents

## Summary

AI Agent Action Firewall is policy and audit middleware for autonomous AI agent actions.

It checks proposed actions and tool calls before execution, returning PASS, BLOCK, or REVIEW with a safety score, failure report, request ID, and audit trail.

## Problem

Autonomous AI agents can call tools, send messages, make API requests, expose sensitive data, spend money, or perform destructive actions faster than humans can inspect them.

Without a pre-execution policy layer, an agent can take unsafe action simply because a model generated a plausible next step.

## Solution

This project acts as a pre-execution firewall for AI-agent actions.

It does not execute the action itself. It evaluates whether the proposed action or tool call satisfies policy conditions before execution.

## Current Endpoints

- GET /
- GET /health
- GET /policies
- POST /verify/action
- POST /verify/tool-call
- GET /usage/summary
- GET /audit/request/{request_id}

## Core Checks

- external side-effect approval
- sensitive data redaction
- destructive action approval
- high-risk action approval
- dangerous tool-call approval
- financial tool-call approval
- estimated cost ceiling
- request ID generation
- usage metering
- audit lookup

## Policy Profiles

- strict
- balanced
- permissive

## Resume Signal

This repo demonstrates backend API design, policy middleware, agent safety architecture, audit logging, request tracing, API authentication, and test-driven infrastructure patterns.

## Status

Experimental portfolio project. Not legal, security, financial, or professional advice.
