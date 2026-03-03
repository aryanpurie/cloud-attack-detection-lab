# Scenario 05 — LLM Agent Tool Abuse → Cloud Blast Radius (Prompt Injection)

## Summary
An internal AI agent has tool access (e.g., “run AWS commands”, “fetch logs”, “open tickets”). An attacker crafts a prompt injection via ticket text, document, or webpage that the agent ingests, causing the agent to enumerate IAM/S3, exfiltrate sensitive data, or make destructive changes. This is a “confused deputy” problem with LLMs: the agent’s role is abused via malicious input. Evidence spans agent logs (tool calls, prompts) and CloudTrail (AWS actions performed by the agent role).

## Preconditions / Assumptions
- An LLM agent or assistant has tools that can call AWS APIs (or equivalent) under an agent-specific IAM role.
- Agent logs (tool invocations, prompts, decisions) are available in addition to CloudTrail.
- CloudTrail management (and optionally data) events are enabled for the account/role.

## Attack Flow (High Level)
1. Attacker injects malicious instructions into input the agent processes (ticket, doc, URL, chat).
2. Agent interprets input as legitimate task and invokes tools (e.g., AWS CLI, ListRoles, GetObject).
3. Agent role performs AWS API calls (enumerate, read secrets, modify resources).
4. Unusual API sequences or sensitive calls without corresponding approved ticket/work item.
5. Data may leave boundary or destructive changes may occur.

## Evidence Sources
- **Agent logs:** tool invocation chain, input that triggered unsafe action, prompt/response snippets.
- **CloudTrail:** API calls by the agent role — e.g. `iam:List*`, `s3:List*`, `s3:GetObject`, `secretsmanager:GetSecretValue`.
- Signals: unusual AWS API sequence by agent role; sensitive calls without approved ticket; broad enumeration (IAM + S3 + Secrets in one session).

## Detection Strategy (Splunk-first)
- Detect unusual AWS API sequences by the agent role.
- Detect sensitive calls (Secrets, S3 crown jewels) without corresponding approved ticket/work item.
- Detect unusually broad enumeration (IAM + S3 + Secrets Manager in one session).

## Triage Workflow
- Identify triggering input (ticket/doc/URL) and isolate it.
- Confirm what data was accessed and whether it left the boundary.
- Verify agent role permissions and scope.
- Review agent logs for tool chain and prompt context.

## Containment Actions
- Disable tool execution or switch agent to read-only mode.
- Rotate secrets potentially exposed.
- Reduce agent role permissions immediately.
- Add allowlisted tool actions and mandatory human approval for high-risk actions.

## Long-term Fixes
- Guardrails: policy-based tool allowlists, step-up approval for sensitive operations, scoped credentials.
- Prompt injection defenses: treat external text as untrusted; content sanitization; avoid passing raw user/ticket content to tools without validation.
- Data boundaries: no secrets in context; retrieval filters; full audit of agent tool use.

## Known False Positives / Tuning
- Legitimate automation that uses same role for many services.
- Approved high-privilege tasks that look like “broad enumeration” (e.g., incident response).
- Allowlist approved ticket IDs or workflows that justify sensitive tool use.

## Validation Approach (How to test)
- Replay sample CloudTrail and agent logs (telemetry/) into Splunk; confirm sequence and sensitive-call detections.
- Red-team with safe prompt injection payloads in test environment.

## Senior Signal Table
| Attack | Evidence | Detection | Triage | Containment | Long-term Fix |
|---|---|---|---|---|---|
| Prompt injection → agent tool misuse | Agent tool logs + CloudTrail | Unusual API sequences by agent role | Trace trigger→tool calls→AWS actions | Disable tools, rotate secrets, reduce role | Allowlists, approvals, data boundaries, auditability |
