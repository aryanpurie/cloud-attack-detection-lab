# Runbook — Scenario 05: LLM Agent Tool Abuse (Prompt Injection)

## Goal
Rapidly confirm whether AWS API activity by the agent role was triggered by prompt injection or misuse, identify the triggering input and scope of actions, and contain by disabling tools and rotating exposed secrets.

## Triage Checklist (10–20 minutes)
1. **Identify the agent role**
   - CloudTrail: `userIdentity.arn` (assumed-role or user for agent).
   - Confirm this is the dedicated agent role (not generic automation).
2. **Identify triggering input**
   - Agent logs: which ticket ID, document, URL, or chat message preceded the tool chain?
   - Extract prompt snippet or input that led to AWS tool invocation.
3. **List AWS actions taken**
   - CloudTrail: eventSource/eventName in the time window (ListRoles, GetObject, GetSecretValue, etc.).
   - Determine if data was read (S3, Secrets) and whether it could have been returned to attacker.
4. **Check for approved workflow**
   - Is there an approved ticket or change request that justifies the sensitive calls? If not, treat as abuse.
5. **Blast radius**
   - Which buckets, secrets, or resources were accessed? Assume exposure if in agent context or if agent was instructed to exfil.

## Containment (Priority Order)
**Immediate**
- Disable agent tool execution (or switch to read-only / allowlisted tools only).
- Rotate any secrets the agent may have accessed (GetSecretValue, or keys in retrieved objects).
- Reduce agent role permissions to minimum (remove Secrets Manager, broad S3, IAM if not required).

**Short-term**
- Add allowlisted tool actions and mandatory human approval for high-risk operations.
- Block or sanitize the input vector (e.g., ticket template, URL blocklist, no raw user doc to tool context).

## Investigation Deep Dive
- Timeline: trigger (ticket/doc/URL) → agent tool chain (from agent logs) → CloudTrail events.
- Full list of API calls and resources touched.
- Whether response was visible to attacker (e.g., ticket comment, email).

## Recovery Validation
- Agent tools restricted; role least-privilege; secrets rotated.
- Prompt injection and input-validation controls in place.
- Audit logging for all agent tool use and correlation with CloudTrail.

## Communications Template (internal)
- What happened: agent was induced via prompt injection to perform AWS actions (enumerate/read/modify).
- Trigger source (ticket, doc, URL); which data or resources were accessed.
- Containment: tools disabled/restricted; secrets rotated; role reduced.
- Next steps: guardrails, allowlists, approval flows, and secure prompt handling.

## Post-Incident Improvements
- Tool allowlists and step-up approval for sensitive AWS operations.
- Treat external input as untrusted; sanitize and validate before passing to tools.
- Data boundaries: no secrets in agent context; retrieval filters; full audit of agent→CloudTrail.
