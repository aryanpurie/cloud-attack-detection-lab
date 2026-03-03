# Controls — Scenario 05: LLM Agent Tool Abuse

## Preventive Controls (Design)
1. **Tool Allowlists and Scoped Credentials**
   - Agent may only invoke allowlisted tools/commands (e.g., read-only AWS APIs, specific S3 prefixes).
   - Use a dedicated agent role with minimal permissions; avoid broad IAM/Secrets/S3.

2. **Step-up Approval**
   - High-risk operations (GetSecretValue, PutObject, IAM changes) require human approval or breakglass workflow before execution.
   - Agent requests approval and logs the request; only after approval does tool execute.

3. **Prompt Injection and Input Hardening**
   - Treat external text (tickets, docs, URLs) as untrusted; do not pass raw content to tool parameters without validation.
   - Sanitize or block known injection patterns; limit context length and sources.
   - Avoid putting secrets in agent context; use retrieval with strict filters.

4. **Data Boundaries**
   - Agent cannot access crown-jewel buckets or secrets unless explicitly allowed by policy and approved.
   - Log and audit all tool invocations and correlate with CloudTrail.

## Detective Controls
- Alert on unusual API sequences by agent role (e.g., IAM + S3 + Secrets in one session).
- Alert on sensitive calls (GetSecretValue, GetObject on sensitive prefix) without corresponding approved ticket in agent logs.
- Correlate agent log (tool call, ticket ID) with CloudTrail (eventName, resource) for full chain.

## Operational Controls
- Maintain allowlist of approved ticket/work item IDs or workflows that justify sensitive tool use.
- Regular review of agent role permissions and tool allowlist.
- Red-team exercises with safe prompt injection in test environment.
