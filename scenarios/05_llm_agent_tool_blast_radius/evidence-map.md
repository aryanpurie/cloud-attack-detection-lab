# Evidence Map — Scenario 05 (LLM Agent Tool Abuse)

## Required Telemetry
| Source | Event(s) / Data | Must-have fields | Why it matters |
|---|---|---|---|
| CloudTrail (Mgmt) | All API calls by agent role | `userIdentity.arn`, `eventSource`, `eventName`, `requestParameters.*`, `sourceIPAddress`, `userAgent`, `recipientAccountId` | attribute actions to agent; detect sequences and sensitive calls |
| CloudTrail (Data, optional) | S3 GetObject by agent | bucket, key, principal | data access by agent |
| Agent logs | Tool invocations, prompts, decisions | tool name, input params, prompt snippet, ticket/work item ID, timestamp | trace trigger (prompt/ticket) → tool call → AWS action |

## Common Gaps
- Agent logs not centralized or not correlated with CloudTrail (hard to link “this ticket caused this API call”).
- No allowlist of “approved” ticket IDs or workflows for sensitive tool use (high false positives or no alert).
- Agent role shared with other automation (need to distinguish agent vs. script by userAgent or session).

## Notes
- High-confidence: agent role performing IAM + S3 + Secrets in one short session; or GetSecretValue/GetObject without matching approved ticket in agent logs.
- Enrich CloudTrail with agent log fields (ticket ID, prompt hash) when possible for triage.
