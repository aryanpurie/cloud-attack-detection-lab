# Splunk Detections — Scenario 05 (LLM Agent Tool Abuse)

## Vendor-neutral detection logic

- **Inputs:** CloudTrail management (and optionally data) events for the dedicated agent role, plus agent logs that record tool invocations, prompts, and ticket/work item IDs.
- **Detection 1 – Broad API sequences:** For the agent role, monitor short windows for combinations of IAM, S3, and Secrets Manager activity. Alert when the role touches an unusually broad set of services or uses APIs outside its normal profile.
- **Detection 2 – Sensitive calls without approved context:** Join agent logs (tickets/requests) with CloudTrail; flag `GetSecretValue` or reads of sensitive S3 prefixes when there is no associated approved ticket or workflow.
- **Detection 3 – High diversity of API calls:** For each agent session, count distinct API operations in a short window; alert on unusually high diversity and volume that resembles scripted enumeration rather than normal task execution.
- **Detection 4 – Suspicious tool chains:** In agent logs, look for prompt patterns that instruct the agent to bypass safety controls or to exfiltrate data (for example, “ignore previous instructions and …”), then correlate those prompts with downstream AWS actions.
- **Context:** Treat the agent as a high-risk “confused deputy”; use allowlists, step-up approval, and scoped credentials to constrain blast radius when detections fire.

Assumption: CloudTrail is in Splunk; agent role has a distinct ARN or userAgent. Optionally agent logs (tool calls, ticket ID) are in Splunk and can be correlated. Adjust index/sourcetype as needed.

## Detection 1 — Unusual API sequence by agent role (IAM + S3 + Secrets in one session)
**Idea:** Agent role should normally perform a limited set of actions; broad enumeration across IAM, S3, and Secrets in short window suggests prompt injection or misuse.

```spl
index=cloudtrail sourcetype="aws:cloudtrail"
| eval actor='userIdentity.arn'
| search [| inputlookup agent_role_arns | fields actor ]
| eval service=eventSource
| bin _time span=15m
| stats dc(service) as distinct_services values(service) as services values(eventName) as events by actor _time recipientAccountId
| where distinct_services >= 3 AND (mvfind(services, "iam.amazonaws.com")>=0 AND (mvfind(services, "s3.amazonaws.com")>=0 OR mvfind(services, "secretsmanager.amazonaws.com")>=0))
| eval risk_reason="Agent role: broad enumeration (IAM + S3/Secrets) in 15m"
```

**Tuning:** Maintain lookup `agent_role_arns` with the agent role ARN(s). Adjust distinct_services and service mix per environment.

## Detection 2 — Sensitive calls by agent role (GetSecretValue, GetObject on sensitive prefix)
**Idea:** Agent accessing secrets or sensitive S3 without approval should be rare; alert and correlate with agent logs for ticket ID.

```spl
index=cloudtrail sourcetype="aws:cloudtrail"
  (eventName="GetSecretValue" OR (eventName="GetObject" AND requestParameters.key LIKE "%sensitive%"))
| eval actor='userIdentity.arn'
| search [| inputlookup agent_role_arns | fields actor ]
| table _time actor eventName requestParameters.secretId requestParameters.bucketName requestParameters.key sourceIPAddress recipientAccountId
| eval risk_reason="Agent role: sensitive API call (validate against approved tickets)"
```

**Tuning:** Refine key/prefix patterns for “sensitive”; correlate with agent log index to match ticket ID or workflow.

## Detection 3 — Agent role: high diversity of eventNames in short window
**Idea:** Many different API calls in a short period may indicate scripted enumeration or injection-driven tool use.

```spl
index=cloudtrail sourcetype="aws:cloudtrail"
| eval actor='userIdentity.arn'
| search [| inputlookup agent_role_arns | fields actor ]
| bin _time span=10m
| stats dc(eventName) as distinct_apis values(eventName) as apis count by actor _time recipientAccountId
| where distinct_apis >= 8 AND count >= 10
| eval risk_reason="Agent role: unusual diversity of API calls in 10m"
```

**Tuning:** Lower threshold for highly sensitive roles; exclude known “admin” workflows with approval.

## Detection 4 — Correlation with agent logs (if available)
**Idea:** Join CloudTrail to agent log index on time and role/session; flag when sensitive CloudTrail event has no matching approved ticket in agent logs.

```spl
index=cloudtrail sourcetype="aws:cloudtrail" eventName="GetSecretValue"
| eval actor='userIdentity.arn'
| search [| inputlookup agent_role_arns | fields actor ]
| table _time actor requestParameters.secretId as secret_id
| join type=left actor _time [ search index=agent_logs sourcetype=agent_tools | eval actor=role_arn | table _time actor ticket_id approved ]
| where isnull(approved) OR isnull(ticket_id)
| eval risk_reason="Agent GetSecretValue without approved ticket in agent logs"
```

**Tuning:** Schema for agent_logs (ticket_id, approved, role_arn) must match; adjust join key (e.g., time window) as needed.

## Enrichment Fields (Recommended)
- **actor** = userIdentity.arn (agent role)
- **eventSource** / **eventName** for sequence analysis
- **requestParameters** (secretId, bucketName, key) for impact
- **ticket_id** / **approved** from agent logs when available
