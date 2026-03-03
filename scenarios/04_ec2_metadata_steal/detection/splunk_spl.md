# Splunk Detections — Scenario 04 (EC2 Metadata Credential Theft)

Assumption: CloudTrail management events are in Splunk; userIdentity.arn reflects assumed-role (instance profile) sessions. Adjust index/sourcetype as needed.

## Detection 1 — Instance role used from new source IP (baseline)
**Idea:** Alert when an assumed-role session that looks like an instance profile (e.g., session name containing instance ID or known app role) is seen from a source IP never seen before for that role.

```spl
index=cloudtrail sourcetype="aws:cloudtrail"
| eval role_arn=case(
  match('userIdentity.arn', "assumed-role"),
  replace('userIdentity.sessionContext.sessionIssuer.arn', "arn:aws:iam::\d+:role/", "")
)
| where isnotnull(role_arn)
| eval actor='userIdentity.arn'
| stats values(sourceIPAddress) as ips values(userAgent) as uas earliest(_time) as first_seen latest(_time) as last_seen by actor
| lookup instance_role_baseline_ips actor OUTPUT actor as known_actor
| where isnull(known_actor) AND first_seen >= relative_time(now(), "-24h")
| eval risk_reason="Instance role from new source IP (possible cred theft)"
```

**Tuning:** Build baseline (e.g., last 7d of sourceIPAddress per instance-role ARN); or use streamstats to detect “first time” in last 24h.

## Detection 2 — GetCallerIdentity from new IP/userAgent then API burst
**Idea:** Attacker often calls GetCallerIdentity first with stolen creds; then uses other APIs. Detect GetCallerIdentity from a principal that rarely calls it, or from new IP/UA.

```spl
index=cloudtrail sourcetype="aws:cloudtrail" eventName="GetCallerIdentity"
| eval actor=coalesce('userIdentity.arn','userIdentity.principalId')
| eval src=sourceIPAddress
| eval ua=userAgent
| lookup instance_role_arns actor OUTPUT actor as is_instance_role
| where isnotnull(is_instance_role)
| stats earliest(_time) as first_seen values(src) as src values(ua) as ua by actor recipientAccountId
| eval risk_reason="GetCallerIdentity by instance role (validate IP/UA against baseline)"
```

**Tuning:** Correlate with subsequent events from same actor in next 15m; if many new eventSources, high confidence.

## Detection 3 — New AWS service usage by instance role (diversity spike)
**Idea:** Instance role suddenly used for many different services (eventSource) in short window — may indicate stolen creds used for discovery/lateral.

```spl
index=cloudtrail sourcetype="aws:cloudtrail"
| eval actor='userIdentity.arn'
| where match(actor, "assumed-role")
| bin _time span=30m
| stats dc(eventSource) as distinct_services values(eventSource) as services count by actor _time recipientAccountId
| where distinct_services >= 5 AND count >= 10
| eval risk_reason="Instance role used for many different services in 30m"
```

**Tuning:** Lower threshold for sensitive roles; exclude known automation that legitimately touches many services.

## Detection 4 — VPC Flow Logs: metadata endpoint access (optional)
**Idea:** If flow logs are in Splunk, detect traffic to 169.254.169.254 from non-host sources or app subnets.

```spl
index=vpc_flow_logs dstaddr="169.254.169.254" dstport=80
| stats count values(srcaddr) as src values(dstaddr) as dst by srcaddr _time
| eval risk_reason="Metadata endpoint (IMDS) access - validate source"
```

**Tuning:** Restrict to app-tier subnets or ENIs; exclude known bastion/maintenance flows. Requires flow logs in Splunk.

## Enrichment Fields (Recommended)
- **actor** = userIdentity.arn (assumed-role)
- **role_name** = sessionIssuer.userName or parsed from ARN
- **src** = sourceIPAddress
- **account** = recipientAccountId
