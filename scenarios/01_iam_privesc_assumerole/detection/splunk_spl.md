# Splunk SPL: Scenario 01 IAM PrivEsc via AssumeRole

## 1) Anomalous AssumeRole into privileged roles
```spl
index=cloudtrail sourcetype=aws:cloudtrail eventSource=sts.amazonaws.com eventName=AssumeRole
| eval src_principal=coalesce(userIdentity.arn, userIdentity.principalId)
| eval target_role=coalesce('requestParameters.roleArn', mvindex(resources{}.ARN, 0))
| where like(target_role, "%Admin%") OR like(target_role, "%PowerUser%") OR like(target_role, "%Security%")
| stats count min(_time) as first_seen max(_time) as last_seen values(sourceIPAddress) as src_ips values(userAgent) as user_agents by src_principal target_role
| where count >= 1
| sort - last_seen
```

**Tuning notes**
- Replace role-name heuristics with explicit allow/deny lists for privileged roles.
- Add approved caller-role lookup to reduce expected automation noise.

## 2) Rapid role chaining detection
```spl
index=cloudtrail sourcetype=aws:cloudtrail eventSource=sts.amazonaws.com eventName=AssumeRole
| eval src_principal=coalesce(userIdentity.arn, userIdentity.principalId)
| eval target_role=coalesce('requestParameters.roleArn', mvindex(resources{}.ARN, 0))
| sort 0 src_principal _time
| streamstats current=f window=1 last(target_role) as prev_role last(_time) as prev_time by src_principal
| eval chain_gap_sec=_time-prev_time
| where isnotnull(prev_role) AND chain_gap_sec>=0 AND chain_gap_sec<=900
| table _time src_principal prev_role target_role chain_gap_sec sourceIPAddress userAgent
| sort - _time
```

**Tuning notes**
- Adjust `chain_gap_sec` for your environment (for example 300-1800 seconds).
- Exclude known broker/automation sessions that intentionally chain roles.

## 3) AssumeRole followed by risky IAM activity
```spl
index=cloudtrail sourcetype=aws:cloudtrail
(
  (eventSource=sts.amazonaws.com eventName=AssumeRole)
  OR
  (eventSource=iam.amazonaws.com eventName IN ("CreateAccessKey","CreateUser","AttachUserPolicy","PutRolePolicy","UpdateAssumeRolePolicy"))
)
| eval principal=coalesce(userIdentity.arn, userIdentity.principalId)
| bin _time span=15m
| stats values(eventName) as events values(eventSource) as sources values(sourceIPAddress) as src_ips values(userAgent) as user_agents by principal _time
| where mvfind(events, "AssumeRole")>=0 AND (mvfind(events, "CreateAccessKey")>=0 OR mvfind(events, "UpdateAssumeRolePolicy")>=0 OR mvfind(events, "AttachUserPolicy")>=0)
| sort - _time
```

**Response guidance**
- Escalate to high severity when assumption into privileged role is followed by IAM persistence actions.
