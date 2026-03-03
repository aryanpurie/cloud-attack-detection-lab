# Splunk Detections — Scenario 01 (IAM PrivEsc via AssumeRole)

## Vendor-neutral detection logic

- **Inputs:** CloudTrail management events for `sts:AssumeRole` and IAM APIs (`ListRoles`, `GetRole`, `ListAttachedRolePolicies`, `GetPolicy`, `GetPolicyVersion`), plus follow-on IAM and secrets activity (`CreateAccessKey`, `UpdateAssumeRolePolicy`, `GetSecretValue`, S3 reads).
- **Detection 1 – Privileged AssumeRole:** For each principal and time window, flag any successful `AssumeRole` into a *privileged* role (identified by role name, tags, or an explicit allowlist) when the caller is not on an approved allowlist for that role.
- **Detection 2 – Role chaining:** For each principal, sort `AssumeRole` events by time and flag when the same caller assumes **two or more distinct roles** within a short window (for example, 10–15 minutes), indicating role chaining.
- **Detection 3 – Enumeration → AssumeRole:** For each principal, look for IAM enumeration activity (role/list/get policy calls) followed by `AssumeRole` for any role within a medium window (for example, 30 minutes). Treat this sequence as suspicious discovery → escalation.
- **Detection 4 – AssumeRole → sensitive actions:** For each principal/session, flag sequences where `AssumeRole` is followed within a short window (for example, 15 minutes) by sensitive actions such as secrets access, new access keys, or trust/policy modifications.
- **Context:** Use allowlists and baselines for expected automation and breakglass roles, and enrich with source IP, user agent, region, and account to prioritize investigations.

Assumption: CloudTrail logs are in Splunk with fields parsed. If your environment uses index=cloudtrail and sourcetype=aws:cloudtrail, keep that; otherwise replace.

## Detection 1 — High-confidence: Suspicious AssumeRole into "Privileged" Roles
**Idea:** Alert when any principal assumes a role matching privileged naming patterns, excluding allowlisted automation/breakglass.

```spl
index=cloudtrail sourcetype="aws:cloudtrail" eventName="AssumeRole"
| eval roleArn=coalesce('requestParameters.roleArn', 'responseElements.assumedRoleUser.arn')
| search roleArn="*Admin*" OR roleArn="*Security*" OR roleArn="*Prod*" OR roleArn="*Root*" OR roleArn="*PowerUser*"
| eval actor=coalesce('userIdentity.arn', 'userIdentity.userName')
| eval src=sourceIPAddress
| eval ua=userAgent
| where isnotnull(roleArn)
| lookup iam_assumerole_allowlist actor OUTPUT actor as allow_actor
| where isnull(allow_actor)
| stats count as assume_count values(roleArn) as roleArn values(src) as src values(ua) as userAgent earliest(_time) as first_seen latest(_time) as last_seen by actor recipientAccountId
| eval risk_reason="AssumeRole into privileged role (non-allowlisted)"
```

**Tuning:** Maintain a KV store/lookup `iam_assumerole_allowlist` for known automation principals.

## Detection 2 — Role Chaining: Multiple AssumeRole calls in a short window
**Idea:** Detect potential chain escalation (AssumeRole → AssumeRole) by the same actor/session.

```spl
index=cloudtrail sourcetype="aws:cloudtrail" eventName="AssumeRole"
| eval actor=coalesce('userIdentity.arn','userIdentity.userName')
| eval roleArn=coalesce('requestParameters.roleArn','responseElements.assumedRoleUser.arn')
| eval src=sourceIPAddress
| bin _time span=10m
| stats dc(roleArn) as distinct_roles values(roleArn) as roles values(src) as src values(userAgent) as uas count as total_assumes by actor _time recipientAccountId
| where distinct_roles >= 2 AND total_assumes >= 2
| eval risk_reason="Potential role chaining (>=2 roles assumed within 10 minutes)"
```

**Tuning:** Exclude deployment roles that legitimately chain in pipelines.

## Detection 3 — Enumeration + AssumeRole correlation (Discovery → Escalation)
**Idea:** If an actor does IAM enumeration then assumes a role shortly after, it's suspicious.

```spl
index=cloudtrail sourcetype="aws:cloudtrail"
| eval actor=coalesce('userIdentity.arn','userIdentity.userName')
| eval src=sourceIPAddress
| eval is_iam_enum=if(eventName IN ("ListRoles","GetRole","ListAttachedRolePolicies","GetPolicy","GetPolicyVersion"), 1, 0)
| eval is_assume=if(eventName="AssumeRole",1,0)
| transaction actor maxspan=30m
| search is_iam_enum=1 is_assume=1
| stats values(eventName) as events values(src) as src values(userAgent) as userAgent earliest(_time) as start latest(_time) as end by actor recipientAccountId
| eval risk_reason="IAM enumeration followed by AssumeRole within 30 minutes"
```

**Tuning:** If transaction is too heavy at scale, we can rewrite with streamstats or join logic.

## Detection 4 — AssumeRole followed by Sensitive Actions (Secrets/IAM changes) within 15m
**Idea:** Escalation is most meaningful when followed by sensitive API calls.

```spl
index=cloudtrail sourcetype="aws:cloudtrail"
| eval actor=coalesce('userIdentity.arn','userIdentity.userName')
| eval is_assume=if(eventName="AssumeRole",1,0)
| eval is_sensitive=if(eventName IN ("GetSecretValue","CreateAccessKey","CreateUser","AttachUserPolicy","AttachRolePolicy","PutRolePolicy","UpdateAssumeRolePolicy"),1,0)
| transaction actor maxspan=15m
| search is_assume=1 is_sensitive=1
| stats values(eventName) as events values('requestParameters.roleArn') as roleArns values(sourceIPAddress) as src earliest(_time) as start latest(_time) as end by actor recipientAccountId
| eval risk_reason="AssumeRole followed by sensitive actions within 15 minutes"
```

**Tuning:** Add where clauses for privileged role patterns if noisy.

## Enrichment Fields (Recommended)
- **actor** = userIdentity.arn (preferred)
- **roleArn** = requestParameters.roleArn
- **src** = sourceIPAddress
- **ua** = userAgent
- **account** = recipientAccountId
