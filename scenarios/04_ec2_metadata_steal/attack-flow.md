# Attack Flow — EC2 Metadata Credential Theft (IMDS → STS → Lateral)

## Phase 1 — Initial Access (assumed)
Attacker gains ability to send HTTP requests from (or as) the instance:
- SSRF in application (user input → request to metadata URL)
- Compromised workload on instance
- Exposed service that proxies or forwards to metadata endpoint

## Phase 2 — Credential Theft via IMDS
- Attacker (or vulnerable app) requests `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` (IMDSv1) or uses IMDSv2 with token.
- Receives temporary access key, secret key, session token for the instance profile role.
- May call `sts:GetCallerIdentity` from instance or from attacker’s own host using stolen creds.

## Phase 3 — API Pivot
- Attacker uses stolen credentials to call AWS APIs from their environment (different IP, userAgent).
- CloudTrail shows assumed-role session (instance profile) making calls from unusual sourceIPAddress/userAgent.
- May enumerate (ListBuckets, ListRoles), access data (GetObject, GetSecretValue), or modify resources.

## Phase 4 — Blast Radius
- Depends on instance profile permissions: S3, Secrets Manager, IAM, Lambda, etc.
- New services used by the role in short window → anomaly.

## Phase 5 — Persistence (optional)
- Create new IAM user/keys, modify roles, or leave backdoors using instance profile permissions.

## Phase 6 — Detection Hooks
- GetCallerIdentity or first API call from instance role from new IP/UA.
- Spike in API diversity (new eventNames) for the same role.
- VPC Flow Logs: connection to 169.254.169.254 from app subnet/ENI.
