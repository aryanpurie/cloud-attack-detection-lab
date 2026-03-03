# Scenario 04 — EC2 Metadata Credential Theft (IMDS → STS → Lateral)

## Summary
An attacker gains code execution on an EC2 instance (e.g., SSRF via application, exposed service, or compromised host), queries the Instance Metadata Service (IMDS) for temporary credentials, then uses those credentials to call AWS APIs and pivot. Evidence includes CloudTrail (GetCallerIdentity, then API calls under the instance profile) and optionally VPC Flow Logs for metadata endpoint access.

## Preconditions / Assumptions
- CloudTrail management events are enabled; instance profile role activity is logged.
- EC2 instances use instance profiles (IAM roles); IMDSv1 may be enabled (easier to exploit via SSRF).
- Optional: VPC Flow Logs or proxy logs that show traffic to 169.254.169.254.

## Attack Flow (High Level)
1. Attacker gains code execution or SSRF on an EC2 instance.
2. Requests instance credentials from IMDS (169.254.169.254).
3. Uses temporary credentials to call AWS APIs (often sts:GetCallerIdentity first, then other services).
4. Instance profile may be used from an unexpected network path (e.g., from outside expected NAT/egress).
5. New services accessed by a role that doesn’t normally use them.

## Evidence Sources
- CloudTrail: `sts:GetCallerIdentity` from new IP/userAgent shortly after credential theft; subsequent API calls with assumed-role session name consistent with instance profile.
- VPC Flow Logs (optional): requests to 169.254.169.254 (metadata endpoint).
- Signals: instance profile used from outside expected path; sudden spike in API calls by instance role; new services used by role.

## Detection Strategy (Splunk-first)
- Sudden new AWS service usage by instance profile role.
- Correlate API calls with deployment anomalies or SSRF indicators.
- If flow logs available: detect metadata endpoint access from app processes/subnets.

## Triage Workflow
- Identify instance role and instance ID association.
- Determine permissions of instance role (blast radius).
- Confirm whether creds were used from unusual IP/userAgent.
- Investigate the instance (host forensics, SSRF check).

## Containment Actions
- Rotate/replace instance (terminate and redeploy).
- Reduce instance profile permissions; apply IMDSv2 enforcement.
- Block egress paths if needed; patch SSRF vulnerability.

## Long-term Fixes
- Enforce IMDSv2 (hop limit, no IMDSv1).
- Minimize instance profile permissions.
- Add egress controls, WAF/SSRF protections, workload identity alternatives where applicable.

## Known False Positives / Tuning
- New deployments or scaling that introduce new instance roles or new service usage.
- Legitimate automation that uses instance role from different paths (e.g., after NAT change).
- Allowlist known instance roles and expected services per role.

## Validation Approach (How to test)
- Replay sample CloudTrail (telemetry/) showing instance-role usage from “new” context.
- If possible, test IMDSv2 enforcement and verify metadata access is logged or blocked as expected.

## Senior Signal Table
| Attack | Evidence | Detection | Triage | Containment | Long-term Fix |
|---|---|---|---|---|---|
| IMDS creds theft → API pivot | CloudTrail GetCallerIdentity + anomalous API use | New service usage by instance role | Map role→instance→actions | Replace instance, reduce role perms | Enforce IMDSv2 + least privilege + SSRF guardrails |
