# Scenario: IAM PrivEsc via AssumeRole (Role Chaining / Trust Abuse)

## Summary
An attacker with low-privilege credentials enumerates IAM roles, finds a weak trust relationship, and uses `sts:AssumeRole` to pivot into a higher-privileged role. The attacker then expands access to sensitive services and may establish persistence.

## Preconditions / Assumptions
- CloudTrail management events are enabled and available in SIEM.
- IAM role assumptions are logged and include caller context.
- A high-privilege role exists with trust policy weaknesses or broad trusted principals.
- Alert routing from SIEM to incident response workflow is operational.

## Attack Flow (High Level)
1. Initial access to a low-privileged IAM principal (user key or role session).
2. IAM reconnaissance (`ListRoles`, `GetRole`, `ListAttachedRolePolicies`).
3. Identify a role with weak trust controls.
4. Assume higher-privileged role via `sts:AssumeRole`.
5. Perform follow-on actions (data access, IAM modification, persistence setup).

## Evidence Sources
- CloudTrail management events (`sts`, `iam`, and post-assumption activity).
- Identity context fields (`userIdentity`, `sessionIssuer`, `sourceIPAddress`, `userAgent`).
- Optional enrichment from GuardDuty and geo/IP intelligence.

## Detection Strategy
- Alert on high-privilege role assumptions by principals not on an allowlist.
- Detect rapid role-chaining patterns (`AssumeRole` followed by `AssumeRole`) in short windows.
- Detect unusual source context for `AssumeRole` (new IP/ASN, unusual user agent, off-hours).
- Correlate `AssumeRole` with risky post-assumption behavior (IAM changes, secrets access).

## Triage Workflow
1. Identify source principal, target role, and assumption timestamp.
2. Validate whether source principal is approved to assume target role.
3. Review all API calls under assumed session to establish impact.
4. Check persistence indicators (new access keys/users, trust policy edits).
5. Determine scope: accounts, regions, data stores, and identities affected.

## Containment Actions
- Disable and rotate compromised access keys.
- Revoke active sessions where possible and block further role assumption.
- Update trust policy to explicitly restrict trusted principals.
- Apply temporary SCP or permission boundary controls to halt escalation paths.

## Long-term Fixes
- Enforce least-privilege trust policies with explicit principals and conditions.
- Introduce preventive SCP denies for risky role assumptions.
- Require stronger controls around privileged role assumption workflows.
- Continuously monitor high-privilege role assumption patterns and drift.

## Known False Positives / Tuning
- Legitimate break-glass/admin automation can resemble anomalous assumption.
- CI/CD and infra automation roles may chain roles by design.
- Tune with role allowlists, approved source CIDRs, expected user agents, and maintenance windows.
- Suppress known-good patterns only after ownership and behavior verification.

## Validation Approach (How to test)
1. Use a test low-priv role to perform IAM enumeration calls.
2. Attempt `AssumeRole` into a lab high-priv role with intentional trust misconfiguration.
3. Verify detections for anomalous assumption and role chaining trigger.
4. Generate benign admin automation traffic to test tuning and suppression quality.
5. Confirm runbook steps can be executed within target response time.

## Senior Signal Table
| Attack | Evidence | Detection | Triage | Containment | Long-term Fix |
|---|---|---|---|---|---|
| AssumeRole privilege escalation | CloudTrail `AssumeRole`, IAM enumeration | Anomalous `AssumeRole` plus role-chaining | Identify principal -> role -> actions | Rotate keys, restrict trust | SCP/least privilege, permission boundaries |
