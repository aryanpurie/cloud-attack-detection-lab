# Scenario 01 — IAM Privilege Escalation via AssumeRole (Role Chaining / Trust Abuse)

## Summary
This scenario models a common AWS escalation path: an attacker obtains a low-privileged principal (user/role credentials), enumerates IAM roles and trust policies, then uses `sts:AssumeRole` into a higher-privileged role. The attacker may chain roles and quickly pivot into sensitive services (Secrets Manager, S3, IAM changes).

## Preconditions / Assumptions
- CloudTrail management events are enabled and delivered to Splunk.
- The environment uses IAM roles and STS role assumption (normal in AWS orgs).
- (Optional but recommended) A baseline exists for "who normally assumes which role".

## Attack Flow (High Level)
1. Compromise low-priv principal (access key, SSO session, federated token).
2. Enumerate roles and trust relationships.
3. Assume a more privileged role via STS.
4. Use the privileged session to access sensitive services or establish persistence.
5. Optionally chain roles for broader access.

## Evidence Sources
- CloudTrail (Mgmt events): `sts:AssumeRole`, IAM reads: `ListRoles`, `GetRole`, `ListAttachedRolePolicies`, `GetPolicyVersion`
- CloudTrail (Follow-on activity): S3/SecretsManager/IAM changes after assume-role
- (Optional) GuardDuty findings for anomalous API calls / credential misuse

## Detection Strategy (Splunk-first)
Primary signals:
- Anomalous `AssumeRole` (rare principal → new role, unusual geo/IP/UA, new time-of-day)
- Role chaining (multiple assumes in short window)
- AssumeRole followed by sensitive actions within minutes (Secrets, IAM changes, S3 bulk reads)

## Triage Workflow
- Identify the source principal and initial compromise scope.
- Validate the target role assumed and the trust policy path that enabled it.
- Determine follow-on actions (data access, privilege changes, persistence).
- Define blast radius and containment requirements.

## Containment Actions
- Revoke/rotate compromised credentials.
- Restrict trust policy on the escalated role immediately.
- Block risky actions temporarily via SCP / explicit denies where needed.
- Invalidate sessions and investigate follow-on actions.

## Long-term Fixes
- Tighten trust relationships (explicit principals, external ID where needed).
- Enforce least-privilege + permission boundaries.
- Add allowlist-based monitoring for high-priv role assumption.
- Add SCP guardrails against unsafe `AssumeRole` patterns.

## Known False Positives / Tuning
- Expected automation roles (CI/CD, breakglass, deployers) assuming roles frequently.
- Incident responders using elevated roles during real incidents.
- Seasonal/onboarding spikes.

## Validation Approach (How to test)
- Replay sample CloudTrail events (provided in `telemetry/`) into Splunk dev index.
- Confirm detection queries trigger as expected.
- Add expected-role allowlists and verify false positive reduction.

## Senior Signal Table
| Attack | Evidence | Detection | Triage | Containment | Long-term Fix |
|---|---|---|---|---|---|
| AssumeRole privilege escalation / chaining | CloudTrail `AssumeRole` + IAM enumeration | Anomalous AssumeRole + role chaining + sensitive follow-on | Who assumed what role and what happened next | Rotate creds + lock trust policy | Least privilege, permission boundaries, SCP guardrails |
