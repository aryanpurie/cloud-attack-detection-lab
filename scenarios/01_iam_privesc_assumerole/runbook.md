# Runbook — Scenario 01: IAM PrivEsc via AssumeRole

## Goal
Rapidly confirm whether role assumption represents legitimate admin activity or malicious privilege escalation, determine blast radius, and drive containment + recovery with minimal business disruption.

## Triage Checklist (10–20 minutes)
1. **Identify the actor**
   - `userIdentity.arn` / username
   - Is this a known automation principal or breakglass role?
2. **Confirm the target role**
   - `requestParameters.roleArn`
   - Does this role grant privileged permissions?
3. **Validate context**
   - `sourceIPAddress`, `userAgent`, `awsRegion`, time-of-day
   - Look for anomalies (new geo/ASN, new UA, unusual hours)
4. **Find precursor behavior**
   - IAM enumeration events: `ListRoles`, `GetRole`, `ListAttachedRolePolicies`
5. **Find follow-on behavior**
   - Secrets access: `GetSecretValue`
   - IAM persistence: `CreateAccessKey`, `CreateUser`, `Attach*Policy`, `UpdateAssumeRolePolicy`
   - Data access patterns if data events exist

## Containment (Priority Order)
**Immediate**
- Disable/rotate compromised access keys (if applicable).
- Restrict trust policy on the target role (remove broad principals; require explicit principal).
- If safe, block further `AssumeRole` into privileged roles via SCP (temporary).

**Short-term**
- Invalidate sessions where possible and force re-authentication.
- Identify and revert any IAM policy/trust modifications.
- Identify and revoke newly created access keys/users/roles.

## Investigation Deep Dive
- Build a timeline: first enumeration → assumeRole → sensitive actions.
- Confirm whether other roles were assumed (role chaining).
- Identify impacted services: Secrets Manager, S3, IAM, KMS, EC2.
- If persistence suspected, search for:
  - new IAM users
  - new access keys
  - updated trust policies
  - inline policies attached to principals

## Recovery Validation
- Confirm CloudTrail logging remained intact during the window.
- Confirm privileged roles trust policies match approved baseline.
- Confirm any secrets potentially accessed are rotated.
- Confirm there are no unmanaged credentials remaining.

## Communications Template (internal)
- What happened (high level)
- When it occurred (UTC/local)
- Impact (services/data potentially accessed)
- What we did (containment)
- Next steps (remediation + monitoring)

## Post-Incident Improvements
- Add/adjust allowlists for known automation.
- Enforce explicit trust policies and permission boundaries.
- Add alert correlation: AssumeRole + sensitive action within short window.
