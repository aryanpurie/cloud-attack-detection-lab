# Runbook: IAM PrivEsc via AssumeRole

## Triage
1. Confirm alert details:
   - Source principal, target role, account, region, and timestamp.
2. Validate legitimacy:
   - Is source principal approved to assume this role?
   - Is source IP/geography/user agent expected?
3. Scope activity after role assumption:
   - Review API actions under the assumed session.
   - Prioritize IAM, Secrets Manager, KMS, and S3 access.
4. Check persistence indicators:
   - `CreateAccessKey`, `CreateUser`, `AttachUserPolicy`, `UpdateAssumeRolePolicy`.
5. Set incident severity:
   - Elevate if high-priv role was used or persistence is detected.

## Containment
- Disable/rotate compromised keys for initiating principal.
- Block role assumption path by tightening trust policy immediately.
- Revoke active sessions where possible.
- Apply temporary SCP restrictions to halt additional escalation.

## Eradication
- Remove unauthorized IAM users/keys/policies created during incident.
- Revert unauthorized trust policy or inline/attached policy modifications.
- Remove unintended cross-account trust links.

## Recovery
- Re-enable approved access paths with least privilege.
- Validate logging and alerting coverage for impacted accounts.
- Perform focused hunt for follow-on compromise in same time window.

## Post-incident Improvements
- Add explicit trusted principals and conditions in privileged role trust policies.
- Add detections for rare principal-to-role assumptions.
- Document known-good automation assumptions to improve precision.
