# Scenario 03 — CloudTrail Tampering / Logging Degradation (Defense Evasion)

## Summary
This scenario models an attacker reducing visibility by stopping trails, changing log destinations, disabling multi-region, deleting trails, or modifying bucket policies to block writes. Evidence is CloudTrail management events (StopLogging, UpdateTrail, DeleteTrail) and S3/KMS changes to log infrastructure.

## Preconditions / Assumptions
- CloudTrail management events are enabled and delivered to SIEM (so that trail-configuration changes are themselves logged).
- At least one trail exists; log archive bucket and optional KMS key are in use.
- An allowlist of approved principals for CloudTrail changes exists or can be built.

## Attack Flow (High Level)
1. Attacker has (or escalates to) permissions that allow CloudTrail or log-bucket modification.
2. Stops logging (StopLogging), updates trail config (UpdateTrail), or deletes trail (DeleteTrail).
3. May alter S3 bucket policy on log archive bucket to block writes or delete objects.
4. May modify KMS key policy or disable key if CloudTrail uses KMS encryption.
5. Operates in a "blind" window until logging is restored.

## Evidence Sources
- CloudTrail management: `cloudtrail:StopLogging`, `cloudtrail:UpdateTrail`, `cloudtrail:DeleteTrail`
- S3: `s3:PutBucketPolicy` on log archive bucket
- KMS: `kms:DisableKey` or key policy change (if trail uses KMS)
- Signals: any logging change by non-approved principals; changes shortly after privilege escalation.

## Detection Strategy (Splunk-first)
- High severity alert on StopLogging / DeleteTrail / UpdateTrail.
- Allowlist expected automation/breakglass roles; alert on everyone else.
- Correlate with role-assumption spikes (Scenario 01).

## Triage Workflow
- Identify who changed logging and from where (principal, IP, userAgent).
- Verify whether logs are missing and the impact window (blind period).
- Validate integrity of log archive bucket and KMS key.

## Containment Actions
- Restore CloudTrail config immediately (IaC preferred).
- Lock down permissions to CloudTrail and log archive bucket.
- Rotate credentials and investigate what happened during the blind window.

## Long-term Fixes
- Org-level CloudTrail with delegated admin where possible.
- SCP to deny StopLogging / DeleteTrail / UpdateTrail except breakglass.
- Immutable log storage (Object Lock, restricted bucket policies).

## Known False Positives / Tuning
- Legitimate automation (e.g., trail updates via Terraform) and breakglass procedures.
- Allowlist approved principals and CI/CD roles.

## Validation Approach (How to test)
- Replay sample CloudTrail events (telemetry/) for trail changes; confirm alerts fire.
- Verify allowlist reduces noise from approved automation.

## Senior Signal Table
| Attack | Evidence | Detection | Triage | Containment | Long-term Fix |
|---|---|---|---|---|---|
| CloudTrail stop/update/delete | CloudTrail mgmt events + S3 policy changes | High-sev allowlist-based | Identify blind window + actor | Restore trails, restrict perms | SCP denies + org trail + immutable logs |
