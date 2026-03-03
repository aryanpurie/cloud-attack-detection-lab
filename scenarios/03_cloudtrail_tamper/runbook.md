# Runbook — Scenario 03: CloudTrail Tampering / Logging Degradation

## Goal
Rapidly confirm who changed CloudTrail (or log bucket/KMS), determine the blind window, restore logging, and lock down permissions.

## Triage Checklist (10–20 minutes)
1. **Identify the actor**
   - `userIdentity.arn` / principal for StopLogging, UpdateTrail, DeleteTrail, or PutBucketPolicy.
   - Is this on the approved CloudTrail-change allowlist?
2. **Identify the change**
   - Trail name (`requestParameters.name`), action (stop/update/delete).
   - If PutBucketPolicy: which bucket? (log archive?)
   - If KMS: which key? (trail’s encryption key?)
3. **Determine blind window**
   - Time of change → time of restoration (or now if not yet restored).
   - Check whether another trail (e.g., org trail) continued to receive events.
4. **Validate log archive and KMS**
   - Log archive bucket: policy still allows CloudTrail delivery? Any object deletion?
   - KMS key: enabled? Policy still allows CloudTrail?

## Containment (Priority Order)
**Immediate**
- Restore CloudTrail: re-enable StopLogging (StartLogging), revert UpdateTrail to known-good config, or recreate deleted trail (prefer IaC).
- Restore log archive bucket policy so CloudTrail can write.
- Restore KMS key policy / re-enable key if it was disabled.

**Short-term**
- Remove or restrict IAM permissions that allowed CloudTrail/log-bucket/KMS changes (except breakglass).
- Rotate credentials of the principal that made the change (if compromised).

## Investigation Deep Dive
- Timeline: privilege escalation (if any) → trail/bucket/KMS change → activity during blind window.
- Query other regions or org-level trail for activity by same principal during blind window.
- Identify all trails and buckets affected.

## Recovery Validation
- Confirm all trails are logging and delivering to S3.
- Confirm log bucket policies and KMS key state match baseline.
- Consider SCP to deny StopLogging/DeleteTrail/UpdateTrail except breakglass.

## Communications Template (internal)
- What happened: CloudTrail (or log storage) was modified; logging was degraded/stopped.
- When (UTC/local) and who (principal).
- Impact: blind window duration and scope (accounts/regions).
- Containment: logging restored; permissions locked.
- Next steps: SCP, immutable logs, allowlist monitoring.

## Post-Incident Improvements
- Implement SCP denies for trail modification except breakglass.
- Enable or rely on org-level CloudTrail; immutable log storage (Object Lock, restricted bucket policies).
- Maintain and alert on allowlist for CloudTrail-change principals.
