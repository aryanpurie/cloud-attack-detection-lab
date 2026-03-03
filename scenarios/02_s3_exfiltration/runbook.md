# Runbook — Scenario 02: S3 Data Exfiltration

## Goal
Rapidly confirm whether S3 access represents legitimate use or data exfiltration, determine scope (buckets, prefixes, volume), and contain access while preserving evidence.

## Triage Checklist (10–20 minutes)
1. **Confirm S3 Data Events**
   - Are Data Events enabled for the affected bucket(s)? If not, treat as visibility gap.
2. **Identify the actor**
   - `userIdentity.arn` / principal
   - Is this a known service/automation principal?
3. **Identify target bucket and prefix**
   - `requestParameters.bucketName`, `requestParameters.key` (or prefix).
   - Classify bucket sensitivity (crown jewel vs. general).
4. **Estimate volume**
   - Count of GetObject (and ListObjects) in the window.
   - Bytes transferred if available (CloudTrail or other logs).
5. **Check KMS usage**
   - Any `kms:Decrypt` by same principal in same window for same account/region.
6. **Context**
   - `sourceIPAddress`, `userAgent`, time window — compare to baseline.

## Containment (Priority Order)
**Immediate**
- Block the principal’s access to the bucket(s) via bucket policy or IAM (explicit deny or remove permissions).
- Rotate compromised credentials (access keys, assume-role sessions) if credentials are suspect.

**Short-term**
- Restrict bucket to VPC endpoint or known IP ranges if feasible.
- Consider temporary bucket policy that denies the principal’s ARN.

## Investigation Deep Dive
- Build timeline: first ListBuckets/ListObjects → first GetObject → burst.
- Identify all buckets and prefixes accessed.
- Correlate with other scenarios (e.g., Scenario 01 if access followed AssumeRole).
- Determine whether data could have left the boundary (egress, external IP).

## Recovery Validation
- Confirm no new persistent access (no new users/roles/keys created for exfil).
- Confirm bucket policies and IAM policies are least-privilege.
- Consider rotating KMS data keys if secrets may have been exposed (key material in objects).

## Communications Template (internal)
- What happened (high level): unauthorized or anomalous S3 access / potential exfil.
- When (UTC/local) and which bucket(s)/prefixes.
- Impact: data volume and sensitivity.
- Containment taken.
- Next steps: remediation, enable data events where missing, monitoring.

## Post-Incident Improvements
- Enable S3 Data Events for all sensitive/crown-jewel buckets.
- Add first-time bucket access and GetObject burst alerts.
- Harden bucket policies and use Access Points; apply KMS and least privilege.
