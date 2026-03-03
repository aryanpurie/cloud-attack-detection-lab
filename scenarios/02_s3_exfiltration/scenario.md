# Scenario 02 — S3 Data Exfiltration (Discovery → Bulk Copy)

## Summary
This scenario models an attacker discovering S3 buckets, enumerating objects, then performing large-scale downloads. The attack is often paired with misconfigured bucket policies, overly broad IAM permissions, or stolen credentials. Evidence relies on S3 Data Events (ListObjects, GetObject) and optionally KMS Decrypt.

## Preconditions / Assumptions
- CloudTrail management events are enabled; S3 Data Events are enabled for sensitive buckets (or at least for crown-jewel buckets).
- S3 and optional KMS events are delivered to Splunk (or SIEM).
- A baseline or allowlist exists for "normal" access patterns to sensitive buckets.

## Attack Flow (High Level)
1. Attacker obtains credentials (compromised principal, stolen keys, or overly permissive role).
2. Discovers buckets (s3:ListBuckets — may not appear if data events not configured for management).
3. Enumerates objects (ListObjects / ListObjectsV2).
4. Performs bulk GetObject downloads; may trigger kms:Decrypt if objects are KMS-encrypted.
5. Exfiltrates data to attacker-controlled destination.

## Evidence Sources
- CloudTrail Data Events: `s3:ListObjects`, `s3:ListObjectsV2`, `s3:GetObject`
- CloudTrail (optional): `s3:ListBuckets` (management)
- KMS: `kms:Decrypt` when attacker accesses KMS-encrypted objects
- Signals: spike in GetObject count/bytes, first-time access to sensitive bucket, downloads from atypical network location, high error rates then success (probing).

## Detection Strategy (Splunk-first)
- Threshold-based anomaly: GetObject burst by principal/bucket.
- First-time access to "crown jewel" buckets.
- Correlation: ListObjects then GetObject burst shortly after.

## Triage Workflow
- Confirm whether S3 Data Events are enabled (if not: visibility gap).
- Identify bucket/object prefix targeted.
- Estimate data volume accessed.
- Identify whether attacker used KMS decrypt (key usage).

## Containment Actions
- Block access via bucket policy / role policy.
- Rotate compromised principals.
- Temporarily require VPC endpoint or restrict to known IPs if feasible.

## Long-term Fixes
- Enable S3 Data Events for sensitive buckets.
- Use Access Points, least privilege, block public access.
- Apply S3 + KMS policy hardening.

## Known False Positives / Tuning
- Backup jobs, ETL pipelines, and analytics workloads that legitimately bulk-read.
- New services or migrations that cause first-time bucket access spikes.
- Allowlist crown-jewel buckets and known automation principals.

## Validation Approach (How to test)
- Ingest sample S3 Data Events (telemetry/) into Splunk dev index.
- Confirm burst and first-time-access detections fire.
- Tune thresholds and allowlists per environment.

## Senior Signal Table
| Attack | Evidence | Detection | Triage | Containment | Long-term Fix |
|---|---|---|---|---|---|
| S3 discovery + bulk exfil | S3 data events GetObject, KMS decrypt | Burst + first-time bucket access | Confirm data volume, prefixes | Restrict policy, rotate creds | Enable data events, access points, KMS hardening |
