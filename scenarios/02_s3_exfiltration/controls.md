# Controls — Scenario 02: S3 Data Exfiltration

## Preventive Controls (Design)
1. **Least Privilege**
   - Grant S3 permissions only to principals that need them; use resource-level (bucket/prefix) and condition keys.
   - Avoid `s3:GetObject` on entire account or broad wildcards.

2. **Block Public Access**
   - Enforce S3 Block Public Access (account and bucket) to prevent accidental public read.

3. **Access Points and Bucket Policies**
   - Use S3 Access Points for applications; restrict via VPC and principal.
   - Bucket policies: explicit allow + deny for known bad patterns (e.g., external root).

4. **KMS and Encryption**
   - Encrypt sensitive buckets with KMS; use key policies and IAM to limit decrypt.
   - Reduces blast radius and creates kms:Decrypt audit trail.

5. **Network and VPC**
   - Where feasible, restrict S3 access to VPC endpoint; reduces exposure from arbitrary IPs.

## Detective Controls
- High-value alerts:
  - GetObject burst by principal and/or bucket (threshold or anomaly).
  - First-time access to crown-jewel buckets.
  - Correlation: ListObjects followed by GetObject burst in short window.
- Enrich with KMS Decrypt when objects are KMS-encrypted.

## Operational Controls
- Enable S3 Data Events for sensitive/crown-jewel buckets (balance cost and retention).
- Maintain allowlists for expected bulk readers (backup, ETL) and tune thresholds.
- Regular review of bucket policies and IAM policies that grant S3 access.
