# Controls — Scenario 03: CloudTrail Tampering

## Preventive Controls (Design)
1. **Least Privilege**
   - Restrict `cloudtrail:StopLogging`, `UpdateTrail`, `DeleteTrail` to breakglass or change-management roles only.
   - Restrict `s3:PutBucketPolicy` on log archive buckets; restrict KMS key policy changes.

2. **Service Control Policies (SCPs)**
   - Deny `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, and high-risk `UpdateTrail` (e.g., S3 bucket, IsMultiRegionTrail) for all principals except an explicit breakglass OU/role.
   - Reduces risk of tampering even if an account is compromised.

3. **Immutable Log Storage**
   - S3 Object Lock on log archive bucket (where compliant with retention policy).
   - Bucket policy that denies DeleteObject and PutBucketPolicy from non–log-delivery principals (where possible).

4. **Organization-Level Trail**
   - Use (or add) an organization trail in a delegated admin account; reduce dependency on single-account trails.

## Detective Controls
- High severity: any StopLogging, DeleteTrail, or UpdateTrail by principal not on allowlist.
- Alert on PutBucketPolicy for log archive bucket and on KMS DisableKey/PutKeyPolicy for trail’s key.
- Correlate with AssumeRole (Scenario 01) for post-escalation tampering.

## Operational Controls
- Maintain allowlist of principals permitted to change CloudTrail (e.g., Terraform role, breakglass); review regularly.
- Prefer IaC for trail and bucket config so restoration is repeatable.
- Test restoration of trail and bucket policy in drills.
