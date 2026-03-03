# Attack Flow — S3 Data Exfiltration (Discovery → Bulk Copy)

## Phase 1 — Initial Access (assumed)
Attacker obtains valid credentials:
- compromised IAM user/role
- stolen access key
- over-permissive bucket policy or role policy

## Phase 2 — Discovery
Attacker discovers buckets and objects:
- `s3:ListBuckets` (management event; may not appear in data-event-only config)
- `s3:ListObjects` / `s3:ListObjectsV2` on target buckets
- Possible `s3:GetBucketLocation`, `s3:GetBucketPolicy` to understand layout

Goal: identify sensitive buckets and object keys for exfiltration.

## Phase 3 — Enumeration and Probing
- List object prefixes; may generate high error rates (403/404) while probing permissions.
- First successful GetObject to validate access.
- Pattern: errors followed by success spike.

## Phase 4 — Bulk Exfiltration
- Large volume of `s3:GetObject` calls.
- If objects are KMS-encrypted: `kms:Decrypt` events per object (or per key).
- Spike in GetObject count and bytes transferred (where available).
- Downloads may originate from atypical source IP/geography.

## Phase 5 — Defense Evasion (optional)
- Operate during off-hours or from VPN/proxy to blend with normal traffic.
- Slow exfil to avoid threshold triggers (tuning required).

## Phase 6 — Exit
- Data transferred to attacker-controlled system.
- Credentials may be retained for future access.
