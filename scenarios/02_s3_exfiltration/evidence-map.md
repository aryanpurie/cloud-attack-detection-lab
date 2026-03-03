# Evidence Map — Scenario 02 (S3 Exfiltration)

## Required Telemetry
| Source | Event(s) | Must-have fields | Why it matters |
|---|---|---|---|
| CloudTrail (Data Events) | `GetObject`, `ListObjects`, `ListObjectsV2` | `userIdentity.*`, `requestParameters.bucketName`, `requestParameters.key`, `sourceIPAddress`, `userAgent`, `recipientAccountId` | attribution + bucket/key + volume and pattern |
| CloudTrail (Data Events) | S3 request metrics | bytes transferred (if logged), request count | volume and burst detection |
| CloudTrail (Mgmt, optional) | `ListBuckets` | `userIdentity.*`, `sourceIPAddress` | bucket discovery |
| CloudTrail (Data/Mgmt) | `kms:Decrypt` | `userIdentity.*`, `requestParameters.keyId`, resources | KMS-backed object access |

## Common Gaps
- S3 Data Events not enabled for sensitive buckets (GetObject invisible).
- No data events on log/archive buckets (attacker may target those first).
- High volume of data events: cost and retention; need focused inclusion (prefix/bucket) for crown jewels.
- Bytes transferred not always present in CloudTrail; may need custom metrics or proxy logs.

## Notes
- Start with high-confidence detections: **GetObject burst by principal/bucket** and **first-time access to crown-jewel buckets**.
- Correlate ListObjects → GetObject burst in short window.
- Enrich with KMS Decrypt when objects are KMS-encrypted.
