# Evidence Map — Scenario 03 (CloudTrail Tampering)

## Required Telemetry
| Source | Event(s) | Must-have fields | Why it matters |
|---|---|---|---|
| CloudTrail (Mgmt) | `StopLogging`, `UpdateTrail`, `DeleteTrail` | `userIdentity.*`, `eventName`, `requestParameters.name` (trail name), `sourceIPAddress`, `userAgent`, `recipientAccountId` | who changed what and when |
| CloudTrail (Mgmt) | `PutBucketPolicy` (on log bucket) | `userIdentity.*`, `requestParameters.bucketName`, `sourceIPAddress` | log bucket tampering |
| CloudTrail (Mgmt) | `DisableKey`, `PutKeyPolicy` (KMS) | `userIdentity.*`, `requestParameters.keyId`, resources | KMS impact on trail delivery |

## Common Gaps
- Only one trail in account/region: when it’s stopped or deleted, no local trail to log the change (rely on org trail or another region).
- No allowlist for “who may change CloudTrail” → noisy or no alert.
- Log archive bucket not in same account/region as trail → need to monitor that bucket’s policy changes elsewhere.

## Notes
- High-confidence detection: **any** StopLogging / DeleteTrail / UpdateTrail by principal not on allowlist.
- Correlate with AssumeRole (Scenario 01) to catch post-escalation tampering.
- Validate log archive bucket policy and KMS key after containment.
