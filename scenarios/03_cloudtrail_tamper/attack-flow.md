# Attack Flow — CloudTrail Tampering / Logging Degradation

## Phase 1 — Prerequisites (assumed)
Attacker has sufficient permissions (e.g., after Scenario 01 escalation):
- `cloudtrail:StopLogging`, `cloudtrail:UpdateTrail`, `cloudtrail:DeleteTrail`
- Possibly `s3:PutBucketPolicy` on the log delivery bucket
- Possibly `kms:DisableKey` or `kms:PutKeyPolicy` if trail uses KMS

## Phase 2 — Disable or Degrade Logging
Attacker executes one or more of:
- `cloudtrail:StopLogging` — stops delivery to S3 (trail remains, no new events)
- `cloudtrail:UpdateTrail` — change S3 bucket, disable multi-region, or alter other settings to reduce coverage or break delivery
- `cloudtrail:DeleteTrail` — remove trail entirely

Goal: create a window where API activity is not (or is less) visible.

## Phase 3 — Persist Blind Window (optional)
- `s3:PutBucketPolicy` on log archive bucket to deny PutObject from CloudTrail service principal (stops new logs even if trail is "on").
- Delete or corrupt existing log objects (if permissions allow).
- `kms:DisableKey` or key policy change to prevent CloudTrail from using the key (delivery fails).

## Phase 4 — Operate in Blind Window
- Attacker performs other objectives (data exfil, persistence, lateral movement) while logging is degraded or stopped.

## Phase 5 — Exit / Restore (optional)
- Attacker may restore trail config to avoid ongoing suspicion, or leave it disabled to prolong blind window.

## Phase 6 — Detection Note
- The change events (StopLogging, UpdateTrail, DeleteTrail, PutBucketPolicy) are management events and are logged by the trail before it is stopped (or by another trail). So detection relies on alerting on these events and allowlisting.
