# Telemetry

This repository includes small, scenario-scoped telemetry bundles to support:
- understanding required event fields,
- validating detection logic conceptually,
- running the demo validator script (no SIEM required).

## Format
Telemetry files are JSON arrays of CloudTrail-like events:

- `scenarios/<scenario>/telemetry/cloudtrail_sample.json`

## Minimum fields used by demo tooling
The demo validator (`tools/detect_assumerole_chain.py`) expects these fields when present:

- `eventTime` (ISO 8601, e.g. `2026-02-25T03:13:02Z`)
- `eventName` (e.g. `AssumeRole`, `GetSecretValue`)
- `sourceIPAddress` (optional, used for display)
- `requestParameters.roleArn` (for `AssumeRole`)
- `userIdentity.type`
- `userIdentity.arn` or `userIdentity.userName`
- `userIdentity.sessionContext.sessionIssuer.arn`  
  (used to build a stable lineage key for assumed-role sessions)

## Notes / Caveats
- CloudTrail event structures vary depending on event type and AWS service.
- Some detections rely on telemetry that may be optional in real environments
  (e.g., S3 data events, VPC Flow Logs, GuardDuty, or agent tool logs).
- The included telemetry focuses on representing **key behaviors** per scenario,
  not full fidelity for every possible field in CloudTrail.
