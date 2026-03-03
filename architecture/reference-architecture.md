# Reference Architecture

The lab assumes a baseline cloud security posture so that the scenario detections and runbooks are realistic and deployable.

## Logging and visibility

- **CloudTrail** management events are enabled and delivered to a centralized log archive (S3). Org-level CloudTrail is preferred so that trail changes in one account are still visible.
- Optionally: S3 Data Events for sensitive buckets, KMS audit, VPC Flow Logs, and agent/tool logs where scenarios require them.
- Logs are ingested into a SIEM or analytics platform; alerts are routed to incident response workflows.

See the logging flow:

- [architecture/diagrams/reference-logging-architecture.mmd](diagrams/reference-logging-architecture.mmd) — CloudTrail → S3 (and optional KMS) → SIEM/alerting.
- [architecture/diagrams/scenario01-sequence.mmd](diagrams/scenario01-sequence.mmd) — Sequence for Scenario 01 (IAM PrivEsc via AssumeRole): enumeration → AssumeRole chain → objectives.
- [architecture/diagrams/scenario-overview.mmd](diagrams/scenario-overview.mmd) — How scenarios map to telemetry and detection.
- [architecture/diagrams/detection-pipeline.mmd](diagrams/detection-pipeline.mmd) — End-to-end detection pipeline from telemetry to controls.

Rendered diagram images (e.g. `mermaid-diagram.png`, `mermaid-diagram-2.png`) are also in `architecture/diagrams/` when available.

## IAM and guardrails

- IAM roles follow least-privilege; trust policies are explicit (no wildcard principals where avoidable).
- Permission boundaries and SCPs are used to cap escalation and to protect logging (e.g. deny StopLogging/DeleteTrail except breakglass).
- Instance profiles are minimal; IMDSv2 is enforced where possible.

## Threat models and boundaries

- Threat models and trust-boundary notes live under `architecture/threat-models/` and `architecture/diagrams/` (e.g. `trust-boundaries.mmd`).
- Use them to align detections and controls with assumed attacker capabilities and trust boundaries.
