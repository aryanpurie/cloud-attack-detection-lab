# Scenarios Index (Start Here)

Each scenario includes:
- `scenario.md` (summary + senior signal table)
- `attack-flow.md` (kill-chain narrative)
- `evidence-map.md` (telemetry requirements + gaps)
- `detection/splunk_spl.md` (Splunk-first detections + tuning)
- `runbook.md` (triage → containment → recovery)
- `controls.md` (preventive + detective guardrails)
- `telemetry/cloudtrail_sample.json` (sample events)

| # | Scenario | Folder | Primary Focus |
|---|----------|--------|---------------|
| 01 | IAM PrivEsc via AssumeRole | `01_iam_privesc_assumerole/` | role chaining, trust abuse |
| 02 | S3 Data Exfiltration | `02_s3_exfiltration/` | discovery → bulk reads, KMS decrypt |
| 03 | CloudTrail Tampering | `03_cloudtrail_tamper/` | stop/update/delete trails, log integrity |
| 04 | EC2 Metadata Credential Theft | `04_ec2_metadata_steal/` | IMDS → instance profile pivot |
| 05 | LLM Agent Tool Abuse | `05_llm_agent_tool_blast_radius/` | prompt injection → tool misuse |
