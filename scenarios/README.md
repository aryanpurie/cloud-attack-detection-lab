## Scenarios overview

This directory contains end-to-end attack simulations that pair **realistic AWS attack chains** with **defensible, portable detection logic** and **incident response workflows**.

Each scenario folder follows the same structure:

- `scenario.md` – high-level description, assumptions, evidence sources, detection strategy, triage, containment, long-term fixes, senior signal table.
- `attack-flow.md` – detailed, stepwise attack narrative.
- `evidence-map.md` – required telemetry, key fields, and common visibility gaps.
- `detection/splunk_spl.md` – concrete detections in Splunk SPL, built from vendor-neutral logic.
- `detection/sigma.yml` – optional Sigma rule mapping (where provided) for cross-SIEM portability.
- `detection/guardduty-mapping.md` – alignment with native AWS detections (if applicable).
- `runbook.md` – incident response runbook (triage → containment → eradication → recovery).
- `controls.md` – preventive and detective control guidance.
- `telemetry/` – sample CloudTrail (and related) events for replay in a lab SIEM.

### Scenario index

1. `01_iam_privesc_assumerole`  
   - **Theme:** IAM privilege escalation via `sts:AssumeRole` and role chaining.  
   - **Goal:** Detect and respond to low-priv → high-priv escalation, including chained role assumptions, and enforce safer trust relationships.

2. `02_s3_exfiltration`  
   - **Theme:** S3 discovery and bulk exfiltration using `ListObjects` and `GetObject` (with optional KMS `Decrypt`).  
   - **Goal:** Spot abnormal S3 read patterns (bursts, first-time access to crown-jewel buckets, enumeration → exfil) and harden bucket + KMS access.

3. `03_cloudtrail_tamper`  
   - **Theme:** Logging degradation via `StopLogging`, `UpdateTrail`, `DeleteTrail`, and log-bucket / KMS tampering.  
   - **Goal:** Treat any change to CloudTrail or its log storage as a high-severity event, restore logging quickly, and enforce org-level, immutable logging.

4. `04_ec2_metadata_steal`  
   - **Theme:** EC2 instance metadata abuse (IMDS) to steal temporary credentials and pivot via the instance profile role.  
   - **Goal:** Detect anomalous instance-role usage (new IPs, new services, diversity spikes), enforce IMDSv2, and minimize instance profile blast radius.

5. `05_llm_agent_tool_blast_radius`  
   - **Theme:** Prompt injection against an LLM agent with AWS tools, leading to enumeration, data access, or destructive changes.  
   - **Goal:** Correlate agent logs with CloudTrail, detect unusual API sequences by the agent role, and enforce tool allowlists and approvals.

### Using these scenarios

- Start with `scenario.md` for context, then follow `attack-flow.md` and `evidence-map.md` to understand how the attack appears in logs.
- Use `detection/splunk_spl.md` as **one implementation** of the vendor-neutral logic; adapt the same logic to other SIEMs, SQL engines, or Sigma.
- Load `telemetry/cloudtrail_sample.json` into a dev index or test harness to validate your implementation before deploying detections to production.

