# cloud-attack-detection-lab
A practitioner-focused lab that models realistic AWS attack chains and pairs each with defensible detection logic, incident response actions, and long-term preventive controls.

This repository is designed to demonstrate senior-level security engineering across:
- **Platform Security:** cloud-native abuse paths, guardrails, and preventative architecture
- **Detection Engineering:** telemetry-driven detection logic, quality considerations, and tuning guidance
- **Incident Response:** triage workflows, containment steps, and recovery validation
- **Security Architecture:** threat models, trust boundaries, and “secure-by-design” mitigations
- **AI Security:** an LLM tool-access scenario that shows how AI can expand blast radius without proper guardrails

> Goal: Show the ability to secure modern cloud systems end-to-end — not just “write queries”.

---

## Start Here
- **Scenario index:** [scenarios/README.md](scenarios/README.md)
- **Recommended first scenario:** [scenarios/01_iam_privesc_assumerole/](scenarios/01_iam_privesc_assumerole/)
- **Detection quality principles:** [docs/detection-quality.md](docs/detection-quality.md)
- **Reference architecture:** [architecture/reference-architecture.md](architecture/reference-architecture.md)

---

## What’s Inside

### Scenarios (end-to-end)
Each scenario contains:
- **Attack flow** (kill-chain narrative)
- **Evidence map** (what logs exist, where, and what fields matter)
- **Detection logic** (Splunk SPL + optional Sigma)
- **Runbook** (triage → containment → eradication → recovery)
- **Controls** (long-term fixes + architectural guardrails)
- **Senior signal table:** Attack → Evidence → Detection → Triage → Containment → Long-term Fix

Scenarios:
1. `01_iam_privesc_assumerole` — Role chaining / AssumeRole privilege escalation
2. `02_s3_exfiltration` — Data exfiltration via S3 enumeration + bulk download
3. `03_cloudtrail_tamper` — Logging defense evasion and CloudTrail degradation
4. `04_ec2_metadata_steal` — Credential theft via IMDS and instance profile misuse
5. `05_llm_agent_tool_blast_radius` — Prompt injection leading to tool misuse and cloud impact

---

## Reference Architecture
The lab assumes a baseline cloud security posture:
- CloudTrail enabled (org-level preferred), centralized log archive
- GuardDuty enabled (where applicable)
- Alerts routed into a SIEM (examples provided as SPL, can be adapted)
- IAM roles follow least-privilege and controlled trust relationships

See: `architecture/reference-architecture.md`

---

## Portfolio Proof (for reviewers)

If you are reviewing this repository as part of an interview or portfolio review, here is how to get value quickly:

- **Core story:** Five realistic AWS attack paths (IAM PrivEsc, S3 exfil, CloudTrail tamper, EC2 metadata theft, LLM agent abuse) each come with attack flow, evidence map, vendor-neutral detection logic, Splunk SPL, sample telemetry, runbook, and controls.
- **Fast navigation (under 2 minutes):**
  - Start with the scenario index: `scenarios/README.md`
  - Open Scenario 01: `scenarios/01_iam_privesc_assumerole/`
  - Skim `scenario.md` → `detection/splunk_spl.md` (vendor-neutral logic + SPL) → `runbook.md`
- **Why these 5 scenarios:** They cover privilege escalation, data exfiltration, logging degradation, credential theft via IMDS, and AI/LLM tool misuse — a representative slice of modern cloud attack surface.
- **How to “run” the lab without Splunk:** Use the included sample telemetry (`telemetry/*.json`) and the demo tool `tools/detect_assumerole_chain.py` to see how detections map to concrete events.
- **What I’d add next (roadmap):** additional scenarios (KMS key abuse, cross-account persistence), Sigma rule equivalents for all detections, and CI to validate detections against evolving telemetry samples.

---

## Detection Quality Principles
This repository emphasizes “defensible detections”:
- Clear assumptions and prerequisites
- Fields and event sources explicitly documented
- Known false positives and tuning guidance included
- Recommendations for suppression (where appropriate)

See: `docs/detection-quality.md`

---

## How to Use This Repo
- If you’re building detections: start in `scenarios/*/detection/`
- If you’re investigating an incident: start in `scenarios/*/runbook.md`
- If you’re designing guardrails: start in `scenarios/*/controls.md` or `controls/`

---

## Disclaimer
This repository is for educational and defensive purposes. It contains simulated telemetry and guidance for detection and response. Do not use this material to target systems you do not own or have explicit permission to test.
