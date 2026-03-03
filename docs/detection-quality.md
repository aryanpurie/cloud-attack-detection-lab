# Detection Quality Principles

This repository emphasizes defensible detections:
- Clear prerequisites and telemetry requirements
- Explicit fields used for attribution and correlation
- False positive drivers documented with tuning guidance
- Severity model aligned to blast radius and intent
- Validation approach using included sample telemetry

## Prerequisites
- CloudTrail management events enabled and centralized.
- (Optional per scenario) S3 data events, GuardDuty, VPC Flow Logs, agent tool logs.

## Quality Bars
A detection should include:
1. **What it detects** (one sentence)
2. **Why it matters** (impact/blast radius)
3. **Data requirements** (sources + fields)
4. **Logic** (portable + SPL)
5. **Tuning guidance** (allowlists, suppressions)
6. **Validation** (how to confirm with sample telemetry)
7. **Response hint** (triage starting point)

## Severity Guidance (Suggested)
- **High:** privilege escalation, logging tamper, secrets access, broad enumeration + objective actions
- **Medium:** suspicious discovery without confirmed objective actions
- **Low:** noisy baselines, partial indicators without corroboration

## Common False Positives
- CI/CD and deployment pipelines assuming roles
- Breakglass usage during incidents
- New service onboarding (spikes in API usage)
- Automated inventory/security tooling

## Recommended Tuning
- Maintain allowlists for automation/breakglass principals
- Add environment scoping (prod vs dev)
- Apply thresholds carefully (count + time window)
- Correlate signals (sequence beats single events)

---

## Detection quality and portability

This lab also treats detections as **engineering artifacts** that can be implemented in any SIEM. Each scenario’s `detection/splunk_spl.md` includes:

- A **vendor-neutral description** of the detection logic (what sequence of events or conditions to look for).
- **Implementation examples** in Splunk SPL; the same logic can be translated into Sigma or other query languages.

### Core quality dimensions
- **Coverage:** Which attacker behaviors and techniques are covered.
- **Confidence:** Behavioral sequences (e.g. enumeration → escalation → persistence) vs. single events.
- **Fidelity / Noise:** Allowlists, baselines, and thresholds per scenario.
- **Actionability:** Runbooks define triage, containment, and recovery.
- **Portability:** Vendor-neutral logic at the top of each `splunk_spl.md` supports reuse across tools.

### Using this document
1. Start from the **scenario’s vendor-neutral logic** and evidence map.
2. Implement the rule in your preferred SIEM or analytics engine.
3. Use the **sample telemetry** under each scenario’s `telemetry/` folder to validate behavior.
4. Review quality bars and severity guidance above before promoting to production.
