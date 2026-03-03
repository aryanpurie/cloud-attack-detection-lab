## Detection quality and portability

This lab treats detections as **engineering artifacts**, not just queries. Each rule should be:

- **Accurate** – it actually detects the modeled behavior.
- **Actionable** – responders know what to do when it fires.
- **Explainable** – the logic is understandable and reviewable.
- **Portable** – the core logic can be implemented across SIEMs and query languages.

To make that concrete, every scenario is split into:

- A **vendor-neutral description** of the detection logic (what sequence of events or conditions to look for).
- One or more **implementation examples** (for example, Splunk SPL in `detection/splunk_spl.md`, optional Sigma, or native detections).

### Core quality dimensions

- **Coverage:** Which attacker behaviors, techniques, and stages of the kill chain are covered. Scenarios reference specific AWS APIs and control points so you can map to ATT&CK or your own framework.
- **Confidence:** How reliably the detection matches malicious behavior versus benign noise. High-confidence rules usually focus on **behavioral sequences** (for example, enumeration → escalation → persistence) rather than a single API call.
- **Fidelity / Noise:** How often a rule fires on expected activity. Allowlists, baselines, and environment-specific thresholds are called out in each scenario’s detection and runbook.
- **Actionability:** Each rule is paired with a runbook that defines triage steps, containment actions, and recovery checks so alerts can be worked quickly.
- **Portability:** The vendor-neutral logic is expressed in prose and tables first, then implemented in SPL. The same logic can be translated into Sigma or any SIEM query language.

### Vendor-neutral detection logic

At the top of each `detection/splunk_spl.md` file you’ll find a **vendor-neutral detection logic** section that describes:

- **Inputs:** required telemetry sources and fields (for example, CloudTrail management vs. data events, key identity fields).
- **Behavioral patterns:** sequences like “enumeration → AssumeRole → sensitive actions” or “ListObjects → GetObject burst”.
- **Windows and thresholds:** recommended time windows (for example, 10–30 minutes) and event-count thresholds that can be tuned per environment.
- **Context:** how to layer in allowlists, baselines, or change-management metadata.

These sections are intentionally free of SPL-specific syntax. You can treat them as:

- The **“definition of done”** for a detection, regardless of tool.
- A bridge to formats like **Sigma**, where the same logic is encoded in YAML and compiled into platform-specific queries.

### Using this document

When you build or adapt detections from this lab:

1. Start from the **scenario’s vendor-neutral logic** and evidence map.
2. Implement the rule in your preferred SIEM or analytics engine.
3. Use the **sample telemetry** under each scenario’s `telemetry/` folder to validate behavior.
4. Review detection quality along the dimensions above (coverage, confidence, fidelity, actionability, portability) before promoting to production.

