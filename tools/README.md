## Tools

This folder contains small helper utilities to support the lab scenarios.

### `detect_assumerole_chain.py`

Demo validator for **Scenario 01 (IAM PrivEsc via AssumeRole)** and related chains. It reads sample CloudTrail JSON, groups events by a **session lineage key** (stable across chained role sessions), and reports:

- `[ROLE CHAINING]` — when the same lineage assumes **2+ distinct roles** in a window.
- `[ESCALATION → OBJECTIVES]` — when sensitive actions occur after the first AssumeRole.

No Splunk required.

**Run from repo root (default: Scenario 01 sample):**

```bash
python3 tools/detect_assumerole_chain.py
```

**Optional arguments:**

- `--file / -f` – path to a CloudTrail JSON file (array of events).
- `--scenario / -s` – one of `01`, `02`, `03`, `04`, `05` to use that scenario’s sample telemetry.

Examples:

```bash
# Explicit file
python3 tools/detect_assumerole_chain.py --file scenarios/01_iam_privesc_assumerole/telemetry/cloudtrail_sample.json

# Use a different scenario’s sample (if compatible)
python3 tools/detect_assumerole_chain.py --scenario 01
```

This gives you a quick “demo” that the repo’s detection logic maps to real events and that role chaining and follow-on objectives can be surfaced without a SIEM.
