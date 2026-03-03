## Tools

This folder contains small helper utilities to support the lab scenarios.

### `detect_assumerole_chain.py`

Vendor-neutral helper for **Scenario 01 (IAM PrivEsc via AssumeRole)** that scans CloudTrail logs for potential `sts:AssumeRole` chaining by the same principal in a short window.

**Input formats**

- A JSON file containing an **array** of CloudTrail events, or  
- A **newline-delimited JSON** file (one CloudTrail event per line).

**Basic usage**

```bash
python tools/detect_assumerole_chain.py path/to/cloudtrail.json
```

Optional arguments:

- `--window-seconds N` – treat two AssumeRole calls by the same principal within `N` seconds as a potential chain (default: `900` seconds = 15 minutes).

Example:

```bash
python tools/detect_assumerole_chain.py scenarios/01_iam_privesc_assumerole/telemetry/cloudtrail_sample.json \
  --window-seconds 900
```

The script will print any detected **from_role → to_role** transitions, including timestamps, gap in seconds, source IP, region, and account, which you can then compare to your SIEM detections.

