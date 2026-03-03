"""
Vendor-neutral helper to detect potential AssumeRole chaining in AWS CloudTrail logs.

This script is intentionally simple and self-contained so it can be reused outside Splunk:

- Input: a JSON file containing either
  - an array of CloudTrail events, or
  - newline-delimited JSON events (one event per line).
- Output: a summary of principals that assumed multiple distinct roles within a short window.

The logic mirrors the lab's vendor-neutral description:
- Filter for sts:AssumeRole events.
- Group events by calling principal.
- Within each principal, sort by time and look for changes in target role ARN
  that occur within a configurable time window (default: 900 seconds / 15 minutes).
"""

import argparse
import datetime
import json
from typing import Any, Dict, Iterable, List, Tuple


def parse_time(ts: str) -> datetime.datetime:
    # CloudTrail uses ISO8601 with Zulu time, for example "2026-02-25T03:13:02Z"
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_events(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()
        if not content:
            return []

        # Try array first
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass

        # Fallback: newline-delimited JSON
        events: List[Dict[str, Any]] = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events


def extract_assumerole_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for e in events:
        if e.get("eventSource") != "sts.amazonaws.com":
            continue
        if e.get("eventName") != "AssumeRole":
            continue
        out.append(e)
    return out


def principal_and_role(event: Dict[str, Any]) -> Tuple[str, str]:
    ui = event.get("userIdentity", {}) or {}
    principal = ui.get("arn") or ui.get("userName") or "UNKNOWN"

    req = event.get("requestParameters", {}) or {}
    role_arn = req.get("roleArn") or "UNKNOWN_ROLE"
    return principal, role_arn


def detect_role_chains(
    events: List[Dict[str, Any]], window_seconds: int = 900
) -> List[Dict[str, Any]]:
    # Group by principal
    per_principal: Dict[str, List[Dict[str, Any]]] = {}
    for e in events:
        principal, _ = principal_and_role(e)
        per_principal.setdefault(principal, []).append(e)

    findings: List[Dict[str, Any]] = []

    for principal, evs in per_principal.items():
        # Sort by time
        evs_sorted = sorted(evs, key=lambda x: x.get("eventTime", ""))
        # Track last role and time
        last_role = None
        last_time: datetime.datetime | None = None

        for e in evs_sorted:
            _, role_arn = principal_and_role(e)
            t = parse_time(e["eventTime"])

            if last_role is not None and role_arn != last_role and last_time is not None:
                delta = (t - last_time).total_seconds()
                if 0 <= delta <= window_seconds:
                    findings.append(
                        {
                            "principal": principal,
                            "from_role": last_role,
                            "to_role": role_arn,
                            "first_event_time": last_time.isoformat(),
                            "second_event_time": t.isoformat(),
                            "gap_seconds": int(delta),
                            "sourceIPAddress": e.get("sourceIPAddress"),
                            "awsRegion": e.get("awsRegion"),
                            "recipientAccountId": e.get("recipientAccountId"),
                        }
                    )

            last_role = role_arn
            last_time = t

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect potential sts:AssumeRole chaining behavior in CloudTrail logs."
    )
    parser.add_argument(
        "path", help="Path to CloudTrail JSON file (array or newline-delimited events)."
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=900,
        help="Time window (in seconds) to treat two AssumeRole calls by the same principal as a chain (default: 900 = 15 minutes).",
    )
    args = parser.parse_args()

    events = load_events(args.path)
    assume_events = extract_assumerole_events(events)
    findings = detect_role_chains(assume_events, window_seconds=args.window_seconds)

    if not findings:
        print("No potential role chaining patterns detected.")
        return

    print("Potential AssumeRole chaining patterns:")
    for f in findings:
        print(
            f"- principal={f['principal']} from_role={f['from_role']} "
            f"to_role={f['to_role']} gap_seconds={f['gap_seconds']} "
            f"first={f['first_event_time']} second={f['second_event_time']} "
            f"src_ip={f.get('sourceIPAddress')} region={f.get('awsRegion')} "
            f"account={f.get('recipientAccountId')}"
        )


if __name__ == "__main__":
    main()

