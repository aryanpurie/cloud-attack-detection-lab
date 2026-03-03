import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Tuple

SENSITIVE_EVENTS = {
    "GetSecretValue",
    "CreateAccessKey",
    "CreateUser",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutRolePolicy",
    "UpdateAssumeRolePolicy",
}

SCENARIO_FILES: Dict[str, str] = {
    "01": "scenarios/01_iam_privesc_assumerole/telemetry/cloudtrail_sample.json",
    "02": "scenarios/02_s3_exfiltration/telemetry/cloudtrail_sample.json",
    "03": "scenarios/03_cloudtrail_tamper/telemetry/cloudtrail_sample.json",
    "04": "scenarios/04_ec2_metadata_steal/telemetry/cloudtrail_sample.json",
    "05": "scenarios/05_llm_agent_tool_blast_radius/telemetry/cloudtrail_sample.json",
}


def parse_time(t: str) -> datetime:
    # CloudTrail eventTime is ISO 8601
    return datetime.fromisoformat(t.replace("Z", "+00:00")).astimezone(timezone.utc)


def resolve_input_path(args: argparse.Namespace) -> str:
    if args.file:
        return args.file
    if args.scenario and args.scenario in SCENARIO_FILES:
        return SCENARIO_FILES[args.scenario]
    # Default: scenario 01
    return SCENARIO_FILES["01"]


def normalize_events(events: List[dict]) -> List[Tuple[datetime, str, str, str, str]]:
    norm: List[Tuple[datetime, str, str, str, str]] = []
    for e in events:
        et = parse_time(e["eventTime"])
        name = e.get("eventName", "unknown")
        role_arn = (e.get("requestParameters", {}) or {}).get("roleArn")
        src = e.get("sourceIPAddress")

        ui = (e.get("userIdentity", {}) or {})
        u_type = ui.get("type")

        sess = ui.get("sessionContext") or {}
        issuer = sess.get("sessionIssuer") or {}
        issuer_arn = issuer.get("arn")

        # lineage_key is stable across chained role sessions
        if u_type == "AssumedRole" and issuer_arn:
            lineage_key = issuer_arn
        else:
            lineage_key = ui.get("arn") or ui.get("userName") or "unknown"

        norm.append((et, lineage_key, name, role_arn, src))

    norm.sort(key=lambda x: x[0])
    return norm


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Demo validator for AssumeRole privilege escalation. "
            "By default uses Scenario 01 sample telemetry."
        )
    )
    parser.add_argument(
        "--file",
        "-f",
        help=(
            "Path to CloudTrail JSON file (array of events). "
            "If not set, use --scenario or default to Scenario 01."
        ),
    )
    parser.add_argument(
        "--scenario",
        "-s",
        choices=sorted(SCENARIO_FILES.keys()),
        help="Scenario code (01–05) to use its sample telemetry.",
    )
    args = parser.parse_args()

    path = resolve_input_path(args)
    with open(path, "r", encoding="utf-8") as f:
        events = json.load(f)

    norm = normalize_events(events)

    # Track AssumeRole and follow-on sensitive actions by lineage key
    assumed_roles: Dict[str, List[Tuple[datetime, str, str]]] = defaultdict(list)
    sensitive_after: Dict[str, List[Tuple[datetime, str, str]]] = defaultdict(list)

    for et, lineage_key, name, role_arn, src in norm:
        if name == "AssumeRole" and role_arn:
            assumed_roles[lineage_key].append((et, role_arn, src))
        if name in SENSITIVE_EVENTS:
            sensitive_after[lineage_key].append((et, name, src))

    print("=== Findings: Potential AssumeRole PrivEsc / Role Chaining ===\n")
    for lineage_key, assumes in assumed_roles.items():
        roles = {r for _, r, _ in assumes}
        if len(roles) >= 2:
            first = assumes[0][0].isoformat()
            last = assumes[-1][0].isoformat()
            print(f"[ROLE CHAINING] lineage={lineage_key}")
            print(f"  window={first} → {last}")
            for t, r, src in assumes:
                print(f"  - {t.isoformat()} AssumeRole roleArn={r} src={src}")
            print()

        # Sensitive actions after assumption (any time after first assume)
        if lineage_key in sensitive_after:
            first_assume_time = assumes[0][0]
            follow = [
                (t, n, s)
                for (t, n, s) in sensitive_after[lineage_key]
                if t >= first_assume_time
            ]
            if follow:
                print(f"[ESCALATION → OBJECTIVES] lineage={lineage_key}")
                for t, n, s in follow:
                    print(f"  - {t.isoformat()} {n} src={s}")
                print()

    print("Done.")


if __name__ == "__main__":
    main()

