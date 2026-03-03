# Runbook — Scenario 04: EC2 Metadata Credential Theft

## Goal
Rapidly confirm whether instance profile credentials were used from an unexpected context (theft/SSRF), identify the instance and blast radius, and contain by replacing instance and reducing role permissions.

## Triage Checklist (10–20 minutes)
1. **Identify the instance role**
   - `userIdentity.sessionContext.sessionIssuer.arn` or assumed-role ARN (e.g., `assumed-role/MyAppRole/i-xxxx`).
   - Resolve session name to instance ID if naming convention includes instance ID.
2. **Confirm anomalous context**
   - `sourceIPAddress`, `userAgent` — compare to baseline (expected NAT, expected UA for this role).
   - First time this role is seen from this IP/UA?
3. **Determine blast radius**
   - List permissions of the instance profile role (policies attached).
   - List API calls made with the stolen session (eventSource/eventName) in the window.
4. **Identify the instance**
   - Map role to instance(s) via tags, launch config, or session name; identify which instance was likely compromised (e.g., SSRF host).
5. **Host investigation**
   - If possible, image or inspect the instance for SSRF vectors, malware, or abuse of metadata.

## Containment (Priority Order)
**Immediate**
- Terminate (or isolate) the affected instance and replace with a new instance (no reuse of same creds).
- Reduce instance profile permissions to minimum required (remove broad S3/Secrets/IAM if not needed).
- Optionally revoke existing session (instance profile sessions expire; shortening TTL for future is a control).

**Short-term**
- Enforce IMDSv2 only (hop limit = 1), disable IMDSv1 where possible.
- Patch SSRF in application; add WAF or input validation to block metadata URL in user input.
- Block egress from workload to metadata from non-host path if feasible (e.g., network policy).

## Investigation Deep Dive
- Timeline: first GetCallerIdentity or first API from new IP/UA → subsequent actions.
- All resources accessed (S3 buckets, secrets, IAM changes).
- Check for new users/keys created by the instance role.

## Recovery Validation
- New instance uses same or reduced role; IMDSv2 enforced.
- No persistence (no new IAM users/keys from the stolen session).
- Application fixed for SSRF.

## Communications Template (internal)
- What happened: instance credentials likely stolen (e.g., SSRF) and used from external context.
- Which role and instance; which resources may have been accessed.
- Containment: instance replaced; role reduced; IMDSv2 enforced.
- Next steps: patch, monitoring, least privilege.

## Post-Incident Improvements
- Enforce IMDSv2; minimize instance profile scope.
- Baseline and alert on “new source IP/userAgent for instance role.”
- Add SSRF testing and WAF/guardrails for user-controlled URLs.
