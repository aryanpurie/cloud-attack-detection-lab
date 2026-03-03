# Evidence Map — Scenario 04 (EC2 Metadata Credential Theft)

## Required Telemetry
| Source | Event(s) | Must-have fields | Why it matters |
|---|---|---|---|
| CloudTrail (Mgmt) | All API calls by instance profile role | `userIdentity.arn` (assumed-role), `userIdentity.sessionContext.sessionIssuer.arn`, `sourceIPAddress`, `userAgent`, `eventSource`, `eventName` | attribute calls to instance role; spot new IP/UA and new services |
| CloudTrail (Mgmt) | `sts:GetCallerIdentity` | `userIdentity.*`, `sourceIPAddress`, `userAgent` | often first call after cred theft; new IP/UA = suspicious |
| VPC Flow Logs (optional) | Any | `srcaddr`, `dstaddr` (169.254.169.254), `dstport` (80) | metadata endpoint access from workload |

## Common Gaps
- No baseline for “normal” source IP or userAgent per instance role (hard to detect “new”).
- Instance role used by multiple instances (e.g., same role on ASG) → need to correlate with instance identity (e.g., session name, tags) where possible.
- VPC Flow Logs not enabled or not retained long enough; or not analyzed for metadata endpoint.

## Notes
- High-confidence: instance profile role making API calls from source IP/userAgent never before seen for that role.
- Correlate with deployment/SSRF indicators (new version, new endpoint, user input to URL).
- Map role → instance (session name or tagging) for containment.
