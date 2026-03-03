# Controls — Scenario 04: EC2 Metadata Credential Theft

## Preventive Controls (Design)
1. **IMDSv2 Enforcement**
   - Require IMDSv2 (session-oriented, hop limit 1) and disable IMDSv1 to limit SSRF-based credential theft.
   - Enforce via launch template / instance config and/or SCP.

2. **Least Privilege for Instance Profiles**
   - Attach only the permissions the workload needs; avoid broad S3, Secrets Manager, or IAM.
   - Use resource-level and condition keys where possible.

3. **Network and SSRF Mitigation**
   - Segment workloads; restrict which instances can reach metadata (e.g., host-only, no proxy to 169.254.169.254).
   - Validate and sanitize user input that could lead to SSRF (block metadata URL patterns); use WAF rules where applicable.

4. **Workload Identity Alternatives**
   - Where feasible, use alternatives to instance metadata (e.g., IRSA for Kubernetes, OIDC, or secret injection with short TTL).

## Detective Controls
- Alert on instance profile role used from new source IP or userAgent (baseline).
- Alert on new AWS service (eventSource) used by an instance role in a short window.
- If VPC Flow Logs available: alert on metadata endpoint (169.254.169.254) access from app-tier subnets or unexpected sources.

## Operational Controls
- Maintain baseline of “expected” source IP/userAgent per instance role (or per ASG/tag).
- Regular review of instance profile policies; remove unused permissions.
- Security testing (e.g., SSRF checks) in CI or pentests.
