# Controls — Scenario 01: AssumeRole PrivEsc

## Preventive Controls (Design)
1. **Tight Trust Policies**
   - Avoid wildcard principals.
   - Restrict to explicit roles/users/accounts.
   - Use conditions where appropriate (`aws:PrincipalArn`, `aws:SourceVpce`, `aws:SourceIp`, `sts:ExternalId` for third parties).

2. **Permission Boundaries**
   - Apply boundaries to limit maximum privileges of assumable roles.
   - Ensure "admin-like" roles are rare and tightly governed.

3. **Limit Role Chaining**
   - Avoid broad "assume anything" patterns in role policies.
   - Use separate roles per workload/environment (dev/prod separation).

4. **Service Control Policies (SCPs)**
   - Deny `sts:AssumeRole` into privileged roles except approved principals.
   - Deny IAM modifications except breakglass/admin workflows.

## Detective Controls
- High severity alerts:
  - `AssumeRole` into privileged roles (non-allowlisted)
  - multiple distinct roles assumed in short window
  - enumeration → assumeRole correlation
  - assumeRole → sensitive actions correlation

## Operational Controls
- Maintain allowlists (automation/breakglass) with ownership and review cadence.
- Require change-management for trust policy modifications.
- Ensure incident responders have controlled breakglass access with monitoring.
