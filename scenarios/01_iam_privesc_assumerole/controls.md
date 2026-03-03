# Controls: IAM PrivEsc via AssumeRole

## Preventive Controls
- Restrict trust policies to explicit principals only.
- Avoid wildcard principals and broad condition sets for privileged roles.
- Require external ID and additional conditions where cross-account assumptions are needed.
- Apply permission boundaries to delegated admin and developer roles.
- Enforce MFA and short session durations for sensitive role assumptions.

## Detective Controls
- Alert on `AssumeRole` into high-priv roles by non-approved principals.
- Alert on short-window role chaining behavior.
- Correlate `AssumeRole` with IAM persistence actions.
- Baseline source IP/user agent for sensitive role assumptions.

## Compensating Guardrails
- SCP deny for `sts:AssumeRole` into designated privileged roles unless caller is allowlisted.
- SCP deny for risky IAM mutation APIs except approved automation/breakglass roles.
- Centralized CloudTrail aggregation with immutable retention policy.

## Operational Hygiene
- Review trust policies regularly for drift and stale principals.
- Tag privileged roles and enforce policy checks in CI.
- Perform periodic access reviews for principals that can call `AssumeRole`.
