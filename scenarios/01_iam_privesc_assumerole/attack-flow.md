# Attack Flow: IAM PrivEsc via AssumeRole

## Narrative
The attacker starts with credentials tied to a low-privilege principal. They enumerate IAM roles and trust relationships to locate a role that can be assumed due to overly broad trust conditions. After successful role assumption, they use elevated permissions to access sensitive resources and potentially establish persistence.

## Step-by-step Chain
1. **Initial foothold**
   - Compromised developer access key, stolen session token, or exposed workload credentials.
2. **Role discovery**
   - Calls to `iam:ListRoles`, `iam:GetRole`, and `iam:ListAttachedRolePolicies`.
3. **Trust abuse**
   - Identify a high-privilege role with weak or unintended trust policy.
4. **Privilege escalation**
   - Execute `sts:AssumeRole` into target role.
5. **Expansion**
   - Access high-value services (for example `s3:GetObject`, `secretsmanager:GetSecretValue`, IAM modifications).
6. **Persistence and cleanup attempts**
   - Possible creation of keys/users, trust policy changes, or additional chained assumptions.

## Primary Detection Signals
- New or rare principal assuming privileged role.
- Source IP, ASN, geography, or user agent outside known baseline.
- Role-chaining sequence in a short period.
- Sensitive follow-on API actions immediately after role assumption.
