# Attack Flow — IAM PrivEsc via AssumeRole

## Phase 1 — Initial Access (assumed)
Attacker obtains valid credentials for a low-privileged user/role:
- leaked access key
- compromised workstation session
- compromised CI token
- stolen SSO session

## Phase 2 — Discovery
Attacker enumerates IAM:
- `iam:ListRoles`
- `iam:GetRole`
- `iam:ListAttachedRolePolicies`
- `iam:GetPolicy` / `iam:GetPolicyVersion`

Goal: identify a role with a trust policy that allows assumption by the compromised principal (or a broadly trusted principal).

## Phase 3 — Privilege Escalation
Attacker calls:
- `sts:AssumeRole` into a higher privilege role
Optionally:
- chains multiple roles, escalating breadth (RoleA -> RoleB -> RoleC)

## Phase 4 — Actions on Objectives
Common follow-on actions:
- `secretsmanager:GetSecretValue`
- S3 read access (`s3:GetObject`) to sensitive buckets
- IAM persistence:
  - `iam:CreateAccessKey`
  - `iam:CreateUser`
  - `iam:AttachUserPolicy`
  - `iam:UpdateAssumeRolePolicy` (backdoor trust)

## Phase 5 — Defense Evasion (optional)
- cloudtrail/logging tamper (Scenario 03)
- minimize actions to avoid detection

## Phase 6 — Exit / Persistence
- leave new keys/users/roles
- leave modified trust policy
- maintain access via long-lived credentials
