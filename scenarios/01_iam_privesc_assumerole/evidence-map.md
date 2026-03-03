# Evidence Map — Scenario 01

## Required Telemetry
| Source | Event(s) | Must-have fields | Why it matters |
|---|---|---|---|
| CloudTrail (Mgmt) | `AssumeRole` | `userIdentity.*`, `requestParameters.roleArn`, `sourceIPAddress`, `userAgent`, `recipientAccountId`, `awsRegion` | attribution + target role + session context |
| CloudTrail (Mgmt) | IAM read enum | `eventName`, `userIdentity.*`, `sourceIPAddress`, `userAgent` | indicates discovery preceding escalation |
| CloudTrail (Mgmt) | IAM changes | `UpdateAssumeRolePolicy`, `Attach*Policy`, `CreateAccessKey` | persistence + privilege changes |
| CloudTrail (Data, optional) | S3 / Secrets | `GetObject`, `GetSecretValue` | post-escalation objectives |

## Common Gaps
- No baseline for "normal AssumeRole patterns"
- Missing data events for S3 (sensitive bucket reads invisible)
- Shared automation roles produce noisy AssumeRole activity

## Notes
- Start with high-confidence detections on **role assumption into privileged roles** or **role chaining**.
- Add allowlists for known automation and breakglass roles as you harden.
