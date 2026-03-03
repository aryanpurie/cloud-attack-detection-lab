## Evidence Map
| Data Source | Must-have fields | Why it matters | Common gaps |
|---|---|---|---|
| CloudTrail | eventName, userIdentity, sourceIPAddress, userAgent, requestParameters | attribution + sequence | missing data events |
| GuardDuty | type, resource, severity | signal enrichment | not enabled org-wide |
| VPC Flow Logs (optional) | srcaddr, dstaddr, dstport | IMDS/egress clues | not retained long enough |

## Scenario-specific Event Map
| Stage | Event(s) | Key fields to inspect | Notes |
|---|---|---|---|
| Role discovery | `iam:ListRoles`, `iam:GetRole`, `iam:ListAttachedRolePolicies` | `userIdentity.arn`, `sourceIPAddress`, `userAgent`, `requestParameters.roleName` | Recon before escalation; low-volume but high context value |
| Privilege escalation | `sts:AssumeRole` | `requestParameters.roleArn`, `requestParameters.roleSessionName`, `sourceIPAddress`, `userIdentity.arn` | Core event for this scenario |
| Role chaining | `sts:AssumeRole` x2+ | session linkage fields, timestamps, `sourceIPAddress` | Detect short-window chain behavior |
| Post-escalation impact | IAM, S3, Secrets Manager, KMS API calls | `eventSource`, `eventName`, `resources`, `errorCode` | Establish blast radius and intent |

## Collection and Quality Checks
- CloudTrail management event retention covers investigation window.
- SIEM parser extracts nested fields in `requestParameters` and `sessionContext`.
- Time synchronization between source logs and SIEM indexes is verified.
