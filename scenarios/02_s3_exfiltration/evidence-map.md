## Evidence Map
| Data Source | Must-have fields | Why it matters | Common gaps |
|---|---|---|---|
| CloudTrail | eventName, userIdentity, sourceIPAddress, userAgent, requestParameters | attribution + sequence | missing data events |
| GuardDuty | type, resource, severity | signal enrichment | not enabled org-wide |
| VPC Flow Logs (optional) | srcaddr, dstaddr, dstport | IMDS/egress clues | not retained long enough |
