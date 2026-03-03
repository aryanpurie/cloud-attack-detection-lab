# Splunk Detections — Scenario 03 (CloudTrail Tampering)

Assumption: CloudTrail management events are in Splunk. Adjust index/sourcetype as needed.

## Detection 1 — High severity: StopLogging / DeleteTrail / UpdateTrail (allowlist-based)
**Idea:** Alert on any principal performing trail-stopping or trail-modifying actions unless they are on an approved allowlist.

```spl
index=cloudtrail sourcetype="aws:cloudtrail" eventSource="cloudtrail.amazonaws.com"
  (eventName="StopLogging" OR eventName="DeleteTrail" OR eventName="UpdateTrail")
| eval actor=coalesce('userIdentity.arn','userIdentity.userName')
| eval trail_name=requestParameters.name
| lookup cloudtrail_change_allowlist actor OUTPUT actor as allow_actor
| where isnull(allow_actor)
| table _time actor trail_name eventName sourceIPAddress userAgent recipientAccountId
| eval risk_reason="CloudTrail tampering (non-allowlisted principal)"
```

**Tuning:** Maintain lookup `cloudtrail_change_allowlist` with ARNs of approved automation/breakglass roles.

## Detection 2 — PutBucketPolicy on log archive bucket
**Idea:** Alert when bucket policy is changed on a known log archive bucket (could block CloudTrail delivery).

```spl
index=cloudtrail sourcetype="aws:cloudtrail" eventName="PutBucketPolicy"
| eval bucket=requestParameters.bucketName
| search [| inputlookup cloudtrail_log_buckets | fields bucket ]
| eval actor=coalesce('userIdentity.arn','userIdentity.userName')
| table _time actor bucket sourceIPAddress userAgent recipientAccountId
| eval risk_reason="Bucket policy change on CloudTrail log bucket"
```

**Tuning:** Maintain lookup `cloudtrail_log_buckets` with bucket names used for CloudTrail logs.

## Detection 3 — KMS DisableKey or PutKeyPolicy (trail encryption key)
**Idea:** If CloudTrail uses KMS, changes to that key can break log delivery.

```spl
index=cloudtrail sourcetype="aws:cloudtrail" eventSource="kms.amazonaws.com"
  (eventName="DisableKey" OR eventName="PutKeyPolicy")
| eval keyId=coalesce(requestParameters.keyId, requestParameters.keyId)
| lookup cloudtrail_kms_keys keyId OUTPUT keyId as is_trail_key
| where isnotnull(is_trail_key)
| eval actor=coalesce('userIdentity.arn','userIdentity.userName')
| table _time actor keyId eventName sourceIPAddress recipientAccountId
| eval risk_reason="KMS key change for CloudTrail encryption"
```

**Tuning:** Maintain lookup `cloudtrail_kms_keys` with KMS key IDs/ARNs used by CloudTrail.

## Detection 4 — Correlation: AssumeRole then CloudTrail change (within 1h)
**Idea:** Escalation followed by logging tamper is high confidence.

```spl
index=cloudtrail sourcetype="aws:cloudtrail"
| eval actor=coalesce('userIdentity.arn','userIdentity.userName')
| eval is_assume=if(eventName="AssumeRole",1,0)
| eval is_tamper=if(eventSource="cloudtrail.amazonaws.com" AND eventName IN ("StopLogging","DeleteTrail","UpdateTrail"),1,0)
| transaction actor maxspan=1h
| search is_assume=1 is_tamper=1
| stats values(eventName) as events values(sourceIPAddress) as src earliest(_time) as start latest(_time) as end by actor recipientAccountId
| eval risk_reason="AssumeRole followed by CloudTrail change within 1 hour"
```

**Tuning:** Exclude known breakglass workflows that assume role then update trail via automation.

## Enrichment Fields (Recommended)
- **actor** = userIdentity.arn
- **trail_name** = requestParameters.name
- **bucket** = requestParameters.bucketName (for PutBucketPolicy)
- **account** = recipientAccountId
