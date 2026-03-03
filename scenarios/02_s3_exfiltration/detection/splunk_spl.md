# Splunk Detections — Scenario 02 (S3 Data Exfiltration)

## Vendor-neutral detection logic

- **Inputs:** S3 Data Events for `ListObjects` / `ListObjectsV2` and `GetObject`, plus optional management events for `ListBuckets` and KMS `Decrypt` activity associated with S3 objects.
- **Detection 1 – GetObject burst:** For each principal and bucket, count `GetObject` events in fixed or sliding windows (for example, 10–15 minutes) and flag bursts above an environment-specific threshold, especially for sensitive buckets.
- **Detection 2 – First-time access to crown jewels:** Maintain a baseline of which principals have previously accessed each “crown-jewel” bucket. Alert when a principal reads or lists objects in such a bucket for the first time in a defined lookback period.
- **Detection 3 – Enumeration → bulk reads:** For each principal and bucket, detect sequences where object listing (`ListObjects*`) is followed within a short window (for example, 30 minutes) by a large number of `GetObject` calls.
- **Detection 4 – KMS Decrypt spike:** When S3 objects are KMS-encrypted, monitor `kms:Decrypt` volumes per principal and time window; flag spikes that correlate with S3 read bursts.
- **Context:** Tune thresholds per bucket sensitivity and allowlist known bulk-read workloads (backups, ETL) to reduce expected noise.

Assumption: CloudTrail logs (including S3 Data Events) are in Splunk with fields parsed. Adjust index/sourcetype as needed.

## Detection 1 — GetObject burst by principal and bucket
**Idea:** Alert when a principal performs an unusually high number of GetObject requests to a bucket in a short window.

```spl
index=cloudtrail sourcetype="aws:cloudtrail" eventName="GetObject"
| eval actor=coalesce('userIdentity.arn','userIdentity.userName')
| eval bucket=requestParameters.bucketName
| bin _time span=15m
| stats count as getobject_count values(bucket) as buckets values(sourceIPAddress) as src values(userAgent) as ua by actor _time recipientAccountId
| where getobject_count >= 100
| eval risk_reason="GetObject burst (threshold)"
```

**Tuning:** Set threshold (e.g., 100) per environment; exclude known ETL/backup principals via lookup.

## Detection 2 — First-time access to crown-jewel bucket
**Idea:** Alert when a principal accesses a sensitive bucket for the first time (no prior GetObject/ListObjects in baseline window).

```spl
index=cloudtrail sourcetype="aws:cloudtrail" (eventName="GetObject" OR eventName="ListObjects" OR eventName="ListObjectsV2")
| eval actor=coalesce('userIdentity.arn','userIdentity.userName')
| eval bucket=requestParameters.bucketName
| search [| inputlookup crown_jewel_buckets | fields bucket ]
| stats earliest(_time) as first_seen latest(_time) as last_seen count by actor bucket recipientAccountId
| where first_seen >= relative_time(now(), "-1d@d")
| eval risk_reason="First-time access to crown-jewel bucket"
```

**Tuning:** Maintain lookup `crown_jewel_buckets` with bucket names; adjust baseline window (e.g., 7d) as needed.

## Detection 3 — ListObjects followed by GetObject burst (correlation)
**Idea:** Discovery then bulk read in short window suggests enumeration and exfil.

```spl
index=cloudtrail sourcetype="aws:cloudtrail" (eventName="ListObjects" OR eventName="ListObjectsV2" OR eventName="GetObject")
| eval actor=coalesce('userIdentity.arn','userIdentity.userName')
| eval bucket=requestParameters.bucketName
| eval is_list=if(eventName IN ("ListObjects","ListObjectsV2"),1,0)
| eval is_get=if(eventName="GetObject",1,0)
| transaction actor bucket maxspan=30m
| search is_list=1 is_get=1
| stats sum(is_get) as get_count values(bucket) as bucket values(sourceIPAddress) as src earliest(_time) as start latest(_time) as end by actor recipientAccountId
| where get_count >= 50
| eval risk_reason="ListObjects then GetObject burst within 30m"
```

**Tuning:** Lower get_count for more sensitive buckets; exclude known automation.

## Detection 4 — KMS Decrypt spike (for KMS-encrypted S3 access)
**Idea:** High volume of Decrypt by a principal may indicate bulk read of encrypted S3 objects.

```spl
index=cloudtrail sourcetype="aws:cloudtrail" eventSource="kms.amazonaws.com" eventName="Decrypt"
| eval actor=coalesce('userIdentity.arn','userIdentity.userName')
| bin _time span=15m
| stats count as decrypt_count values(sourceIPAddress) as src by actor _time recipientAccountId
| where decrypt_count >= 200
| eval risk_reason="KMS Decrypt spike (possible S3 bulk read)"
```

**Tuning:** Threshold and window depend on normal KMS usage; correlate with GetObject when both are logged.

## Enrichment Fields (Recommended)
- **actor** = userIdentity.arn
- **bucket** = requestParameters.bucketName
- **key** = requestParameters.key (for object-level context)
- **src** = sourceIPAddress
- **account** = recipientAccountId
