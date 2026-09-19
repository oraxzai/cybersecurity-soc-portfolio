# Windows Failed Logon Investigation — Microsoft Sentinel

## Summary

An authorized incorrect-password test on a Windows lab VM generated Event ID 4625. Azure Monitor Agent collected the event into the `law-soc-lab` workspace. A scheduled Microsoft Sentinel analytics rule detected it and created one alert in Incident #2, **SOC-LAB - Windows Failed Logon Test**.

The alert's related event matched the deliberately generated test. The incident was resolved after review. This was a guided lab exercise, not a confirmed malicious attack or a brute-force simulation.

## Environment and collection

| Component | Configuration |
|---|---|
| Endpoint | Windows 10 Pro lab VM, `DESKTOP-C70T8EA` |
| Account tested | Local account `Healisu` |
| Resource group | `rg-soc-lab` |
| Log Analytics workspace | `law-soc-lab` |
| Machine connection | Azure Arc |
| Collection agent | Azure Monitor Agent, extension version 1.45.0.0 |
| Connector | Windows Security Events via AMA |
| Data collection rule | `dcr-windows-security-lab` |
| Destination table | `SecurityEvent` |

The custom collection filter selected successful and failed logons:

```text
Security!*[System[(EventID=4624 or EventID=4625)]]
```

Arc connectivity alone did not establish successful log ingestion. Collection was verified by an Azure Monitor Agent heartbeat and then actual `SecurityEvent` records in the workspace.

## Investigation steps

1. Verified that the Azure Monitor Agent extension completed provisioning and `MonAgentCore` was running.
2. Confirmed that the collection rule was associated with the VM and targeted `law-soc-lab`.
3. Located the actual agent data directory using its process command line: `C:\Resources\Directory\AMADataStore.DESKTOP-C70T8EA`. Initial checks used a path without the computer-name suffix; those path errors did not prove that configuration download had failed.
4. Confirmed configuration files and a configuration chunk existed. A subsequent workspace query returned the agent's heartbeat.
5. Observed successful logons (4624) for `NT AUTHORITY\SYSTEM`, logon type 5. These represented service logons and did not by themselves indicate an attack.
6. Attempted a controlled test with `runas`; it returned `Unable to acquire user password`. This output did not confirm a failed authentication event.
7. Generated the actual test by locking the lab VM, entering an incorrect password once, and then unlocking with the correct password.
8. Queried Event ID 4625, inspected its failure codes, and configured a scheduled lab detection rule.
9. Opened Incident #2 and checked the alert's related event against the previously observed test record.

## Confirmed evidence

| Field | Observed value / interpretation |
|---|---|
| Event time (UTC) | `2026-09-19T10:16:59.0755149Z` |
| Event time (UTC+05:00) | September 19, 2026, 3:16:59 PM |
| Computer | `DESKTOP-C70T8EA` |
| Account | `DESKTOP-C70T8EA\Healisu` |
| Event ID | `4625` — failed logon, selected by the query |
| Logon type | `2` — interactive |
| Source IP | `127.0.0.1` — loopback, referring to the local machine |
| Failure reason | `%%2313` — unknown username or bad password |
| Status | `0xC000006D` — general logon failure |
| Substatus | `0xC000006A` — incorrect password |
| Incident ID | `2` |
| Alert count shown | `1` |
| Incident creation time shown (UTC+05:00) | September 19, 2026, 3:35:17 PM |

The account, timestamp, local source address, and incorrect-password substatus were consistent with the authorized test. The incident's related-events view contained one matching record. The interval between the test and incident creation included manual rule setup, so it is not a measurement of normal detection latency.

## Queries used

### Check agent communication

```kusto
Heartbeat
| where TimeGenerated > ago(30m)
| summarize LastSeen=max(TimeGenerated) by Computer, Category
```

### Inspect failed logons

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| where TargetUserName =~ "Healisu"
| project TimeGenerated, Computer, Account, LogonType, IpAddress,
          FailureReason, Status, SubStatus
| order by TimeGenerated desc
```

### Scheduled rule query

```kusto
SecurityEvent
| where EventID == 4625
| where Computer =~ "DESKTOP-C70T8EA"
| project TimeGenerated, Computer, Account, TargetUserName,
          LogonType, IpAddress, FailureReason, Status, SubStatus
```

The scheduled rule's lookback setting supplied its time scope. It matched any failed logon on this VM, not only the tested account.

## Detection configuration

| Setting | Value |
|---|---|
| Rule name | `SOC-LAB - Windows Failed Logon Test` |
| Severity | Informational |
| Frequency | Every 5 minutes |
| Lookback | 1 hour |
| Threshold | More than 0 query results |
| Event grouping | All returned events grouped into one alert |
| Suppression | Stop running for 1 hour after an alert |
| Incident creation | Enabled |
| Rule-level alert grouping | Disabled |
| Incident correlation | Tenant default |
| Entity mapping | Not configured |
| MITRE ATT&CK mapping | Not configured |
| Automated response | Not configured |

The empty incident entity graph was consistent with the absence of entity mapping. The rule was deliberately sensitive for collection-and-alert validation. One failed login does not establish brute force. Suppression pauses the entire rule, including detection of new failures during that period; it is not selective event deduplication.

## Disposition and cleanup

The finding was authorized security testing: the rule correctly detected the deliberately generated failed logon. The closure workflow used **Informational, expected activity → Security testing**. The incident was confirmed **Resolved** by the lab operator.

After the test, the operator confirmed disabling the analytics rule and uploading its JSON export as [`rules/windows-failed-logon-test.json`](rules/windows-failed-logon-test.json). The export was not independently inspected for this report. Disabling the analytics rule stops its scheduled detection queries; it does not stop Windows log collection.

## Skills practiced and limits

This guided exercise practiced Windows Security event interpretation, Azure Arc and agent troubleshooting, collection-rule configuration, basic KQL filtering, scheduled detection configuration, alert evidence review, and incident closure.

It did not demonstrate independent mastery, production-ready brute-force detection, Linux log analysis, Splunk or Wazuh operation, threat-intelligence enrichment, or containment and recovery. No malicious compromise was established. Future improvements include entity mapping and a separately tested rule for repeated failures, with thresholds and exceptions based on observed activity.

## Supporting evidence

Screenshots reviewed during the exercise showed the heartbeat result, successful Windows logons, the failed-logon record, rule settings, Incident #2, and its related event. Final resolution, rule disabling, and export upload were confirmed by the operator. This report accompanies the separate Azure Activity investigation in Project 9; it does not mark the dedicated Project 10 KQL work as complete.
