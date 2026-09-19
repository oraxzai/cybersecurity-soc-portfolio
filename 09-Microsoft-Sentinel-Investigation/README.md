# Microsoft Sentinel Investigation

## Objective

Collect Azure Activity and Windows Security logs, investigate authorized
lab activity, and validate scheduled Microsoft Sentinel analytics rules
from source events through alert generation and incident closure.

This project contains two guided investigations:

1. Azure resource-group write detection.
2. Windows failed-logon detection.

## Lab Environment

| Component | Configuration |
|---|---|
| Platform | Microsoft Azure and a local Windows lab VM |
| SIEM | Microsoft Sentinel, connected to the Microsoft Defender portal |
| Workspace | `law-soc-lab` |
| Workspace resource group | `rg-soc-lab` |
| Region | East US |
| Data sources | Azure Activity and Windows Security events |
| Event tables | `AzureActivity` and `SecurityEvent` |
| Agent verification table | `Heartbeat` |
| Azure test resource group | `rg-soc-detection-test` |
| Windows endpoint | Windows 10 Pro, `DESKTOP-C70T8EA` |
| Machine connection | Azure Arc |
| Windows collection agent | Azure Monitor Agent (AMA) |
| Windows connector | Windows Security Events via AMA |
| Data collection rule | `dcr-windows-security-lab` |

## Work Completed

### Shared Setup

- Configured a workspace daily ingestion cap of 0.1 GB.
- Connected the Sentinel workspace to the Defender portal.

### Investigation 1: Azure Activity

- Configured Azure Activity log forwarding through Azure Policy.
- Verified ingestion by querying the `AzureActivity` table.
- Correlated deployment and diagnostic-setting events.
- Matched an event's `Caller` to the policy's managed identity.
- Created and tested a resource-group write detection rule.
- Investigated Incident #1 and resolved it as expected security testing.
- Disabled and exported the rule after testing.

### Investigation 2: Windows Failed Logon

- Connected the Windows lab VM to Azure Arc and provisioned AMA.
- Configured collection of successful and failed logons:
  Event IDs 4624 and 4625.
- Checked the agent process, collection-rule association, destination,
  and downloaded configuration while troubleshooting missing results.
- Verified the agent heartbeat and Windows Security events in the workspace.
- Generated one controlled failed sign-in using an incorrect password.
- Used KQL to inspect the account, timestamp, logon type, source address,
  and failure codes.
- Created and tested a scheduled failed-logon detection rule.
- Verified that the alert's related event matched the authorized test.
- Investigated and resolved Incident #2.
- Disabled and exported the rule after testing.

## Windows Log Collection

The data collection rule used this custom filter:

```text
Security!*[System[(EventID=4624 or EventID=4625)]]
```

- **4624:** Successful logon.
- **4625:** Failed logon.

Azure Arc connectivity alone did not prove that Windows logs were arriving.
Collection was verified through an AMA heartbeat and actual records in
the `SecurityEvent` table.

## Detection Rules

| Setting | Azure Activity Rule | Windows Security Rule |
|---|---|---|
| Name | `SOC-LAB - Test Resource Group Write` | `SOC-LAB - Windows Failed Logon Test` |
| Matches | Successful writes to `rg-soc-detection-test` | Event ID 4625 on `DESKTOP-C70T8EA` |
| Severity | Informational | Informational |
| Run frequency | Every 5 minutes | Every 5 minutes |
| Lookback | 1 hour | 1 hour |
| Alert threshold | More than 0 results | More than 0 results |
| Event grouping | All matching events into one alert | All matching events into one alert |
| Suppression | 1 hour after an alert | 1 hour after an alert |
| Incident creation | Enabled | Enabled |
| Final rule state | Disabled | Disabled |

### Windows Failed-Logon Rule Query

```kusto
SecurityEvent
| where EventID == 4625
| where Computer =~ "DESKTOP-C70T8EA"
| project TimeGenerated, Computer, Account, TargetUserName,
          LogonType, IpAddress, FailureReason, Status, SubStatus
```

The rule's scheduling settings supplied the time scope.

This rule detects any failed logon on the specified VM. It does not
require repeated attempts and is not a brute-force detection rule.

## Verified Results

### Incident #1: Azure Resource-Group Write

The rule generated one alert in Incident #1.

The alert's related event matched the original successful creation of
the test resource group on September 16, 2026, at approximately
**09:48:15 UTC**.

A later resource-group tag update also succeeded, but it was not the
event shown in the inspected alert.

The incident was resolved using
**Informational, expected activity → Security testing**.
The incident header displayed **Benign Positive**.

### Incident #2: Windows Failed Logon

The rule generated one alert in Incident #2.

The alert's related event matched the deliberately generated
incorrect-password test.

| Evidence Field | Observed Value |
|---|---|
| Event time (UTC) | September 19, 2026, 10:16:59 |
| Event time (UTC+05:00) | September 19, 2026, 3:16:59 PM |
| Computer | `DESKTOP-C70T8EA` |
| Account | `DESKTOP-C70T8EA\Healisu` |
| Event ID | `4625` — failed logon |
| Logon type | `2` — interactive |
| Source address | `127.0.0.1` — loopback |
| Failure reason | `%%2313` — unknown username or bad password |
| Status | `0xC000006D` — general logon failure |
| Substatus | `0xC000006A` — incorrect password |

The account, timestamp, source address, and failure codes were consistent
with the authorized test.

The incident was confirmed **Resolved** after the security-testing
closure workflow.

## Reports and Evidence

- [Azure Activity investigation report](investigation-report.md)
- [Windows failed-logon investigation report](windows-failed-logon-investigation.md)
- [Lab screenshots](screenshots/)
- [Exported Azure Activity analytics rule](rules/sentinel-lab-resource-group-write.json)
- [Exported Windows failed-logon analytics rule](rules/windows-failed-logon-test.json)

## Skills Practiced

- Azure Activity and Windows Security log collection and validation.
- Basic KQL filtering, field selection, sorting, and aggregation.
- Interpretation of Windows logon events and authentication failure codes.
- Basic scheduled detection-rule configuration and testing.
- Alert triage and related-event verification.
- Incident classification and closure.
- Agent and configuration troubleshooting.
- Investigation documentation.

These were guided exercises. They demonstrate practice with the
documented tasks, not independent mastery or complete SOC coverage.

## Limitations

- Both investigations used authorized lab activity, not confirmed attacks.
- Resource-group writes and individual failed logons do not establish
  malicious intent.
- Windows Security collection was restricted to Event IDs 4624 and 4625.
- Detecting the test events does not establish complete detection coverage
  or production readiness.
- The one-hour suppression period pauses the entire rule, including
  detection of additional matching events during that period.
- Entity mapping was not configured for the Windows rule, so its incident
  had no mapped entities in the graph.
- No automated response, containment, or recovery was tested.
- This project did not demonstrate Linux log collection, Splunk, Wazuh,
  threat-intelligence enrichment, or MITRE ATT&CK mapping.
- A workspace daily ingestion cap is not a guaranteed spending limit
  and can interrupt collection when reached.
- Screenshots and exported rules do not replace original log records.

## Retained Configuration

Both analytics rules were disabled after testing and exported.

The Sentinel workspace, Azure Activity forwarding configuration,
Azure test resource group, Windows Arc connection, AMA installation,
and Windows data collection rule were retained.

Disabling an analytics rule stops its scheduled detection queries;
it does not disable log ingestion.

Windows collection can continue while the VM and agent are running
and connected. Shutting down the VM stops it from sending new logs
while offline; it does not stop Azure Activity forwarding.
