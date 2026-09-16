# Microsoft Sentinel Investigation

## Objective

Configure Azure Activity log collection, investigate recorded changes,
and validate a scheduled Microsoft Sentinel analytics rule using
authorized lab activity.

## Lab Environment

| Component | Configuration |
|---|---|
| Platform | Microsoft Azure |
| SIEM | Microsoft Sentinel, connected to the Microsoft Defender portal |
| Workspace | law-soc-lab |
| Workspace resource group | rg-soc-lab |
| Region | East US |
| Data source | Azure Activity |
| Test resource group | rg-soc-detection-test |

## Work Completed

- Configured a workspace daily ingestion cap of 0.1 GB.
- Connected the Sentinel workspace to the Defender portal.
- Configured Azure Activity log forwarding through Azure Policy.
- Verified ingestion by querying the AzureActivity table.
- Correlated deployment and diagnostic-setting events.
- Matched an event's Caller to the policy's managed identity.
- Created and tested a scheduled analytics rule.
- Investigated Incident 1 and resolved it as expected security testing.
- Disabled and exported the rule after testing.

## Detection Rule

**Name:** SOC-LAB - Test Resource Group Write

The rule detects successful resource-group write operations affecting
`rg-soc-detection-test`.

| Setting | Value |
|---|---|
| Severity | Informational |
| Run frequency | Every 5 minutes |
| Lookback | 1 hour |
| Alert threshold | More than 0 results |
| Event grouping | All matching events into one alert |
| Suppression | 1 hour after an alert |
| Incident creation | Enabled |
| Final rule state | Disabled |

## Verified Result

The rule generated one alert in Incident 1.

The alert's related event matched the original successful creation of
the test resource group on September 16, 2026, at approximately
09:48:15 UTC.

A later resource-group tag update also succeeded, but it was not the
event shown in the inspected alert.

The incident was resolved using
**Informational, expected activity → Security testing**.
The incident header displayed **Benign Positive**.

## Evidence

- [Lab screenshots](screenshots/)
- [Exported analytics rule](rules/sentinel-lab-resource-group-write.json)

The detailed investigation report will be added separately.

## Limitations

- This was a controlled lab, not a real attack investigation.
- Resource-group writes alone do not establish malicious activity.
- The verified data source was Azure Activity; local Windows Security
  logs were not ingested in this exercise.
- Successful detection of one test event does not establish complete
  detection coverage.
- The one-hour suppression period pauses detection of additional
  matching events during that period.
- A workspace daily ingestion cap is not a guaranteed spending limit.
- Screenshots and the exported rule do not replace original log records.

## Retained Configuration

The analytics rule was disabled after testing. The Sentinel workspace,
Azure Activity forwarding configuration, and test resource group were
retained.
