# Microsoft Sentinel Investigation Report

## Summary

On September 16, 2026, I configured Azure Activity log collection in
Microsoft Sentinel and tested a scheduled analytics rule using
authorized resource-group activity.

The rule generated one alert in Incident 1. Investigation matched
the alert to the original successful creation of
`rg-soc-detection-test`.

I resolved the incident as expected security testing, disabled the
rule, and exported its configuration.

## Objective

Demonstrate the workflow from log collection to incident closure:

- Verify Azure Activity log ingestion.
- Correlate related administrative events.
- Identify the caller responsible for a configuration change.
- Create and validate a scheduled analytics rule.
- Investigate and classify the resulting incident.
- Preserve evidence and document limitations.

## Lab Environment

| Component | Configuration |
|---|---|
| Cloud platform | Microsoft Azure |
| SIEM | Microsoft Sentinel |
| Investigation portal | Microsoft Defender |
| Log Analytics workspace | law-soc-lab |
| Workspace resource group | rg-soc-lab |
| Region | East US |
| Log table | AzureActivity |
| Test resource group | rg-soc-detection-test |
| Workspace daily ingestion cap | 0.1 GB |

All test actions were performed in my own authorized lab subscription.

The daily ingestion cap was a cost-control measure, not a guaranteed
spending limit.

## 1. Configure Azure Activity Collection

I installed the Azure Activity solution and assigned this policy:

`Configure Azure Activity logs to stream to specified Log Analytics workspace`

The assignment targeted the lab subscription and used a system-assigned
managed identity to configure forwarding to `law-soc-lab`.

### Setup issue

The initial remediation-task creation failed with an error stating
that `Microsoft.PolicyInsights` was not registered.

When checked afterward, the provider showed as registered.
The available evidence does not establish why the registration
error occurred.

I verified that the policy assignment already existed instead of
creating a duplicate. The assignment subsequently reported one
compliant subscription.

Successful diagnostic-setting events and log-query results confirmed
that forwarding was working despite the earlier remediation-task error.

### Verify ingestion

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| order by TimeGenerated desc
| take 20
```

The query returned deployment, policy, and diagnostic-setting events
in `law-soc-lab`.

**Finding:** Log ingestion was verified through actual records,
rather than relying only on policy compliance or connector status.

## 2. Investigate a Diagnostic-Setting Write

A recorded administrative event showed a successful write to the
subscription-level diagnostic setting named `subscriptiontola`.

| Field | Observed value |
|---|---|
| TimeGenerated | 2026-09-16 09:25:01.233 UTC |
| OperationNameValue | MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE |
| ActivityStatusValue | Success |
| ActivitySubstatusValue | OK |
| CategoryValue | Administrative |
| Diagnostic-setting name | subscriptiontola |
| CorrelationId | 42f9be7e-8461-4864-b54f-0377e5207ed1 |

Resource ID structure, with the subscription identifier redacted:

```text
/subscriptions/<subscription-id>/providers/microsoft.insights/diagnosticsettings/subscriptiontola
```

### Identify the caller

The event's Caller value was:

```text
09e693ce-60f7-4809-9cf8-e0486e6bb437
```

I opened the policy assignment's Managed Identity tab and compared
its Principal ID with this value.

They matched exactly.

**Finding:** The recorded caller was the policy assignment's managed
identity. This was consistent with the lab's log-forwarding setup.

### Correlate related records

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where CorrelationId == "42f9be7e-8461-4864-b54f-0377e5207ed1"
| project TimeGenerated, OperationNameValue,
          ActivityStatusValue, Caller, ResourceId
| order by TimeGenerated asc
```

The query returned eight records sharing the same CorrelationId.

### Selected timeline

All times are UTC on September 16, 2026.

| Time | Operation | Status |
|---|---|---|
| 09:24:52.444 | Deployment write | Start |
| 09:24:58.561 | Diagnostic-setting write | Start |
| 09:25:01.233 | Diagnostic-setting write | Success |
| 09:25:01.436 | Deployment write | Success |
| 09:28:59.134 | DeployIfNotExists policy operation | Success |

The diagnostic-setting write's recorded start-to-success interval
was **2.672 seconds**.

The shared CorrelationId linked related operations. It did not mean
every record represented the same individual operation.

## 3. Generate Controlled Resource-Group Activity

I created an empty resource group:

```text
rg-soc-detection-test
```

I then searched for its write events:

```kusto
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue =~ "Microsoft.Resources/subscriptions/resourceGroups/write"
| where ResourceGroup =~ "rg-soc-detection-test"
| project TimeGenerated, ActivityStatusValue,
          Caller, ResourceGroup, CorrelationId
| order by TimeGenerated asc
```

### Results

| TimeGenerated (UTC) | ActivityStatusValue |
|---|---|
| 2026-09-16 09:48:13.838 | Start |
| 2026-09-16 09:48:15.166 | Success |

The Caller field showed the account used for the authorized lab.

The operation name identifies a resource-group write. The known
creation action provided the context for interpreting this particular
write as resource-group creation.

## 4. Build the Scheduled Analytics Rule

### General settings

| Setting | Value |
|---|---|
| Name | SOC-LAB - Test Resource Group Write |
| Severity | Informational |
| Initial status | Enabled |
| MITRE ATT&CK mapping | None assigned |

Description:

> Detects successful write operations on rg-soc-detection-test.
> Created to validate Sentinel alert and incident generation using
> authorized lab activity.

### Rule query

```kusto
AzureActivity
| where OperationNameValue =~ "Microsoft.Resources/subscriptions/resourceGroups/write"
| where ResourceGroup =~ "rg-soc-detection-test"
| where ActivityStatusValue =~ "Success"
| project TimeGenerated, Caller, CallerIpAddress,
          ResourceGroup, ResourceId, CorrelationId, OperationNameValue
```

The query selects successful resource-group writes affecting the
specific lab resource group.

It does not distinguish legitimate activity from malicious activity.

### Scheduling and alert settings

| Setting | Value |
|---|---|
| Run frequency | Every 5 minutes |
| Lookback | 1 hour |
| Start running | Automatically |
| Alert threshold | More than 0 query results |
| Event grouping | Group all events into a single alert |
| Suppression | Stop querying for 1 hour after an alert |
| Incident creation | Enabled |
| Rule-level grouping of related alerts | Disabled |
| Entity mapping | Not configured |
| Automated response | Not configured |

The suppression setting reduced repeated alerts from overlapping
lookback windows. It also paused detection of additional matching
events during the suppression period.

No attack technique was assigned because this exercise demonstrated
an authorized administrative action.

## 5. Perform an Additional Test Update

After creating the rule, I used Azure Cloud Shell to update the test
resource group:

```bash
az group update \
  --subscription "Azure subscription 1" \
  --name rg-soc-detection-test \
  --set tags.SentinelLab=RuleValidation
```

The output showed:

```json
{
  "name": "rg-soc-detection-test",
  "properties": {
    "provisioningState": "Succeeded"
  },
  "tags": {
    "SentinelLab": "RuleValidation"
  }
}
```

This excerpt confirms that the tag update succeeded.

However, the inspected alert contained the earlier resource-group
creation event. Detection of this later tag update was not established.

## 6. Investigate the Generated Incident

The initial incident-list filter included High, Medium, and Low
severity but excluded Informational.

After removing that filter, the lab incident became visible.

| Field | Observed value |
|---|---|
| Incident ID | 1 |
| Incident name | SOC-LAB - Test Resource Group Write |
| Severity | Informational |
| Initial incident status | Active |
| Alert count | 1 |
| Related query-result count | 1 |
| Activity time displayed | September 16, 2026, 14:48:15 |
| Corresponding activity time in UTC | September 16, 2026, 09:48:15 |
| Incident creation time displayed | September 16, 2026, 15:05:59 |

The portal's displayed activity time matched the original creation
event after accounting for the UTC+05:00 display offset.

### Triggering event

I opened the alert's Related events section and inspected its query
result.

| Field | Finding |
|---|---|
| ResourceGroup | RG-SOC-DETECTION-TEST |
| OperationNameValue | MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/WRITE |
| Caller | Authorized lab account |
| CorrelationId | 8ebb6dc4-b286-4f3b-b58b-366610ea51cb |
| Event time | Matched the original successful creation |

The rule's success filter and the matching event details linked the
alert to the original resource-group creation.

**Finding:** The scheduled rule generated an alert from an existing
event within its lookback window.

The difference between event time and incident creation time is not
a general detection-latency measurement: the rule was configured
after the original activity.

## 7. Classify and Resolve the Incident

The action was deliberately performed as part of the lab, and the
rule correctly matched its intended condition.

I selected:

```text
Informational, expected activity → Security testing
```

The saved incident header showed:

| Field | Final observed value |
|---|---|
| Status | Resolved |
| Classification | Benign Positive |

This documented the activity as an expected detection from authorized
testing.

## 8. Disable and Export the Rule

After validation, I disabled the analytics rule and exported its
configuration.

Exported filename:

```text
sentinel-lab-resource-group-write.json
```

The rule was retained for future reuse.

Disabling an analytics rule stops its scheduled detection runs.
It does not stop Azure Activity log forwarding.

## Evidence

- [Screenshots](screenshots/)
- [Exported analytics rule](rules/sentinel-lab-resource-group-write.json)

### Key screenshots

| Filename | Evidence |
|---|---|
| 01-workspace-daily-cap.png | Workspace daily ingestion cap |
| 02-sentinel-workspace-overview.png | Sentinel workspace setup |
| 03-sentinel-defender-workspace-connected.png | Defender workspace connection |
| 04-azure-activity-solution-installed.png | Azure Activity solution installation |
| 05-azure-activity-policy-assigned.png | Existing policy assignment |
| 06-azure-activity-policy-compliant.png | Policy compliance result |
| 07-azure-activity-ingestion-verified.png | Ingested AzureActivity records |
| 08-azure-activity-correlated-timeline.png | Related configuration events |
| 09-policy-managed-identity-caller-match.png | Caller attribution |
| 10-test-resource-group-created.png | Test resource group |
| 11-test-resource-group-activity.png | Original write start and success |
| 12-sentinel-lab-rule-enabled.png | Enabled analytics rule |
| 13-test-resource-group-update.png | Additional tag update |
| 14-sentinel-lab-incident.png | Generated incident |
| 15-alert-triggering-event.png | Event included in the alert |
| 16-lab-incident-resolved.png | Incident closure |
| 17-lab-rule-disabled.png | Final rule state |

Personal details should be redacted in public evidence copies while
originals are retained privately.

## Findings

1. Azure Activity records reached the intended Log Analytics workspace.
2. The diagnostic-setting write was attributed to the policy's managed
   identity by matching Caller and Principal ID.
3. CorrelationId connected related configuration events.
4. The scheduled rule detected the original successful test
   resource-group creation.
5. The incident was investigated and resolved as expected security
   testing.
6. The later tag update succeeded, but its detection was not verified.
7. The analytics rule was disabled and exported after testing.

## Limitations

- This was a controlled lab, not a real attack investigation.
- A resource-group write alone does not establish malicious intent.
- An account or identity match identifies the recorded caller; it
  does not independently prove authorization.
- Azure Activity was the verified data source. Local Windows Security
  logs were not ingested during this exercise.
- One successful test does not establish complete detection coverage
  or production readiness.
- The one-hour suppression period pauses detection of new matching
  activity as well as repeated matches.
- No entity mapping or automated response was configured.
- No separate alert for the later tag update was verified.
- Relative-time queries require an appropriate date range when rerun
  after the original lab.
- Screenshots and an exported rule do not replace original log records.
- A workspace daily ingestion cap is not a guaranteed spending limit.

## Retained Configuration

The following were retained:

- Microsoft Sentinel and the `law-soc-lab` workspace.
- Azure Activity forwarding and its policy assignment.
- The test resource group.
- The disabled analytics rule.

## Skills Demonstrated

- Configuring cloud log collection.
- Troubleshooting policy deployment.
- Verifying ingestion with KQL.
- Correlating administrative events.
- Attributing activity to a managed identity.
- Creating and testing a scheduled analytics rule.
- Investigating an alert's underlying event.
- Classifying and resolving authorized test activity.
- Exporting rule configuration and documenting evidence limitations.
