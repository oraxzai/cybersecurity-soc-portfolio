# KQL Query Notes

## Objective

Practise Kusto Query Language (KQL) for Windows authentication
investigations in Microsoft Sentinel and Azure Log Analytics.

The exercises use collected Windows Security events and synthetic
datasets. Synthetic results validate query logic; they do not represent
actual activity on the lab computer.

## Lab Environment

- Workspace: `law-soc-lab`
- Log table: `SecurityEvent`
- Windows computer: `DESKTOP-C70T8EA`
- Collection: Azure Monitor Agent on an Azure Arc-connected machine
- Query interface: Log Analytics
- Status: Completed

## 1. Windows Authentication Events

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |

| Logon type | Meaning |
|---|---|
| 2 | Interactive logon |
| 5 | Service logon |

A successful service logon does not necessarily represent a person
signing in.

## 2. Basic Filtering

```kusto
SecurityEvent
| where TimeGenerated > ago(2d)
| where EventID in (4624, 4625)
| project TimeGenerated, Computer, Account, EventID, LogonType
| order by TimeGenerated desc
```

- `where` filters rows.
- `project` selects columns.
- `ago(2d)` selects the previous two days.
- `in` matches multiple values.
- `order by` sorts the results.

## 3. Count Events by Account and Outcome

```kusto
SecurityEvent
| where TimeGenerated > ago(2d)
| where EventID in (4624, 4625)
| extend Outcome = iff(EventID == 4624, "Success", "Failure")
| summarize TotalEvents = count() by Account, Outcome
| order by TotalEvents desc
```

Observed counts during the lab:

| Account | Outcome | Total events |
|---|---|---:|
| NT AUTHORITY\SYSTEM | Success | 30 |
| DESKTOP-C70T8EA\Healisu | Success | 2 |
| DESKTOP-C70T8EA\Healisu | Failure | 1 |

These are counts for the selected query period, not permanent totals.

## 4. Inspect Apparently Duplicate Events

Two successful events appeared almost simultaneously:

| Event ID | EventRecordId | TargetLogonId |
|---|---:|---|
| 4624 | 27835 | 0x226b347 |
| 4624 | 27836 | 0x226b372 |

Because the record IDs and logon IDs differ, they should be treated as
distinct Windows events. They are not automatically duplicate ingestion.

Both events showed:

- Logon type: `2`
- Logon process: `User32`
- Authentication package: `Negotiate`
- Process: `C:\Windows\System32\svchost.exe`

These fields do not by themselves explain why two sessions were created.

## 5. Count Failed Logons in Fixed Time Bins

```kusto
SecurityEvent
| where TimeGenerated > ago(2d)
| where EventID == 4625
| summarize FailedLogins = count()
    by Computer, Account, bin(TimeGenerated, 10m)
| where FailedLogins >= 5
```

This query groups failures by:

- Computer
- Account
- Fixed 10-minute time bin

The output name must remain consistent:

```kusto
FailedLogins = count()
```

must be referenced as:

```kusto
| where FailedLogins >= 5
```

A result may be empty if no computer/account group reached five failures
inside one fixed 10-minute bin.

Events from different computers are not combined.

## 6. Add First Seen, Last Seen, and Failure Span

```kusto
SecurityEvent
| where TimeGenerated > ago(2d)
| where EventID == 4625
| summarize
    FailedLogins = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer, Account, bin(TimeGenerated, 10m)
| where FailedLogins >= 5
| extend FailureSpan = LastSeen - FirstSeen
| order by FailedLogins desc
```

| Field | Meaning |
|---|---|
| `FailedLogins` | Number of failures in the group |
| `FirstSeen` | Earliest failure |
| `LastSeen` | Latest failure |
| `FailureSpan` | Difference between first and last failure |
| `bin(TimeGenerated, 10m)` | Start of the fixed time window |

`min(TimeGenerated)` returns the first event.

`max(TimeGenerated)` returns the last event.

### Synthetic Validation

A synthetic test produced:

| Computer | Account | Bin start | Failed logins | First seen | Last seen | Failure span |
|---|---|---|---:|---|---|---|
| PC-C | LabUser | 2026-09-20 10:10 UTC | 5 | 10:11 | 10:15 | 00:04:00 |

PC-A and PC-B each had three failures and therefore did not meet the
threshold of five.

## 7. Failure Followed by Successful Logon

The following query matches a failed logon with a later successful logon
for the same computer and account:

```kusto
(
    SecurityEvent
    | where TimeGenerated > ago(7d)
    | where EventID == 4625
    | summarize LastFailure = max(TimeGenerated)
        by Computer, Account
)
| join kind=inner
(
    SecurityEvent
    | where TimeGenerated > ago(7d)
    | where EventID == 4624
    | project Computer,
              Account,
              SuccessTime = TimeGenerated,
              SuccessEventRecordId = EventRecordId
)
on Computer, Account
| where SuccessTime > LastFailure
| extend TimeToSuccess = SuccessTime - LastFailure
| where TimeToSuccess <= 10m
| project Computer,
          Account,
          LastFailure,
          SuccessTime,
          TimeToSuccess,
          SuccessEventRecordId
| order by LastFailure desc
```

### Query Logic

- The first subquery selects failed events.
- `max(TimeGenerated)` identifies the last failure.
- The second subquery selects successful events.
- `join kind=inner` matches the same Computer and Account.
- `SuccessTime > LastFailure` confirms the success occurred afterward.
- `TimeToSuccess` calculates the elapsed time.
- `TimeToSuccess <= 10m` keeps successes within ten minutes.

## 8. Synthetic Failure-to-Success Test

```kusto
let Events = datatable(
    TimeGenerated:datetime,
    Computer:string,
    Account:string,
    EventID:int
)
[
    datetime(2026-09-21T10:01:00Z), "PC-A", "LabUser", 4625,
    datetime(2026-09-21T10:03:00Z), "PC-A", "LabUser", 4625,
    datetime(2026-09-21T10:05:00Z), "PC-A", "LabUser", 4624,
    datetime(2026-09-21T10:06:00Z), "PC-A", "OtherUser", 4624
];
let Failures = Events
| where EventID == 4625
| summarize LastFailure = max(TimeGenerated) by Computer, Account;
let Successes = Events
| where EventID == 4624
| project Computer, Account, SuccessTime = TimeGenerated;
Failures
| join kind=inner (Successes) on Computer, Account
| where SuccessTime > LastFailure
| extend TimeToSuccess = SuccessTime - LastFailure
| where TimeToSuccess <= 10m
| project Computer, Account, LastFailure, SuccessTime, TimeToSuccess
```

Expected result:

| Computer | Account | Last failure | Success time | Time to success |
|---|---|---|---|---|
| PC-A | LabUser | 10:03 | 10:05 | 00:02:00 |

OtherUser is excluded because it has no matching failed logon.

### Boundary Tests

| Last failure | Success | Gap | Result |
|---|---|---:|---|
| 10:03 | 10:05 | 2 minutes | Included |
| 10:03 | 10:13 | 10 minutes | Included |
| 10:03 | 10:15 | 12 minutes | Excluded |

The `<= 10m` condition includes exactly ten minutes.

## 9. Real Windows Event Validation

Because there were no matching records in the previous two days, the
real-event query used a seven-day lookback.

The query found:

| Field | Value |
|---|---|
| Computer | `DESKTOP-C70T8EA` |
| Account | `DESKTOP-C70T8EA\Healisu` |
| Failed event | `4625` |
| Successful events | `4624` |
| Success record IDs | `27835`, `27836` |
| Time to success | Approximately 9 seconds |
| Logon type | `2` |
| Source address | `127.0.0.1` |
| Logon process | `User32` |
| Authentication package | `Negotiate` |
| Process | `C:\Windows\System32\svchost.exe` |
| Status | `0xc000006d` |
| Substatus | `0xc000006a` |
| Failure reason | `%%2313` |

Interpretation:

- `127.0.0.1` is the local loopback address.
- The authentication was local rather than from a remote IP.
- `0xc000006d` is a general bad-credentials status.
- `0xc000006a` is consistent with an incorrect password.
- `LogonType 2` represents an interactive logon.
- The failed event was followed by two distinct successful events.
- The two successful events are distinct because their record IDs differ.

The sequence demonstrates a failed authentication followed shortly by
successful authentication. It does not, by itself, prove brute force,
compromise, or malicious activity.

## 10. Investigation Method

For an authentication alert, check:

1. Account and destination computer.
2. Event ID and event timestamp.
3. Failure reason, status, and substatus.
4. Source address.
5. Logon type.
6. Number and timing of failures.
7. Whether a later success occurred for the same account and computer.
8. Process and authentication package.
9. Activity after the successful logon.
10. Whether the activity was authorized lab testing.

Always separate observed facts from assumptions.

## 11. KQL Concepts Practised

| Concept | Purpose |
|---|---|
| `where` | Filter records |
| `project` | Select or rename fields |
| `extend` | Add calculated fields |
| `iff()` | Create conditional labels |
| `summarize` | Aggregate records |
| `count()` | Count events |
| `min()` | Find the earliest timestamp |
| `max()` | Find the latest timestamp |
| `bin()` | Group timestamps into fixed windows |
| `order by` | Sort results |
| `datatable` | Create synthetic test data |
| `let` | Define reusable query expressions |
| `join kind=inner` | Match related records |
| Timestamp subtraction | Calculate elapsed time |

## 12. Limitations

- A fixed 10-minute bin is not a rolling time window.
- Events split across bin boundaries may not meet the threshold.
- The failure-to-success query selects only the latest failure per
  computer/account pair.
- Multiple successful events may create multiple result rows.
- The query does not match source address or logon ID.
- A successful logon after failures does not prove compromise.
- `svchost.exe` is a hosting process and does not identify the exact
  originating service by itself.
- Synthetic records validate query logic but are not real activity.
- No result may mean the selected time range or threshold is too strict.

## 13. Project Status

Completed:

- Basic Windows authentication filtering.
- Success and failure counting.
- Event ID and logon type analysis.
- Time-binned failed-logon detection.
- First-seen, last-seen, and failure-span calculations.
- Synthetic failure-to-success correlation.
- Ten-minute boundary testing.
- Real Windows failure-to-success validation.
- Interpretation of account, source, reason, destination, and timing.

Project 10 KQL investigation is complete. The final remaining action is
to commit the updated notes, queries, and evidence to the repository.
