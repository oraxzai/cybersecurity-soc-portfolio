# KQL Query Notes

## Objective

Practise Kusto Query Language (KQL) for Windows authentication
investigations in Microsoft Sentinel and Azure Log Analytics.

Exercises use both collected Windows Security events and synthetic
datasets. Synthetic results validate query logic; they do not represent
actual activity on the lab computer.

## Lab Environment

- Workspace: `law-soc-lab`
- Log table: `SecurityEvent`
- Windows computer: `DESKTOP-C70T8EA`
- Collection: Azure Monitor Agent on an Azure Arc-connected machine
- Query interface: Log Analytics
- Status: In progress

## 1. Windows Authentication Events

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |

The following logon types were observed:

| Logon type | Meaning |
|---|---|
| 2 | Interactive logon |
| 5 | Service logon |

A successful service logon does not necessarily represent a person
signing in.

## 2. Basic Filtering and Selecting Columns

```kusto
SecurityEvent
| where TimeGenerated > ago(2d)
| where EventID in (4624, 4625)
| project TimeGenerated, Computer, Account, EventID, LogonType
| order by TimeGenerated desc
```

- `where` filters rows.
- `ago(2d)` selects a relative time boundary two days before execution.
- `in` matches any listed value.
- `project` selects the output columns.
- `order by ... desc` places the latest timestamps first.
- `order by ... asc` places the earliest timestamps first.

Results from relative time ranges change as time passes.

## 3. Counting Events by Account and Outcome

```kusto
SecurityEvent
| where TimeGenerated > ago(2d)
| where EventID in (4624, 4625)
| extend Outcome = iff(EventID == 4624, "Success", "Failure")
| summarize TotalEvents = count() by Account, Outcome
| order by TotalEvents desc
```

`extend` adds a calculated column. Here, `iff` labels each selected event
as either Success or Failure.

`summarize` returns one row for each distinct Account and Outcome
combination.

The following counts were observed during the earlier lab query:

| Account | Outcome | TotalEvents |
|---|---|---|
| NT AUTHORITY\SYSTEM | Success | 30 |
| DESKTOP-C70T8EA\Healisu | Success | 2 |
| DESKTOP-C70T8EA\Healisu | Failure | 1 |

These were counts from that query's time range, not permanent totals.

To display counts from smallest to largest, use:

```kusto
| order by TotalEvents asc
```

Sorting by `Account` sorts account names rather than event counts.

## 4. Checking Apparently Duplicate Events

Two successful logon events appeared at almost the same time.

| Event ID | EventRecordId | TargetLogonId |
|---|---|---|
| 4624 | 27835 | 0x226b347 |
| 4624 | 27836 | 0x226b372 |

The different event record IDs and logon IDs supported treating them as
distinct recorded events rather than assuming duplicate ingestion.

Both events showed:

- Logon type: `2`
- Logon process: `User32`
- Authentication package: `Negotiate`
- Process: `C:\Windows\System32\svchost.exe`

These fields alone did not establish why Windows created both logon
sessions. Two events also do not necessarily mean two separate manual
sign-in attempts.

## 5. Counting Failures Within Fixed Time Bins

```kusto
SecurityEvent
| where TimeGenerated > ago(2d)
| where EventID == 4625
| summarize FailedLogins = count()
    by Computer, Account, bin(TimeGenerated, 10m)
| where FailedLogins >= 5
```

This query:

1. Selects failed logons.
2. Groups them by computer, account, and fixed 10-minute time bin.
3. Counts the events in each group.
4. Returns groups containing at least five failures.

The output name must be consistent:

```kusto
FailedLogins = count()
```

must be referenced as:

```kusto
| where FailedLogins >= 5
```

`FailedLogin` and `FailedLogins` are different column names.

### Grouping Matters

Failures on different computers remain separate even when the account
name is the same.

For example:

- PC-A / LabUser: 3 failures
- PC-B / LabUser: 3 failures

Neither group reaches five failures. The query does not combine them
into a count of six.

### Time-Bin Boundaries

A 10-minute bin beginning at 10:10 includes:

- 10:10:00
- Times after 10:10 and before 10:20

An event at exactly 10:20 belongs to the next bin.

A fixed-bin query does not evaluate every possible rolling 10-minute
interval. Failures split across a boundary can fall below the threshold
in both bins.

## 6. Adding First Seen, Last Seen, and Failure Span

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
| FailedLogins | Number of failures in the group |
| FirstSeen | Earliest failure timestamp |
| LastSeen | Latest failure timestamp |
| FailureSpan | Time between the first and last failure |
| TimeGenerated | Start of the fixed time bin after aggregation |

`min(TimeGenerated)` returns the earliest timestamp.

`max(TimeGenerated)` returns the latest timestamp.

`FailureSpan` describes the observed events' span. It is not necessarily
equal to the full 10-minute bin duration.

### Synthetic Validation

The synthetic dataset produced this qualifying result:

| Computer | Account | Bin start UTC | Failures | FirstSeen UTC | LastSeen UTC | FailureSpan |
|---|---|---|---|---|---|---|
| PC-C | LabUser | 2026-09-20 10:10 | 5 | 2026-09-20 10:11 | 2026-09-20 10:15 | 00:04:00 |

PC-A and PC-B each had three failures and did not meet the threshold.

### Stored-Log Result

The threshold query returned no matching rows during testing against
the stored Windows events.

This means no group met all the query conditions within the selected
time range. It does not mean there were no Windows events or that the
query failed.

Earlier inspection found one failed logon in the examined data.

## 7. Failed Logon Followed by a Successful Logon

### Objective

Match a computer/account pair's last failure with a later success,
then calculate the elapsed time.

### Complete Synthetic Practice Query

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

### How the Query Works

- `let` names a dataset or query expression for reuse.
- `datatable` creates synthetic rows for testing.
- `Failures` keeps the latest failure for each computer/account pair.
- `Successes` selects successful logons and names their timestamp
  `SuccessTime`.
- `join kind=inner` retains matching Computer and Account values.
- `SuccessTime > LastFailure` requires the success to occur afterward.
- `TimeToSuccess` calculates the elapsed time.
- `TimeToSuccess <= 10m` keeps gaps of up to and including 10 minutes.

OtherUser is excluded because it has no matching failure, even though
it has a successful logon on PC-A.

### Verified Initial Result

| Computer | Account | LastFailure UTC | SuccessTime UTC | TimeToSuccess |
|---|---|---|---|---|
| PC-A | LabUser | 2026-09-21 10:03 | 2026-09-21 10:05 | 00:02:00 |

The gap is calculated from the last failure at 10:03, not the first
failure at 10:01.

### Boundary Tests

Only LabUser's success timestamp was changed for these tests.

| Last failure UTC | Success UTC | Gap | Result |
|---|---|---|---|
| 10:03 | 10:05 | 2 minutes | Included |
| 10:03 | 10:15 | 12 minutes | Excluded |
| 10:03 | 10:13 | 10 minutes | Included |

The exactly-10-minute case passes because `<=` includes equality.

### Limitations of This Practice Query

- The data is synthetic and does not create actual Windows logins.
- The query selects only the latest failure for each computer/account
  pair across the input dataset.
- It can therefore miss earlier failure-success sequences when a newer
  failure exists.
- Multiple qualifying successes can produce multiple output rows.
- It does not require a minimum number of failures.
- It matches computer and account, but does not require matching source
  addresses or logon types.
- A time-based association does not prove that the same person caused
  both events.
- A success after failures does not establish compromise or brute force.

This is a learning query, not a production-ready detection rule.

## 8. Investigation Approach

For an authentication alert, examine:

1. Account and destination computer.
2. Failure reason, status, and substatus.
3. Source address and logon type.
4. Number and timing of failures.
5. Whether a later success occurred for the same account and computer.
6. Activity after the success, when supporting logs are available.
7. Whether the activity matches authorized testing or expected usage.

Separate observed facts from assumptions. Document missing evidence
and avoid classifying an attack from a single indicator.

## 9. KQL Concepts Practised

| Concept | Purpose |
|---|---|
| where | Filter rows |
| project | Select or rename columns |
| extend | Add calculated columns |
| iff | Choose between values based on a condition |
| summarize | Aggregate rows into groups |
| count() | Count events |
| min() | Find the earliest timestamp |
| max() | Find the latest timestamp |
| bin() | Group timestamps into fixed intervals |
| order by | Sort results |
| datatable | Build synthetic test data |
| let | Name reusable expressions |
| join kind=inner | Match rows between datasets |
| Timestamp subtraction | Calculate elapsed time |

## 10. Current Progress and Next Step

Completed exercises:

- Filtered and inspected Windows authentication events.
- Counted successes and failures by account.
- Checked identifiers on apparently duplicate successful logons.
- Tested failure thresholds by computer, account, and fixed time bin.
- Calculated first seen, last seen, and failure span.
- Matched synthetic failures with later successes.
- Tested below-limit, exact-boundary, and above-limit time gaps.

Next step:

Apply failure-to-success correlation to the stored Windows Security
events and compare the result with the previously inspected timeline.

The join-based query has been validated with synthetic data so far;
its use against stored Windows events remains to be completed.
