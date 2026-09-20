# KQL Practice Notes

## Repeated Failed-Logon Search

Query: [repeated-failed-logons.kql](queries/repeated-failed-logons.kql)

### Investigation Question

Which computer-and-account combinations have at least five failed-logon
records in a fixed 10-minute window during the last two days?

### Query

```kusto
// Find at least 5 failed-logon records per computer, account,
// and fixed 10-minute window during the last two days.
// Matches require investigation; they do not prove an attack.
// Fixed windows can split related failures across boundaries.
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

### How It Works

| Expression | Purpose |
|---|---|
| `SecurityEvent` | Read Windows Security records |
| `where TimeGenerated > ago(2d)` | Keep records from the last two days |
| `where EventID == 4625` | Keep failed-logon records |
| `count()` | Count the records in each group |
| `by Computer, Account, bin(TimeGenerated, 10m)` | Create separate groups for each computer, account, and fixed 10-minute window |
| `where FailedLogins >= 5` | Keep groups containing at least five records |

### Real-Data Observation

During the initial exercise, the account-and-time-window version of
the query returned no matching groups. Earlier queries found one
failed-logon record from the authorized Windows lab test.

The query was subsequently refined to include Computer in the grouping.

No results means no group met the threshold. It does not mean
there were no failed logons.

## Why Grouping Matters

The fields after `by` determine which records are counted together.

| Grouping | One Result Row Represents |
|---|---|
| `by Account` | One account |
| `by Account, bin(TimeGenerated, 10m)` | One account in one time window |
| `by Computer, Account, bin(TimeGenerated, 10m)` | One account on one computer in one time window |

For example, three failures for LabUser on PC-A and three on PC-B
could be combined into six when grouping only by account and time.

Adding Computer keeps those groups separate. Each has three failures,
so neither reaches a threshold of five.

## Synthetic Test

Query: [test-repeated-failed-logons.kql](queries/test-repeated-failed-logons.kql)

### Purpose

Test whether the query keeps computers separate and includes a group
that reaches the threshold exactly.

### Input

All records use Event ID 4625 and fall within the same fixed window:
September 20, 2026, from 10:10 UTC up to, but not including, 10:20 UTC.

| Computer | Account | Failed-Logon Records |
|---|---|---:|
| PC-A | LabUser | 3 |
| PC-B | LabUser | 3 |
| PC-C | LabUser | 5 |

### Expected Result

| Computer | Account | Window Start (UTC) | FailedLogins |
|---|---|---|---:|
| PC-C | LabUser | 2026-09-20 10:10:00 | 5 |

PC-A and PC-B should be excluded because each has fewer than five
failures. Their counts must not be combined.

### Actual Result

The query returned exactly one row: PC-C, LabUser,
2026-09-20 10:10:00 UTC, FailedLogins = 5.

Test passed: the group at the threshold was included, and the
below-threshold groups on separate computers were excluded.
### Synthetic Data Handling

`datatable` supplies temporary records for the query. It does not
insert those records into the workspace's stored security logs.

The synthetic test intentionally omits the relative two-day filter
so its fixed timestamps remain usable when the test is run later.
It tests event filtering, grouping, and the count threshold.

## Fixed Time Windows

`bin(TimeGenerated, 10m)` groups timestamps into fixed intervals.

For example:

- 10:10:00 up to, but not including, 10:20:00.
- 10:20:00 up to, but not including, 10:30:00.

An event at 10:16 belongs to the window labelled 10:10.
The original stored event timestamp is not changed.

### Boundary Limitation

Closely spaced failures can fall on opposite sides of a window boundary.

For example, three failures just before 10:20 and two just after 10:20
form separate groups of three and two. Neither reaches five, even
though all five failures might occur within a short period.

Fixed windows are not the same as checking every possible rolling
10-minute interval.

## Timing Enhancement and Validation

The query now includes:

- FirstSeen: earliest event in each group.
- LastSeen: latest event in each group.
- FailureSpan: LastSeen minus FirstSeen.

The synthetic test returned PC-C / LabUser with five failures,
FirstSeen 10:11 UTC, LastSeen 10:15 UTC, and FailureSpan 00:04:00.

The updated real-data query returned no matching groups during
validation. No group met the threshold of five failures within
a fixed 10-minute window.

## Lessons Learned

- `where` filters rows.
- `project` selects columns.
- `extend` adds calculated columns to query results.
- `iff` selects a value based on a condition.
- `summarize` groups records and calculates results.
- `count()` counts records within each group.
- Adding grouping fields can create more result rows.
- `where` after `summarize` filters calculated groups.
- `==` compares values; `=` names a calculated column.
- `asc` sorts ascending; `desc` sorts descending.
- `bin` groups timestamps into fixed intervals.
- One result row can represent multiple source events.
- No results after a threshold filter does not mean no events occurred.

## Investigation Context

The original Windows lab test produced:

- One failed interactive logon for Healisu.
- Two distinct successful-logon records approximately nine seconds later.
- Different event record IDs and target logon IDs for the two successes.

The records were consistent with the known incorrect-password test
followed by a successful sign-in. The available fields did not establish
why Windows created two successful logon sessions.

Matching timestamps alone are not sufficient to identify duplicate events.

## Limitations

- Repeated failures do not prove an attack.
- Five failures is an illustrative lab threshold, not a validated
  production threshold.
- Fixed windows can split related failures across boundaries.
- Counts represent event records, not necessarily distinct human actions.
- Grouping by computer keeps host activity separate, but this query
  does not detect attempts distributed across multiple computers.
- The query does not distinguish source IP addresses within each group.
- Missing or delayed logs can affect the results.
- The two-day time filter moves with the query execution time.
- These saved queries do not create or enable an automatic analytics rule.
- Synthetic tests validate selected logic; they do not establish
  production detection coverage.
