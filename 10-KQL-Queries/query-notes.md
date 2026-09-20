# KQL Practice Notes

## Repeated Failed-Logon Search

Query: [repeated-failed-logons.kql](queries/repeated-failed-logons.kql)

### Question

Which accounts have at least five failed-logon records in a fixed
10-minute window during the last two days?

### How It Works

| Expression | Purpose |
|---|---|
| `SecurityEvent` | Read Windows Security records |
| `where TimeGenerated > ago(2d)` | Keep records from the last two days |
| `where EventID == 4625` | Keep failed logons |
| `count() by Account, bin(TimeGenerated, 10m)` | Count records for each account and fixed 10-minute window |
| `where FailedLogins >= 5` | Keep groups containing at least five records |

### Observed Result

The real-data query returned no matching groups during this exercise.
The earlier investigation found one failed-logon record.

No results means no group met the threshold, not that no failures occurred.

## Synthetic Test

Query: [test-repeated-failed-logons.kql](queries/test-repeated-failed-logons.kql)

The test supplies five failures for LabUser and one for OtherUser
within the same 10-minute window.

Expected result: one row for LabUser, window start 10:10 UTC,
with FailedLogins equal to 5.

Synthetic records are temporary query input and are not stored logs.

## Lessons Learned

- `where` filters rows.
- `project` selects columns.
- `summarize` groups records and calculates results.
- Grouping by account and time window can produce several rows
  for the same account.
- `where` after `summarize` filters calculated groups.
- `==` compares values; `=` names a calculated column.
- `asc` sorts ascending; `desc` sorts descending.

## Limitations

- Repeated failures do not prove an attack.
- Fixed windows can split related failures across boundaries.
- Counts represent event records, not necessarily distinct human actions.
- Grouping only by Account and time can combine activity across computers.
- This is a saved search, not an enabled analytics rule.
