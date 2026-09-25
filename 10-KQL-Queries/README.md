# KQL Queries and Windows Authentication Investigation

## Objective

Use Kusto Query Language (KQL) to investigate Windows authentication
events in Microsoft Sentinel and Azure Log Analytics.

This project covers filtering, aggregation, time-window detection, and
correlation of failed and successful logons.

## Environment

- Workspace: `law-soc-lab`
- Table: `SecurityEvent`
- Computer: `DESKTOP-C70T8EA`
- Data collection: Azure Monitor Agent through Azure Arc
- Query platform: Microsoft Sentinel / Log Analytics

## Queries and Notes

- [Repeated failed-logon search](queries/repeated-failed-logons.kql)
- [Synthetic detection test](queries/test-repeated-failed-logons.kql)
- [Query explanations and findings](query-notes.md)

## Techniques Practised

- Filtering Event IDs `4624` and `4625`
- Counting events by account and outcome
- Grouping failures by computer, account, and time bin
- Applying thresholds to repeated failures
- Calculating first seen, last seen, and failure span
- Joining failed logons with later successful logons
- Calculating time to successful authentication
- Validating query results with synthetic data
- Investigating status, substatus, source address, logon type, and process

## Verified Result

A failed logon was followed by two successful logons for:

- Computer: `DESKTOP-C70T8EA`
- Account: `DESKTOP-C70T8EA\Healisu`
- Failed event: `4625`
- Successful event records: `27835` and `27836`
- Time to success: approximately 9 seconds
- Logon type: `2` (interactive)
- Source address: `127.0.0.1`
- Process: `C:\Windows\System32\svchost.exe`
- Authentication: `User32` / `Negotiate`
- Failure status: `0xc000006d`
- Failure substatus: `0xc000006a`

The result showed a local failed authentication followed shortly by
successful authentication. It did not independently prove brute force,
compromise, or malicious activity.

## Limitations

- The real-event query used a seven-day lookback because the previous
  two days contained no matching records.
- Fixed time bins are not rolling windows.
- The query selects the latest failure for each computer/account pair.
- Multiple successful events can produce multiple result rows.
- A successful login after a failure is not proof of compromise.
- `svchost.exe` is a hosting process and does not identify the exact
  originating service by itself.
- Some testing used synthetic data to validate query logic.

## Progress

Project completed.

The project demonstrates basic KQL investigation and authentication
event correlation. The next project will focus on complete SOC alert
triage, incident classification, response recommendations, and case
documentation.
