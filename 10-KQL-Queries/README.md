# KQL Query Practice

## Objective

Practice writing and explaining Kusto Query Language (KQL) queries
using Windows Security logs in Microsoft Sentinel.

## Status

In progress.

## Topics Practiced

- Filtering by time range and event ID.
- Selecting columns with `project`.
- Counting and grouping records with `summarize`.
- Creating outcome labels with `extend` and `iff`.
- Sorting results.
- Grouping events into fixed time windows with `bin`.
- Filtering grouped counts using thresholds.

## Data Sources

- Windows Security events collected during Project 9.
- Temporary synthetic data created with `datatable` for logic testing.

## Limitations

These are learning exercises. Matching a failed-login threshold
does not prove malicious activity. Fixed time windows can split
related events across boundaries.
