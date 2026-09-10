# Investigation Report: Logon-to-PowerShell Correlation

## Summary

On September 10, 2026, I correlated a successful local logon,
PowerShell process creation, and a PowerShell script-block event
on DESKTOP-C70T8EA.

The activity was generated through an authorized home-lab exercise
using the local account soclab.

## Objective

Determine whether the observed PowerShell process belonged to the
successful soclab logon and whether the marked script block was
recorded by that same process.

## Evidence Reviewed

| Log | Event ID | Record ID | Purpose |
|---|---|---|---|
| Security | 4624 | 8296 | Successful authentication |
| Security | 4688 | 8298 | PowerShell process creation |
| Microsoft-Windows-PowerShell/Operational | 4104 | 85 | Script-block content |

Supporting evidence included account details and console output
showing the soclab identity and PowerShell PID 8796.

## Timeline

Date: September 10, 2026.
Times are rounded to milliseconds.

| Local time (UTC+05:00) | UTC time | Activity |
|---|---|---|
| 13:44:56.440 | 08:44:56.440 | soclab logon succeeded |
| 13:44:56.497 | 08:44:56.497 | PowerShell process created |
| 13:59:20.333 | 08:59:20.333 | Marked script block recorded |

The process-creation event followed the successful logon by
approximately 57 milliseconds.

The script-block event followed process creation by approximately
14 minutes 24 seconds. The PowerShell window remained open while
the lab instructions were followed.

## 1. Authentication Analysis

Event 4624, record 8296, recorded:

- Subject account: Healisu
- Subject Logon ID: 0x44A11
- New Logon account: soclab
- New Logon ID: 0x27BC798
- Logon Type: 2
- Elevated Token: No
- Source address: ::1
- Logon process: seclogo

The New Logon fields identify the successfully authenticated account
and its new session. The Subject fields describe the requesting
account context.

The event is consistent with the authorized local runas exercise.
Localhost alone would not establish that an activity was benign.

## 2. Process-Creation Analysis

Event 4688, record 8298, recorded:

- Creator Subject SID: S-1-5-18, SYSTEM
- Creator Subject Logon ID: 0x3E7
- Target Subject account: soclab
- Target Subject Logon ID: 0x27BC798
- New Process ID: 0x225c
- New Process Name:
  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- Creator Process ID: 0x1194
- Creator Process Name: C:\Windows\System32\runas.exe
- Process Command Line: powershell.exe
- Token Elevation Type: %%1936
- Mandatory Label: Medium Mandatory Level

The Target Subject account and Logon ID match the successful
soclab session in event 4624.

The SYSTEM creator context does not mean PowerShell ran as SYSTEM.
The Target Subject and console whoami output identify soclab.

The Target Subject SID was NULL SID in this record, so it was not
used for a SID match. The target account, domain, session ID, host,
and timing support the link.

The default token type does not by itself establish administrator
privileges. Medium integrity and the non-elevated logon are
consistent with this standard-user exercise.

## 3. Script-Block Analysis

Event 4104, record 85, recorded:

- User: soclab
- Execution ProcessID: 8796
- ScriptBlock ID: 7d5af204-21bc-4d05-829d-6167501393e5
- MessageNumber: 1
- MessageTotal: 1
- Path: empty

Script-block text:

    Write-Output "DAY7-SOCLAB-CHECK: PID=$PID"

The code matches the deliberately entered lab marker.

The 4104 user SID matches the soclab SID in the 4624 event.
The empty Path is consistent with an interactive command.

## Correlation Findings

### Successful logon to PowerShell

4624 New Logon ID:

    0x27BC798

4688 Target Subject Logon ID:

    0x27BC798

### PowerShell to script block

4688 New Process ID:

    0x225c

4104 Execution ProcessID:

    8796

These are the same numeric PID in hexadecimal and decimal.

The same host, account context, and compatible timestamps support
the relationships. The supplied 4104 does not contain a Logon ID
field, so no direct session-ID match to that event was claimed.

## Disposition

Classification: Authorized home-lab activity.

The evidence supports the expected sequence: soclab authenticated,
PowerShell started in that session, and the same process recorded
the marked code.

No malicious activity or automated SIEM alert was generated.
No containment action was required for the known test activity.

## Limitations

- These selected records do not show everything done in the session.
- Script-block logging records code, not console output or proof of
  successful completion of every operation.
- PIDs can be reused; host and process-lifetime context matter.
- Record IDs from different logs cannot establish event order.
- The 4104 task label does not independently establish remote access.
- This was not a brute-force simulation or full incident investigation.

## L1 Application

For unexplained activity in a company environment, an L1 analyst
would validate the underlying logs, establish these connections,
review the recorded code and surrounding telemetry, verify
authorization, and escalate according to the response playbook.

## Screenshot Evidence

- [Test account](screenshots/01-day7-test-account.png)
- [soclab shell and PID](screenshots/02-day7-soclab-powershell.png)
- [Successful logon](screenshots/03-day7-soclab-successful-logon.png)
- [PowerShell process](screenshots/04-day7-soclab-process-4688.png)
- [Script-block text](screenshots/05-day7-soclab-scriptblock-4104.png)
- [Script-block PID](screenshots/06-day7-scriptblock-pid.png)
