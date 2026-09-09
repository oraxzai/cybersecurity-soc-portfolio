# Investigation Report: PowerShell Startup and Script-Block Correlation

## Summary

On September 9, 2026, I correlated a Windows Security process-creation
event with a PowerShell script-block event in my Windows VM.

The final exercise used PowerShell process 7120 and a harmless,
uniquely marked command. The evidence matched the authorized activity.

## Scope and Evidence

- Host: DESKTOP-C70T8EA
- Account: Healisu
- PowerShell: Windows PowerShell 5.1, Desktop edition
- Security event: 4688, Record ID 7233
- PowerShell Operational event: 4104, Record ID 62
- Supporting evidence: logging configuration and console screenshots

This report covers the final run using PID 7120.
Earlier practice attempts are excluded from this timeline.

## Controlled Procedure

1. Verified Script Block Logging was enabled.
2. Opened a fresh, non-elevated Windows PowerShell window.
3. Ran $PID and obtained 7120.
4. Recorded the date, time, and timezone.
5. Entered:

       Write-Output "DAY6-FINAL-CHECK: PID=$PID"

6. Located the corresponding 4688 and 4104 events.
7. Compared process IDs, host, account, and timestamps.

## Timeline

Date: September 9, 2026.
Times are rounded to milliseconds.

| Local time (UTC+05:00) | UTC time | Event | Record ID |
|---|---|---|---|
| 17:22:18.409 | 12:22:18.409 | PowerShell process created — 4688 | 7233 |
| 17:22:56.375 | 12:22:56.375 | Script block recorded — 4104 | 62 |

The interval was approximately 37.97 seconds, calculated from
the full XML timestamps.

## Analysis of Event 4688

Security record 7233 showed:

- Creator account: Healisu
- Creator Logon ID: 0x44A7C
- New Process ID: 0x1bd0
- New Process Name:
  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- Creator Process ID: 0x2280
- Creator Process Name: C:\Windows\explorer.exe
- Token Elevation Type: %%1938
- Mandatory Label: Medium Mandatory Level

The creator process is consistent with opening PowerShell through
the Windows desktop interface.

The token and integrity fields indicate a non-elevated process.
They do not independently establish whether its activity is safe.

The startup command line contained only the PowerShell executable
path. It did not include the instruction entered afterward.

## Analysis of Event 4104

PowerShell Operational record 62 contained:

    Write-Output "DAY6-FINAL-CHECK: PID=$PID"

Its XML recorded:

- Execution ProcessID: 7120
- ScriptBlock ID: 0097ba4a-7a32-4ddf-900d-9382e28226b9
- MessageNumber: 1
- MessageTotal: 1
- Path: empty
- Host: DESKTOP-C70T8EA
- User SID: matched the Healisu account in the 4688 event

The complete script-block text was present in one event.

The empty Path field is consistent with the interactive command.
The event's task-category label does not by itself prove remote
execution.

## Correlation

The numeric process identifiers match:

    0x1bd0 hexadecimal = 7120 decimal

The match is supported by:
- The same computer
- Matching account SID
- Process creation before the script-block event
- The PowerShell window remaining open during the exercise
- Script-block text matching the deliberately entered command

For this correlation, I used New Process ID from event 4688
and Execution ProcessID from event 4104.

The System/Execution ProcessID of 4 in the Security event describes
that event provider's execution context. It was not used as the
new PowerShell process ID.

The 4688 creator Logon ID provides session context. The supplied
4104 does not contain a matching Logon ID field, so I did not
claim a direct Logon ID match between these records.

## Assessment

Classification: Authorized home-lab activity.

The evidence supports linking the PowerShell startup with the
subsequent marked script block.

This demonstrates how process-creation logs and script-block logs
provide different, complementary information.

No malicious activity or SIEM alert was generated in this exercise.

## Limitations

- Event 4104 records code, not its console output.
- A script-block record does not prove every operation completed.
- PID matching alone is insufficient because PIDs can be reused.
- Record IDs from different logs cannot establish chronological order.
- No comprehensive file, network, or process-termination investigation
  was performed.
- Missing historical script blocks cannot be recovered simply by
  enabling logging afterward.

## L1 Application

For an unexplained PowerShell execution in a company environment:

1. Review the process-start event and its account/session context.
2. Identify the parent process and startup command line.
3. Locate related script-block records using PID, host, and time.
4. Review the code and available surrounding activity.
5. Verify authorization through approved channels.
6. Document evidence gaps and escalate according to the playbook.

## Supporting Screenshots

- [Logging policy](screenshots/01-powershell-scriptblock-policy.png)
- [Console commands and output](screenshots/02-powershell-command-output.png)
- [PowerShell creation event](screenshots/03-powershell-startup-4688.png)
- [Script-block code](screenshots/04-powershell-scriptblock-4104.png)
- [Script-block PID](screenshots/05-powershell-scriptblock-pid.png)
