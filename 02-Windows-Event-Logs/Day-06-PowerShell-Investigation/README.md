# Day 6 — PowerShell Log Correlation

## Objective

Connect a PowerShell process-creation event with its script-block
event to understand the difference between starting a program
and processing code inside it.

This was a harmless, authorized home-lab exercise.

## Environment

- Windows VM running in VMware on a MacBook Air
- Windows PowerShell 5.1, Desktop edition
- Windows Event Viewer
- Process Creation auditing with command-line inclusion enabled
- PowerShell Script Block Logging enabled

## What I Did

I opened a normal, non-elevated PowerShell window and ran:

    $PID
    Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"
    Write-Output "DAY6-FINAL-CHECK: PID=$PID"

The process ID was 7120.

I then located the process-start event in the Security log and
the marked script block in the PowerShell Operational log.

## Verified Timeline

Date: September 9, 2026.
Local times use UTC+05:00 and are rounded to milliseconds.

| Local time | Event ID | Log | Record ID | Activity |
|---|---|---|---|---|
| 17:22:18.409 | 4688 | Security | 7233 | PowerShell started |
| 17:22:56.375 | 4104 | PowerShell Operational | 62 | Marked script block recorded |

The script block was recorded approximately 38 seconds after
PowerShell started.

## Process Creation — Event 4688

Security record 7233 showed:

- Host: DESKTOP-C70T8EA
- Creator account: Healisu
- Creator Logon ID: 0x44A7C
- New process: powershell.exe
- New Process ID: 0x1bd0
- Creator process: C:\Windows\explorer.exe
- Creator Process ID: 0x2280
- Token Elevation Type: %%1938
- Mandatory Label: Medium Mandatory Level

The startup command line contained the PowerShell executable path.
It did not contain the command entered later.

The limited token and medium integrity matched opening a normal
PowerShell window.

## Script-Block Content — Event 4104

PowerShell Operational record 62 contained:

    Write-Output "DAY6-FINAL-CHECK: PID=$PID"

Additional fields:

- Execution ProcessID: 7120
- User: Healisu
- Host: DESKTOP-C70T8EA
- ScriptBlock ID: 0097ba4a-7a32-4ddf-900d-9382e28226b9
- Message: 1 of 1
- Path: empty, consistent with the interactive command

The event records the code. Console output is separate evidence
of the result returned by that code.

## How the Events Were Connected

The process IDs match:

    0x1bd0 hexadecimal = 7120 decimal

I also checked the host, account, and timestamps. The PowerShell
window remained open during the final exercise.

The 4688 New Process ID identifies the newly created PowerShell
process. The 4104 Execution ProcessID identifies the process
that emitted the script-block event.

## Assessment

The records match the known, authorized lab activity.

Event 4688 established how PowerShell started. Event 4104 added
visibility into code processed afterward.

This exercise did not simulate malware or generate a SIEM alert.

## Limitations and Lessons

- A familiar executable or non-elevated token does not prove safety.
- Event 4104 records script-block code, not console output or
  proof that every operation completed successfully.
- PIDs can be reused, so host and time context matter.
- Record IDs belong to their individual logs. Record 62 cannot
  be ordered against Security record 7233 using its number alone.
- The 4104 task label "Execute a Remote Command" does not by itself
  establish remote access.
- Enabling logging cannot recover previously unrecorded commands.

## Screenshot Evidence

- [Script Block Logging policy](screenshots/01-powershell-scriptblock-policy.png)
- [Command and console output](screenshots/02-powershell-command-output.png)
- [PowerShell startup — 4688](screenshots/03-powershell-startup-4688.png)
- [Script-block text — 4104](screenshots/04-powershell-scriptblock-4104.png)
- [Script-block process ID](screenshots/05-powershell-scriptblock-pid.png)
