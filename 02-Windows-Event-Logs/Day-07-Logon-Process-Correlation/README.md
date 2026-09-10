# Day 7 — Windows Logon, Process, and PowerShell Correlation

## Objective

Connect a successful Windows logon to a PowerShell process and
then to the code recorded by that process.

This was an authorized home-lab exercise using the local account
soclab. It was not a simulated attack or a full incident investigation.

## Environment

- Windows VM running in VMware on a MacBook Air
- Windows PowerShell 5.1
- Windows Event Viewer
- Logon auditing, process-creation auditing, command-line recording,
  and PowerShell Script Block Logging enabled

## Lab Procedure

1. Checked that the local soclab account was active.
2. Used runas to start PowerShell as soclab:

       runas /user:%COMPUTERNAME%\soclab powershell.exe

3. Confirmed the new shell's identity with whoami.
4. Used $PID to identify PowerShell process 8796.
5. Recorded the date, time, and timezone.
6. Entered a harmless marked command:

       Write-Output "DAY7-SOCLAB-CHECK: PID=$PID"

7. Examined the related 4624, 4688, and 4104 events.

## Verified Timeline

Date: September 10, 2026.
Local times use UTC+05:00 and are rounded to milliseconds.

| Local time | Event ID | Log | Record ID | Activity |
|---|---|---|---|---|
| 13:44:56.440 | 4624 | Security | 8296 | soclab logged on |
| 13:44:56.497 | 4688 | Security | 8298 | PowerShell created for soclab |
| 13:59:20.333 | 4104 | PowerShell Operational | 85 | Marked script block recorded |

PowerShell started approximately 57 milliseconds after the successful
logon event. The marked script block was recorded approximately
14 minutes 24 seconds after process creation.

## Connection 1 — Logon to Process

The successful 4624 event recorded:

- New Logon account: soclab
- New Logon ID: 0x27BC798
- Logon Type: 2
- Elevated Token: No
- Source address: ::1

The PowerShell 4688 event recorded:

- Target Subject account: soclab
- Target Logon ID: 0x27BC798
- New Process ID: 0x225c
- New Process Name: powershell.exe
- Creator Process Name: runas.exe
- Creator Process ID: 0x1194

The matching session ID links the successful soclab logon to the
PowerShell process on the same host.

The 4688 Creator Subject was SYSTEM, while Target Subject identified
soclab. The creator context must not be mistaken for the account
under which the new PowerShell process ran.

## Connection 2 — Process to Script Block

The 4104 event recorded:

- User: soclab
- Execution ProcessID: 8796
- ScriptBlock ID: 7d5af204-21bc-4d05-829d-6167501393e5
- ScriptBlockText:

       Write-Output "DAY7-SOCLAB-CHECK: PID=$PID"

The process IDs match:

    0x225c hexadecimal = 8796 decimal

The matching host, account context, timestamps, and open process
support this correlation. The 4104 user SID also matches the
soclab SID in the successful-logon event.

## Privilege Context

The PowerShell process recorded Token Elevation Type %%1936 and
Medium Mandatory Level.

Type 1/default token does not automatically mean administrator
privileges. These fields, the non-elevated logon, and the lab's
account context are consistent with standard-user activity.

## Assessment

The evidence matches the known authorized sequence:

- soclab authenticated successfully.
- PowerShell started in that logon session.
- The same PowerShell process recorded the marked command.

No malicious activity or SIEM alert was generated.

## Limitations

- Event 4104 records code, not console output or proof that every
  operation completed successfully.
- PIDs can be reused, so correlation requires host and time context.
- Record IDs from different logs cannot determine chronological order.
- These records do not describe all activity in the session.
- Authorization was known from the controlled lab; company activity
  would require independent validation.

## Screenshot Evidence

- [Test account](screenshots/01-day7-test-account.png)
- [soclab shell identity and PID](screenshots/02-day7-soclab-powershell.png)
- [Successful logon](screenshots/03-day7-soclab-successful-logon.png)
- [PowerShell process creation](screenshots/04-day7-soclab-process-4688.png)
- [Script-block content](screenshots/05-day7-soclab-scriptblock-4104.png)
- [Script-block process ID](screenshots/06-day7-scriptblock-pid.png)

## Main Lesson

Use the appropriate Logon ID fields to connect authentication with
process creation. Then use process IDs, host, time, and account
context to connect the process with PowerShell script-block content.
