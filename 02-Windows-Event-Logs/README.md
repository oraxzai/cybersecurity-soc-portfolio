# Windows Event Log Investigation

## Objective

Investigate Windows authentication, process creation, and PowerShell
activity using Event Viewer. Correlate evidence to build timelines
and explain findings and limitations.

## Lab Environment

- Windows 10 VM running in VMware Fusion.
- Hostname: DESKTOP-C70T8EA.
- Log sources: Windows Security and
  Microsoft-Windows-PowerShell/Operational.
- All exercises use authorized home-lab activity.

## Investigation Exercises

| Exercise | Focus |
|---|---|
| [Day 3: Authentication Logs](Day-03-Authentication-Logs/) | Successful and failed logons, account details, and logon types |
| [Day 5: Process Creation](Day-05-Process-Creation/) | Process names, command lines, and parent-child relationships |
| [Day 6: PowerShell Investigation](Day-06-PowerShell-Investigation/) | Connecting process creation with PowerShell script-block text |
| [Day 7: Logon and Process Correlation](Day-07-Logon-Process-Correlation/) | Connecting a successful login to a process and its recorded code |

Each exercise folder contains its own documentation and evidence.

## Events Investigated

| Event ID | Log | Meaning |
|---|---|---|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4688 | Security | Process creation |
| 4104 | PowerShell Operational | Script-block text |

## Correlation Approach

- Match the host and relevant time range.
- Identify the account and logon session.
- Match appropriate Logon ID fields between authentication and process events.
- Match process identifiers between process creation and PowerShell events.
- Convert hexadecimal and decimal process IDs when necessary.
- Consider process lifetime because process IDs can be reused.

## Evidence Limitations

- Failed logons alone do not prove an attack.
- A successful logon does not establish that activity was authorized.
- PowerShell script-block text does not establish command output or success.
- Event record IDs belong to their respective logs and cannot establish
  chronological order across different logs.
- These exercises demonstrate controlled lab investigations, not
  production SOC experience.

## Planned Extensions

- Event 4672: special privileges assigned to a new logon.
- Event 7045 in the System log: service installation.

These extensions have not yet been completed.

## Related Investigation

[Controlled Failed Logons Followed by Success](../03-Brute-Force-Investigation/)
