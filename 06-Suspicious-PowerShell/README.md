# Suspicious PowerShell Investigation

## Overview

Investigate a harmless PowerShell command launched with
-EncodedCommand. Decode its contents and correlate process creation,
script-block logging, and terminal output.

## Lab Environment

- Windows 10 VM in VMware Fusion.
- Computer: DESKTOP-C70T8EA.
- Account: Healisu.
- Windows PowerShell: 5.1.19041.1682.
- Investigation date: September 14, 2026.
- Local timezone: UTC+05:00.

## Work Performed

- Verified process creation and script-block logging settings.
- Launched a Base64-encoded lab command.
- Located the recorded startup command in Event 4688.
- Located the readable script text in Event 4104.
- Correlated the events using host, time, account, and process ID.
- Decoded the command without executing the decoded text.

## Key Findings

| Evidence | Finding |
|---|---|
| 4688, record 20934 | PowerShell started with -EncodedCommand |
| New Process ID | 0x5b8, equivalent to decimal 1464 |
| 4104, record 269 | Matching script-block text recorded by process 1464 |
| Manual decoding | Matched the text recorded in 4104 |
| Terminal output | Displayed the lab marker and PID=1464 |
| Privilege context | Elevated token and High integrity |

The decoded command printed a lab marker and its process ID.
No malicious behavior was established by the reviewed evidence.

## Investigation Report

[Read the full investigation report](investigation-report.md)

## Original Evidence

Download the event files and open them in Windows Event Viewer:

- [PowerShell process creation — 4688](logs/01-encoded-powershell-4688.evtx)
- [Readable script-block event — 4104](logs/02-decoded-scriptblock-4104.evtx)
- [Screenshots](screenshots/)

## Skills Demonstrated

- Inspecting encoded PowerShell command lines.
- Decoding Base64 text without executing it.
- Correlating hexadecimal and decimal process IDs.
- Interpreting account, parent-process, and elevation context.
- Distinguishing recorded instructions from observed output.
- Assessing suspicious techniques without assuming malicious intent.

## Scope

This was an authorized exercise using a known harmless command.
No SIEM alert or automated detection rule was created.

Encoding is not encryption. The presence of -EncodedCommand alone
does not prove malware.

## Related Projects

- [Windows Event Log Investigation](../02-Windows-Event-Logs/)
- [Wireshark Network Investigations](../05-Wireshark-Investigations/)
