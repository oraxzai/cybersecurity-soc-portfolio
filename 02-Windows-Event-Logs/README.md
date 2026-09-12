# Windows Event Log Investigation

## Objective

Investigate Windows authentication, privilege assignment, process
creation, PowerShell activity, and service installation using Event Viewer.

Correlate related evidence to build timelines, while keeping unrelated
examples separate and explaining the limits of each finding.

## Lab Environment

- Windows 10 VM running in VMware Fusion.
- Hostname: DESKTOP-C70T8EA.
- Investigation tool: Windows Event Viewer.
- Log sources:
  - Windows Security.
  - Windows System.
  - Microsoft-Windows-PowerShell/Operational.
- Exercises use authorized home-lab activity and existing VM records.

## Investigation Exercises

| Exercise | Focus |
|---|---|
| [Day 3: Authentication Logs](Day-03-Authentication-Logs/) | Successful and failed logons, account details, and logon types |
| [Day 5: Process Creation](Day-05-Process-Creation/) | Process names, command lines, and parent-child relationships |
| [Day 6: PowerShell Investigation](Day-06-PowerShell-Investigation/) | Connecting process creation with PowerShell script-block text |
| [Day 7: Logon and Process Correlation](Day-07-Logon-Process-Correlation/) | Connecting a successful login to a process and its recorded code |
| [Privileged Logon and Service Installation](Privileged-Logon-and-Service-Installation/) | Correlating 4624 with 4672 and separately interpreting a historical 7045 service-installation event |

Each exercise folder contains its own documentation and evidence.

## Events Investigated

| Event ID | Log | Meaning |
|---|---|---|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4672 | Security | Sensitive privileges assigned to a new logon |
| 4688 | Security | Process creation |
| 4104 | PowerShell Operational | Script-block text |
| 7045 | System | Service installation |

## Correlation Approach

- Match the host and relevant time range.
- Identify the account and logon session.
- Match appropriate Logon ID fields between authentication and process events.
- Connect 4624 New Logon ID to 4672 Subject Logon ID.
- Match process identifiers between process creation and PowerShell events.
- Convert hexadecimal and decimal process IDs when necessary.
- Consider process lifetime because process IDs can be reused.
- Use timestamps as supporting evidence rather than proof of a relationship.
- Keep unrelated events separate when no supporting connection is established.

## Key Findings

### Authentication and Process Activity

Successful logon records identify the new session. Relevant Logon ID
fields can connect that session to subsequent process activity.

Process creation records identify the new process, its creator, and
the startup command line when command-line auditing is enabled.

### PowerShell Activity

PowerShell script-block records provide visibility into recorded code
that may not appear in the process startup command line.

Matching the PowerShell event's execution PID to the process creation
event's New Process ID, alongside host, time, and account context,
supports correlation.

### Privileged Logon

A controlled Healisu login produced matching 4624 and 4672 records
with Logon ID 0x72FB8B.

The records showed a successful login and sensitive privileges
assigned to that session. They did not establish privilege use.

### Service Installation

A historical 7045 event recorded installation of the KslD driver service.

The event identified its configured file path, driver type, and demand-start
setting. It did not establish that the driver started or that the
installation was malicious.

No connection was established between this September 10 installation
and the September 12 privileged-login exercise.

## Evidence Limitations

- Failed logons alone do not prove an attack.
- A successful logon does not establish that activity was authorized.
- Privilege assignment does not prove privilege use.
- PowerShell script-block text does not establish command output or success.
- Service installation does not prove service execution.
- Demand start is a configuration setting, not a running-state indicator.
- Event Record IDs belong to their respective logs and cannot establish
  chronological order across different logs.
- Logging coverage depends on the settings enabled at the time.
- These exercises demonstrate home-lab practice, not production SOC experience.
- This project used manual event review; no SIEM alert was generated.

## Skills Practised

- Finding and filtering relevant Windows events.
- Distinguishing requesting accounts from target accounts.
- Identifying logon sessions and process relationships.
- Reading privilege and service-installation records.
- Building evidence-based timelines.
- Separating observations, possible explanations, and conclusions.
- Documenting investigation scope and uncertainty.

## Related Investigation

[Controlled Failed Logons Followed by Success](../03-Brute-Force-Investigation/)
