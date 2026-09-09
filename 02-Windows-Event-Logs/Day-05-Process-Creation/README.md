# Day 5 — Windows Process Creation Investigation

## Objective

Investigate Windows Security Event ID 4688 and correlate a parent
process with its child using process IDs, timestamps, account context,
and command lines.

## Environment

- Windows VM running in VMware on a MacBook Air
- Windows Event Viewer — Security log
- Administrator Command Prompt
- Dedicated, authorized home-lab exercise

## Audit Configuration

I enabled successful Process Creation auditing and command-line
inclusion in process-creation events.

I verified:
- Process Creation auditing: Success
- ProcessCreationIncludeCmdLine_Enabled: 0x1

Command-line arguments are recorded as plain text, so passwords and
tokens should not be supplied in lab commands.

## Controlled Activity

From an Administrator Command Prompt, I ran:

    cmd.exe /c whoami

The original shell started another cmd.exe process, which then
started whoami.exe.

## Verified Evidence

Date: September 9, 2026.
Times below use UTC+05:00 and are rounded to milliseconds.

| Local time | Record ID | New process | New PID | Creator PID |
|---|---|---|---|---|
| 12:51:27.970 | 4971 | cmd.exe | 0x18a4 | 0xf58 |
| 12:51:27.997 | 4972 | whoami.exe | 0x1a94 | 0x18a4 |

Both records are Event ID 4688 on DESKTOP-C70T8EA.

## Correlation and Findings

The cmd.exe event's New Process ID, 0x18a4, matches the
whoami.exe event's Creator Process ID.

Additional matching context:
- Creator account: Healisu
- Creator Logon ID: 0x44A11
- Same host
- Process starts approximately 27 milliseconds apart
- Command lines: cmd.exe /c whoami and whoami

Both processes recorded:
- Token Elevation Type: %%1937 — elevated token
- Mandatory Label: High Mandatory Level

This matches the use of an Administrator Command Prompt.

The original shell, PID 0xf58, is identified as the creator in
record 4971. Its own process-creation event was not reviewed.

## Assessment

The two records support the expected parent-child relationship
from the authorized exercise.

The presence of cmd.exe or whoami.exe alone does not establish
malicious activity. In a company investigation, the analyst would
also examine authorization, process ancestry, account context,
and surrounding activity.

## Limitations

Event 4688 records process creation. These records do not contain
the command's output or establish successful completion.

PIDs can be reused after processes exit, so PID correlation must
also consider the host, timestamps, and process lifetime.

No SIEM alert was generated and no malicious activity was simulated.

## Screenshot Evidence

- [Process creation auditing](screenshots/01-process-creation-audit-policy.png)
- [Command-line auditing](screenshots/02-command-line-audit-policy.png)
- [cmd.exe creation](screenshots/03-cmd-process-creation.png)
- [whoami.exe creation](screenshots/04-whoami-process-creation.png)

## Lessons Learned

- Event ID identifies the event type.
- Event Record ID identifies an entry within a particular log.
- PID identifies a process instance.
- Logon ID identifies a logon session.
- The child's Creator Process ID links to its parent's PID.
- Processes in the same session can have different PIDs.
- Audit Success means process creation succeeded, not that the
  process was safe or its task completed.
