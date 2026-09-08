# Windows Authentication Investigation

## Overview

I investigated three failed Windows logon attempts followed by a
successful logon in my own Windows VM.

This was an authorized, manual exercise using a dedicated local account,
`soclab`. Its purpose was to practice investigating a pattern that could
raise suspicion of password guessing—not to demonstrate a confirmed attack.

## Environment and Tools

- Windows VM running in VMware on a MacBook Air
- Windows Event Viewer — Security log
- Command Prompt
- auditpol, net accounts, runas, and whoami

## Lab Procedure

1. Verified that logon auditing recorded success and failure.
2. Checked the local account lockout policy.
3. Created a dedicated local test account named soclab.
4. Used runas with an incorrect password three times.
5. Used the correct password to start Command Prompt as soclab.
6. Verified the shell identity using whoami.
7. Investigated the corresponding 4625 and 4624 events.

## Verified Timeline

Date: September 8, 2026.
Times below use the VM's displayed timezone, UTC+05:00.

| Time | Event ID | Record ID | Account | Outcome |
|---|---|---|---|---|
| 11:04:58.299 | 4625 | 3754 | soclab | Incorrect password |
| 11:05:16.599 | 4625 | 3756 | soclab | Incorrect password |
| 11:05:24.615 | 4625 | 3758 | soclab | Incorrect password |
| 11:05:41.604 | 4624 | 3761 | soclab | Successful logon |

The failures spanned approximately 26.3 seconds.
Success followed the final failure by approximately 17.0 seconds.

## Findings

- All four events targeted the same local account on the same host.
- All used Logon Type 2 and recorded the source address as ::1,
  the IPv6 loopback address.
- Each failure had status 0xC000006D and substatus 0xC000006A,
  indicating an incorrect password.
- The requesting account was Healisu, with Subject Logon ID 0x44A11.
- The successful logon created a new soclab session: 0x6B07DD.
- The successful event recorded Elevated Token: No.
- The caller process was C:\Windows\System32\svchost.exe,
  with logon process seclogo.

## Assessment and Limitations

The records match the known, authorized runas exercise.
No unauthorized compromise was established.

Without the lab context, failures followed by success would require
investigation: both legitimate mistakes and password guessing can produce
this pattern.

No SIEM detection rule or alert was generated in this exercise.
Post-logon process logs were not analyzed. The command screenshot confirms
the soclab shell identity but does not establish all subsequent activity.

## Screenshot Evidence

- [Logon audit policy](screenshots/01-logon-audit-policy.png)
- [Account lockout policy](screenshots/02-account-lockout-policy.png)
- [Controlled logon attempts](screenshots/03-controlled-logon-attempts.png)
- [Authentication timeline](screenshots/04-authentication-timeline.png)
- [Failed logon details](screenshots/05-failed-logon-details.png)
- [Successful logon details](screenshots/06-successful-logon-details.png)

## Lessons Learned

- Correlate accounts, hosts, timestamps, logon types, and processes.
- Distinguish the requesting account from the account being authenticated.
- Distinguish the original session ID from the newly created session ID.
- Normalize timezones when comparing event timestamps.
- Localhost does not automatically mean safe.
- Repeated failures followed by success do not alone prove compromise.
