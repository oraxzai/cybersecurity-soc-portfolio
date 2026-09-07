# Windows Authentication Event Log Investigation

## Objective

Investigate Windows Security Event Logs to understand authentication activity and practice the workflow used by a SOC analyst when analyzing login events.

## Environment

* Operating System: Windows
* Virtualization: VMware
* Log Analysis Tool: Windows Event Viewer
* Log Source: Windows Security Event Log

## Events Investigated

| Event ID | Logon Type | Description                  |
| -------- | ---------: | ---------------------------- |
| 4624     |          2 | Successful interactive logon |
| 4625     |          2 | Failed interactive logon     |
| 4624     |          5 | Successful service logon     |

## Investigation

### Event 4625 — Failed Logon

The event showed:

* Account: `Healisu`
* Logon Type: `2`
* Failure reason: Bad password
* Source IP: `127.0.0.1`
* Process: `svchost.exe`
* Status: `0xC000006D`
* Substatus: `0xC000006A`

The event represents a failed local interactive authentication attempt.

A single failed authentication event is not enough evidence to classify the activity as a brute-force attack.

### Event 4624 — Successful Interactive Logon

The event showed:

* Account: `Healisu`
* Logon Type: `2`
* Source IP: `127.0.0.1`
* Elevated Token: Yes
* Process: `svchost.exe`

This represents a successful local interactive logon.

The activity was not automatically classified as malicious because additional context and correlation would be required.

### Event 4624 — Service Logon

The event showed:

* Account: `SYSTEM`
* Logon Type: `5`
* Process: `services.exe`
* Authentication Package: `Negotiate`

Type 5 represents a service logon. The SYSTEM account, `services.exe`, and absence of a remote source are consistent with normal Windows service activity.

## Timeline

| Time        | Event       | Interpretation                     |
| ----------- | ----------- | ---------------------------------- |
| 12:04:39 AM | 4624 Type 2 | Successful local interactive logon |
| 12:14:00 AM | 4625 Type 2 | Failed local interactive logon     |
| 12:31:26 AM | 4624 Type 5 | SYSTEM service logon               |

## Assessment

No confirmed malicious activity was identified from these three events alone.

The failed authentication event indicates an incorrect password, but there was not enough evidence to classify it as a brute-force attack.

The service logon was consistent with normal Windows activity.

This investigation demonstrates the importance of correlating events and avoiding conclusions based on a single log entry.

## Key SOC Lessons

* Event ID 4624 = successful logon
* Event ID 4625 = failed logon
* Logon Type 2 = interactive logon
* Logon Type 5 = service logon
* `127.0.0.1` = localhost
* `0xC000006A` = bad password
* A suspicious event is not automatically a malicious event
* SOC analysts must correlate events, timestamps, accounts, processes, and source information

## Skills Demonstrated

* Windows Event Viewer
* Windows Security Logs
* Authentication investigation
* Event correlation
* Timeline analysis
* Basic SOC alert investigation
* False-positive assessment
* Security documentation

## Disclaimer

This investigation was performed in an isolated Windows virtual machine for educational and authorized cybersecurity training purposes.
