# Investigation Report: Failed Logons Followed by Success

## Summary

On September 8, 2026, I investigated three failed authentications
followed by a successful logon to the local account soclab on
DESKTOP-C70T8EA.

The activity was generated manually during an authorized Windows VM
exercise. The evidence supports the expected test sequence; it does
not establish an unauthorized compromise.

## Investigation Objective

Determine whether the observed failures and success were related,
identify the failure reason, and distinguish suspicious patterns
from confirmed malicious activity.
 
## Evidence Reviewed

- Command output showing three runas authentication errors
- A successful command shell with whoami identifying soclab
- Security log records 3754, 3756, 3758, and 3761
- Logon auditing and local account-policy screenshots

This investigation used Windows Event Viewer directly.
No SIEM alert or automated detection was generated.

## Timeline

Date: September 8, 2026.
Local timestamps below use UTC+05:00.

| Local time | UTC time | Event ID | Record ID | Result |
|---|---|---|---|---|
| 11:04:58.299 | 06:04:58.299 | 4625 | 3754 | Bad password |
| 11:05:16.599 | 06:05:16.599 | 4625 | 3756 | Bad password |
| 11:05:24.615 | 06:05:24.615 | 4625 | 3758 | Bad password |
| 11:05:41.604 | 06:05:41.604 | 4624 | 3761 | Successful logon |

The failures spanned approximately 26.3 seconds.
The success occurred approximately 17.0 seconds after the last failure.
The entire sequence spanned approximately 43.3 seconds.

## Correlation Analysis

All four records shared:

- Host: DESKTOP-C70T8EA
- Target account: soclab
- Subject account: Healisu
- Subject Logon ID: 0x44A11
- Logon Type: 2
- Source address: ::1
- Source port: 0
- Caller process: C:\Windows\System32\svchost.exe
- Caller process ID: 0x168c
- Logon process: seclogo

These matching fields, the short time interval, and the recorded
manual actions support linking the events to the same exercise.

## Failed Authentication Analysis

All three 4625 records contained:

- Status: 0xC000006D
- Substatus: 0xC000006A

The substatus identifies an incorrect password as the failure reason.

Healisu was the requesting account context.
soclab was the account whose authentication failed.

The source address ::1 identifies the local computer.
It does not establish that activity is benign by itself.

## Successful Authentication Analysis

Record 3761 was Event ID 4624 and identified:

- New Logon account: soclab
- New Logon ID: 0x6B07DD
- Logon Type: 2
- Elevated Token: No

The new session ID differs from the requesting session ID, 0x44A11.

For further investigation, 0x6B07DD could help correlate subsequent
events that contain the relevant logon-session field on the same host.

The command screenshot independently shows a shell running as soclab.

## Alternative Explanations

Without the known lab context, this pattern could reflect:

| Explanation | Evidence to seek |
|---|---|
| A legitimate user mistyped a password before succeeding | User confirmation and expected access |
| An attacker guessed a valid password | Unauthorized access and suspicious subsequent activity |
| An authorized administrator tested credentials | Approved task details and matching administrator activity |

Timing and event counts alone cannot distinguish these explanations.

## Disposition

Classification: Authorized lab activity.

The evidence matches three intentionally incorrect passwords followed
by the correct password supplied through runas.

No incident-response containment action was warranted for the known
test activity. This was not classified as a false-positive alert,
because no alert was generated.

## Limitations

- Only the supplied authentication records and command evidence
  were analyzed.
- Post-logon process, file-access, and network logs were not examined.
- A non-elevated logon does not establish that all subsequent
  activity was harmless.
- This manual local exercise does not demonstrate remote brute force,
  password spraying, or an automated detection capability.

## Evidence Location

Supporting screenshots are in the [screenshots folder](screenshots/).

## Lessons Learned

1. Build a timeline from actual timestamps, with the timezone labeled.
2. Avoid counting the same Event Record ID twice.
3. Distinguish the requesting account from the target account.
4. Correlate multiple fields rather than relying on timing alone.
5. Separate observed facts, possible explanations, and conclusions.
