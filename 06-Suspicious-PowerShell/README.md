# Suspicious PowerShell Investigation

## Objective

Investigate a PowerShell process launched with `-EncodedCommand`.
Recover the readable command and correlate process creation,
script-block logging, and terminal output.

The exercise demonstrates how to investigate a potentially suspicious
technique without assuming that its presence proves malicious activity.

## Lab Environment

| Component | Details |
|---|---|
| Host machine | MacBook Air |
| Virtualization | VMware Fusion |
| Investigation system | Windows 10 VM |
| Computer name | DESKTOP-C70T8EA |
| Account | Healisu |
| PowerShell version | 5.1.19041.1682 |
| Investigation date | September 14, 2026 |
| Local timezone | UTC+05:00 |

### Logging Settings Checked

- PowerShell Script Block Logging: enabled.
- Process Creation auditing: Success enabled.
- Include command line in process creation events: enabled.

## Scenario

An authorized lab command launched a new PowerShell process using
a Base64-encoded instruction.

The investigation answered:

1. What command was supplied to PowerShell?
2. Which process recorded the script-block text?
3. What did the command actually do?
4. Did the evidence establish malicious activity?

No SIEM alert was generated. The event was reviewed manually.

## Lab Command

The original command was:

```powershell
Write-Output "SOC-P6-ENCODED-LAB"; Write-Output "PID=$PID"
```

It prints a lab marker and the process ID of the PowerShell process
executing it.

The command was encoded and launched using:

```powershell
$labCommand = 'Write-Output "SOC-P6-ENCODED-LAB"; Write-Output "PID=$PID"'
$labEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($labCommand))

Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"
powershell.exe -NoProfile -EncodedCommand $labEncoded
```

Windows PowerShell expects the Base64 command to represent
UTF-16LE text. The Unicode encoding used above produces those bytes.

Base64 is encoding, not encryption. Decoding requires no secret key.

### Observed Terminal Output

```text
2026-09-14 14:47:52 +05:00
SOC-P6-ENCODED-LAB
PID=1464
```

The displayed timestamp was collected immediately before the launch.
The event timestamps below provide the recorded event times.

### Earlier Failed Attempt

An earlier attempt at 14:46:09 returned a missing-command error and
did not print the lab marker.

An empty or unavailable variable in that PowerShell session was the
likely explanation. The investigation below concerns the successful
attempt at 14:47:52.

## Evidence Reviewed

- Terminal command and output.
- Security Event 4688, record 20934.
- PowerShell Operational Event 4104, record 269.
- Manual Base64 decoding output.
- Exported event files and screenshots.

## Timeline

Date: September 14, 2026.

| Local time — UTC+05:00 | UTC time | Evidence | Observation |
|---|---|---|---|
| 14:47:52.9059462 | 09:47:52.9059462 | 4688, record 20934 | PowerShell process created with an encoded command |
| 14:47:54.7628091 | 09:47:54.7628091 | 4104, record 269 | Readable script-block text recorded by PID 1464 |

The script-block event was recorded approximately 1.86 seconds
after the process creation event.

Record IDs identify records within their respective logs.
They were not used to establish order across the two logs.

## Process Creation Analysis — Event 4688

| Field | Observed value |
|---|---|
| Computer | DESKTOP-C70T8EA |
| Creator account | Healisu |
| Creator Logon ID | 0x72FB8B |
| New Process ID | 0x5b8 |
| New process | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| Creator Process ID | 0x8b8 |
| Creator process | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| Token Elevation Type | %%1937 — elevated token |
| Mandatory Label | S-1-16-12288 — High integrity |

The recorded command line was:

```text
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMATwBDAC0AUAA2AC0ARQBOAEMATwBEAEUARAAtAEwAQQBCACIAOwAgAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAIgBQAEkARAA9ACQAUABJAEQAIgA=
```

### Interpretation

An existing PowerShell process launched another PowerShell process.

- `-NoProfile` skipped PowerShell profile scripts.
- `-EncodedCommand` supplied the command as Base64 text.
- The child process ran elevated with High integrity.
- Administrator privileges were unnecessary for this command.

The presence of an encoded command justified inspecting its contents.
It did not establish malicious intent.

## Script-Block Analysis — Event 4104

| Field | Observed value |
|---|---|
| Computer | DESKTOP-C70T8EA |
| User | DESKTOP-C70T8EA\Healisu |
| Execution ProcessID | 1464 |
| Event Record ID | 269 |
| ScriptBlock ID | 4afdffde-4301-486c-8453-9a032bfb8a01 |
| Message | 1 of 1 |
| Path | Empty |

The event recorded:

```powershell
Write-Output "SOC-P6-ENCODED-LAB"; Write-Output "PID=$PID"
```

### Interpretation

Event 4104 exposed the readable script text associated with the
PowerShell process.

The event recorded code, not the command's output. The terminal
screenshot separately showed the marker and PID being printed.

The displayed task category, "Execute a Remote Command", was not
treated as proof of remote execution.

## Correlation

The process identifiers matched:

```text
4688 New Process ID:        0x5b8
Converted to decimal:      1464
4104 Execution ProcessID:  1464
Terminal output:           PID=1464
```

Additional supporting evidence included:

- The same computer.
- The same account context.
- A closely aligned timeline.
- Matching decoded command text.

The 4688 New Process ID was matched with the 4104 Execution ProcessID.
The 4688 Creator Process ID identifies the parent and was not used
as the child process identifier.

Process IDs can be reused. Host, timing, and process lifetime must
be considered when applying this correlation in other investigations.

## Manual Decoding

The encoded command was decoded without executing the decoded text:

```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($labEncoded))
```

Result:

```powershell
Write-Output "SOC-P6-ENCODED-LAB"; Write-Output "PID=$PID"
```

This exactly matched the script-block text in Event 4104.

For this lab, decoding used the variable prepared for the launch.
The same Base64 value was visible in the recorded 4688 command line.

If Event 4104 were unavailable, the complete Base64 argument in
4688 could still be decoded to recover the supplied instruction.
Decoding alone would not establish successful execution.

## Findings

| Question | Finding |
|---|---|
| Was PowerShell launched with an encoded command? | Yes, recorded in 4688 |
| Was the command recoverable? | Yes, through Base64 decoding |
| Did 4104 match the process? | Yes, PID 1464 matched 0x5b8 |
| What did the inspected code do? | Printed a lab marker and its process ID |
| Was output observed? | Yes, in the terminal |
| Did the process run elevated? | Yes |
| Was malicious activity established? | No |

The decoded script contained two output commands. It did not contain
a download, network request, persistence action, or file modification.

This statement describes the inspected script; it is not a claim
that all activity on the computer was examined.

## Assessment

Classification: Authorized encoded PowerShell lab activity.

The encoded command, script-block text, process ID, and terminal
output were consistent with the known exercise.

No compromise or malicious behavior was established by the
reviewed evidence. No containment action was warranted for the
known lab activity.

This was not classified as a false-positive alert because no alert
was generated.

## Detection Considerations

An encoded PowerShell command can be a useful investigation lead.

In an unknown environment, an analyst should:

1. Preserve the full command line.
2. Decode the argument without executing it.
3. Examine the parent process and account context.
4. Correlate relevant script-block events.
5. Investigate resulting process, file, and network activity.
6. Compare the behavior with an approved task or expected application.

Legitimate automation and malicious tools can both use encoded
commands. A verdict requires context and behavior beyond the flag
itself.

No automated detection rule was implemented in this exercise.

## Limitations

- The command was deliberately harmless and known in advance.
- Only the selected process event, script-block event, decoding
  output, and terminal evidence were examined.
- No independent network or file-activity investigation was performed.
- The parent process's full history was not investigated.
- Manual decoding used the prepared lab variable.
- Script-block text alone does not establish command output or success.
- This exercise does not demonstrate detection of every form of
  PowerShell abuse or obfuscation.

## Original Event Evidence

Download the files and open them in Windows Event Viewer:

- [Encoded PowerShell process creation — 4688](logs/01-encoded-powershell-4688.evtx)
- [Readable script-block event — 4104](logs/02-decoded-scriptblock-4104.evtx)

## Screenshots

- [Encoded command and terminal output](screenshots/01-encoded-command-and-output.png)
- [Process creation event and command line](screenshots/02-encoded-powershell-4688.png)
- [Readable script-block text](screenshots/03-decoded-scriptblock-4104.png)
- [Script-block process ID](screenshots/04-scriptblock-process-id.png)
- [Manual decoding result](screenshots/05-manually-decoded-command.png)

## Lessons Learned

1. Encoding is not encryption and does not automatically indicate malware.
2. Process creation logs can preserve an encoded startup command.
3. Script-block logging can reveal its readable code.
4. Match the correct process ID fields across events.
5. Distinguish recorded code from observed output.
6. Use account, parent process, elevation, and behavior as context.
7. Document failed attempts separately from the successful run.
8. Reach a verdict supported by evidence rather than a suspicious flag alone.

## Related Projects

- [Windows Event Log Investigation](../02-Windows-Event-Logs/)
- [Wireshark Network Investigations](../05-Wireshark-Investigations/)

## Disclaimer

This project documents educational testing on my own authorized
Windows lab VM.
