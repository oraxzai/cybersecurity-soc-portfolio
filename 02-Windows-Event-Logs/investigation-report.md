# Windows Authentication Event Log Investigation

## 1. Objective

The objective of this investigation was to analyze Windows Security Event Logs and practice the basic workflow of a SOC analyst when investigating authentication activity.

The investigation focused on Event IDs **4624** and **4625**, with particular attention to logon types, accounts, timestamps, source information, and processes.

---

## 2. Environment

* Operating System: Windows
* Virtualization: VMware
* Analysis Tool: Windows Event Viewer
* Log Source: Windows Security Event Log
* Environment: Isolated virtual machine

---

## 3. Events Investigated

Three Windows Security events were analyzed:

1. Event ID 4625 — Failed interactive logon
2. Event ID 4624 — Successful service logon
3. Event ID 4624 — Successful interactive logon

---

## 4. Event Analysis

### Event 4625 — Failed Logon

**Time:** 12:14:00 AM

**Important fields:**

* Account: `Healisu`
* Logon Type: `2`
* Failure Reason: Unknown user name or bad password
* Status: `0xC000006D`
* Substatus: `0xC000006A`
* Source IP: `127.0.0.1`
* Source Port: `0`
* Process: `C:\Windows\System32\svchost.exe`

### Analysis

This event represents a failed local interactive authentication attempt.

The substatus `0xC000006A` indicates that the password was incorrect.

The source address `127.0.0.1` represents the local machine.

Only one failed authentication event was observed, so there is insufficient evidence to classify this activity as a brute-force attack.

---

### Event 4624 — Successful Service Logon

**Time:** 12:31:26 AM

**Important fields:**

* Account: `SYSTEM`
* Logon Type: `5`
* Process: `C:\Windows\System32\services.exe`
* Authentication Package: `Negotiate`

### Analysis

Logon Type 5 represents a service logon.

The SYSTEM account and `services.exe` process are consistent with normal Windows service activity.

No remote source IP was associated with this event.

Based on the available evidence, this event was assessed as normal system activity.

---

### Event 4624 — Successful Interactive Logon

**Time:** 12:04:39 AM

**Important fields:**

* Account: `Healisu`
* Logon Type: `2`
* Source IP: `127.0.0.1`
* Source Port: `0`
* Elevated Token: Yes
* Process: `C:\Windows\System32\svchost.exe`
* Workstation: `DESKTOP-C70T8EA`

### Analysis

This event represents a successful local interactive logon.

The source address is localhost and the account is the local user account.

The elevated token is worth noting during investigation, but it does not by itself indicate malicious activity.

Additional process and timeline correlation would be required before making a malicious activity determination.

---

## 5. Timeline

| Time        | Event ID | Logon Type | Activity                     |
| ----------- | -------: | ---------: | ---------------------------- |
| 12:04:39 AM |     4624 |          2 | Successful interactive logon |
| 12:14:00 AM |     4625 |          2 | Failed interactive logon     |
| 12:31:26 AM |     4624 |          5 | SYSTEM service logon         |

---

## 6. Investigation Assessment

No confirmed malicious activity was identified from these three events alone.

The 4625 event indicates an incorrect password, but a single failed authentication attempt is not sufficient evidence of brute-force activity.

The 4624 Type 5 event is consistent with normal Windows service activity.

The 4624 Type 2 event shows a successful local interactive logon. Although the elevated token and process information are useful investigation points, they do not independently establish malicious activity.

---

## 7. SOC Investigation Lessons

This investigation demonstrated several important SOC concepts:

* Event ID 4624 indicates a successful logon.
* Event ID 4625 indicates a failed logon.
* Logon Type 2 represents an interactive logon.
* Logon Type 5 represents a service logon.
* `127.0.0.1` represents localhost.
* `0xC000006A` indicates an incorrect password.
* A single suspicious-looking event does not automatically mean an attack occurred.
* Analysts should correlate timestamps, accounts, processes, source addresses, and other events before reaching a conclusion.

---

## 8. Conclusion

The investigation was assessed as **benign / no confirmed malicious activity** based on the available evidence.

The main SOC lesson was the importance of **context and event correlation** rather than treating individual security events as proof of compromise.

## Disclaimer

This investigation was conducted in an isolated virtual machine for educational and authorized cybersecurity training purposes only.
