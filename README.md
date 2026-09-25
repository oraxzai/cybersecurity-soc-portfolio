# Cybersecurity SOC Portfolio

Hands-on cybersecurity portfolio focused on Security Operations, Windows
security monitoring, log analysis, SIEM investigation, KQL detection,
network analysis, and incident documentation.

## About

I am a Computer Systems Engineer who completed a B.Sc. in Computer Systems
Engineering at the University of Engineering and Technology, Peshawar, in
2026.

This portfolio documents my practical development toward a Junior SOC
Analyst or Security Operations Analyst role. The projects are based on
controlled labs, simulated security scenarios, and authorized testing
environments.

My work focuses on understanding how security events are collected,
filtered, correlated, investigated, documented, and converted into useful
detections.

## Projects

### 01 — [SOC Home Lab](01-SOC-Home-Lab/)

Built and documented a Windows-based security monitoring lab using virtual
machines and Windows Event Viewer.

### 02 — [Windows Event Log Investigation](02-Windows-Event-Logs/)

Analyzed Windows Security events including successful logons, failed
logons, privilege assignments, process creation, PowerShell activity, and
service installation events.

### 03 — [Brute-Force Investigation](03-Brute-Force-Investigation/)

Investigated repeated authentication failures followed by successful
authentication and evaluated whether the activity represented a genuine
brute-force attack or controlled testing.

### 04 — [Nmap Scan Detection](04-Nmap-Scan-Detection/)

Analyzed TCP reconnaissance from Kali Linux to Windows using Nmap and
Wireshark. Compared scan results with firewall behavior and packet-level
evidence.

### 05 — [Wireshark Investigations](05-Wireshark-Investigations/)

Investigated HTTP, HTTPS, DNS, and periodic network traffic using packet
captures, request timing, response codes, and protocol behavior.

### 06 — [Suspicious PowerShell Investigation](06-Suspicious-PowerShell/)

Investigated a harmless encoded PowerShell command by correlating process
creation and PowerShell Script Block Logging events.

### 07 — [DNS Investigation](07-DNS-Investigation/)

Analyzed successful DNS queries and NXDOMAIN responses using PowerShell,
`nslookup`, Wireshark, and local DNS server logs.

### 08 — [Phishing Investigation](08-Phishing-Investigation/)

Inspected a synthetic phishing email for sender inconsistencies, reply-to
mismatches, suspicious links, social-engineering indicators, and attachment
characteristics.

### 09 — [Microsoft Sentinel Investigation](09-Microsoft-Sentinel-Investigation/)

Configured Azure Activity and Windows Security event collection in
Microsoft Sentinel. Created scheduled analytics rules, investigated
generated incidents, and documented the results.

### 10 — [KQL Authentication Investigation](10-KQL-Queries/)

Created and tested KQL queries for filtering, aggregation, fixed time
windows, repeated failed-logon detection, and failure-to-success
authentication correlation.

The project also validated a real Windows event sequence in which one
failed logon was followed by two successful logons for the same local
account.

## Technical Skills Demonstrated

### Security Monitoring and Investigation

- Windows Security Event analysis
- Event IDs 4624, 4625, 4672, 4688, 4104, and 7045
- Authentication and logon analysis
- Process and session correlation
- Timeline construction
- Alert validation and investigation documentation
- Basic incident classification

### SIEM and Detection

- Microsoft Sentinel
- Azure Log Analytics
- Kusto Query Language (KQL)
- Azure Monitor Agent
- Azure Arc-enabled machine monitoring
- Scheduled analytics rules
- Data collection rules
- Alert thresholds and suppression
- Incident investigation and closure

### Network and Protocol Analysis

- Wireshark packet analysis
- Nmap reconnaissance analysis
- TCP SYN and port behavior
- DNS and NXDOMAIN analysis
- HTTP and HTTPS traffic inspection
- Firewall behavior comparison
- Basic network segmentation concepts

### Endpoint and Script Analysis

- Windows Event Viewer
- PowerShell process investigation
- Encoded PowerShell decoding
- Command-line analysis
- PowerShell Script Block Logging
- Process ID and event correlation
- Basic service and privilege-event analysis

### Tools

- Microsoft Sentinel
- Azure Log Analytics
- Azure Monitor Agent
- Azure Arc
- KQL
- Windows Event Viewer
- PowerShell
- Wireshark
- Nmap
- Kali Linux
- Python
- Git and GitHub
- Cisco Packet Tracer
- VMware

## Certifications and Training

- Certified Ethical Hacker (CEH), EC-Council
- NAVTTC Cyber Security training based on CEH and CHFI curricula
- Cisco Networking Academy:
  - Introduction to Networks
  - Switching, Routing, and Wireless Essentials

## Methodology

The projects follow this workflow:

**Learn → Build a Lab → Collect Evidence → Investigate → Detect →
Document → Communicate**

All activities are performed in controlled and authorized environments.

## Planned Next Project

### 11 — SOC Alert Triage and Incident Response

The next project will combine the previous work into a complete SOC
workflow:

**Alert → Validate → Investigate → Classify → Respond → Document → Close**

It will focus on alert triage, timeline analysis, incident classification,
response recommendations, and final case documentation.

## Portfolio Links

- GitHub: [github.com/oraxzai](https://github.com/oraxzai)
- Portfolio repository:
  [cybersecurity-soc-portfolio](https://github.com/oraxzai/cybersecurity-soc-portfolio)
- LinkedIn: [linkedin.com/in/haris456](https://www.linkedin.com/in/haris456)

## Disclaimer

This portfolio contains educational labs and authorized simulations. No
unauthorized systems or real-world targets were intentionally attacked.
