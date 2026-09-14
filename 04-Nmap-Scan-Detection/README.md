# Nmap Scan Detection & Investigation


## Overview

Investigate an authorized four-port Nmap scan against a Windows VM
using scanner output, a Wireshark capture, and Windows Firewall logs.

## Lab Environment

- VMware Fusion on a MacBook Air.
- Network: Private to my Mac.
- Kali scanner: 172.16.152.128.
- Windows target: 172.16.152.129.
- Tools: Nmap, Wireshark, and Windows Firewall logging.

## Work Performed

- Scanned TCP ports 135, 139, 445, and 3389.
- Examined SYN packets and repeated connection attempts.
- Investigated Nmap's filtered-port results.
- Enabled dropped-packet logging and performed a separate repeat scan.
- Compared the repeat scan with Windows Firewall records.

## Key Findings

- Nmap reported all four ports as filtered.
- The first capture showed outgoing SYN packets without return IPv4
  traffic; an ARP response was also present.
- Firewall records from the repeat scan confirmed dropped traffic
  to ports 135, 139, and 445.
- No matching drop record for port 3389 was found in the evidence reviewed.
- Filtered results did not establish whether the ports were open or closed.

## Investigation Report

[Read the full investigation report](investigation-report.md)

## Original Evidence

- [First Nmap scan output](Logs/lab-scan.txt)
- [First scan packet capture](Logs/01-windows-port-scan.pcapng)
- [Repeat Nmap scan output](Logs/lab-scan-firewall-check.txt)
- [Windows Firewall log](Logs/windows-firewall-scan.log)
- [Screenshots](screenshots/)

## Skills Demonstrated

- Interpreting Nmap port states.
- Identifying scan patterns in packet captures.
- Reviewing host firewall evidence.
- Separating observations from assumptions.
- Documenting evidence limitations.

## Scope

This was a controlled manual investigation of four TCP ports.
No automated alert or malicious compromise was demonstrated.

The first scan and the firewall-check scan were separate runs.
Evidence from one was not treated as direct proof of the other.

## Retained Lab Configuration

Windows Firewall remained enabled. Dropped-packet logging and
the lab ICMP allow rule for Kali were retained for future exercises.

## Related Project

[Wireshark Network Investigations](../05-Wireshark-Investigations/)
