# DNS Investigation & Threat Hunting

## Overview

Investigate successful DNS resolution and repeated NXDOMAIN
responses in a controlled Windows and Kali lab.

The investigation compares client output, Wireshark packet captures,
and DNS server log evidence.

## Lab Environment

- VMware Fusion on a MacBook Air.
- Network: Private to my Mac.
- Windows client: 172.16.152.129.
- Kali DNS server: 172.16.152.128.
- Tools: dnsmasq, nslookup, PowerShell, and Wireshark.
- Investigation date: September 15, 2026.

## Work Performed

- Configured a temporary local DNS server.
- Compared a successful A-record lookup with NXDOMAIN.
- Generated six queries for distinct missing names.
- Measured query timing.
- Matched requests and responses using names, endpoints,
  transaction IDs, and timing.
- Compared packet evidence with server log lines.
- Documented alternative explanations and follow-up actions.

## Key Findings

- portal.soc-lab.test resolved to 172.16.152.128.
- missing.soc-lab.test returned NXDOMAIN.
- Six numbered test names each received NXDOMAIN responses.
- Repeated queries were approximately 2.03–2.11 seconds apart.
- Transaction ID 0x0003 was reused across exchanges.
- Server log evidence supported the inspected packet result.
- The known PowerShell loop explained the activity;
  malware was not established.

## Investigation Report

[Read the full investigation report](investigation-report.md)

## Evidence

- [Successful lookup and NXDOMAIN capture](logs/01-dns-success-and-nxdomain.pcapng)
- [Repeated NXDOMAIN capture](logs/02-repeated-nxdomain-queries.pcapng)
- [Screenshots](screenshots/)

## Skills Demonstrated

- Interpreting DNS query types and response codes.
- Correlating DNS requests and responses.
- Measuring repeated query patterns.
- Distinguishing A and PTR lookups.
- Comparing multiple evidence sources.
- Forming follow-up questions without assuming malicious intent.

## Scope and Limitations

This project combines controlled DNS lab exercises with external
source research. It is not a production malware investigation.

- The local tests used deliberately configured and missing DNS names.
- The repeated-query test contained six distinct names.
- No malware, DNS tunneling, or command-and-control activity was confirmed.
- No automated detection rule or independent endpoint process
  attribution was implemented.
- External research covered a historical Mandiant report, a
  timestamped DNS lookup, and Cloudflare's published IP ranges.
- The September 15, 2026 DNS results do not establish the domain's
  IP addresses during the 2017 WannaCry campaign.
- Provider-range membership does not identify the domain operator,
  origin server, or responsible person.
- No registry lookup, domain ownership verification, or current
  reputation verdict was completed.
- The historical research example was separate from the local
  NXDOMAIN captures.
- The reviewed names and addresses were not established as
  currently malicious indicators.
  
## Related Projects

- [Wireshark Network Investigations](../05-Wireshark-Investigations/)
- [Suspicious PowerShell Investigation](../06-Suspicious-PowerShell/)
