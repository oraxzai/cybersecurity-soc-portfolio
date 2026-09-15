# Investigation Report: Repeated DNS NXDOMAIN Responses

## Summary

On September 15, 2026, I investigated successful and unsuccessful
DNS lookups in an authorized Windows and Kali lab.

A baseline test resolved portal.soc-lab.test successfully.
A lookup for missing.soc-lab.test returned NXDOMAIN.

A separate test queried six distinct names, check1.soc-lab.test
through check6.soc-lab.test. All six received NXDOMAIN responses,
with requests approximately two seconds apart.

The activity matched the known lab commands. The evidence did not
establish malware, domain-generation algorithm activity, or
command-and-control communication.

## Objective

- Distinguish successful DNS resolution from NXDOMAIN.
- Correlate DNS requests with their responses.
- Examine repeated failed lookups and their timing.
- Compare client output, packet evidence, and server logs.
- Identify appropriate follow-up actions without assuming malware.

## Environment

| Component | Details |
|---|---|
| Virtualization | VMware Fusion on a MacBook Air |
| Network | Private to my Mac |
| Windows client | 172.16.152.129 |
| Kali DNS server | 172.16.152.128 |
| Capture interface | Kali eth0 |
| DNS software | dnsmasq |
| Client tools | nslookup and Windows PowerShell |
| Packet analysis | Wireshark |
| Windows displayed timezone | UTC+05:00 |

## DNS Server Configuration

The temporary DNS server was started on Kali using:

```bash
sudo dnsmasq --no-daemon \
  --conf-file=/dev/null \
  --no-resolv --no-hosts \
  --listen-address=172.16.152.128 \
  --bind-interfaces \
  --local=/soc-lab.test/ \
  --host-record=portal.soc-lab.test,172.16.152.128 \
  --log-queries
```

The configuration supplied one known name:

```text
portal.soc-lab.test → 172.16.152.128
```

The lab domain was handled locally. No records were configured for
the missing or numbered test names.

The server was stopped with Ctrl+C after evidence collection.

## Evidence Reviewed

- Windows nslookup output.
- PowerShell loop and its output.
- Baseline DNS packet capture.
- Repeated-query packet capture.
- Packet details for a query-response pair.
- dnsmasq terminal log lines preserved in a screenshot.

No SIEM alert or automated detection rule was generated.

## Test 1: Successful and Unsuccessful Resolution

### Commands

```cmd
nslookup -type=A portal.soc-lab.test 172.16.152.128
```

```cmd
nslookup -type=A missing.soc-lab.test 172.16.152.128
```

### Results

| Query | Request packet | Response packet | Result |
|---|---:|---:|---|
| portal.soc-lab.test | 5 | 6 | A record: 172.16.152.128 |
| missing.soc-lab.test | 11 | 12 | NXDOMAIN |

Packet numbers refer to:

```text
01-dns-success-and-nxdomain.pcapng
```

For the failed lookup, the response details showed:

```text
Reply code: No such name (3)
```

This is the DNS response code for NXDOMAIN.

### Interpretation

The DNS server answered both queries.

NXDOMAIN indicated that the requested name did not exist according
to the responding server. It was not a timeout or evidence that the
server was unreachable.

The successful lookup established a name-to-address mapping.
It did not establish that Windows subsequently visited a website.

Both exchanges used transaction ID 0x0003. Therefore, the transaction
ID alone could not distinguish the two exchanges.

## Test 2: Repeated Queries for Missing Names

### Activity

The following loop was run in Windows PowerShell:

```powershell
1..6 | ForEach-Object {
    $labName = "check$_.soc-lab.test"
    Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"
    nslookup -type=A $labName 172.16.152.128
    if ($_ -lt 6) { Start-Sleep -Seconds 2 }
}
```

It generated six lookups for different names and waited two seconds
between completed lookups.

### Client Output

The displayed local timestamps were:

| Name | Time — UTC+05:00 | Result |
|---|---|---|
| check1.soc-lab.test | 14:14:15 | Non-existent domain |
| check2.soc-lab.test | 14:14:17 | Non-existent domain |
| check3.soc-lab.test | 14:14:19 | Non-existent domain |
| check4.soc-lab.test | 14:14:21 | Non-existent domain |
| check5.soc-lab.test | 14:14:23 | Non-existent domain |
| check6.soc-lab.test | 14:14:25 | Non-existent domain |

These timestamps were printed before each lookup and had
one-second display precision.

### Packet Timeline

Packet times below are relative to the beginning of:

```text
02-repeated-nxdomain-queries.pcapng
```

| Name | Query packet | Response packet | Query time, seconds |
|---|---:|---:|---:|
| check1.soc-lab.test | 5 | 6 | 0.007153 |
| check2.soc-lab.test | 11 | 12 | 2.113382 |
| check3.soc-lab.test | 17 | 18 | 4.143146 |
| check4.soc-lab.test | 23 | 24 | 6.209315 |
| check5.soc-lab.test | 29 | 30 | 8.248254 |
| check6.soc-lab.test | 35 | 36 | 10.312148 |

The filtered packet list contained:

- Six A-record queries.
- Six matching NXDOMAIN responses.
- Six distinct queried names.

The intervals between queries ranged from approximately
2.03 to 2.11 seconds.

The first-to-last query interval was approximately 10.30 seconds.
This describes the selected queries, not necessarily the full
capture duration.

These were queries for different names, not six retransmissions
of the same query.

## Query-Response Correlation

The first pair in the repeated-query capture showed:

| Field | Query — packet 5 | Response — packet 6 |
|---|---|---|
| Source IP | 172.16.152.129 | 172.16.152.128 |
| Destination IP | 172.16.152.128 | 172.16.152.129 |
| UDP source port | 50040 | 53 |
| UDP destination port | 53 | 50040 |
| Transaction ID | 0x0003 | 0x0003 |
| Query name | check1.soc-lab.test | check1.soc-lab.test |
| Role | Request | NXDOMAIN response |

Wireshark also identified packet 6 through the query's
"Response In" field.

The reversed endpoints, matching transaction ID, query name,
and close timing supported pairing these packets.

Transaction IDs were reused across the displayed exchanges.
They were not treated as globally unique identifiers.

## DNS Server Evidence

The dnsmasq terminal contained:

```text
dnsmasq: query[A] check1.soc-lab.test from 172.16.152.129
dnsmasq: config check1.soc-lab.test is NXDOMAIN
```

These lines supported the packet evidence that Windows queried
the name and Kali generated an NXDOMAIN result.

The terminal also showed a reverse lookup:

```text
dnsmasq: query[PTR] 128.152.16.172.in-addr.arpa from 172.16.152.129
dnsmasq: config 172.16.152.128 is portal.soc-lab.test
```

The PTR query asked for a name associated with the DNS server's
IP address. It was separate from the A-record query for check1.

The server log excerpt was preserved as a screenshot.
A standalone server log file was not exported.

## Investigation Details Extracted

| Detail | Value |
|---|---|
| Client IP | 172.16.152.129 |
| DNS server IP | 172.16.152.128 |
| Inspected transport | UDP |
| DNS server port | 53 |
| First inspected client port | 50040 |
| Query type | A |
| Lab domain | soc-lab.test |
| Repeated names | check1 through check6 under soc-lab.test |
| Failed response | NXDOMAIN, code 3 |
| Approximate query interval | 2.03–2.11 seconds |

These are lab investigation details, not confirmed malicious
indicators of compromise.

## Analysis and Alternative Explanations

The repeated timing and changing names supported identifying
automated DNS activity.

In this exercise, the PowerShell loop explained the pattern.
In an unknown environment, further investigation would be needed.

| Possible explanation | Evidence to seek |
|---|---|
| Incorrect application configuration | Expected hostnames, configuration files, and owner confirmation |
| An approved script testing names | Script contents and approved task details |
| Malware generating or testing domains | Process attribution, broader query history, endpoint findings, and domain context |

Six sequential lab names do not establish a domain-generation
algorithm, DNS tunneling, or command-and-control activity.

## Recommended Follow-Up in an Unknown Environment

1. Identify the process responsible using suitable endpoint telemetry.
2. Review its parent process, command line, and application purpose.
3. Check whether the queried names are expected in its configuration.
4. Review a longer period for query volume, repetition, and affected hosts.
5. Examine successful lookups and any subsequent connections.
6. Assess relevant real-world domains using threat intelligence
   and other contextual evidence.

These are proposed follow-up actions. They were not all performed
during this exercise.

Wireshark alone did not identify the Windows process.
The PowerShell and nslookup activity was known from the lab commands.

## Historical Threat-Intelligence Review

### Purpose

Use published research to understand a domain's reported role,
rather than classify it solely by its appearance or association
with malware.

This review was separate from the local DNS exercises.

### Source

[Mandiant: WannaCry Ransomware Campaign — Threat Details and Risk Management](https://cloud.google.com/blog/topics/threat-intelligence/wannacry-ransomware-campaign/)

- Original publication date: May 15, 2017.
- Section reviewed: Malware Characteristics.
- Review date: September 15, 2026.

### Domain Reviewed

Defanged notation:

`www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com`

The brackets prevent the indicator from being presented as a
normal clickable domain.

### Published Finding

Mandiant described the domain as a kill-switch check used by
a WannaCry variant.

In the testing described in the report, successful contact
prevented that variant from performing encryption and
self-propagation. The report also noted differing observations
about propagation from other organizations.

The domain's reported role was not a malware-download location.

### Interpretation

An association with malware does not, by itself, establish
a domain's function or justify blocking it.

The role, reporting date, and relevant malware variant must
be considered before deciding how to respond.

### Limitations

- This was historical source review, not live malware analysis.
- A separate September 15, 2026 lookup and provider-range review
  are documented below. Historical IP mappings, domain ownership,
  and current reputation were not established.
- No associated IP address was investigated.
- No evidence reviewed established this domain's presence
  in our local lab captures.
- The finding should not be generalized to every WannaCry variant.

### Evidence

[Published report and domain context](screenshots/11-threat-intelligence-domain-context.png)

## Domain Resolution and IP Network Context

### Lookup

On September 15, 2026, at 09:58:14 UTC, a DNS lookup from the
Mac queried:

`www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com`

The resolver at 192.168.1.1 returned:

- 104.16.166.228
- 104.16.167.228

These were results observed at the time of this lookup.
They do not establish the domain's addresses during the 2017
WannaCry campaign.

### Network Context

Both addresses fall within 104.16.0.0/13, which appears in
[Cloudflare's official IPv4 range list](https://www.cloudflare.com/ips-v4/).

This verifies membership in a provider-published range.
A registry lookup was not completed.

### Interpretation

The DNS results and published range identify Cloudflare network
context. They do not identify the domain's operator, an origin
server, or the person responsible for any activity.

Neither a malware-related historical domain nor a provider's
IP range should be classified as currently malicious solely
from this evidence.

No current maliciousness verdict was established.

### Evidence

- [Timestamped DNS lookup](screenshots/12-domain-dns-resolution.png)
- [Cloudflare's published range](screenshots/13-ip-network-context.png)

## Assessment

Classification: Authorized DNS lab activity.

The client output, packet captures, and server log excerpt were
consistent with the configured tests.

No malware or unauthorized compromise was established.
No containment action was warranted for the known exercise.

This was not classified as a false-positive alert because no alert
was generated.

## Troubleshooting Note

An initial attempt pasted the PowerShell loop into Command Prompt.
The PowerShell syntax failed, and nslookup queried the literal
string $labName, receiving a Query refused response.

The loop was then run in PowerShell using a fresh capture.
The failed attempt was not counted as part of the six-name test.

## Limitations

- The queried names were deliberately configured or omitted.
- Only six names were used in the repeated-query test.
- No production traffic or actual malware was investigated.
- No independent endpoint DNS-to-process correlation was performed.
- External research was limited to one historical Mandiant report;
  no current domain reputation or associated IP assessment was performed.
- No automated alert or detection rule was created.
- The selected DNS activity did not establish subsequent connections.
- Server log evidence was limited to a screenshot.
- Packet numbers belong to their respective capture files.
- External research covered a historical Mandiant report,
  a timestamped DNS lookup, and Cloudflare's published IP ranges.
  No registry lookup or current reputation verdict was completed.

## Useful Wireshark Display Filters

### Baseline queries and responses

```text
dns.qry.name == "portal.soc-lab.test" || dns.qry.name == "missing.soc-lab.test"
```

### Six numbered test names

```text
dns.qry.name matches "^check[1-6]\\.soc-lab\\.test$"
```

## Original Evidence

Download and open the captures in Wireshark:

- [Successful lookup and NXDOMAIN capture](logs/01-dns-success-and-nxdomain.pcapng)
- [Repeated NXDOMAIN capture](logs/02-repeated-nxdomain-queries.pcapng)

## Screenshots

- [DNS server configuration](screenshots/01-local-dns-server.png)
- [Successful client lookup](screenshots/02-successful-dns-lookup.png)
- [NXDOMAIN client output](screenshots/03-nxdomain-lookup.png)
- [Successful and failed DNS exchanges](screenshots/04-dns-success-vs-nxdomain.png)
- [NXDOMAIN response code](screenshots/05-nxdomain-response-details.png)
- [Repeated lookup command and output](screenshots/06-repeated-dns-lookups.png)
- [Repeated query-response pairs](screenshots/07-repeated-nxdomain-packets.png)
- [Query details](screenshots/08-dns-query-details.png)
- [Response details](screenshots/09-dns-response-details.png)
- [DNS server query log](screenshots/10-dns-server-query-log.png)

## Lessons Learned

1. Distinguish NXDOMAIN from a timeout or unreachable server.
2. Match DNS exchanges using multiple fields.
3. Do not treat a transaction ID as globally unique.
4. Separate distinct queries from retransmissions.
5. Use packet timestamps to measure the observed pattern.
6. Distinguish A-record lookups from PTR reverse lookups.
7. Compare client, network, and server evidence.
8. Investigate the originating application before assigning a verdict.
