# Wireshark Network Investigations

## Objective

Investigate HTTP, DNS, and HTTPS traffic in a controlled home lab.
Use packet evidence to explain how connections work, what information
is visible, and what encryption prevents an analyst from reading.

## Lab Environment

| Component | Role | IP address |
|---|---|---|
| Windows VM | Web browser and DNS client | 172.16.152.129 |
| Kali VM | HTTP, HTTPS, and DNS servers; packet capture | 172.16.152.128 |

- Host machine: MacBook Air.
- Virtualization: VMware Fusion.
- Network: Private to my Mac.
- Capture interface: Kali `eth0`.
- Tools: Wireshark, Python, dnsmasq, OpenSSL, and Windows nslookup.
- Scope: Authorized traffic between my own lab VMs.

## Investigation 1: HTTP over TCP

### Activity

Windows opened a page hosted by a temporary Python HTTP server on Kali:

```text
http://172.16.152.128:8000/
```

### Evidence Observed

| Packets | Observation |
|---|---|
| 1–3 | TCP three-way handshake: SYN, SYN-ACK, ACK |
| 4 | Windows sent `GET / HTTP/1.1` |
| 10 | Kali returned `HTTP/1.0 200 OK` |
| 14 | Windows requested `/favicon.ico` |
| 17 | Kali returned `404 File not found` |

The main-page connection used:

- Client: `172.16.152.129:63649`
- Server: `172.16.152.128:8000`

The favicon request used a separate connection with Windows client
port `63650`.

Follow TCP Stream displayed readable request headers, response
headers, and the page text:

```text
SOC Lab: successful HTTP connection
```

### Interpretation

The server successfully returned the main page.

The favicon request received a 404 response because the requested
resource was unavailable. This did not mean the web server or
TCP connection was unavailable.

The HTTP capture exposed the request and response content because
this connection did not use TLS encryption.

## Investigation 2: DNS over UDP

### Activity

A temporary dnsmasq server on Kali provided a local DNS record:

```text
soc-lab.test → 172.16.152.128
```

Windows queried that server directly:

```cmd
nslookup -type=A soc-lab.test 172.16.152.128
```

### Evidence Observed

| Field | Observation |
|---|---|
| Query packet | 5 |
| Response packet | 6 |
| Client | 172.16.152.129 |
| DNS server | 172.16.152.128 |
| Query name | soc-lab.test |
| Query type | A |
| Transaction ID | 0x0003 |
| Transport | UDP |
| Client source port | 53290 |
| Server destination port | 53 |
| Answer address | 172.16.152.128 |

The response reversed the source and destination IP addresses.
The matching transaction ID, query name, and network endpoints
supported linking the response to the request.

### Interpretation

The lookup returned the configured IPv4 address for `soc-lab.test`.

This DNS exchange used UDP, so there was no TCP three-way handshake.
DNS can also use TCP; this exercise demonstrated DNS over UDP.

A successful DNS lookup does not prove that the client subsequently
connected to the returned address or visited a website.

## Investigation 3: HTTPS over TLS

### Activity

A temporary Python HTTPS server on Kali served the lab page at:

```text
https://172.16.152.128:8443/
```

The server used a temporary self-signed certificate. Windows displayed
a certificate warning because the certificate was not automatically
trusted.

After proceeding for this lab address, the browser displayed:

```text
SOC Lab: successful HTTP connection
```

The page text stayed the same as the HTTP exercise, but the connection
used HTTPS.

The server served a separate `public` directory. The private key
remained outside that directory and was excluded from the repository.

### Evidence Observed

Wireshark identified TLSv1.3 traffic and multiple TCP connections.

An early TCP stream contained binary TLS data without readable HTTP
request or page text. That stream alone did not establish that the
page was delivered.

A later connection used:

- Client: `172.16.152.129:63665`
- Server: `172.16.152.128:8443`

| Packets | Observation |
|---|---|
| 90–92 | TCP three-way handshake |
| 93 | Client Hello from Windows |
| 95 | Server Hello from Kali |
| 98 | Application Data from Windows to Kali |
| 99 | Application Data from Kali to Windows |

### Interpretation

The browser evidence showed the lab page loading over HTTPS.
The capture showed TLS exchanges and encrypted records.

Without TLS decryption, the HTTP request, response status, and page
content were not readable in the packet capture.

The exact HTTP content of the later connection was not established.
An Application Data label alone does not identify a particular web
request or prove that it succeeded.

HTTPS protects traffic in transit. It does not prove that a website,
download, or user activity is safe.

## Investigation 4: Periodic HTTP Requests

### Objective

Identify repeated HTTP requests, measure their timing, and extract
details that could support further investigation.

### Activity

On September 14, 2026, a PowerShell loop on Windows requested a
harmless file from Kali six times, waiting five seconds between
completed requests.

```powershell
1..6 | ForEach-Object {
    Get-Date -Format "HH:mm:ss"
    Invoke-WebRequest -Uri "http://172.16.152.128:8000/heartbeat.txt" -UseBasicParsing |
        Select-Object StatusCode
    if ($_ -lt 6) { Start-Sleep -Seconds 5 }
}
```

The activity was generated manually as an authorized lab simulation.

### Packet Timeline

Times below are seconds relative to the beginning of this capture.

| Request packet | Relative time | Gap from previous request |
|---|---:|---:|
| 4 | 0.005 | — |
| 14 | 5.398 | 5.393 seconds |
| 24 | 10.528 | 5.130 seconds |
| 34 | 15.655 | 5.127 seconds |
| 44 | 20.780 | 5.126 seconds |
| 54 | 25.935 | 5.154 seconds |

Values are rounded independently from the packet timestamps.

Six requests occurred over approximately 25.93 seconds.
The gaps ranged from approximately 5.13 to 5.39 seconds.

The script waited five seconds after each completed request.
Request processing and execution overhead contributed to intervals
longer than five seconds.

### Extracted Investigation Details

| Field | Observed value |
|---|---|
| Source IP | 172.16.152.129 |
| Destination IP | 172.16.152.128 |
| Destination TCP port | 8000 |
| HTTP method | GET |
| Request path | /heartbeat.txt |
| Host header | 172.16.152.128:8000 |
| User-Agent identifier | WindowsPowerShell/5.1.19041.1682 |
| Successful responses | Six HTTP 200 responses |
| Inspected response body | SOC lab heartbeat |
| Inspected response Content-Length | 18 bytes |
| Inspected response Date header | September 14, 2026, 09:15:18 GMT |

These values are investigation details from the exercise,
not confirmed indicators of compromise.

The User-Agent identified itself as PowerShell. This agreed with
the known command evidence, but the header alone would not prove
which process generated the traffic because it can be changed.

### Analysis

The repeated destination, request path, and approximately regular
intervals support identifying automated periodic HTTP activity.

The capture contained six matching GET requests and six HTTP
200 responses. Inspection of one TCP stream showed the requested
file content being returned.

Periodic communication can have legitimate or malicious purposes:

| Possible explanation | Additional evidence to seek |
|---|---|
| An approved health check | Monitoring configuration and owner confirmation |
| An application polling for updates | Application settings and process activity |
| Malware checking for instructions | Endpoint evidence, destination context, and suspicious commands |

Timing alone cannot distinguish these explanations.

### Assessment

Classification: Authorized periodic HTTP lab activity.

The observed pattern matched the PowerShell loop used in the
exercise. No malware, command-and-control activity, or compromise
was established.

In an unknown environment, this pattern would justify checking the
originating process, destination, application purpose, and other
endpoint or network evidence before reaching a verdict.

### Limitations

- Only six requests were generated.
- No automated detection or alert was created.
- The originating process was known from the lab command evidence;
  it was not independently attributed through endpoint network logs.
- One request-response stream was inspected in detail.
- No external threat-intelligence assessment was performed.
- No malicious indicator was confirmed.

### Evidence

- [Original packet capture](logs/04-periodic-http-requests.pcapng)
- [PowerShell command and output](screenshots/15-periodic-http-command-output.png)
- [Six periodic HTTP requests](screenshots/16-periodic-http-requests.png)
- [Inspected request and response](screenshots/17-periodic-http-request-response.png)
- [Six successful HTTP responses](screenshots/18-periodic-http-success-responses.png)

### Display Filters

Requests for the lab file:

```text
http.request.method == "GET" && http.request.uri == "/heartbeat.txt"
```

Successful HTTP responses:

```text
http.response.code == 200
```

## Visibility Comparison

| Information | HTTP capture | HTTPS capture |
|---|---|---|
| Source and destination IP addresses | Visible | Visible |
| TCP ports | Visible | Visible |
| Packet timing and sizes | Visible | Visible |
| HTTP request path | Readable | Not readable without decryption |
| HTTP response status | Readable | Not readable without decryption |
| Page content | Readable | Not readable without decryption |
| TLS handshake information | Not applicable | Partly visible |

## Useful Wireshark Display Filters

### HTTP lab connection

```text
tcp.port == 8000
```

### HTTP requests and responses

```text
http
```

### Main-page TCP connection

```text
tcp.port == 63649 && tcp.port == 8000
```

### Favicon TCP connection

```text
tcp.port == 63650 && tcp.port == 8000
```

### Local DNS query and response

```text
dns.qry.name == "soc-lab.test"
```

### HTTPS lab connections

```text
tcp.port == 8443
```

The client-port filters refer to these specific captures. Client
ports may change when the exercise is repeated.

## Original Evidence

Download the captures and open them in Wireshark:

- [HTTP packet capture](logs/01-successful-http-connection.pcapng)
- [DNS packet capture](logs/02-local-dns-query.pcapng)
- [HTTPS packet capture](logs/03-https-connection.pcapng)

Packet numbers in this report refer to their respective capture
files, not a shared sequence across all three files.

## Screenshots

### HTTP Evidence

- [TCP handshake and HTTP overview](screenshots/01-tcp-handshake-and-http-overview.png)
- [Readable HTTP request and response](screenshots/02-http-request-and-response.png)
- [Homepage and favicon responses](screenshots/03-http-homepage-and-favicon.png)
- [Main-page TCP connection](screenshots/04-homepage-tcp-connection.png)
- [Favicon TCP connection](screenshots/05-favicon-tcp-connection.png)

### DNS Evidence

- [Temporary DNS server](screenshots/06-local-dns-server.png)
- [DNS query and response](screenshots/07-dns-query-and-response.png)
- [DNS answer details](screenshots/08-dns-answer-details.png)
- [Windows nslookup result](screenshots/09-windows-nslookup-result.png)

### HTTPS Evidence

- [Self-signed certificate warning](screenshots/10-https-certificate-warning.png)
- [TLS packet overview](screenshots/11-https-tls-packets.png)
- [Early TLS stream viewed as text](screenshots/12-https-tcp-stream.png)
- [HTTPS page loaded in Windows](screenshots/13-https-page-loaded.png)
- [Later encrypted data exchange](screenshots/14-https-later-data-exchange.png)

## Assessment

Classification: Authorized lab activity.

The observations matched the HTTP, DNS, and HTTPS tests generated
between the two lab VMs. These exercises did not demonstrate an
unauthorized compromise.

The IP addresses and test domain document the lab endpoints.
They are not established indicators of compromise.

## Limitations

- These were controlled protocol exercises, not production incidents.
- No automated alert or detection rule was created.
- A controlled periodic HTTP pattern was investigated; no actual
  malicious traffic or confirmed malicious IOC was demonstrated.
- No TLS decryption was performed.
- Unreadable bytes alone do not prove encryption; the TLS protocol
  evidence provides the necessary context.
- A packet's Application Data label does not reveal the encrypted
  message or its purpose.
- An IP address identifies an observed network endpoint, not a
  person's identity.
- Successful communication does not establish that activity is
  authorized or harmless.

## Lessons Learned

1. Identify clients and servers using direction, addresses, and ports.
2. Separate TCP connection establishment from application responses.
3. Distinguish a missing HTTP resource from an unavailable server.
4. Correlate DNS requests and responses using multiple fields.
5. Explain what HTTPS reveals and what remains encrypted.
6. Combine browser evidence with packet evidence without overstating
   what either source proves.
7. Preserve original captures alongside screenshots and conclusions.

## Related Investigation

[Nmap Scan Detection and Investigation](../04-Nmap-Scan-Detection/)

## Disclaimer

This project documents educational testing performed on my own
authorized home-lab systems.
