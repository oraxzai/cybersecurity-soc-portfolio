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
- Suspicious-traffic analysis and malicious IOC extraction were
  outside the scope of these exercises.
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
