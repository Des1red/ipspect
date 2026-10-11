
# IPSpect

`ipspect` is a command-line IPv4 network scanner written in Go, designed for host discovery, device identification, TCP SYN scanning, and evidence-based service fingerprinting.

IPSpect combines three independently selectable scanning engines:

- **ICMP** — Discover hosts using ICMP Echo requests.
- **ARP** — Discover local devices and identify their manufacturers and hostnames.
- **TCP** — Perform half-open SYN scanning and identify services running on open ports.

Service identification combines an embedded IANA service registry with active protocol fingerprinting. Both results are preserved, allowing IPSpect to explain why it selected a particular service.

The scanner produces structured, colored terminal output and can export its findings as a Markdown report.

## Features

### Engine Selection

- Three independently selectable engines: ICMP, ARP, and TCP
- All engines enabled by default
- Select individual engines using `-icmp`, `-arp`, and `-tcp`
- Combine multiple engine flags in any order
- Dynamic stage numbering based on enabled engines
- TCP service identification runs only when TCP scanning is enabled

### Host Discovery

- Single IPv4 targets and IPv4 CIDR ranges
- Concurrent ICMP Echo discovery
- Multiple ICMP attempts per target
- Active ARP discovery on directly connected networks
- ICMP and ARP response deduplication
- Discovery-based target prioritization
- Preservation of undiscovered targets for TCP scanning

### Device Identification

- ARP IP and MAC address discovery
- Local network interface identification
- Manufacturer lookup using IEEE MAC registries
- Support for MA-L, MA-M, and MA-S assignments
- Reverse DNS (PTR) hostname resolution
- NetBIOS Node Status hostname discovery
- Offline manufacturer lookups using embedded databases
- Detection of locally administered MAC addresses

### TCP SYN Scanning

- Half-open TCP SYN scanning
- Default port range: `1-65535`
- Custom ports and ranges using `-p`
- Single ports, lists, ranges, and mixed specifications
- Concurrent SYN probe scheduling
- Open, closed, and filtered port classification
- Memory-conscious storage for multi-target scans

### Service Identification

- Embedded IANA TCP service registry
- Passive TCP banner inspection
- Active HTTP and HTTPS fingerprinting
- Active DNS-over-TCP fingerprinting
- SSH, FTP, and SMTP banner recognition
- HTTP server product identification
- HTTP response header collection
- Service alias normalization
- Fingerprint confidence and supporting evidence
- Final service resolution with an explanation
- TCP connection latency measurement

### Output and Reporting

- Colored terminal output
- Connected stage borders
- Dynamic stage numbers
- Separate discovery, identification, and results sections
- Formatted tables
- Per-port evidence and explanations
- Sensitive HTTP header redaction
- Markdown report export

---

## Requirements

- Linux
- Go
- Root privileges or appropriate raw-socket capabilities
- Network access to the selected targets

IPSpect uses raw sockets for ICMP, ARP, and TCP SYN operations.

Run directly from the source directory:

```bash
sudo go run main.go
```

Or use the installed binary:

```bash
sudo ipspect
```

ARP discovery uses Linux `AF_PACKET` sockets and only works for eligible targets on directly connected Layer 2 networks.

## Installation

From the project directory:

```bash
sudo go run main.go install
```

This builds and installs the IPSpect binary.

Run the installed binary:

```bash
sudo ipspect
```

Uninstall:

```bash
sudo ipspect uninstall
```

### Available Commands

| Command | Description |
|---|---|
| `install` | Build and install the binary |
| `uninstall` | Remove the installed binary |
| `help` | Display CLI usage |
| `version` | Display the current version |

---

## Usage

Start a scan:

```bash
sudo ipspect
```

IPSpect prompts for a target:

```text
IP >> 192.168.1.20
```

CIDR ranges are also supported:

```text
IP >> 192.168.1.0/24
```

The maximum supported CIDR size is `/16`.

Targets are selected interactively at runtime.

By default, IPSpect enables all three scanning engines and scans TCP ports `1-65535`.

## Engine Selection

IPSpect provides three independent engines.

| Engine | Flag | Function |
|---|---|---|
| ICMP | `-icmp` | ICMP Echo discovery |
| ARP | `-arp` | Local device discovery and identification |
| TCP | `-tcp` | TCP SYN scanning and service identification |

### Default Behavior

Running IPSpect without engine flags enables every engine:

```bash
sudo ipspect
```

Execution order:

```text
ICMP Discovery
      |
      v
ARP Discovery
      |
      v
TCP SYN Scanning
      |
      v
Service Identification
      |
      v
Scan Results
```

### Selective Execution

When one or more engine flags are specified, only those engines execute.

ICMP only:

```bash
sudo ipspect -icmp
```

ARP only:

```bash
sudo ipspect -arp
```

TCP only:

```bash
sudo ipspect -tcp
```

ICMP and ARP:

```bash
sudo ipspect -icmp -arp
```

ARP and TCP:

```bash
sudo ipspect -arp -tcp
```

All three explicitly:

```bash
sudo ipspect -icmp -arp -tcp
```

Engine flags can be combined in any order.

For example, these commands select the same engines:

```bash
sudo ipspect -arp -icmp
sudo ipspect -icmp -arp
```

Regardless of flag order, IPSpect follows its predefined execution order:

```text
ICMP -> ARP -> TCP
```

### Engine Execution Rules

- With no engine flags, all three engines are enabled.
- With engine flags, only explicitly selected engines are enabled.
- ICMP and ARP can run independently without TCP scanning.
- TCP can run without ICMP or ARP discovery.
- Service fingerprinting and final TCP results belong to the TCP engine.
- Port selection with `-p` applies to TCP scanning.

### Dynamic Stage Numbering

IPSpect calculates the number of active stages before execution.

| Command | Stages |
|---|---|
| `ipspect` | 5 |
| `ipspect -icmp` | 1 |
| `ipspect -arp` | 1 |
| `ipspect -tcp` | 3 |
| `ipspect -icmp -arp` | 2 |
| `ipspect -arp -tcp` | 4 |
| `ipspect -icmp -tcp` | 4 |

For example:

```bash
sudo ipspect -arp
```

Produces:

```text
┌──────────────────────────────────────────┐
│ 01 / 01  ARP Discovery                   │
├──────────────────────────────────────────┘
│ accept arp [192.168.1.1]
│ IP           MAC                VENDOR
│ 192.168.1.1  d4:76:ea:1a:57:b2  zte corporation
└──────────────────────────────────────────
```

Stage numbering is based on the selected execution flow rather than fixed stage identifiers.

---

## Port Selection

Use `-p` to control TCP port coverage.

### Single Port

```bash
sudo ipspect -tcp -p 22
```

### Port Range

```bash
sudo ipspect -tcp -p 1-1000
```

### Multiple Ports

```bash
sudo ipspect -tcp -p 21,22,80,443
```

### Mixed Ports and Ranges

```bash
sudo ipspect -tcp -p 21,22,80,443,8000-8100
```

### Combining Flags

```bash
sudo ipspect -arp -tcp -p 22,80,443
```

This runs ARP discovery and TCP scanning, limiting the TCP scan to ports 22, 80, and 443.

Port selection supports:

- TCP port numbers from `1` through `65535`
- Comma-separated lists
- Inclusive port ranges
- Mixed lists and ranges

Duplicate ports are removed and selected ports are sorted.

**Without `-p`, TCP scanning covers all 65,535 TCP ports.**

There are no separate quick, smart, or full scanning modes. Port coverage is controlled through `-p`.

---

## Scan Architecture

IPSpect separates target discovery, TCP packet handling, service identification, and result formatting.

```text
Target Input
     |
     v
Engine Selection
     |
     +-----------------------+
     |                       |
     v                       v
ICMP Discovery          ARP Discovery
     |                       |
     |                  ARP Enrichment
     |                       |
     |                  +----+----+
     |                  |    |    |
     |                 IEEE PTR  NetBIOS
     |                  |    |    |
     |                  +----+----+
     |                       |
     +-----------+-----------+
                 |
                 v
       Target Prioritization
                 |
                 v
          TCP SYN Scanning
                 |
                 v
          Open TCP Ports
                 |
                 v
       Service Identification
                 |
          +------+------+
          |             |
          v             v
     IANA Lookup    Fingerprinting
          |             |
          |        TCP / HTTP
          |        HTTPS / DNS
          |        Banner Analysis
          |             |
          +------+------+
                 |
                 v
         Service Resolution
                 |
                 v
           Final Results
                 |
                 v
          Markdown Export
```

The flow is conditional on the selected engines.

For example, an ARP-only scan stops after device discovery and identification.

The main controller lives in:

```text
internal/portscan/controller.go
```

It coordinates the enabled engines and delegates their implementation to individual packages.

---

## ICMP Discovery

ICMP discovery is implemented in:

```text
internal/portscan/ping/
```

The engine sends ICMP Echo requests to the requested targets and records responding addresses.

### Configuration

| Setting | Value |
|---|---|
| Concurrent discovery window | 500 |
| Reply timeout | 750 ms |
| Retries | 3 |
| Maximum attempts per target | 4 |

ICMP replies are associated with their outstanding requests using identification and sequence information.

Discovered hosts are stored in:

```go
models.LOOT.ICMPReachable
```

### Behavior

ICMP discovery provides host reachability evidence.

A host that does not respond to ICMP is not necessarily offline. Firewalls, routing behavior, and device configuration can prevent replies.

When TCP scanning is enabled, ICMP results are used to prioritize responding hosts.

When ICMP is selected alone, IPSpect performs only ICMP discovery.

---

## ARP Discovery

ARP discovery is implemented in:

```text
internal/portscan/arp/
```

The engine discovers directly connected IPv4 devices using Ethernet ARP requests.

ARP discovery supports both single-IP and CIDR targets.

### Discovery Process

1. Enumerate eligible local interfaces.
2. Identify target addresses belonging to directly connected networks.
3. Send ARP requests through the appropriate interfaces.
4. Receive and validate ARP replies.
5. Extract the IP and MAC addresses.
6. Record the interface associated with each response.
7. Deduplicate discovered devices.
8. Enrich discovered devices with manufacturer and hostname information.

### Configuration

| Setting | Value |
|---|---|
| ARP request rate | 500 packets/second |
| Final reply wait | 750 ms |
| Requests per eligible target | 1 |

### ARP Result Model

ARP results preserve:

| Field | Description |
|---|---|
| IP | Discovered IPv4 address |
| MAC | Responding MAC address |
| Vendor | Registered manufacturer or organization |
| Interface | Local interface used for discovery |
| Hostname | Preferred discovered hostname |
| PTRName | Reverse DNS hostname |
| NetBIOSName | NetBIOS workstation/server name |

Results are stored in:

```go
models.LOOT.ARPReachable
models.LOOT.ARPResults
```

`ARPReachable` provides addresses for target prioritization.

`ARPResults` preserves detailed device information.

### Device Enrichment

ARP device enrichment is implemented under:

```text
internal/portscan/arp/enrich/
```

It uses three identification methods.

#### IEEE Manufacturer Lookup

IPSpect uses embedded IEEE MAC assignment registries:

- MA-L — 24-bit assignments
- MA-M — 28-bit assignments
- MA-S — 36-bit assignments

The most specific matching assignment takes priority.

These databases identify the organization associated with a MAC prefix, not necessarily the exact product or device model.

Locally administered or randomized MAC addresses may not identify a reliable manufacturer.

Manufacturer lookups run locally without requiring an API request during scanning.

IEEE registry information:

https://standards.ieee.org/products-programs/regauth/

#### Reverse DNS (PTR)

IPSpect attempts to resolve a hostname using reverse DNS.

Example:

```text
192.168.1.1 -> _gateway
```

PTR resolution depends on the network's DNS configuration and may return no result.

A PTR hostname is not automatically proof of the device's identity.

#### NetBIOS Node Status

IPSpect sends a NetBIOS Node Status request over UDP port 137.

When a compatible device responds, the engine extracts a suitable unique workstation or server name.

This is particularly useful for devices exposing legacy Windows/NetBIOS naming services.

NetBIOS results may be empty when the service is disabled, blocked, or unsupported.

### ARP Limitations

- ARP operates on the local Layer 2 network.
- Ordinary routers do not forward ARP requests to remote networks.
- MAC address assignments do not guarantee exact device identity.
- PTR and NetBIOS hostnames may be absent or misleading.
- ARP responses do not provide cryptographic authentication.

---

## Target Prioritization

Target prioritization is implemented in:

```text
internal/portscan/priority.go
```

When TCP scanning is enabled, IPSpect builds a deduplicated scanning order using the discovery results available from the selected engines.

### Priority Rules

| Priority | Targets |
|---|---|
| 1 | ICMP responders |
| 2 | ARP responders not already included |
| 3 | Remaining original targets |

### Example

Original targets:

```text
192.168.1.10
192.168.1.11
192.168.1.12
192.168.1.13
192.168.1.14
```

ICMP discovered:

```text
192.168.1.12
192.168.1.14
```

ARP discovered:

```text
192.168.1.11
192.168.1.12
```

Final TCP scan order:

```text
192.168.1.12  ICMP
192.168.1.14  ICMP
192.168.1.11  ARP
192.168.1.10  Remaining
192.168.1.13  Remaining
```

The address `192.168.1.12` appears only once despite responding to both discovery protocols.

### Guarantees

- Original unique targets are retained.
- Duplicate addresses are removed.
- Discovery does not add out-of-scope targets to the TCP scan.
- ICMP responders receive the highest priority.
- ARP-only responders follow.
- Undiscovered hosts remain eligible for TCP scanning.
- Each unique target is scheduled once by the TCP search stage.

Prioritization changes scanning order, not total TCP port coverage.

If only TCP is enabled, scanning proceeds without ICMP or ARP discovery results.

---

## TCP SYN Scanning

TCP scanning is implemented through two packages:

```text
internal/portscan/search/
internal/portscan/probe/
```

### Search Package

The `search/` package manages:

- Target and port iteration
- Scan job scheduling
- Outstanding probe tracking
- SYN dispatch
- Reply classification
- Probe timeouts
- Port-state recording

### Probe Package

The `probe/` package handles:

- Raw TCP sockets
- Source IPv4 selection
- Source port allocation
- TCP sequence generation
- TCP segment construction
- TCP checksums
- SYN transmission
- RST transmission
- TCP reply reception

### Half-Open SYN Exchange

For an open TCP port:

```text
IPSpect -> SYN
Target  -> SYN/ACK
IPSpect -> RST
```

The TCP three-way handshake is not completed during SYN port discovery.

Service enrichment later uses ordinary TCP connections to open ports.

### Port States

| Response | Classification |
|---|---|
| SYN/ACK | Open |
| RST | Closed |
| No matching response before timeout | Filtered |

The scanner maintains up to 500 outstanding SYN probes and uses a 500 ms timeout.

Silent ports are classified as filtered by the scanner, but this does not guarantee that a firewall is present. Packet loss, filtering, and other network behavior may produce the same result.

---

## Result Storage

IPSpect adjusts result storage based on the number of targets and whether specific ports were requested.

### Single Target

For a single target:

- Open ports are retained individually.
- Closed and filtered port information may be retained internally.
- The normal output summarizes large closed and filtered sets as counts.

### Multiple Targets

For default full-range multi-target scans:

- Open ports are recorded individually.
- Closed ports are counted.
- Filtered ports are counted.
- Individual closed and filtered port numbers are omitted to reduce memory usage.

### Explicit Port Selection

When `-p` is used, selected closed and filtered port information can also be retained for detailed reporting.

This makes focused scans easier to inspect without requiring the same storage overhead as full-range scans across large networks.

---

## Service Identification

Service identification is implemented in:

```text
internal/portscan/enrich/
```

Only TCP ports classified as open are enriched.

IPSpect separates the identification process into three stages:

1. IANA database lookup
2. Protocol fingerprinting
3. Final service resolution

### Stage 1 — IANA Database Lookup

IPSpect embeds the official IANA Service Name and Transport Protocol Port Number Registry.

The registry provides registered service names associated with TCP port numbers.

Database:

https://www.iana.org/assignments/service-names-port-numbers/

The CSV registry is embedded into the compiled binary and loaded once into memory.

Example:

| Port | Registered Service |
|---|---|
| 53 | domain |
| 80 | http |
| 443 | https |
| 52869 | unknown |

A registered service name is only a lookup result.

For example, a service listening on port 443 is not automatically an HTTPS server.

IPSpect preserves the original database result separately from the detected service.

### Stage 2 — Protocol Fingerprinting

Fingerprinting is implemented in:

```text
internal/portscan/enrich/fingerprint/
```

The engine examines observable network behavior instead of trusting a port number.

Supported identification methods currently include:

| Protocol | Identification Method |
|---|---|
| HTTP | Valid HTTP response to an active plaintext request |
| HTTPS | HTTP response received over a TLS connection |
| DNS | Valid matching DNS-over-TCP response |
| SSH | SSH identification banner |
| FTP | Recognizable FTP greeting |
| SMTP | Recognizable SMTP/ESMTP greeting |

#### Passive Banner Inspection

IPSpect first attempts to collect an unsolicited TCP banner.

For example:

```text
SSH-2.0-OpenSSH_9.x
```

Recognizable protocol signatures can identify a service without relying on the registered port.

FTP and SMTP detection is conservative because both protocols can use similar response codes.

#### HTTP Fingerprinting

IPSpect can send an HTTP request to an open TCP port:

```http
GET / HTTP/1.0
Host: 192.168.1.20
User-Agent: ipspect
Connection: close
```

A recognizable HTTP response provides protocol evidence.

Example:

```text
HTTP/1.0 200 OK
```

The fingerprint engine can extract the server product from the HTTP `Server` header.

Example:

```text
Mini web server 1.0 ZTE corp 2005.
```

HTTP detection is not restricted to port 80.

#### HTTPS Fingerprinting

HTTPS is tested independently using a TLS connection followed by an HTTP request.

A successful plaintext HTTP probe does not automatically prevent the HTTPS probe.

This allows the engine to distinguish:

- HTTP only
- HTTPS only
- Both observed protocols
- No confirmed HTTP protocol

TLS certificate verification is disabled for this identification probe.

A successful TLS connection therefore confirms protocol behavior but does not authenticate the server's identity.

Some TLS services return an HTTP error to plaintext requests. IPSpect attempts to recognize known diagnostic responses, although ambiguous replies can still occur.

#### DNS Fingerprinting

IPSpect sends a framed DNS-over-TCP query and validates the response.

Validation includes:

- Matching transaction identifier
- DNS response flags
- Expected question count
- Matching DNS question

Example evidence:

```text
Valid DNS-over-TCP response (RCODE=NOERROR)
```

A valid DNS response can confirm the DNS protocol independently of the registered port name.

The current DNS fingerprint supports a specific response format and may not recognize every valid implementation.

#### Multiple Fingerprints

IPSpect can preserve multiple confirmed protocol observations for a single TCP port.

For example:

```text
Port: 8443

Fingerprint 1:
  Service: http
  Evidence: HTTP response

Fingerprint 2:
  Service: https
  Evidence: HTTP response over TLS
```

The fingerprint results retain their own evidence, banners, and available product information.

### Stage 3 — Final Service Resolution

The final resolver compares the original IANA name with the fingerprint evidence.

It preserves:

| Field | Purpose |
|---|---|
| DBLookup | Original IANA registered service |
| Fingerprint | Observed protocol identification |
| Service | Final resolved service |
| ServiceReason | Explanation of the selected result |

Example:

```text
Port: 443

DB Lookup:
  https

Fingerprint:
  http

Final Service:
  http

Reason:
  Fingerprint overrides IANA "https"
```

### Service Aliases

Some IANA service names differ from their common protocol names.

For example:

```text
IANA: domain
Fingerprint: dns
```

IPSpect uses a service alias registry to recognize compatible names.

Supported aliases include:

| IANA Name | Normalized Protocol |
|---|---|
| domain | dns |
| www | http |
| www-http | http |
| http-alt | http |
| submission | smtp |

Alias matching does not mean that all service variants are interchangeable.

For example, plaintext HTTP and HTTPS remain distinct.

### Service Resolution Rules

- High-confidence fingerprints determine the final service.
- Compatible IANA names can corroborate a fingerprint.
- Conflicting IANA entries remain preserved for inspection.
- Multiple confirmed protocols can be retained.
- An unverified IANA entry does not become a confirmed service.
- If no supported fingerprint matches, the final service remains `unknown`.

The fingerprint engine does not guarantee identification of every possible TCP service.

### HTTP Header Collection

For recognized HTTP services, IPSpect records response headers.

Examples include:

- Content-Type
- Content-Length
- Server
- Cache-Control
- Connection
- X-Frame-Options

Sensitive headers such as `Set-Cookie` are redacted before reporting.

### Latency

The TCP enrichment stage measures connection latency for its initial TCP connection attempt.

This is not the same as the SYN probe round-trip time or the total fingerprinting duration.

---

## Terminal Output

Terminal formatting is implemented in:

```text
internal/output/
```

IPSpect uses connected stage containers to organize its results.

The terminal theme includes:

- Orange stage borders
- Cyan section headings
- Yellow table column headings
- Green successful discoveries
- Gray closed-port summaries
- Yellow filtered-port summaries and warnings

### Stage 1 — ICMP Discovery

Example:

```text
┌──────────────────────────────────────────┐
│ 01 / 05  ICMP Discovery                  │
├──────────────────────────────────────────┘
│ accept icmp [192.168.1.1]
└──────────────────────────────────────────
```

### Stage 2 — ARP Discovery

Example:

```text
┌──────────────────────────────────────────┐
│ 02 / 05  ARP Discovery                   │
├──────────────────────────────────────────┘
│ accept arp [192.168.1.1]
│ IP           MAC                VENDOR           PTR       NETBIOS  INTERFACE
│ 192.168.1.1  d4:76:ea:1a:57:b2  zte corporation  _gateway  -        wlp8s0
└──────────────────────────────────────────
```

### Stage 3 — TCP SYN Scanning

Example:

```text
┌──────────────────────────────────────────┐
│ 03 / 05  TCP SYN Scanning                │
├──────────────────────────────────────────┘
│ 192.168.1.1
│ open     [53, 80, 443]
│ closed   54724
│ filtered 10808
└──────────────────────────────────────────
```

### Stage 4 — Service Identification

IPSpect presents the database lookup and fingerprint results separately.

Example:

```text
┌──────────────────────────────────────────┐
│ 04 / 05  Service Identification          │
├──────────────────────────────────────────┘
│
│ DB Lookup
│ HOST         PORT  IANA SERVICE
│ 192.168.1.1  53    domain
│ 192.168.1.1  80    http
│ 192.168.1.1  443   https
│
│ Fingerprint Lookup
│ HOST         PORT  DETECTED  CONFIDENCE
│ 192.168.1.1  53    dns       high
│ 192.168.1.1  80    http      high
│ 192.168.1.1  443   http      high
└──────────────────────────────────────────
```

The actual fingerprint table also includes product, banner, and evidence information.

### Stage 5 — Scan Results

The final output separates the compact port summary from detailed evidence.

Example:

```text
┌──────────────────────────────────────────┐
│ 05 / 05  Scan Results                    │
├──────────────────────────────────────────┘
│ HOST  192.168.1.1
│ PORT  STATE  SERVICE  LATENCY
│ 53    open   dns      11.647992ms
│ 80    open   http     11.682057ms
│ 443   open   http     7.320794ms
│
│ Port 53 — Details
│   Reason: Fingerprint confirmed IANA
│
│ Port 80 — Details
│   Banner: HTTP/1.0 200 OK
│   Reason: Fingerprint confirmed IANA
│   Headers:
│     Content-Type: text/html; charset=utf-8
│     Server: Mini web server 1.0 ZTE corp 2005.
│     Set-Cookie: [redacted]
│
│ Port 443 — Details
│   Banner: HTTP/1.1 400 Bad Request
│   Reason: Fingerprint overrides IANA "https"
└──────────────────────────────────────────
```

Examples are illustrative of the current output format. Actual results depend on the target and network conditions.

---

## Saving Results

Use `-s` to save the scan results as Markdown:

```bash
sudo ipspect -s
```

Combine it with engine selection:

```bash
sudo ipspect -arp -s
```

Or with TCP port selection:

```bash
sudo ipspect -tcp -p 22,80,443 -s
```

### Markdown Report Contents

The exported report follows the same five-stage organization:

1. ICMP Discovery
2. ARP Discovery
3. TCP SYN Scanning
4. Service Identification
5. Scan Results

Depending on which engines were enabled, some stages may contain no recorded results.

The report preserves:

- Target specification
- Selected TCP port specification
- ICMP-reachable hosts
- ARP device details
- IEEE manufacturer information
- PTR and NetBIOS hostnames
- TCP port summaries
- IANA registered services
- Fingerprint results and evidence
- Final resolved services
- Service resolution reasons
- TCP banners and connection latency
- HTTP response headers
- Multiple fingerprint observations when present

Sensitive HTTP authentication and cookie header values are redacted during export.

### Output Filename

The filename is derived from the target specification.

For example:

```text
192.168.1.1.md
```

The report is written to the current working directory.

---

## Project Structure

The following is an abbreviated package-level view of the main IPSpect components.

```text
ipspect/
├── cmd/
│   ├── flags.go
│   ├── lifecycle.go
│   └── root.go
│
├── internal/
│   ├── bootstrap/
│   │   ├── install.go
│   │   └── uninstall.go
│   │
│   ├── models/
│   │   ├── scope.go
│   │   └── ...
│   │
│   ├── output/
│   │   ├── format.go
│   │   ├── logger.go
│   │   ├── stage.go
│   │   └── save.go
│   │
│   ├── portscan/
│   │   ├── controller.go
│   │   ├── priority.go
│   │   │
│   │   ├── ping/
│   │   │   └── ...
│   │   │
│   │   ├── arp/
│   │   │   ├── controller.go
│   │   │   ├── scan.go
│   │   │   ├── result.go
│   │   │   ├── ...
│   │   │   └── enrich/
│   │   │       ├── controller.go
│   │   │       ├── ieee.go
│   │   │       ├── ptr.go
│   │   │       ├── netbios.go
│   │   │       └── data/
│   │   │
│   │   ├── search/
│   │   │   └── ...
│   │   │
│   │   ├── probe/
│   │   │   └── ...
│   │   │
│   │   └── enrich/
│   │       ├── controller.go
│   │       ├── registry.go
│   │       ├── service.go
│   │       ├── port.go
│   │       ├── resolve.go
│   │       ├── tcp.go
│   │       ├── data/
│   │       │   └── services.csv
│   │       └── fingerprint/
│   │           ├── controller.go
│   │           ├── detect.go
│   │           ├── dns.go
│   │           └── http.go
│   │
│   └── input.go
│
├── go.mod
├── go.sum
├── main.go
└── README.md
```

### Package Responsibilities

| Package | Responsibility |
|---|---|
| `cmd` | CLI flags, commands, and engine selection |
| `internal` | Target input and port selection |
| `models` | Shared configuration, engine state, and results |
| `bootstrap` | Installation and removal |
| `portscan` | Engine orchestration and target prioritization |
| `ping` | ICMP discovery |
| `arp` | Local ARP discovery |
| `arp/enrich` | Manufacturer and hostname identification |
| `search` | TCP SYN scheduling and classification |
| `probe` | Low-level TCP packet operations |
| `enrich` | IANA lookup, banner collection, and service resolution |
| `fingerprint` | Protocol identification and supporting evidence |
| `output` | Terminal presentation and Markdown export |

---

## Embedded Databases

IPSpect uses local CSV registries instead of requiring online lookups for every scan.

### IEEE MAC Registries

Located under:

```text
internal/portscan/arp/enrich/data/
```

The embedded IEEE files support manufacturer identification from MAC assignments.

### IANA Service Registry

Located at:

```text
internal/portscan/enrich/data/services.csv
```

The IANA database maps registered TCP port numbers to service names.

### Updating the Databases

Database files can be refreshed from their respective official sources.

IEEE:

https://standards-oui.ieee.org/

IANA:

https://www.iana.org/assignments/service-names-port-numbers/

Because the databases are embedded into the Go binary, **the binary must be rebuilt or reinstalled after updating the files**.

Database updates do not change the service fingerprinting logic.

---

## Design Principles

### Engine Independence

ICMP, ARP, and TCP can be selected independently.

Enabling one engine does not automatically enable the others.

Service identification belongs to the TCP scanning workflow.

### Discovery Does Not Exclude Targets

ICMP and ARP discovery results improve scan ordering.

Targets that do not respond remain eligible for TCP scanning when TCP is enabled.

### Deduplication Prevents Repeated Scans

ICMP responders, ARP responders, and original target addresses are merged into a unique ordered list.

Each unique IP is scanned once by the TCP search stage.

### Port Registration Is Not Service Identification

IANA provides registered service names, not proof that a particular application is running.

A service listening on port 443 is not automatically HTTPS.

IPSpect uses fingerprint evidence to determine the final service.

### Evidence Is Preserved

IPSpect retains the original database result, detected protocol information, and final decision.

Service resolution does not silently discard conflicting evidence.

### Packet Discovery Is Separate From Enrichment

TCP SYN scanning identifies open ports without completing TCP handshakes during the port-discovery stage.

Full TCP connections are used afterward for service inspection.

### Port Coverage Is User-Controlled

The default TCP scan covers ports `1-65535`.

Users control port coverage through `-p`, without requiring additional scanning modes.

### Output Reflects Execution

Stage numbers are calculated from the enabled engines.

The terminal output follows the selected scanning workflow.

### Components Have Separate Responsibilities

Scanning engines, packet operations, manufacturer lookups, fingerprinting, service resolution, and reporting are implemented in separate packages.

---

## Limitations

- TCP SYN scanning currently targets IPv4.
- CIDR scanning supports IPv4 networks with the configured `/16` size limit.
- ARP discovery is limited to directly connected networks.
- ARP cannot directly identify hosts behind ordinary routers.
- IEEE MAC assignments do not guarantee exact device models.
- Randomized or locally administered MAC addresses may hide manufacturer identity.
- PTR and NetBIOS hostname resolution may fail or return misleading names.
- ICMP nonresponse does not imply that a host is offline.
- TCP SYN timeouts may reflect filtering, packet loss, or network congestion.
- Service fingerprinting currently supports a limited set of protocols.
- Some services require application-specific probes that are not yet implemented.
- Unrecognized services remain `unknown`.
- HTTP and HTTPS fingerprinting can encounter ambiguous server responses.
- TLS certificate authenticity is not verified during HTTPS fingerprinting.
- Some services do not provide readable TCP banners.
- Connection latency does not represent total fingerprinting time.
- Full-range scans of large CIDR networks can produce substantial network traffic and require significant time.

---

## Legal Notice

Only scan systems and networks that you own or have explicit authorization to assess.

IPSpect performs active network probing, including raw TCP SYN scans and application-level identification requests. Use it responsibly and respect the rules governing the networks being assessed.
