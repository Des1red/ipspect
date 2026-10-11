
# ipspect

`ipspect` is a command-line network scanner written in Go, designed for IPv4 host discovery, TCP port scanning, and service inspection.

It combines ICMP and ARP discovery with a prioritized, half-open TCP SYN scan. Open ports are subsequently enriched through TCP connections to identify services, retrieve banners, inspect HTTP responses, and measure connection latency.

Discovery results are used to prioritize targets, not to exclude them. Every requested IP is still included in the TCP scan, even if it does not respond to ICMP or ARP.

## Features

### Host Discovery
- Single IPv4 addresses and IPv4 CIDR ranges
- Concurrent ICMP Echo discovery
- Three ICMP retries after the initial request
- Active ARP discovery on directly connected IPv4 networks
- ARP MAC address and interface identification
- ICMP/ARP discovery result deduplication
- Target prioritization before TCP scanning
- Preservation of undiscovered targets for TCP scanning

### TCP Port Scanning
- Half-open TCP SYN scanning
- Default port range: `1-65535`
- Configurable port selection with `-p`
- Single ports, ranges, lists, and mixed specifications
- Concurrent window of 500 outstanding SYN probes
- Open, closed, and filtered classification
- Memory-conscious results for CIDR scans

### Service Enrichment
- Built-in TCP port/service mapping
- Concurrent enrichment with 128 workers
- TCP banner grabbing
- HTTP and HTTPS probing
- HTTP response header extraction
- TCP connection latency measurement

### Output
- Colored terminal output
- ICMP and ARP discovery information
- ARP IP, MAC, and interface details
- Per-host TCP port summaries
- Service information and HTTP headers
- Markdown report export

## Requirements

- Linux
- Go
- Root privileges or appropriate raw-socket capabilities
- Network access to the selected targets

`ipspect` uses raw sockets for ICMP, ARP, and TCP SYN operations.

Run with elevated privileges:

```bash
sudo go run main.go
```

Or, after installation:

```bash
sudo ipspect
```

ARP discovery uses Linux `AF_PACKET` sockets and operates only on directly connected Ethernet-style networks.

## Installation

From the project directory:

```bash
sudo go run main.go install
```

This builds and installs the `ipspect` binary.

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

## Usage

Start a scan:

```bash
sudo ipspect
```

The program prompts for a target:

```text
IP >> 192.168.1.20
```

CIDR scanning is also supported:

```text
IP >> 192.168.1.0/24
```

The maximum supported CIDR size is `/16`.

By default, the scanner inspects every TCP port from `1` through `65535`.

## Port Selection

Use `-p` to control which ports are scanned.

### Single Port

```bash
sudo ipspect -p 22
```

### Port Range

```bash
sudo ipspect -p 1-1000
```

### Multiple Ports

```bash
sudo ipspect -p 21,22,80,443
```

### Mixed Ports and Ranges

```bash
sudo ipspect -p 21,22,80,443,8000-8100
```

Port selection supports values between `1` and `65535`.

Duplicate ports are automatically removed, and the selected ports are sorted before scanning.

There are no separate quick, smart, or full scanning modes. The `-p` flag controls coverage.

If `-p` is omitted, all 65,535 TCP ports are scanned.

## Scan Architecture

The scanner is divided into independent discovery, scheduling, packet handling, enrichment, and output stages.

```text
Target Input
     |
     v
ICMP Discovery
     |
     v
ARP Discovery
     |
     v
Target Prioritization
     |
     |-- Priority 1: ICMP responders
     |-- Priority 2: ARP-only responders
     |-- Priority 3: Remaining targets
     |
     |-- Deduplicate IP addresses
     |
     v
TCP SYN Search
     |
     |-- SYN/ACK -> Open -> RST
     |-- RST     -> Closed
     |-- Timeout -> Filtered
     |
     v
Port Result Sorting
     |
     v
Service Enrichment
     |
     |-- Service lookup
     |-- TCP banner
     |-- HTTP/HTTPS inspection
     |-- HTTP headers
     |-- Connection latency
     |
     v
Terminal Results / Markdown Export
```

The main scanning controller orchestrates these stages.

Each scanning package exposes its own controller while keeping its internal operations private.

## ICMP Discovery

ICMP discovery is handled by `internal/portscan/ping/`.

It uses `golang.org/x/net/icmp` and supports IPv4 and IPv6 Echo operations internally, although TCP SYN scanning currently targets IPv4.

### Configuration

| Setting | Value |
|---|---|
| Concurrent discovery window | 500 |
| Reply timeout | 750 ms |
| Retries | 3 |
| Maximum requests per target | 4 |

Each outstanding request receives an ICMP sequence number.

Responses are validated using the ICMP identifier, sequence number, and source IP.

Discovered addresses are stored in:

```go
models.LOOT.ICMPReachable
```

ICMP failure does not prevent TCP scanning.

## ARP Discovery

ARP discovery is handled by `internal/portscan/arp/`.

It uses Linux raw Ethernet sockets to identify devices on directly connected IPv4 networks.

ARP discovery runs for both single-IP and CIDR scans.

### Process

1. Enumerate eligible local network interfaces.
2. Identify target IPs belonging to directly connected subnets.
3. Send ARP requests on the appropriate interface.
4. Receive and validate ARP replies.
5. Extract the responding IP and MAC address.
6. Associate each response with its local interface.
7. Deduplicate and sort the discovered hosts.

### Configuration

| Setting | Value |
|---|---|
| ARP request rate | 500 packets/second |
| Final reply wait | 750 ms |
| Requests per target | 1 |

ARP results contain:

| Field | Description |
|---|---|
| IP | Discovered IPv4 address |
| MAC | Responding hardware address |
| Interface | Local interface used for discovery |
| Vendor | Reserved for future manufacturer identification |

Results are stored in:

```go
models.LOOT.ARPReachable
models.LOOT.ARPResults
```

`ARPReachable` provides IP addresses for prioritization.

`ARPResults` preserves detailed information including the MAC address and interface.

Vendor identification is not implemented yet.

### ARP Limitations

ARP discovery is limited to the local Layer 2 network.

It cannot directly discover devices behind ordinary routers.

Only eligible local IPv4 targets are probed, and targets outside those networks are left for other discovery and TCP scanning stages.

ARP replies also do not provide cryptographic proof of a host's identity.

## Target Prioritization

Target prioritization is implemented in:

```text
internal/portscan/priority.go
```

After ICMP and ARP discovery finish, IPSpect constructs a single ordered target list.

### Priority Rules

| Priority | Targets |
|---|---|
| 1 | ICMP-discovered hosts |
| 2 | ARP-discovered hosts not already included |
| 3 | All remaining original targets |

### Example

Original target range:

```text
192.168.1.10
192.168.1.11
192.168.1.12
192.168.1.13
192.168.1.14
```

ICMP discovery:

```text
192.168.1.12
192.168.1.14
```

ARP discovery:

```text
192.168.1.11
192.168.1.12
```

Final scanning order:

```text
192.168.1.12  ICMP
192.168.1.14  ICMP
192.168.1.11  ARP
192.168.1.10  Remaining
192.168.1.13  Remaining
```

Even though `192.168.1.12` was discovered by both protocols, it appears only once.

### Guarantees

- Every original unique target is retained.
- Duplicate IPs are removed.
- Discovery does not add addresses outside the requested scope.
- ICMP responders receive the highest priority.
- ARP-only responders are prioritized next.
- Silent hosts are still scanned.
- Each unique target is processed only once by the TCP search stage.

Prioritization changes the scanning order, not the selected port range or total coverage.

## TCP SYN Scanning

TCP scanning is divided between two packages:

```text
internal/portscan/search/
internal/portscan/probe/
```

### Search

The `search/` package manages:

- Scan jobs and scheduling
- Target and port iteration
- Active probe tracking
- SYN dispatch
- Reply classification
- Probe timeouts
- Port-state recording

### Probe

The `probe/` package handles:

- Raw TCP socket initialization
- Source IPv4 selection
- Source port allocation
- TCP sequence generation
- TCP segment construction
- TCP checksums
- SYN and RST transmission
- TCP reply reception

### Half-Open SYN Exchange

For an open port:

```text
ipspect -> SYN
target  -> SYN/ACK
ipspect -> RST
```

The handshake is not completed during port discovery.

### Port States

| Response | Classification |
|---|---|
| SYN/ACK | Open |
| RST | Closed |
| No matching response before timeout | Filtered |

The scanner maintains up to 500 outstanding SYN probes and uses a 500 ms timeout.

Valid responses are correlated with pending probes using the target address, source/destination ports, and TCP acknowledgment information.

## Result Storage

IPSpect adapts its result storage depending on the target count and selected ports.

### Single Target

Open ports are recorded individually.

During a default full-range scan, closed and filtered port numbers may be retained internally, while the normal summary displays their counts.

When `-p` is specified, selected closed and filtered ports are also retained as individual results.

### Multiple Targets

For a default full-range CIDR scan:

- Open ports are retained individually.
- Closed ports are counted.
- Filtered ports are counted.
- Individual closed and filtered port numbers are not retained.

This avoids storing tens of thousands of unnecessary records for every address in a large CIDR range.

### Explicit Port Selection

When `-p` is supplied, the selected closed and filtered ports are retained even during multi-target scans.

This preserves detailed results for focused scans.

## Service Enrichment

Service enrichment is handled by:

```text
internal/portscan/enrich/
```

Only ports classified as open are enriched.

The enrichment stage uses a worker pool with 128 concurrent workers.

For each open port, IPSpect attempts to identify its service using the built-in common-port table.

Unknown ports receive the service label:

```text
unknown
```

### TCP Banner Grabbing

For non-HTTP services, IPSpect establishes a full TCP connection and attempts to read a service banner.

Example:

```text
SSH-2.0-OpenSSH_9.x
```

Connection latency is recorded during the TCP connection attempt.

### HTTP and HTTPS Inspection

Known HTTP/HTTPS service ports receive an HTTP-aware probe.

The request uses HTTP/1.0 and includes:

```http
GET / HTTP/1.0
Host: 192.168.1.20
User-Agent: ipspect
Connection: close
```

IPSpect collects the HTTP status line and response headers.

For HTTPS, a TLS connection is established before sending the request.

TLS certificate verification is disabled during this inspection stage to permit service probing of endpoints with untrusted certificates. Certificate authenticity is therefore not verified.

HTTP headers are retained as part of the port details.

## Terminal Output

The output package is located in:

```text
internal/output/
```

It provides colored terminal messages, port summaries, discovery output, and formatted result tables.

### ICMP Output

```text
accept icmp [192.168.1.20]
```

### ARP Output

```text
accept arp [192.168.1.20]

IP            MAC                INTERFACE
192.168.1.20  aa:bb:cc:dd:ee:ff  enp9s0
```

The MAC and interface values above are illustrative.

### Port Summary

```text
192.168.1.20
open     [5355, 27500]
closed   65533
filtered 0
```

### Detailed Results

```text
HOST   192.168.1.20
PORT   STATE  SERVICE      BANNER  LATENCY
5355   open   llmnr                203.788µs
27500  open   tw-auth-key          199.04µs
```

The exact results depend on the target, network conditions, and selected ports.

## Saving Results

Use `-s` to export the scan as Markdown:

```bash
sudo ipspect -s
```

It can be combined with port selection:

```bash
sudo ipspect -s -p 22,80,443
```

The Markdown report currently contains:

- Original target specification
- Selected port specification
- ICMP-reachable hosts
- Port results
- Service names
- TCP banners
- Connection latency
- HTTP response headers

ARP information is collected and displayed in the terminal, but ARP result export has not yet been added to the Markdown writer.

The output filename is generated from the target specification.

## Project Structure

```text
.
├── cmd/
│   ├── flags.go
│   ├── lifecycle.go
│   └── root.go
│
├── docs/
│   └── changelog files
│
├── internal/
│   ├── bootstrap/
│   │   ├── install.go
│   │   └── uninstall.go
│   │
│   ├── models/
│   │   ├── scope.go
│   │   └── version.go
│   │
│   ├── output/
│   │   ├── format.go
│   │   ├── logger.go
│   │   └── save.go
│   │
│   ├── portscan/
│   │   ├── controller.go
│   │   ├── priority.go
│   │   │
│   │   ├── arp/
│   │   │   ├── controller.go
│   │   │   ├── interfaces.go
│   │   │   ├── recieve_linux.go
│   │   │   ├── result.go
│   │   │   ├── scan.go
│   │   │   ├── send_linux.go
│   │   │   ├── socket_linux.go
│   │   │   └── types.go
│   │   │
│   │   ├── ping/
│   │   │   ├── controller.go
│   │   │   ├── dispatch.go
│   │   │   ├── recieve.go
│   │   │   ├── reply.go
│   │   │   ├── result.go
│   │   │   ├── scan.go
│   │   │   ├── scanner.go
│   │   │   ├── send.go
│   │   │   ├── sequence.go
│   │   │   ├── timeout.go
│   │   │   └── types.go
│   │   │
│   │   ├── probe/
│   │   │   ├── checksum.go
│   │   │   ├── packet.go
│   │   │   ├── recieve.go
│   │   │   ├── scanner.go
│   │   │   ├── send.go
│   │   │   ├── sequence.go
│   │   │   └── source.go
│   │   │
│   │   ├── search/
│   │   │   ├── controller.go
│   │   │   ├── dispach.go
│   │   │   ├── ports.go
│   │   │   ├── reply.go
│   │   │   ├── search.go
│   │   │   ├── state.go
│   │   │   ├── timeout.go
│   │   │   └── types.go
│   │   │
│   │   └── enrich/
│   │       ├── common_ports.go
│   │       ├── controller.go
│   │       ├── headers.go
│   │       ├── http.go
│   │       ├── port.go
│   │       ├── service.go
│   │       └── tcp.go
│   │
│   └── input.go
│
├── go.mod
├── go.sum
├── main.go
└── README.md
```

## Package Responsibilities

| Package | Responsibility |
|---|---|
| `cmd` | CLI commands, flags, lifecycle |
| `internal` | Target parsing and port selection |
| `models` | Shared configuration and results |
| `bootstrap` | Binary installation and removal |
| `portscan` | Main scanning orchestration and target prioritization |
| `ping` | ICMP host discovery |
| `arp` | Local IPv4 ARP discovery and MAC collection |
| `search` | TCP SYN scheduling and state classification |
| `probe` | Low-level TCP packet operations |
| `enrich` | Service identification and network enrichment |
| `output` | Terminal formatting and Markdown export |

The architecture separates orchestration from the individual scanning engines.

The main controller coordinates scanning stages, while each subsystem is responsible for its own internal execution.

## Design Principles

### Discovery Does Not Exclude Targets

ICMP and ARP are used to improve host discovery and scanning priority.

A target that does not respond remains eligible for TCP scanning.

### Deduplication Prevents Repeated Scans

Discovered and original target lists are merged into one ordered sequence.

Each unique IP is scanned only once by the TCP search stage.

### Packet Discovery Is Separate From Enrichment

SYN scanning determines port state without completing a TCP connection for every port.

Full TCP connections are reserved for enrichment of open ports.

### Port Coverage Is User-Controlled

The default scan covers ports `1-65535`.

The `-p` flag allows users to choose a smaller range without introducing separate scanning modes or changing the default behavior.

### Components Have Separate Responsibilities

The main controller manages execution order.

ICMP, ARP, SYN search, raw packet operations, and enrichment are implemented in separate packages.

## Limitations

- TCP SYN scanning currently supports IPv4.
- CIDR scanning currently supports IPv4.
- CIDR ranges larger than `/16` are rejected.
- ARP discovery only works on directly connected IPv4 networks.
- Silent ports may be classified as filtered.
- Service identification uses best-effort port mapping.
- Some services do not provide readable banners.
- HTTP probing is based on the identified service type.
- Network filtering, packet loss, rate limiting, and routing behavior may influence results.
- Full-range scans of large CIDRs can generate substantial network traffic and require significant time.

## Legal Notice

Only scan hosts and networks that you own or have explicit authorization to assess.
