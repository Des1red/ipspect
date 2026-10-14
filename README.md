# IPSpect

IPSpect is a Linux command-line IPv4 network scanner written in Go. It combines **ICMP discovery**, **local ARP discovery**, and **TCP SYN scanning** with device identification, service fingerprinting, and structured reports.

The engines can run independently or together. IPSpect uses adaptive timeouts, bounded retries, and paced transmission; its diagnostics distinguish scan results from the completeness of their accounting.

## Features

- **Host discovery:** ICMP Echo and local-network ARP, with deduplication and discovery-based scan ordering.
- **Device identification:** MAC addresses, IEEE manufacturer assignments, reverse DNS (PTR), and NetBIOS names.
- **TCP SYN scanning:** Open, closed, and filtered ports; default range **1–65535**, or a custom `-p` specification.
- **Service identification:** Embedded IANA port registry, TCP banners, HTTP/HTTPS and DNS-over-TCP probes, fingerprint evidence, and service-resolution explanations.
- **Network reliability:** Per-engine adaptive timeouts, bounded retransmissions, send pacing, and congestion handling.
- **Reporting:** Colored terminal stages, scan durations, network performance and diagnostics, and Markdown export.

For the implementation details and configuration, see [Technical Documentation](docs/TECHNICAL.md).

## Requirements

- Linux
- Go (for building from source)
- Root privileges or the appropriate raw-socket capabilities
- Permission to scan the selected network or host

ICMP and TCP SYN discovery use raw IP sockets; local ARP discovery uses Linux `AF_PACKET` sockets. ARP is limited to directly connected Layer 2 networks.

## Installation

From the project directory:

```bash
sudo go run main.go install
```

Run the installed binary:

```bash
sudo ipspect
```

To remove the installed binary:

```bash
sudo ipspect uninstall
```

You can also run directly from source without installing:

```bash
sudo go run main.go
```

The CLI also provides `help` and `version` commands.

## Usage

Without an explicit target, IPSpect prompts for an IPv4 address or CIDR range. By default, **all three engines run**, and TCP scans **ports 1–65535**.

```bash
# All engines against one host
sudo ipspect -t 192.168.1.1

# ICMP discovery across a subnet
sudo ipspect -t 192.168.1.0/24 --icmp

# Local ARP discovery and device identification
sudo ipspect -t 192.168.1.0/24 --arp --verbose

# TCP SYN scan of selected ports, followed by fingerprinting
sudo ipspect -t 192.168.1.1 --tcp -p 22,23,53,80,1900,7547

# TCP SYN scan of an inclusive range
sudo ipspect -t 192.168.1.1 --tcp -p 1-1000

# Combine discovery engines
sudo ipspect -t 192.168.1.0/24 --icmp --arp

# Save a Markdown report
sudo ipspect -t 192.168.1.1 --tcp -s
```

The same scan flags can be used with `sudo go run main.go` instead of `sudo ipspect`.

### Main options

| Option | Purpose |
|---|---|
| `-t`, `--target` | Supply a single IPv4 target or CIDR range without a prompt |
| `--icmp` | Enable ICMP discovery |
| `--arp` | Enable local ARP discovery |
| `--tcp` | Enable TCP SYN scanning, service identification, and final results |
| `-p` | Specify TCP ports: `22`, `22,80,443`, `1-1000`, or mixed values |
| `--verbose` | Show verbose scan output |
| `-s` | Export scan findings as Markdown |

If no engine flag is provided, ICMP, ARP, and TCP are all enabled. With engine flags, only the selected engines run. Their execution order is always **ICMP → ARP → TCP**. Service identification follows TCP scanning when it is enabled.

The maximum supported IPv4 CIDR scope is `/16`. Port lists are deduplicated and sorted. Discovery does **not** remove nonresponding hosts from the TCP scan.

## What the output means

IPSpect separates network discovery, TCP port states, IANA lookups, fingerprint evidence, resolved services, and timing information.

After a scan, two additional sections report transmission behavior:

- **Network Performance:** `Sent`, `Retries`, `Received`, `Dropped`, `TimedOut`, RTT (min/avg/max), and average transmission rate.
- **Network Diagnostics:** Unique requests, responses, response rate, coverage, unclassified operations, and classification status.

```text
Unique requests = Sent - Retries
Coverage = (Received + TimedOut + Dropped) / Unique requests
Response rate = Received / Unique requests
```

`Complete` means every recorded request has a final outcome; it **does not** mean the network is healthy or that every target responded. For example, a subnet with mostly unused addresses can have a low discovery response rate and 100% coverage. `Dropped` also includes non-timeout operation failures or unusable protocol replies; it does not necessarily mean network packet loss.

A TCP port is considered **open** when a matching SYN/ACK is received, **closed** on a matching RST, and **filtered** when its permitted probes expire without a classifying response.

## Reports and testing

Use `-s` to write a Markdown report in the current working directory, with a filename derived from the target specification. Reports include device discoveries, port states, service evidence, and available response headers. Sensitive cookie/authentication headers are redacted.

Run the Go tests:

```bash
go test ./...
go test -race ./internal/network/... ./internal/portscan/...
go test -count=20 ./internal/network/... ./internal/portscan/...
```

Regression coverage includes retry failures, final timeouts, late/duplicate replies, and network-statistics consistency.

## Documentation

See [docs/TECHNICAL.md](docs/TECHNICAL.md) for engine internals, timing and retry policies, packet handling, service fingerprinting, data sources, result storage, diagnostics, and limitations.

## Responsible use

Scan only systems and networks you own or are explicitly authorized to assess. IPSpect performs active network probing and can generate substantial traffic, particularly over a full port range or large CIDR scope.
