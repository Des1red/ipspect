# IPSpect — Technical Documentation

This document describes the scanning model, packet handling, reliability controls, service fingerprinting, reporting, and limitations of IPSpect. For installation and common commands, see the [README](../README.md).

## 1. Execution model

Three selectable engines run in a fixed order when enabled:

```text
Target / CIDR input
       |
       v
Engine selection
       |
       +--> ICMP discovery -----------------+
       |                                    |
       +--> ARP discovery -> device details -+--> discovery-based target priority
                                                   |
                                                   v
                                              TCP SYN scanning
                                                   |
                                                   v
                                              Open TCP ports
                                                   |
                                           +-------+--------+
                                           |                |
                                      IANA lookup     Fingerprinting
                                           |                |
                                           +-------+--------+
                                                   |
                                              Service resolution
                                                   |
                                              Results / export
```

The execution stages are conditional: an ARP-only scan stops after local-device discovery; TCP-only scanning does not require an ICMP or ARP response. The controller calculates terminal stage numbers from the selected engines.

### Targets and port selection

- Single IPv4 targets and IPv4 CIDR ranges are supported, up to the configured `/16` scope limit.
- `-t` / `--target` bypasses the interactive target prompt.
- TCP scanning covers **ports 1–65535 by default**. `-p` accepts individual ports, lists, inclusive ranges, and mixed expressions.
- Selected ports are deduplicated and sorted.
- ICMP and ARP responses prioritize scanning order but do **not** exclude the original targets.

The priority order for TCP is: (1) discovered ICMP responders, (2) ARP-only responders, and (3) remaining original targets. Each unique original target is scanned once.

## 2. Shared timeout and retry infrastructure

The reliability components are organized under:

```text
internal/network/
  timeout/   Adaptive deadline estimation and retry backoff
  app/       Per-protocol transmission, RTT and outcome accounting
```

The timeout manager provides `Duration(mode, scope)`, `Observe(mode, scope, rtt)` and `Backoff(mode, scope, retry)`. It maintains per-scope RTT estimates with mode-level fallback, uses smoothed RTT and RTT variation, and requires a warmup of **four valid samples** before applying learned deadlines. Observations and manager state are synchronized for concurrent access.

Retries are counted as additional **transmissions**, not additional logical requests. A response after retransmission may correspond to an earlier attempt, so ARP/ICMP/TCP avoid using ambiguous post-retry RTTs to train the adaptive estimator. Failed transmissions do not consume the permitted network retry allowance in the paced ICMP/TCP schedulers.

### Engine policies

| Setting | ARP | ICMP | TCP SYN |
|---|---:|---:|---:|
| Initial timeout | 1.25 s | 1.5 s | 7 s |
| Adaptive minimum | 350 ms | 500 ms | 750 ms (manager) |
| Additional initial floor | — | — | 3 s (scanner) |
| Adaptive maximum | 5 s | 8 s | 12 s |
| Retries after initial send | 2 | 3 | 1 |
| Send pacing | 500 pkt/s | 50 pkt/s | 500 pkt/s |
| Outstanding probe window | Per-target ARP state | 500 | 2,048 |

The TCP-specific initial minimum is deliberately stricter than the manager's generic minimum: short RST RTTs from closed ports should not cause delayed SYN/ACK responses to be treated as filtered too aggressively.

Backoff doubles the estimated deadline and respects the mode's maximum. With no learned samples, representative waits are:

- **ARP:** initial 1.25 s, retry 1 after 2.5 s, retry 2 after 5 s.
- **ICMP:** initial 1.5 s, then 3 s, 6 s, and 8 s (capped).
- **TCP SYN:** initial 7 s, then a retry wait capped at 12 s.

A timeout is counted only at a **final, exhausted outcome**, not at each intermediate retry deadline. Schedulers independently enforce transmission pacing; the adaptive timeout manager sets deadlines, not packet rates.

### Congestion behavior

The ICMP and TCP schedulers handle transient `ENOBUFS`/`EAGAIN` send failures by pausing and trying again without advancing the logical job or retry count. A persistent run of send failures terminates with an error instead of falsely declaring the target filtered or timed out. ICMP and TCP start with a 150 ms congestion pause and a 20-consecutive-failure threshold.

## 3. ICMP discovery

Implementation: `internal/scanner/icmp/`.

The engine sends ICMP Echo requests to the selected addresses using raw sockets. Replies are matched using the ICMP identifier, sequence number, and source IP. Up to 500 probes can be pending while actual transmissions are paced at 50 packets/second.

A target receives an initial attempt and up to three successful retransmissions. Replies remove pending requests and enter the deduplicated reachable-host set. Timeouts are recorded only after the final deadline.

The engine keeps results in `models.LOOT.ICMPReachable`.

**Important:** ICMP nonresponse does not prove that a host is offline. Firewalls and router behavior can block or deprioritize Echo replies.

## 4. ARP discovery and enrichment

Implementation: `internal/scanner/arp/` and `internal/scanner/arp/enrich/`.

ARP uses Linux `AF_PACKET` raw sockets on eligible directly connected interfaces. It groups destinations by interface, sends ARP requests, and validates replies against the local target IP/MAC and pending requests. A successful reply records the responding IPv4 address, the ARP payload's sender MAC and the receiving interface.

ARP uses individual deadlines and two retries per target. Late replies are accepted while the target remains pending; duplicate replies are ignored. The receiver does not require the outer Ethernet source MAC to match the ARP payload sender MAC, which accommodates observed forwarded or rewritten local-network frames.

Device enrichment may add:

| Field | Method / meaning |
|---|---|
| IP / MAC | Validated ARP reply |
| Interface | Local interface used for discovery |
| Vendor | Embedded IEEE assignment registry (MA-L, MA-M, MA-S) |
| PTR name | Reverse DNS lookup |
| NetBIOS name | UDP/137 Node Status response |
| Locally administered MAC | MAC assignment-bit classification |

More-specific IEEE assignments take precedence over less-specific ones. Vendor associations identify registered organizations, not guaranteed device models. Randomized or locally administered MAC addresses often cannot be attributed reliably. PTR and NetBIOS names are supplementary evidence and may be absent or misleading.

ARP cannot normally discover addresses behind a router because ordinary routing does not forward Layer 2 ARP broadcasts.

## 5. TCP SYN scanning

Implementation:

```text
internal/scanner/tcp/
  search/   Target/port cursor, scheduler, retries, reply classification
  probe/    Raw socket, packet creation, checksums, SYN/RST transmission, receiver
  enrich/   TCP banner, IANA lookup, fingerprinting, service resolution
```

A half-open SYN probe does not complete the TCP three-way handshake:

```text
Open:   IPSpect --> SYN     --> target
        IPSpect <-- SYN/ACK <-- target
        IPSpect --> RST     --> target

Closed: IPSpect --> SYN     --> target
        IPSpect <-- RST     <-- target

Filtered/unanswered: No matching response before the final retry deadline
```

Each outstanding probe tracks its destination IP/port, local source IP/port, TCP sequence number, send time, retry count and deadline. Matching replies classify ports as:

| Observed event | Classification |
|---|---|
| Matching SYN/ACK | `open` |
| Matching RST | `closed` |
| No valid response after permitted retries and final deadline | `filtered` |

The scanner reserves source ports for outstanding probes, releases them on completion, and uses matching source/destination ports and target IPs to associate incoming TCP replies. ACK values are checked for SYN/ACK and RST/ACK replies. RST cleanup packets are **not** counted as discovery requests.

The scanner sends at up to 500 packets/second with a 2,048-probe window and one SYN retransmission. A raw-receiver channel is buffered (8,192 replies) and uses backpressure instead of silently dropping replies when the application channel fills. Kernel-level packet loss and network-device behavior remain possible.

A `filtered` result indicates an unclassified/expired probe, not proof of a firewall; packet loss and congestion can have the same effect.

### Result storage

- Single-target scans preserve open port details and may retain individual closed/filtered ports.
- Default full-range multi-target scans count closed/filtered ports instead of retaining every individual port number.
- Explicit `-p` selections can retain individual closed/filtered port details for focused inspection.
- Open ports remain individually available for enrichment.

### Performance considerations

A full scan contains 65,535 port requests per target, before any retries. At a maximum of 500 transmitted packets/second, send pacing alone imposes a lower bound of roughly 131 seconds for one full-range scan, excluding retransmissions, waiting for outstanding probes, and fingerprinting. Large scopes or unresponsive targets can take significantly longer.

## 6. Service identification

Service identification runs only against TCP ports classified as open.

1. **IANA lookup:** read the embedded registered service name for the TCP port.
2. **Fingerprinting:** inspect banners and, where supported, send application-level probes.
3. **Resolution:** preserve registered and observed services separately, then select a final service with a reason.

A registered name is not proof of the running application. A fingerprint can override the IANA association; if no supported fingerprint matches, the service may remain `unknown`.

### Supported fingerprint evidence

| Protocol | Evidence |
|---|---|
| SSH | Identification banner such as `SSH-2.0-...` |
| FTP | Recognizable greeting |
| SMTP | Recognizable SMTP/ESMTP greeting |
| HTTP | Valid response to an active HTTP request |
| HTTPS | HTTP response obtained over TLS |
| DNS | Framed DNS-over-TCP response with matching transaction ID, flags, question count and question |

IPSpect can preserve multiple protocol observations per port. IANA aliases such as `domain` → `dns` allow compatible registry/fingerprint labels without conflating HTTP and HTTPS. The resolver retains evidence and explains confirmed, corroborated, conflicting, and unknown results.

### Application probes and headers

- Banner collection opens a regular TCP connection and attempts to read an initial response.
- HTTP requests gather status, headers, and supported product hints; sensitive headers such as `Set-Cookie`, `WWW-Authenticate`, and `Proxy-Authenticate` are redacted.
- HTTPS probing does not validate certificate authenticity; an observed TLS handshake is not proof of server identity.
- DNS-over-TCP sends a length-framed DNS question and validates the reply before recording DNS service evidence.
- Telnet negotiations may be visible as binary banner evidence without receiving a confirmed Telnet fingerprint.
- Reported service latency comes from a TCP connection attempt, **not** the SYN round-trip time or total fingerprinting duration.

For TLS-enabled raw probes and HTTPS, the current `TCPConnect` performance metric includes the TLS handshake in the connection outcome. This is an accounting convention, not strictly a measurement of bare TCP establishment.

## 7. Network Performance and Network Diagnostics

Implementation: `internal/network/app/`.

Each protocol has separate counters and timing state. Protocols include ICMP, ARP, TCP SYN, DNS, NetBIOS, TCP Connect, HTTP, HTTPS, and DNS-TCP.

### Counters

| Counter | Definition |
|---|---|
| `Sent` | Successful request transmissions or initiated application operations, including successful retries |
| `Retries` | Successful additional network transmissions of an existing logical request |
| `Received` | Requests/operations completed with a classifying response |
| `TimedOut` | Requests/operations with a final timeout |
| `Dropped` | Non-timeout operation failure or invalid/unusable response; not necessarily an actual dropped packet |
| RTT | Minimum, average and maximum recorded valid RTT samples |
| Rate | Total recorded sends divided by active elapsed time (`pkt/s` or `op/s`) |

`app.Fail(protocol, err)` counts timeout-classified `net.Error` values as `TimedOut` and other non-nil errors as `Dropped`. Application protocol validation paths call `Drop` when a response is not usable. A successful connection can be counted as `TCPConnect: Received` while the subsequent HTTP or DNS-TCP request fails independently.

A retransmission increments both `Sent` and `Retries`. A reply following a retry is one final `Received` outcome, and ambiguous post-retry RTTs are omitted from the adaptive estimator.

### Diagnostics formulas

```text
UniqueRequests = Sent - Retries
Classified     = Received + TimedOut + Dropped
Unclassified   = UniqueRequests - Classified
ResponseRate   = Received / UniqueRequests × 100
Coverage       = Classified / UniqueRequests × 100
```

Diagnostic statuses:

- **Complete:** all recorded logical requests have final outcomes.
- **Partial:** some recorded requests lack classified outcomes.
- **Inconsistent:** impossible counters (negative counts, retries exceeding sends, or outcomes exceeding unique requests).
- **No data:** no operations were recorded.

Coverage measures *accounting completeness*, not device availability or network health. A subnet with four responding hosts and hundreds of unused addresses may have a low response rate and **100% coverage**. Similarly, NetBIOS can have 0% response and 100% coverage when every attempt ends in a recorded timeout or unusable response.

## 8. Output and Markdown export

The terminal presents only the enabled stages, followed by execution times, Network Performance, and Network Diagnostics. TCP stages add DB Lookup, Fingerprint Lookup and final port-level evidence.

Use `-s` to write a Markdown report named from the target specification into the current directory. Reports can include target and port specifications, ICMP and ARP discoveries, manufacturer/hostname evidence, TCP states, IANA services, fingerprint observations, banners, headers and reasons for final resolution. Sensitive HTTP authentication and cookie fields are redacted.

## 9. Code layout and data

```text
ipspect/
  cmd/                       CLI, flags and lifecycle commands
  internal/
    bootstrap/               Binary installation and removal
    database/load/           Embedded data loading (including probe requests)
    models/                  Scope, configuration, and scan results
    network/
      app/                   Counters, RTT, diagnostics and error classification
      timeout/               Adaptive RTT estimator and backoff
    output/                  Terminal formatting and Markdown reporting
    scanner/
      icmp/                  ICMP discovery
      arp/
        enrich/              IEEE, PTR, NetBIOS device enrichment
      tcp/
        probe/               Raw TCP packet operations
        search/              SYN port scheduling and classification
        enrich/              Banners, fingerprinting, service resolution
  docs/
    TECHNICAL.md
  README.md
```

IEEE MAC assignment data and IANA service-name data are embedded locally so scans do not need an external API for those lookups. The exact datasets are refreshed from their upstream registries and require rebuilding/reinstalling the binary after an update.

- IEEE Registration Authority: <https://standards.ieee.org/products-programs/regauth/>
- IEEE assignment data: <https://standards-oui.ieee.org/>
- IANA Service Name and Transport Protocol Port Number Registry: <https://www.iana.org/assignments/service-names-port-numbers/>

## 10. Testing and verification

```bash
# Complete repository test suite
go test ./...

# Race detection on network and scanning packages
go test -race ./internal/network/... ./internal/scanner/...

# Repeat regression tests to expose intermittent failures
go test -count=20 ./internal/network/... ./internal/scanner/...
```

The regression tests cover ARP expiry, queued retries and late replies; ICMP congestion/retry accounting and final timeouts; TCP late RST-ACK replies, retry send failures and filtered classification; and network counter consistency. They exercise state-machine behavior without opening raw sockets. Integration behavior still depends on the running kernel, routing, network conditions and target behavior.

## 11. Limitations and responsible use

- Linux-only raw-socket and local ARP implementation; TCP SYN scanning currently targets IPv4.
- ARP is restricted to directly connected Layer 2 domains; it does not discover hosts across normal routers.
- Host nonresponse is not proof of absence; a filtered SYN port is not conclusive proof of a firewall.
- MAC vendor associations, PTR names and NetBIOS names are not authenticated identities.
- Fingerprinting recognizes only supported protocols and response formats; unusual implementations can remain `unknown`.
- Certificate verification is disabled for the HTTPS fingerprint identification probe.
- Full-range scans across multiple targets can create heavy traffic and long execution times.

**Only scan systems and networks you own or are explicitly authorized to assess.**
