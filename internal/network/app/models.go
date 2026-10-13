package app

import (
	"sync"
	"time"
)

type Protocol string

const (
	ICMP       Protocol = "icmp"
	ARP        Protocol = "arp"
	DNS        Protocol = "dns"
	NetBIOS    Protocol = "netbios"
	TCP        Protocol = "tcp"
	TCPConnect Protocol = "tcp-connect"
	HTTP       Protocol = "http"
	HTTPS      Protocol = "https"
	DNSTCP     Protocol = "dns-tcp"
)

type RTTStats struct {
	Minimum time.Duration
	Average time.Duration
	Maximum time.Duration
}

type ProtocolStats struct {
	Sent     int
	Retries  int
	Received int
	Dropped  int
	TimedOut int

	RTT              RTTStats
	TransmissionRate float64
}

type NetworkStats struct {
	ICMP       ProtocolStats
	ARP        ProtocolStats
	DNS        ProtocolStats
	NetBIOS    ProtocolStats
	TCP        ProtocolStats
	TCPConnect ProtocolStats
	HTTP       ProtocolStats
	HTTPS      ProtocolStats
	DNSTCP     ProtocolStats
}
type protocolState struct {
	mu sync.Mutex

	stats ProtocolStats

	rttSamples int
	rttTotal   time.Duration

	started time.Time
	stopped time.Time
}

var (
	icmpState       protocolState
	arpState        protocolState
	dnsState        protocolState
	netbiosState    protocolState
	tcpState        protocolState
	tcpConnectState protocolState
	httpState       protocolState
	httpsState      protocolState
	dnsTCPState     protocolState
)

func stateFor(
	protocol Protocol,
) *protocolState {
	switch protocol {
	case ICMP:
		return &icmpState

	case ARP:
		return &arpState

	case DNS:
		return &dnsState

	case NetBIOS:
		return &netbiosState

	case TCP:
		return &tcpState

	case TCPConnect:
		return &tcpConnectState

	case HTTP:
		return &httpState

	case HTTPS:
		return &httpsState

	case DNSTCP:
		return &dnsTCPState

	default:
		return nil
	}
}
