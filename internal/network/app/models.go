package app

import (
	"sync"
	"time"
)

type Protocol string

const (
	ICMP Protocol = "icmp"
	ARP  Protocol = "arp"
	TCP  Protocol = "tcp"
)

type RTTStats struct {
	Minimum time.Duration
	Average time.Duration
	Maximum time.Duration
}

type ProtocolStats struct {
	Sent     int
	Received int
	Dropped  int
	TimedOut int

	RTT              RTTStats
	TransmissionRate float64
}

type NetworkStats struct {
	ICMP ProtocolStats
	ARP  ProtocolStats
	TCP  ProtocolStats
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
	icmpState protocolState
	arpState  protocolState
	tcpState  protocolState
)

func stateFor(
	protocol Protocol,
) *protocolState {
	switch protocol {
	case ICMP:
		return &icmpState

	case ARP:
		return &arpState

	case TCP:
		return &tcpState

	default:
		return nil
	}
}
