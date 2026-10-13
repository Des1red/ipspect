package search

import (
	synprobe "ipspect/internal/portscan/tcp/probe"
	"net"
	"time"
)

const (
	synWindow  = 500
	synTimeout = 10 * time.Second
)

type scanJob struct {
	hostIndex int
	ip        net.IP
	port      int
}

type pendingProbe struct {
	job      scanJob
	srcIP    net.IP
	srcPort  uint16
	seq      uint32
	sentAt   time.Time
	deadline time.Time
}

type scanState struct {
	scanner *synprobe.SYNScanner

	ports []int

	pending map[uint16]*pendingProbe

	usedPorts map[uint16]struct{}

	hostIndex int
	portIndex int

	moreJobs bool
}
