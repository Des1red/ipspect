package search

import (
	synprobe "ipspect/internal/portscan/probe"
	"net"
	"time"
)

const (
	synWindow  = 500
	synTimeout = 500 * time.Millisecond
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
