package search

import (
	"net"
	"time"

	"ipspect/internal/network/timeout"
	synprobe "ipspect/internal/portscan/tcp/probe"
)

const (
	synWindow           = 2048
	synPacketsPerSecond = 500
	synRetries          = 1

	synMinimumTimeout = 3 * time.Second

	synCongestionPause = 150 * time.Millisecond
	synMaxSendFailures = 20
)

type scanJob struct {
	hostIndex int
	ip        net.IP
	port      int
}

type pendingProbe struct {
	job     scanJob
	srcIP   net.IP
	srcPort uint16
	seq     uint32

	attempts int

	sentAt   time.Time
	deadline time.Time
}

type scanState struct {
	scanner  *synprobe.SYNScanner
	timeouts *timeout.Manager

	ports []int

	pending   map[uint16]*pendingProbe
	usedPorts map[uint16]struct{}

	hostIndex int
	portIndex int

	moreJobs bool

	pauseUntil              time.Time
	consecutiveSendFailures int

	retrySend func(*pendingProbe) error
}
