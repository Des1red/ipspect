package ping

import (
	"net"
	"time"

	"ipspect/internal/network/timeout"

	"golang.org/x/net/icmp"
)

const (
	icmpWindow  = 500
	icmpRetries = 3

	icmpPacketsPerSecond = 50

	icmpCongestionPause = 150 * time.Millisecond
	icmpMaxSendFailures = 20
)

type icmpReply struct {
	ip  net.IP
	seq int

	receivedAt time.Time
}

type icmpProbe struct {
	ip net.IP

	seq int

	attempts int

	sentAt   time.Time
	deadline time.Time
}

type icmpScanner struct {
	id int

	v4 *icmp.PacketConn
	v6 *icmp.PacketConn

	replies chan icmpReply
}

type scanState struct {
	scanner                 *icmpScanner
	timeouts                *timeout.Manager
	pauseUntil              time.Time
	consecutiveSendFailures int
	total                   int

	pending map[int]*icmpProbe

	usedSequences map[int]struct{}

	live map[string]net.IP

	nextTarget   int
	nextSequence int

	retrySend func(*icmpProbe) error
}
