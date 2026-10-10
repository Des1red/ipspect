package ping

import (
	"net"
	"time"

	"golang.org/x/net/icmp"
)

const (
	icmpWindow  = 500
	icmpTimeout = 750 * time.Millisecond
	icmpRetries = 3
)

type icmpReply struct {
	ip  net.IP
	seq int
}

type icmpProbe struct {
	ip net.IP

	seq int

	attempts int

	deadline time.Time
}

type icmpScanner struct {
	id int

	v4 *icmp.PacketConn
	v6 *icmp.PacketConn

	replies chan icmpReply
}

type scanState struct {
	scanner *icmpScanner

	total int

	pending map[int]*icmpProbe

	usedSequences map[int]struct{}

	live map[string]net.IP

	nextTarget   int
	nextSequence int
}
